"""Bounded concurrent scanner execution; failures are coverage gaps, not passes."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import signal
import sys
import tempfile
import time
import uuid
from pathlib import Path

from models import ScannerResult, ScanReport, SecurityFinding, compute_finding_id
from redaction import redact_secrets
from scope_guard import resolve_target
from scope_proxy import scoped_proxy

MAX_OUTPUT = 32 * 1024 * 1024
ZAP_INTERNAL_FAILURE = 3  # zap-baseline's exit code for "other failure"
ZAP_SCOPE_ABORT = 43  # our scope hook's fail-closed exit; never confused with 3


def _which(binary: str) -> str | None:
    candidate = Path(sys.executable).parent / binary
    return shutil.which(binary) or (str(candidate) if candidate.is_file() else None)


async def _exec(
    *argv: str, cwd: str | None = None, timeout: int = 600, env_extra: dict | None = None
) -> tuple[int, str, str]:
    binary = _which(argv[0])
    if not binary:
        return 127, "", f"{argv[0]} not installed"
    env = dict(os.environ)
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    env.update(env_extra or {})
    # A temp file caps memory usage. Kill the process group on timeout/cancel.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = await asyncio.create_subprocess_exec(
            binary, *argv[1:], cwd=cwd, env=env, stdout=out, stderr=err, start_new_session=True
        )
        waiter = asyncio.create_task(proc.wait())
        code = 0
        try:
            async with asyncio.timeout(timeout):
                while proc.returncode is None:
                    if os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > MAX_OUTPUT:
                        code = 125
                        break
                    try:
                        await asyncio.wait_for(asyncio.shield(waiter), timeout=0.2)
                    except TimeoutError:
                        pass
                if not code:
                    code = proc.returncode or 0
        except TimeoutError:
            code = 124
        finally:
            if proc.returncode is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await proc.wait()
            await waiter
        if os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > MAX_OUTPUT:
            code = 125
        out.seek(0)
        err.seek(0)
        return (
            code,
            out.read(MAX_OUTPUT).decode(errors="replace"),
            err.read(8192).decode(errors="replace"),
        )


def _load_json(text: str, expected=dict):
    data = json.loads(text)
    if not isinstance(data, expected):
        raise ValueError("Unexpected scanner JSON shape")
    return data


def parse_semgrep(data: dict) -> list[SecurityFinding]:
    levels = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    return [
        SecurityFinding(
            tool_name="Semgrep",
            rule_id=r["check_id"],
            severity=levels.get(r.get("extra", {}).get("severity"), "INFO"),
            file_path=r["path"],
            line_number=r.get("start", {}).get("line"),
            column_number=r.get("start", {}).get("col"),
            raw_description=r.get("extra", {}).get("message", ""),
            code_snippet=r.get("extra", {}).get("lines"),
        )
        for r in data.get("results", [])
    ]


def parse_gitleaks(data: list) -> list[SecurityFinding]:
    # Secret evidence is never retained, even for an unrecognized credential type.
    return [
        SecurityFinding(
            tool_name="Gitleaks",
            rule_id=r.get("RuleID", "secret"),
            severity="HIGH",
            file_path=r.get("File"),
            line_number=r.get("StartLine") or None,
            raw_description=r.get("Description", "Potential exposed credential"),
            code_snippet="[REDACTED_SECRET_EVIDENCE]",
        )
        for r in data
    ]


def _trivy_cvss(item: dict) -> tuple[float | None, str | None, str | None]:
    """Published CVSS 3.x base score and vector, preferring NVD, then GHSA."""
    sources = item.get("CVSS") or {}
    for name in ("nvd", "ghsa", "redhat", *sources):
        entry = sources.get(name) or {}
        score, vector = entry.get("V3Score"), entry.get("V3Vector")
        if isinstance(score, (int, float)) and 0 <= score <= 10:
            return float(score), vector if isinstance(vector, str) else None, name.upper()
    return None, None, None


def parse_trivy(data: dict) -> list[SecurityFinding]:
    findings = []
    for result in data.get("Results", []) or []:
        for group in ("Vulnerabilities", "Misconfigurations", "Secrets"):
            for item in result.get(group, []) or []:
                rule = item.get("VulnerabilityID") or item.get("ID") or item.get("RuleID") or group
                # Distinguish two affected packages sharing one CVE and manifest.
                if item.get("PkgName"):
                    rule += ":" + item["PkgName"]
                level = item.get("Severity", "INFO").upper()
                description = item.get("Title") or item.get("Description") or rule
                if group == "Secrets":
                    snippet = "[REDACTED_SECRET_EVIDENCE]"
                elif group == "Misconfigurations":
                    snippet = item.get("Message") or None
                    if item.get("Resolution"):
                        description += f". Fix: {item['Resolution']}"
                else:
                    snippet = (
                        f"{item.get('PkgName', '')} {item.get('InstalledVersion', '')}; "
                        f"fixed: {item.get('FixedVersion') or 'no fixed version yet'}"
                    )
                score, vector, source = (
                    _trivy_cvss(item) if group == "Vulnerabilities" else (None,) * 3
                )
                line = item.get("StartLine") or (item.get("CauseMetadata") or {}).get("StartLine")
                findings.append(
                    SecurityFinding(
                        tool_name="Trivy",
                        rule_id=rule,
                        severity=level
                        if level in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
                        else "INFO",
                        file_path=result.get("Target"),
                        line_number=line or None,
                        raw_description=description,
                        code_snippet=snippet,
                        cvss_score=score,
                        cvss_vector=vector,
                        cvss_source=f"published advisory ({source})" if source else None,
                    )
                )
    return findings


def parse_zap(data: dict) -> list[SecurityFinding]:
    findings = []
    for site in data.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            for instance in alert.get("instances") or [{"uri": site.get("@name")}]:
                findings.append(
                    SecurityFinding(
                        tool_name="OWASP ZAP",
                        rule_id=str(alert.get("pluginid", "unknown")),
                        severity={"3": "HIGH", "2": "MEDIUM", "1": "LOW"}.get(
                            str(alert.get("riskcode")), "INFO"
                        ),
                        endpoint_url=instance.get("uri"),
                        raw_description=re.sub(r"<[^>]+>", "", alert.get("desc", "")),
                        code_snippet=redact_secrets(instance.get("evidence", ""))[:1000],
                    )
                )
    return findings


def _normalize(findings: list[SecurityFinding], root: Path):
    for finding in findings:
        if finding.file_path:
            path = Path(finding.file_path)
            resolved = (path if path.is_absolute() else root / path).resolve()
            try:
                finding.file_path = resolved.relative_to(root).as_posix()
            except ValueError:
                # Never open scanner-supplied paths outside the approved source.
                finding.file_path = "[outside-source]/" + path.name
            else:
                if (
                    finding.tool_name == "Semgrep"
                    and finding.line_number
                    and resolved.is_file()
                    and resolved.stat().st_size <= 2_000_000
                ):
                    lines = resolved.read_text(errors="replace").splitlines()
                    row = finding.line_number - 1
                    finding.code_snippet = "\n".join(lines[max(0, row - 2) : row + 3])[:4000]
        finding.raw_description = redact_secrets(finding.raw_description)
        finding.code_snippet = redact_secrets(finding.code_snippet or "")
        if finding.endpoint_url:
            finding.endpoint_url = redact_secrets(finding.endpoint_url)
        finding.finding_id = compute_finding_id(
            finding.tool_name,
            finding.rule_id,
            finding.file_path,
            finding.line_number,
            finding.endpoint_url,
        )


async def _scan(
    tool: str,
    argv: list[str],
    parser,
    root: Path,
    *,
    report_path=None,
    accepted=(0,),
    expected=dict,
    env=None,
) -> ScannerResult:
    start = time.monotonic()
    code, out, err = await _exec(*argv, cwd=str(root), env_extra=env)
    status = "skipped" if code == 127 else "timeout" if code == 124 else "failed"
    result = ScannerResult(
        tool_name=tool,
        status=status,
        exit_code=code,
        duration_seconds=round(time.monotonic() - start, 2),
    )
    if code not in accepted:
        # Do not expose arbitrary scanner stderr: it can contain secrets.
        result.message = {
            127: "Executable not installed",
            124: "Scanner timed out",
            125: "Output limit exceeded",
        }.get(code, f"Scanner exited {code}; check local tool configuration")
        return result
    try:
        if report_path:
            path = Path(report_path)
            if path.stat().st_size > MAX_OUTPUT:
                raise ValueError("Report too large")
            out = path.read_text()
        data = _load_json(out, expected)
        result.findings = parser(data)
        _normalize(result.findings, root)
        result.finding_count = len(result.findings)
        result.status = "completed"
        if tool == "Semgrep" and data.get("errors"):
            errors = data["errors"]
            # Per-file timeouts and partial parses are warnings; anything not
            # explicitly a warning is treated as a failed scan.
            fatal = [e for e in errors if not isinstance(e, dict) or e.get("level") != "warn"]
            if fatal:
                result.status = "failed"
                result.message = "Semgrep reported scan errors; available partial findings retained"
            else:
                result.message = (
                    f"{len(errors)} file-level warnings (timeouts or partial parses); "
                    "those files may be under-scanned"
                )
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        result.message = "Missing, invalid or unsupported scanner report"
    return result


_RULES_DIR = Path(__file__).parent / "rules"


def semgrep_configs(offline: bool, config: str | None) -> list[str]:
    if config:
        return [config]
    # Bundled rules: the baseline, bug classes found in manual review, and
    # standard OWASP classes that p/default does not cover.
    local = [
        str(_RULES_DIR / name)
        for name in ("baseline.yml", "manual-lessons.yml", "coverage-extras.yml")
    ]
    if offline:
        # Local snapshot of the p/default pack (fetch_rules.py), when downloaded.
        pack = _RULES_DIR / "p-default.yml"
        return ([str(pack)] if pack.is_file() else []) + local
    # Semgrep refuses `--config auto` when metrics are off, so name the pack.
    return ["p/default", *local]


async def scan_semgrep(root: Path, offline: bool, config: str | None):
    configs = semgrep_configs(offline, config)
    if offline and not all(Path(c).is_file() for c in configs):
        return ScannerResult(
            tool_name="Semgrep", status="failed", message="Offline mode requires a local rule file"
        )
    config_args = [arg for c in configs for arg in ("--config", c)]
    result = await _scan(
        "Semgrep",
        [
            "semgrep",
            "scan",
            *config_args,
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
            ".",
        ],
        parse_semgrep,
        root,
        env={"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"},
    )
    _strip_local_rule_prefix(result.findings, configs)
    if offline and not config and not (_RULES_DIR / "p-default.yml").is_file():
        note = "Only the small bundled rules ran; run fetch_rules.py for the full offline pack."
        result.message = f"{result.message} {note}".strip()
    return result


def _strip_local_rule_prefix(findings: list[SecurityFinding], configs: list[str]) -> None:
    """Semgrep prefixes rules from a local file with that file's directory path
    (home.user.project.rules.<id>). Strip it so fingerprints match across machines,
    install locations, and online vs offline runs of the same pack."""
    prefixes = sorted(
        {
            str(Path(c).resolve().parent).strip("/").replace("/", ".") + "."
            for c in configs
            if Path(c).is_file()
        },
        key=len,
        reverse=True,
    )
    for finding in findings:
        prefix = next((p for p in prefixes if finding.rule_id.startswith(p)), None)
        if prefix:
            finding.rule_id = finding.rule_id[len(prefix) :]
            finding.finding_id = compute_finding_id(
                finding.tool_name,
                finding.rule_id,
                finding.file_path,
                finding.line_number,
                finding.endpoint_url,
            )


async def scan_gitleaks(root: Path):
    with tempfile.TemporaryDirectory(prefix="ssp-gitleaks-") as directory:
        output = str(Path(directory) / "report.json")
        return await _scan(
            "Gitleaks",
            [
                "gitleaks",
                "detect",
                "--source",
                ".",
                "--no-git",
                "--report-format",
                "json",
                "--report-path",
                output,
                "--redact=100",
                "--no-banner",
                "--exit-code",
                "0",
            ],
            parse_gitleaks,
            root,
            report_path=output,
            expected=list,
        )


async def scan_trivy(root: Path, offline: bool):
    argv = ["trivy", "fs", "--quiet", "--format", "json", "--scanners", "vuln,misconfig,secret"]
    if offline:
        argv += [
            "--offline-scan",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
        ]
    return await _scan("Trivy", argv + ["."], parse_trivy, root)


async def scan_zap(root: Path, target_url: str, offline: bool):
    target = resolve_target(target_url)  # direct callers cannot bypass scope validation
    if not _which("docker"):
        return ScannerResult(
            tool_name="OWASP ZAP", status="skipped", message="Docker not installed"
        )
    with (
        tempfile.TemporaryDirectory(prefix="ssp-zap-") as directory,
        scoped_proxy(target) as proxy_port,
    ):
        # Run as the directory owner; never make hooks/reports world-writable.
        hook = Path(directory) / "scope_hook.py"
        hook.write_text(f"""import os\n
def zap_started(zap, target):
    try:
        def ok(result):
            if result != 'OK':
                raise RuntimeError('Scope configuration refused')
        ok(zap.network.set_socks_proxy_enabled(False))
        ok(zap.network.set_http_proxy('127.0.0.1', {proxy_port}))
        for exclusion in zap.network.get_http_proxy_exclusions:
            ok(zap.network.remove_http_proxy_exclusion(exclusion['host']))
        ok(zap.network.set_http_proxy_enabled(True))
        if str(zap.network.is_http_proxy_enabled).lower() != 'true':
            raise RuntimeError('Scope proxy is not enabled')
        zap.spider.set_option_process_form(False)
        zap.spider.set_option_post_form(False)
    except Exception:
        # Hook exceptions are otherwise logged/ignored by the baseline script.
        os._exit({ZAP_SCOPE_ABORT})
""")
        os.chmod(hook, 0o644)
        name = "ssp-zap-" + uuid.uuid4().hex[:12]
        argv = [
            "docker",
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            "host",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--workdir",
            "/zap/wrk",
            "--pull=never" if offline else "--pull=missing",
            "-v",
            f"{directory}:/zap/wrk:rw",
            os.getenv("SSP_ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:stable"),
            "zap-baseline.py",
            "-t",
            target.url,
            "-J",
            "zap.json",
            "-I",
            "--autooff",
            "--hook=/zap/wrk/scope_hook.py",
            "-z",
            "-dir /zap/wrk/zap-home -config autoupdate.checkOnStart=false "
            "-config autoupdate.installAddonUpdates=false",
            "-m",
            "1",
            "-T",
            "5",
        ]
        name_index = argv.index("--name") + 1
        result = None
        # zap-baseline exits 3 for internal failures (e.g. a slow daemon start),
        # which was seen intermittently under load. Retry that once. The scope
        # hook runs again on the retry, so scope enforcement is never skipped.
        for attempt in (1, 2):
            argv[name_index] = f"{name}-{attempt}"
            (Path(directory) / "zap.json").unlink(missing_ok=True)
            shutil.rmtree(Path(directory) / "zap-home", ignore_errors=True)
            try:
                result = await _scan(
                    "OWASP ZAP",
                    argv,
                    parse_zap,
                    root,
                    report_path=Path(directory) / "zap.json",
                    accepted=(0, 1, 2),
                )
            finally:
                # Killing the docker CLI alone does not stop its container.
                await _exec("docker", "rm", "-f", argv[name_index], timeout=20)
            if result.exit_code != ZAP_INTERNAL_FAILURE or attempt == 2:
                break
        if result.exit_code == ZAP_SCOPE_ABORT:
            result.message = (
                "ZAP could not be forced through the scope proxy; scan aborted before "
                "crawling (fail-closed)"
            )
        elif result.exit_code == ZAP_INTERNAL_FAILURE:
            result.message = "ZAP failed internally on two attempts; try the scan again"
        elif attempt == 2:
            result.message = (
                f"{result.message} Completed on retry after a ZAP internal failure.".strip()
            )
        return result


async def run_scanners(
    target_dir: str,
    target_url: str | None = None,
    *,
    offline: bool = True,
    semgrep_config: str | None = None,
) -> ScanReport:
    if target_url:
        resolve_target(target_url)  # happens BEFORE any scanner subprocess
    root = Path(target_dir).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Source must be an existing directory")
    if semgrep_config and Path(semgrep_config).is_file():
        semgrep_config = str(Path(semgrep_config).resolve())
    report = ScanReport(
        target_dir=str(root),
        target_url=redact_secrets(target_url) if target_url else None,
        scope_reason="Validated loopback target" if target_url else "Static source scan only",
    )
    tasks = [
        scan_semgrep(root, offline, semgrep_config),
        scan_gitleaks(root),
        scan_trivy(root, offline),
    ]
    names = ["Semgrep", "Gitleaks", "Trivy"]
    if target_url:
        tasks.append(scan_zap(root, target_url, offline))
        names.append("OWASP ZAP")
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for name, result in zip(names, results, strict=True):
        if isinstance(result, BaseException):
            result = ScannerResult(
                tool_name=name, status="failed", message="Scanner could not complete"
            )
        report.scanners.append(result)
        report.findings.extend(result.findings)
    report.total_raw_findings = len(report.findings)
    return report.recount()
