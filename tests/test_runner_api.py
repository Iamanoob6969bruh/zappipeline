import asyncio
import json
import sys

import pytest
from fastapi.testclient import TestClient

import main
import runner


def test_scanner_error_is_not_clean(monkeypatch, tmp_path):
    async def execute(*args, **kwargs):
        return 124, "", ""

    monkeypatch.setattr(runner, "_exec", execute)
    report = asyncio.run(runner.run_scanners(str(tmp_path)))
    assert not report.scan_complete
    assert all(s.status == "timeout" for s in report.scanners)


def test_report_parsing_and_snippet_recovery(monkeypatch, tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.js").write_text("eval(request.body);\n")

    async def execute(*args, **kwargs):
        if args[0] == "semgrep":
            return (
                0,
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "full.rule.id",
                                "path": "src/a.js",
                                "start": {"line": 1},
                                "extra": {"severity": "ERROR", "lines": "requires login"},
                            }
                        ]
                    }
                ),
                "",
            )
        return 127, "", ""

    monkeypatch.setattr(runner, "_exec", execute)
    report = asyncio.run(runner.run_scanners(str(tmp_path)))
    assert report.findings[0].code_snippet == "eval(request.body);"
    assert report.findings[0].rule_id == "full.rule.id"
    assert report.scanners[0].status == "completed"
    assert not report.scan_complete


def test_semgrep_partial_errors_retained(monkeypatch, tmp_path):
    async def execute(*args, **kwargs):
        return 0, '{"results": [], "errors": [{"message":"bad file"}]}', ""

    monkeypatch.setattr(runner, "_exec", execute)
    result = asyncio.run(runner.scan_semgrep(tmp_path, True, None))
    assert result.status == "failed"


def test_trivy_includes_all_categories():
    data = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-1", "PkgName": "a"},
                    {"VulnerabilityID": "CVE-1", "PkgName": "b"},
                ],
                "Misconfigurations": [{"ID": "config"}],
                "Secrets": [{"RuleID": "secret", "Match": "password"}],
            }
        ]
    }
    fs = runner.parse_trivy(data)
    assert len(fs) == 4 and fs[0].finding_id != fs[1].finding_id
    assert "password" not in fs[-1].code_snippet


def test_zap_retains_each_endpoint():
    data = {
        "site": [
            {
                "alerts": [
                    {
                        "pluginid": 1,
                        "instances": [{"uri": "http://localhost/a"}, {"uri": "http://localhost/b"}],
                    }
                ]
            }
        ]
    }
    fs = runner.parse_zap(data)
    assert len(fs) == 2 and fs[0].finding_id != fs[1].finding_id


def test_subprocess_timeout():
    result = asyncio.run(
        runner._exec(sys.executable, "-c", "import time; time.sleep(20)", timeout=0.1)
    )
    assert result[0] == 124


def test_api_refusal_and_preview_only(tmp_path):
    with TestClient(main.app, client=("127.0.0.1", 50000)) as client:
        response = client.post(
            "/scan", json={"target_dir": str(tmp_path), "target_url": "http://8.8.8.8"}
        )
        assert response.status_code == 403
        assert client.get("/health").status_code == 200
        payload = {
            "repo_full_name": "me/repo",
            "finding": {"tool_name": "Semgrep", "rule_id": "x"},
            "dry_run": False,
        }
        assert client.post("/github/draft-issue", json=payload).status_code == 403
        assert client.post("/github/draft-pr", json=payload).status_code == 403
        assert (
            client.post("/scan", json={"target_dir": str(tmp_path), "allow_llm": True}).status_code
            == 422
        )
        assert client.get("/health", headers={"origin": "http://evil.example"}).status_code == 403


def test_api_token_and_source_root(monkeypatch, tmp_path):
    monkeypatch.setenv("SSP_API_TOKEN", "test-access-token")
    monkeypatch.setenv("SSP_SOURCE_ROOT", str(tmp_path / "allowed"))
    with TestClient(main.app) as client:
        assert client.get("/health").status_code == 401
        headers = {"authorization": "Bearer test-access-token"}
        assert client.get("/health", headers=headers).status_code == 200
        assert (
            client.post("/scan", headers=headers, json={"target_dir": str(tmp_path)}).status_code
            == 403
        )


def test_zap_scope_hook_fails_closed(monkeypatch, tmp_path):
    from contextlib import contextmanager
    from pathlib import Path
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    import pytest

    @contextmanager
    def proxy(_target):
        yield 12345

    monkeypatch.setattr(runner, "scoped_proxy", proxy)
    monkeypatch.setattr(runner, "_which", lambda _: "/usr/bin/docker")
    called = []

    async def scan(tool, argv, parser, root, **kwargs):
        from models import ScannerResult

        directory = Path(kwargs["report_path"]).parent
        assert directory.stat().st_mode & 0o077 == 0
        namespace = {}
        exec((directory / "scope_hook.py").read_text(), namespace)

        def fail(code):
            raise SystemExit(code)

        namespace["os"] = SimpleNamespace(_exit=fail)
        zap = MagicMock()
        zap.network.set_socks_proxy_enabled.return_value = "OK"
        zap.network.set_http_proxy.return_value = "OK"
        zap.network.set_http_proxy_enabled.return_value = "OK"
        zap.network.get_http_proxy_exclusions = []
        zap.network.is_http_proxy_enabled = "true"
        namespace["zap_started"](zap, "http://localhost")
        zap.network.set_http_proxy.assert_called_once_with("127.0.0.1", 12345)
        zap.network.is_http_proxy_enabled = "false"
        with pytest.raises(SystemExit) as refusal:
            namespace["zap_started"](zap, "http://localhost")
        assert refusal.value.code == runner.ZAP_SCOPE_ABORT
        called.append(argv)
        return ScannerResult(tool_name=tool, status="completed")

    async def execute(*args, **kwargs):
        return 0, "", ""

    monkeypatch.setattr(runner, "_scan", scan)
    monkeypatch.setattr(runner, "_exec", execute)
    result = asyncio.run(runner.scan_zap(tmp_path, "http://localhost", True))
    assert result.status == "completed"
    assert "--pull=never" in called[0]
    assert "--user" in called[0]


def test_semgrep_never_uses_auto_config():
    # Semgrep refuses `--config auto` together with `--metrics=off`.
    assert runner.semgrep_configs(False, None)[0] == "p/default"
    assert "auto" not in runner.semgrep_configs(False, None)
    offline = runner.semgrep_configs(True, None)
    assert any(c.endswith("baseline.yml") for c in offline)
    assert any(c.endswith("manual-lessons.yml") for c in offline)
    assert any(c.endswith("coverage-extras.yml") for c in offline)
    assert runner.semgrep_configs(True, "custom.yml") == ["custom.yml"]


def test_api_allows_same_loopback_origin_only():
    with TestClient(
        main.app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000)
    ) as client:
        own = {"origin": "http://127.0.0.1:8000"}
        assert client.get("/health", headers=own).status_code == 200
        # DNS rebinding: a hostname resolving to loopback is still refused.
        rebound = {"origin": "http://evil.example:8000", "host": "evil.example:8000"}
        assert client.get("/health", headers=rebound).status_code == 403


def test_semgrep_warning_level_errors_still_complete(monkeypatch, tmp_path):
    async def execute(*args, **kwargs):
        return 0, '{"results": [], "errors": [{"level": "warn", "type": "Timeout"}]}', ""

    monkeypatch.setattr(runner, "_exec", execute)
    result = asyncio.run(runner.scan_semgrep(tmp_path, True, None))
    assert result.status == "completed"
    assert "1 file-level warnings" in result.message


def test_manual_lesson_rules_catch_known_bug_classes(tmp_path):
    import subprocess

    semgrep = runner._which("semgrep")
    if not semgrep:
        pytest.skip("semgrep not installed")
    (tmp_path / "nginx.conf").write_text(
        "add_header Content-Security-Policy \"script-src 'self' 'nonce-fixed123'\";\n"
        'proxy_set_header X-Internal-Token "${INTERNAL_API_TOKEN}";\n'
    )
    (tmp_path / "feed.js").write_text("const x = `<item><link>${item.link}</link></item>`;\n")
    (tmp_path / "safe.js").write_text("const y = `<link>${escapeXml(item.link)}</link>`;\n")
    rules = str(runner._RULES_DIR / "manual-lessons.yml")
    out = subprocess.run(
        [semgrep, "scan", "--config", rules, "--json", "--metrics=off", "--quiet", "."],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    hits = {r["check_id"].split(".")[-1] for r in json.loads(out.stdout)["results"]}
    paths = {r["path"] for r in json.loads(out.stdout)["results"]}
    assert hits == {
        "csp-static-nonce",
        "nginx-injects-internal-credential",
        "xml-feed-unescaped-interpolation",
    }
    assert "safe.js" not in paths


def test_local_rule_path_prefix_is_stripped(tmp_path):
    rules = tmp_path / "some dir" / "rules"
    rules.mkdir(parents=True)
    config = rules / "pack.yml"
    config.write_text("rules: []\n")
    prefix = str(rules.resolve()).strip("/").replace("/", ".")
    f = runner.SecurityFinding(
        tool_name="Semgrep", rule_id=prefix + ".js.eval.eval", file_path="a.js"
    )
    runner._strip_local_rule_prefix([f], [str(config)])
    assert f.rule_id == "js.eval.eval"
    assert (
        f.finding_id
        == runner.SecurityFinding(
            tool_name="Semgrep", rule_id="js.eval.eval", file_path="a.js"
        ).finding_id
    )


def test_coverage_extra_rules_catch_owasp_classes_without_checksum_noise(tmp_path):
    import subprocess

    semgrep = runner._which("semgrep")
    if not semgrep:
        pytest.skip("semgrep not installed")
    (tmp_path / "search.component.ts").write_text(
        "this.html = this.sanitizer.bypassSecurityTrustHtml(this.query)\n"
        "this.ok = this.sanitizer.bypassSecurityTrustHtml('<b>static</b>')\n"
    )
    (tmp_path / "track.ts").write_text(
        "db.orders.find({ $where: `this.orderId === '${id}'` })\n"
        "db.orders.find({ $where: 'this.a > 1' })\n"
    )
    (tmp_path / "auth.ts").write_text(
        "export const hashPassword = (p: string) => crypto.createHash('md5').update(p)\n"
        "function verifyDownload(zip) { return createHash('md5').update(zip) }\n"
    )
    rules = str(runner._RULES_DIR / "coverage-extras.yml")
    out = subprocess.run(
        [semgrep, "scan", "--config", rules, "--json", "--metrics=off", "--quiet", "."],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    hits = sorted(
        (r["check_id"].split(".")[-1], r["path"], r["start"]["line"])
        for r in json.loads(out.stdout)["results"]
    )
    assert hits == [
        ("angular-bypass-security-trust", "search.component.ts", 1),
        ("nosql-where-injection", "track.ts", 1),
        ("weak-hash-algorithm", "auth.ts", 1),
    ]


def _fake_zap(monkeypatch, exit_codes):
    from contextlib import contextmanager

    from models import ScannerResult

    @contextmanager
    def proxy(_target):
        yield 12345

    monkeypatch.setattr(runner, "scoped_proxy", proxy)
    monkeypatch.setattr(runner, "_which", lambda _: "/usr/bin/docker")
    calls = []

    async def scan(tool, argv, parser, root, **kwargs):
        code = exit_codes[len(calls)]
        calls.append(argv[argv.index("--name") + 1])
        status = "completed" if code == 0 else "failed"
        return ScannerResult(tool_name=tool, status=status, exit_code=code)

    async def execute(*args, **kwargs):
        return 0, "", ""

    monkeypatch.setattr(runner, "_scan", scan)
    monkeypatch.setattr(runner, "_exec", execute)
    return calls


def test_zap_internal_failure_is_retried_once(monkeypatch, tmp_path):
    calls = _fake_zap(monkeypatch, [3, 0])
    result = asyncio.run(runner.scan_zap(tmp_path, "http://localhost", True))
    assert result.status == "completed" and "retry" in result.message
    assert len(calls) == 2 and calls[0] != calls[1]  # fresh container name


def test_zap_scope_abort_is_never_retried(monkeypatch, tmp_path):
    calls = _fake_zap(monkeypatch, [runner.ZAP_SCOPE_ABORT, 0])
    result = asyncio.run(runner.scan_zap(tmp_path, "http://localhost", True))
    assert result.status == "failed" and "fail-closed" in result.message
    assert len(calls) == 1
