"""Turn a ScanReport into an assessment report in the SIH PS-163 template.

For each finding group: title, description, affected component, severity with a
CVSS estimate, steps to reproduce, proof of concept, business impact and
remediation. Findings sharing a rule are grouped so a large scan stays readable.

Everything here is derived from scanner output and fixed guidance text. Nothing
is marked confirmed: automated findings are leads until a person reproduces
them. Markdown and HTML are generated; HTML escapes every value.
"""

from __future__ import annotations

import html
import re
from collections import Counter, defaultdict
from dataclasses import dataclass

from models import ScanReport, SecurityFinding
from redaction import redact_secrets
from triage_tier2 import _SEV_CVSS, _safe_probe

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_MAX_LOCATIONS = 15


@dataclass(frozen=True)
class Guidance:
    name: str
    owasp: str
    impact: str
    remediation: str


# Ordered: the first matching pattern wins.
_CATEGORIES: list[tuple[str, Guidance]] = [
    (
        r"nosql|\$where",
        Guidance(
            "NoSQL / database code injection",
            "A03:2021 Injection",
            "An attacker may read or modify database records or run code on the database server.",
            "Never build $where or query operators from strings; use typed query objects "
            "and validate input types.",
        ),
    ),
    (
        r"sql|sequelize|knex-raw|tainted-sql",
        Guidance(
            "SQL injection",
            "A03:2021 Injection",
            "An attacker may read, change or delete data, or bypass login.",
            "Use parameterized queries or the ORM's bound parameters; never concatenate "
            "input into SQL.",
        ),
    ),
    (
        r"eval|dynamic-function|code-string-concat|code-injection|vm-|10110|dangerous-js",
        Guidance(
            "Code injection",
            "A03:2021 Injection",
            "An attacker may execute arbitrary code on the server or in the browser.",
            "Remove eval/new Function on data; use a parser or an allowlist of operations.",
        ),
    ),
    (
        r"xml-feed|xml-injection|xxe",
        Guidance(
            "XML injection",
            "A03:2021 Injection",
            "Injected markup can corrupt feeds or be rendered as active content by consumers.",
            "Escape values for XML (&, <, >, quotes) or use an XML builder.",
        ),
    ),
    (
        r"xss|bypass-?security-?trust|innerhtml|script-tag|unescaped|document-write|raw-html|"
        r"sanitiz",
        Guidance(
            "Cross-site scripting / HTML injection",
            "A03:2021 Injection",
            "An attacker may run script in users' browsers, steal sessions or deface pages.",
            "Escape output for its context, keep framework sanitization on, and use a "
            "strict nonce- or hash-based CSP.",
        ),
    ),
    (
        r"ssrf|request-forgery|urllib|data-exfiltration|tainted-url",
        Guidance(
            "Server-side request forgery / data exfiltration",
            "A10:2021 Server-Side Request Forgery",
            "The server can be made to call internal services or send data to attacker URLs.",
            "Allowlist destination hosts, block private address ranges, and never let input "
            "choose the full URL.",
        ),
    ),
    (
        r"open-redirect",
        Guidance(
            "Open redirect",
            "A01:2021 Broken Access Control",
            "Attackers can use a trusted domain to redirect victims to phishing pages.",
            "Redirect only to an allowlist of paths or hosts.",
        ),
    ),
    (
        r"traversal|sendfile|directory-listing|path-join",
        Guidance(
            "Path traversal / file exposure",
            "A01:2021 Broken Access Control",
            "An attacker may read files outside the intended directory or browse files.",
            "Resolve paths and check they stay inside the base directory; disable listings.",
        ),
    ),
    (
        r"nonce",
        Guidance(
            "Static CSP nonce",
            "A05:2021 Security Misconfiguration",
            "A public, fixed nonce lets any injected script tag run, disabling CSP's XSS protection.",
            "Generate a random nonce per response, or use hash-based CSP.",
        ),
    ),
    (
        r"injects-internal-credential|local-token",
        Guidance(
            "Internal credential injected by proxy",
            "A07:2021 Identification and Authentication Failures",
            "Any client that reaches the proxy passes the upstream's authentication check.",
            "Authenticate clients instead of injecting a shared secret; bind internal "
            "services to loopback.",
        ),
    ),
    (
        r"weak-hash|md5|sha1|gcm|cipher|insecure-random|pseudo-random|weak-crypto",
        Guidance(
            "Weak or misused cryptography",
            "A02:2021 Cryptographic Failures",
            "Protected data, passwords or tokens can be decrypted, cracked or forged.",
            "Use bcrypt/scrypt/argon2 for passwords, SHA-256+ or HMAC for tokens, and "
            "authenticated encryption with full-length tags.",
        ),
    ),
    (
        r"jwt|hmac|private-key|secret|api-key|password|credential|token|generic-api-key",
        Guidance(
            "Hardcoded secret or credential",
            "A07:2021 Identification and Authentication Failures",
            "Anyone with the code can impersonate the service or access linked accounts.",
            "Remove it from the code and history, rotate it, and load secrets from a vault "
            "or environment.",
        ),
    ),
    (
        r"cors|cross-domain|10098",
        Guidance(
            "Permissive cross-origin policy",
            "A05:2021 Security Misconfiguration",
            "Other websites may read responses that should be same-origin only.",
            "Allow only trusted origins; never reflect arbitrary origins with credentials.",
        ),
    ),
    (
        r"insecure-websocket|insecure-transport|http-not-https|cleartext|tls-|ssl-",
        Guidance(
            "Insecure transport",
            "A02:2021 Cryptographic Failures",
            "Traffic can be read or modified by anyone on the network path.",
            "Use TLS (https://, wss://) for all connections and reject downgrades.",
        ),
    ),
    (
        r"csp|header|hsts|nosniff|permissions-policy|cross-origin|x-frame|10038|10055|10063|"
        r"10021|10035|90004|10020",
        Guidance(
            "Missing or weak security header",
            "A05:2021 Security Misconfiguration",
            "Browser protections against XSS, clickjacking and MIME sniffing are weaker.",
            "Set CSP, HSTS, X-Content-Type-Options, frame-ancestors and related headers.",
        ),
    ),
    (
        r"version|banner|10036|10009|10096|disclos",
        Guidance(
            "Information disclosure",
            "A05:2021 Security Misconfiguration",
            "Version and internal details help attackers pick known exploits.",
            "Remove version banners and internal details from responses.",
        ),
    ),
    (
        r"integrity|90003|10017|missing-integrity",
        Guidance(
            "Third-party script without integrity check",
            "A08:2021 Software and Data Integrity Failures",
            "If the third-party host is compromised, its script runs with full page access.",
            "Add Subresource Integrity (integrity=) or self-host the script.",
        ),
    ),
    (
        r"regexp|redos|allerrors|resource-exhaustion",
        Guidance(
            "Denial of service (ReDoS / resource exhaustion)",
            "A04:2021 Insecure Design",
            "Crafted input can make the regex engine hang and exhaust CPU.",
            "Avoid regexes built from input, bound input sizes, and disable costly options "
            "such as collecting all validation errors on untrusted data.",
        ),
    ),
    (
        r"github-actions|gha-|run-shell-injection|workflow|dependabot|npm-|minimum-release",
        Guidance(
            "CI/CD or supply-chain weakness",
            "A08:2021 Software and Data Integrity Failures",
            "A malicious contributor or dependency could run code in CI or steal CI secrets.",
            "Pin actions to commit SHAs and pass untrusted values through environment variables.",
        ),
    ),
    (
        r"command-injection|spawn-shell|shell-true|child-process|exec-|detect-child",
        Guidance(
            "OS command injection",
            "A03:2021 Injection",
            "An attacker may run operating-system commands on the server.",
            "Call processes with an argument list (no shell) and never pass input to a shell.",
        ),
    ),
    (
        r"prototype-pollution|object-assign|mass-assign|remote-property-injection",
        Guidance(
            "Prototype pollution / mass assignment",
            "A08:2021 Software and Data Integrity Failures",
            "Attackers may inject object properties that change logic or security checks.",
            "Copy only allowlisted keys, reject __proto__/constructor, or use Object.create(null).",
        ),
    ),
    (
        r"^(ds|ksv|avd)-|docker|dockerfile|missing-user|container|aws-|terraform|k8s|"
        r"misconfig|nginx|missing-internal|request-host",
        Guidance(
            "Infrastructure or container misconfiguration",
            "A05:2021 Security Misconfiguration",
            "A compromise can escalate further, or infrastructure is exposed more than intended.",
            "Apply least privilege: non-root containers, private networking, encryption, logging.",
        ),
    ),
]

_DEPENDENCY = Guidance(
    "Vulnerable dependency",
    "A06:2021 Vulnerable and Outdated Components",
    "Known, published vulnerabilities in a dependency may be exploitable in this app.",
    "Upgrade to the fixed version shown, then retest.",
)
_GENERIC = Guidance(
    "Security weakness",
    "Unclassified",
    "Depends on whether untrusted input reaches the flagged code.",
    "Review the flagged code against the rule description and fix or document the risk.",
)


def classify(finding: SecurityFinding) -> Guidance:
    if finding.tool_name == "Trivy" and re.match(r"(CVE|GHSA)-", finding.rule_id):
        return _DEPENDENCY
    # The rule ID is the stronger signal; descriptions can mention other classes.
    for text in (finding.rule_id.lower(), finding.raw_description[:200].lower()):
        for pattern, guidance in _CATEGORIES:
            if re.search(pattern, text):
                return guidance
    return _GENERIC


def _location(f: SecurityFinding) -> str:
    if f.endpoint_url:
        return f.endpoint_url
    return f"{f.file_path or '?'}" + (f":{f.line_number}" if f.line_number else "")


def _cvss(group: list[SecurityFinding]) -> float:
    scored = [f.cvss_score for f in group if f.cvss_score is not None]
    return max(scored) if scored else _SEV_CVSS[group[0].severity]


def _steps(f: SecurityFinding) -> list[str]:
    if f.tool_name == "OWASP ZAP":
        return [
            "Start the application locally (loopback only).",
            f"Request `{f.endpoint_url}` and inspect the response headers and body.",
            "Confirm the condition described above is present.",
        ]
    if f.tool_name == "Trivy" and f.code_snippet:
        return [
            f"Open `{f.file_path}` and find the installed version: {f.code_snippet}.",
            "Check the advisory to see whether the vulnerable function is used.",
        ]
    if f.tool_name == "Gitleaks":
        return [
            f"Open `{_location(f)}` (the value is redacted in this report).",
            "Check whether it is a real, live credential or a placeholder.",
            "If real, check git history and any service it grants access to.",
        ]
    return [
        f"Open `{_location(f)}` and review the flagged code.",
        "Trace whether untrusted input (request data, URL, upstream feed) reaches it.",
        "If it does, build a local test input that shows the unsafe behaviour.",
    ]


@dataclass
class Group:
    guidance: Guidance
    tool: str
    rule_id: str
    severity: str
    findings: list[SecurityFinding]


def build_groups(report: ScanReport) -> list[Group]:
    # Severity is part of the key so downgraded test fixtures never inflate a
    # HIGH group of the same rule.
    buckets: dict[tuple[str, str, str], list[SecurityFinding]] = defaultdict(list)
    for f in report.findings:
        if not f.is_false_positive:
            buckets[(f.tool_name, f.rule_id, f.severity)].append(f)
    groups = []
    for (tool, rule_id, severity), items in buckets.items():
        groups.append(Group(classify(items[0]), tool, rule_id, severity, items))
    groups.sort(key=lambda g: (_SEVERITY_ORDER.index(g.severity), -len(g.findings), g.rule_id))
    return groups


def _short_rule(rule_id: str) -> str:
    return rule_id.rsplit(".", 1)[-1]


def to_markdown(report: ScanReport, title: str = "Security Assessment Report") -> str:
    groups = build_groups(report)
    raw = report.total_raw_findings or 1
    out = [f"# {title}", ""]
    out += [
        f"- **Target source:** `{report.target_dir}`",
        f"- **Target URL:** {report.target_url or 'none (static scan only)'}",
        f"- **Scan ID / time:** `{report.run_id}` · {report.created_at}",
        f"- **Coverage complete:** {'yes' if report.scan_complete else 'NO, see below'}",
        "",
        "> Automated findings are leads, not confirmed vulnerabilities. CVSS values are "
        "estimates from scanner severity; confirm each with a CVSS 3.1 calculator.",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Raw alerts | {report.total_raw_findings} |",
        f"| Exact duplicates | {report.duplicate_count} |",
        f"| Filtered by policy | {report.deterministic_filtered_count} |",
        f"| Actionable | {report.actionable_count} ({report.actionable_count / raw:.0%} of raw) |",
        f"| Known / new | {report.known_count} / {report.new_count} |",
        f"| Finding groups | {len(groups)} |",
        "",
        "## Scanner coverage",
        "",
        "| Scanner | Status | Findings | Notes |",
        "|---|---|---|---|",
    ]
    for s in report.scanners:
        out.append(f"| {s.tool_name} | {s.status} | {s.finding_count} | {_cell(s.message)} |")
    out += ["", "## Findings by severity", ""]
    sev = Counter(g.severity for g in groups)
    out.append(", ".join(f"{k}: {sev[k]}" for k in _SEVERITY_ORDER if sev[k]) or "None")
    out.append("")
    for i, g in enumerate(groups, 1):
        first = g.findings[0]
        out += [
            f"### {i}. {g.guidance.name}: `{_short_rule(g.rule_id)}`",
            "",
            f"- **Severity:** {g.severity} · **CVSS (estimate):** {_cvss(g.findings):.1f}",
            f"- **OWASP:** {g.guidance.owasp} · **Source:** {g.tool} · "
            f"**Occurrences:** {len(g.findings)}",
            f"- **Status:** {first.status}"
            + (f" ({first.known_source})" if first.known_source else ""),
            "",
            f"**Description.** {_text(first.raw_description) or g.guidance.name}",
            "",
            "**Affected components:**",
            "",
        ]
        for f in g.findings[:_MAX_LOCATIONS]:
            out.append(f"- `{_location(f)}`")
        if len(g.findings) > _MAX_LOCATIONS:
            out.append(f"- …and {len(g.findings) - _MAX_LOCATIONS} more (see JSON report)")
        out += ["", "**Steps to reproduce:**", ""]
        out += [f"{n}. {step}" for n, step in enumerate(_steps(first), 1)]
        if first.code_snippet and first.tool_name != "Gitleaks":
            out += ["", "**Evidence:**", "", _fence(redact_secrets(first.code_snippet))]
        probe = first.poc_command or _safe_probe(first)
        out += [
            "",
            "**Proof of concept:** "
            + (
                f"read-only probe, not executed by the tool: `{probe}`"
                if probe
                else "not generated automatically; confirm manually as described above."
            ),
            "",
            f"**Business impact.** {g.guidance.impact}",
            "",
            f"**Remediation.** {g.guidance.remediation}",
            "",
        ]
        if first.filter_reason:
            out += [f"_Triage note: {_text(first.filter_reason)}_", ""]
    out += ["## Filtered by policy", "", "| Reason | Count |", "|---|---|"]
    reasons = Counter(
        (f.filter_reason or "unspecified") for f in report.findings if f.is_false_positive
    )
    for reason, count in reasons.most_common():
        out.append(f"| {_cell(reason)} | {count} |")
    if report.warnings:
        out += ["", "## Warnings", ""] + [f"- {_text(w)}" for w in report.warnings]
    out.append("")
    return redact_secrets("\n".join(out))


def _text(value: str | None) -> str:
    return re.sub(r"\s+", " ", redact_secrets(value or "")).strip()


def _cell(value: str | None) -> str:
    return _text(value).replace("|", "\\|")


def _fence(code: str) -> str:
    fence = "~~~~" if "```" in code else "```"
    return f"{fence}\n{code.rstrip()}\n{fence}"


def write_report(report: ScanReport, path: str) -> None:
    """Write Markdown or HTML by extension. Never overwrites an existing file."""
    body = to_html(report) if path.lower().endswith((".html", ".htm")) else to_markdown(report)
    with open(path, "x", encoding="utf-8") as handle:
        handle.write(body)


def main(argv: list[str] | None = None) -> int:
    """Build a report from a saved scan: python assessment_report.py scan.json out.md"""
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Assessment report from a saved scan JSON")
    parser.add_argument("scan_json")
    parser.add_argument("output", help=".html for HTML, otherwise Markdown")
    args = parser.parse_args(argv)
    try:
        with open(args.scan_json, encoding="utf-8") as handle:
            report = ScanReport.model_validate_json(handle.read())
        write_report(report, args.output)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Assessment report written to {args.output}")
    return 0


def to_html(report: ScanReport, title: str = "Security Assessment Report") -> str:
    """Standalone HTML version. Every value is escaped."""
    groups = build_groups(report)
    e = html.escape
    rows = "".join(
        f"<tr><td>{e(s.tool_name)}</td><td>{e(s.status)}</td><td>{s.finding_count}</td>"
        f"<td>{e(_text(s.message))}</td></tr>"
        for s in report.scanners
    )
    cards = []
    for i, g in enumerate(groups, 1):
        first = g.findings[0]
        locs = "".join(f"<li><code>{e(_location(f))}</code></li>" for f in g.findings[:15])
        more = f"<li>…and {len(g.findings) - 15} more</li>" if len(g.findings) > 15 else ""
        steps = "".join(f"<li>{e(s.replace('`', ''))}</li>" for s in _steps(first))
        evidence = (
            f"<pre>{e(redact_secrets(first.code_snippet))}</pre>"
            if first.code_snippet and first.tool_name != "Gitleaks"
            else ""
        )
        probe = first.poc_command or _safe_probe(first)
        poc = (
            f"read-only probe, not executed by the tool: <code>{e(probe)}</code>"
            if probe
            else "not generated automatically; confirm manually."
        )
        cards.append(
            f'<section class="card sev-{e(g.severity.lower())}">'
            f"<h3>{i}. {e(g.guidance.name)}: <code>{e(_short_rule(g.rule_id))}</code></h3>"
            f'<p class="meta"><b>{e(g.severity)}</b> · CVSS estimate {_cvss(g.findings):.1f}'
            f" · {e(g.guidance.owasp)} · {e(g.tool)} · {len(g.findings)} occurrence(s)"
            f" · {e(first.status)}</p>"
            f"<p>{e(_text(first.raw_description))}</p>"
            f"<h4>Affected components</h4><ul>{locs}{more}</ul>"
            f"<h4>Steps to reproduce</h4><ol>{steps}</ol>{evidence}"
            f"<h4>Proof of concept</h4><p>{poc}</p>"
            f"<h4>Business impact</h4><p>{e(g.guidance.impact)}</p>"
            f"<h4>Remediation</h4><p>{e(g.guidance.remediation)}</p></section>"
        )
    raw = report.total_raw_findings or 1
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<style>
:root {{ --bg:#fff; --fg:#1d1d1f; --muted:#5f6368; --line:#e2e2e2; --card:#fafafa;
  --crit:#b3261e; --high:#c5531b; --med:#9a6b00; --low:#2f6fb0; --info:#6b6b6b; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#141414; --fg:#ececec; --muted:#a0a0a0;
  --line:#333; --card:#1d1d1d; }} }}
body {{ background:var(--bg); color:var(--fg); font:15px/1.55 system-ui, sans-serif;
  max-width:980px; margin:0 auto; padding:24px 16px; }}
h1 {{ font-size:26px; }} h3 {{ margin:0 0 6px; font-size:17px; }} h4 {{ margin:14px 0 4px; }}
table {{ border-collapse:collapse; width:100%; }} td,th {{ border:1px solid var(--line);
  padding:6px 8px; text-align:left; vertical-align:top; }}
.card {{ background:var(--card); border:1px solid var(--line); border-left:5px solid var(--info);
  border-radius:8px; padding:14px 16px; margin:14px 0; overflow-wrap:anywhere; }}
.sev-critical {{ border-left-color:var(--crit); }} .sev-high {{ border-left-color:var(--high); }}
.sev-medium {{ border-left-color:var(--med); }} .sev-low {{ border-left-color:var(--low); }}
.meta {{ color:var(--muted); margin:0 0 8px; }} pre {{ overflow-x:auto; padding:8px;
  border:1px solid var(--line); border-radius:6px; }} .note {{ color:var(--muted); }}
</style></head><body>
<h1>{e(title)}</h1>
<p class="note">Source <code>{e(report.target_dir)}</code> · URL {e(report.target_url or "none")}
· scan <code>{e(report.run_id)}</code> · {e(report.created_at)}</p>
<p class="note">Automated findings are leads, not confirmed vulnerabilities. CVSS values are
estimates; confirm with a CVSS 3.1 calculator.</p>
<h2>Summary</h2>
<table><tr><th>Raw alerts</th><td>{report.total_raw_findings}</td></tr>
<tr><th>Filtered by policy</th><td>{report.deterministic_filtered_count}</td></tr>
<tr><th>Actionable</th><td>{report.actionable_count} ({report.actionable_count / raw:.0%})</td></tr>
<tr><th>Finding groups</th><td>{len(groups)}</td></tr>
<tr><th>Coverage complete</th><td>{"yes" if report.scan_complete else "NO"}</td></tr></table>
<h2>Scanner coverage</h2>
<table><tr><th>Scanner</th><th>Status</th><th>Findings</th><th>Notes</th></tr>{rows}</table>
<h2>Findings</h2>
{"".join(cards) or "<p>No actionable findings.</p>"}
</body></html>
"""
    return redact_secrets(doc)


if __name__ == "__main__":
    raise SystemExit(main())
