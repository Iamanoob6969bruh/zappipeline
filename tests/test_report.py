import pytest

import assessment_report as ar
from models import ScannerResult, ScanReport, SecurityFinding


def finding(**kwargs):
    return SecurityFinding(
        **{"tool_name": "Semgrep", "rule_id": "rule", "file_path": "src/a.ts", "line_number": 1}
        | kwargs
    )


def report(findings):
    r = ScanReport(
        target_dir="/tmp/app",
        findings=findings,
        total_raw_findings=len(findings),
        scanners=[ScannerResult(tool_name="Semgrep", status="completed", finding_count=1)],
    )
    return r.recount()


def test_markdown_has_every_sih_template_field():
    md = ar.to_markdown(
        report([finding(rule_id="js.sequelize.express-sequelize-injection", severity="HIGH")])
    )
    for field in (
        "SQL injection",
        "**Severity:** HIGH",
        "**CVSS 3.1:** 7.4 HIGH",
        "**Scope area:** Input validation and data handling",
        "**Description.**",
        "**Affected components:**",
        "`src/a.ts:1`",
        "**Steps to reproduce:**",
        "**Proof of concept.**",
        "**Business impact.**",
        "**Remediation.**",
    ):
        assert field in md, field


def test_html_escapes_hostile_scanner_text_and_redacts_secrets():
    hostile = finding(
        raw_description="<script>alert(1)</script>",
        file_path="src/<img src=x onerror=alert(1)>.ts",
        code_snippet='const key = "AKIAIOSFODNN7EXAMPLE";',
    )
    page = ar.to_html(report([hostile]))
    assert "<script>alert" not in page and "<img src=x" not in page
    assert "&lt;script&gt;" in page
    assert "AKIAIOSFODNN7EXAMPLE" not in page
    assert "AKIAIOSFODNN7EXAMPLE" not in ar.to_markdown(report([hostile]))


def test_groups_split_by_severity_and_skip_filtered():
    fs = [
        finding(tool_name="Gitleaks", rule_id="generic-api-key", severity="HIGH"),
        finding(tool_name="Gitleaks", rule_id="generic-api-key", severity="LOW", line_number=2),
        finding(rule_id="noise", is_false_positive=True, line_number=3),
    ]
    groups = ar.build_groups(report(fs))
    assert [(g.rule_id, g.severity, len(g.findings)) for g in groups] == [
        ("generic-api-key", "HIGH", 1),
        ("generic-api-key", "LOW", 1),
    ]


@pytest.mark.parametrize(
    ("tool", "rule", "expected"),
    [
        ("Trivy", "CVE-2025-1234:lodash", "Vulnerable dependency"),
        ("Trivy", "DS-0002", "Container runs as root"),
        ("Trivy", "DS-0026", "Container has no health check"),
        ("Semgrep", "wildcard-postmessage-configuration", "Unrestricted postMessage"),
        ("Semgrep", "xml-feed-unescaped-interpolation", "XML injection"),
        ("Semgrep", "csp-static-nonce", "Static CSP nonce"),
        ("Semgrep", "nosql-where-injection", "NoSQL / database code injection"),
        ("Semgrep", "angular-bypass-security-trust", "Cross-site scripting / HTML injection"),
        ("Semgrep", "spawn-shell-true", "OS command injection"),
        ("OWASP ZAP", "10038", "Missing or weak security header"),
        ("Semgrep", "unknown-rule-xyz", "Security weakness"),
    ],
)
def test_classification(tool, rule, expected):
    assert ar.classify(finding(tool_name=tool, rule_id=rule)).name == expected


def test_write_report_never_overwrites(tmp_path):
    path = tmp_path / "out.md"
    ar.write_report(report([finding()]), str(path))
    with pytest.raises(FileExistsError):
        ar.write_report(report([finding()]), str(path))
    html_path = tmp_path / "out.html"
    ar.write_report(report([finding()]), str(html_path))
    assert html_path.read_text().startswith("<!doctype html>")
