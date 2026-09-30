import itertools
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

import assessment_report as ar
import cvss
import evidence
from models import ScanReport, SecurityFinding
from runner import parse_trivy
from triage_tier1 import check_ast_reachability
from triage_tier2 import ai_triage_finding


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 4.7),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_base_scores_match_the_specification(vector, score):
    assert cvss.base_score(vector) == score


@pytest.mark.parametrize(
    "vector", ["AV:N/AC:L", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:X"]
)
def test_cvss_rejects_malformed_vectors(vector):
    with pytest.raises(ValueError):
        cvss.base_score(vector)


def test_trivy_keeps_published_cvss_and_misconfiguration_details():
    data = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2025-0001",
                        "PkgName": "lib",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                        "Severity": "HIGH",
                        "Title": "lib: bug",
                        "CVSS": {
                            "nvd": {
                                "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                "V3Score": 7.5,
                            }
                        },
                    }
                ],
            },
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS-0002",
                        "Severity": "HIGH",
                        "Title": "Image user should not be 'root'",
                        "Message": "Specify at least 1 USER command in Dockerfile",
                        "Resolution": "Add 'USER <non root user name>' line to the Dockerfile",
                        "CauseMetadata": {"StartLine": 3},
                    }
                ],
            },
        ]
    }
    dep, misconfig = parse_trivy(data)
    assert (dep.cvss_score, dep.cvss_source) == (7.5, "published advisory (NVD)")
    assert dep.cvss_vector.startswith("CVSS:3.1/")
    assert misconfig.code_snippet == "Specify at least 1 USER command in Dockerfile"
    assert "Fix: Add 'USER" in misconfig.raw_description
    assert misconfig.line_number == 3 and "fixed:" not in misconfig.code_snippet


def test_offline_tier2_never_replaces_a_published_score():
    f = SecurityFinding(
        tool_name="Trivy",
        rule_id="CVE-2025-0001:lib",
        severity="HIGH",
        cvss_score=7.5,
        cvss_source="published advisory (NVD)",
    )
    ai_triage_finding(f)
    assert (f.cvss_score, f.cvss_source) == (7.5, "published advisory (NVD)")
    g = SecurityFinding(tool_name="Semgrep", rule_id="x", severity="MEDIUM")
    ai_triage_finding(g)
    assert (g.cvss_score, g.cvss_source) == (5.3, "estimate from scanner severity")


@pytest.mark.parametrize(
    ("tool", "path", "snippet"),
    [
        ("Trivy", "gitleaks.json", "[REDACTED_SECRET_EVIDENCE]"),
        ("Semgrep", "semgrep.json", None),
        ("Gitleaks", "scan-wm.json", None),
    ],
)
def test_saved_scanner_output_in_the_target_is_filtered(tmp_path, tool, path, snippet):
    f = SecurityFinding(tool_name=tool, rule_id="r", file_path=path, code_snippet=snippet)
    filtered, reason = check_ast_reachability(f, tmp_path, {}, tracked={"src/a.ts"})
    assert filtered and "scanner output" in reason


def test_untracked_trivy_secret_is_filtered_but_tracked_one_is_not(tmp_path):
    secret = dict(tool_name="Trivy", rule_id="stripe-publishable-token")
    secret["code_snippet"] = "[REDACTED_SECRET_EVIDENCE]"
    local = SecurityFinding(file_path="notes/local.txt", **secret)
    tracked = SecurityFinding(file_path="src/config.ts", **secret)
    assert check_ast_reachability(local, tmp_path, {}, tracked={"src/config.ts"})[0]
    assert not check_ast_reachability(tracked, tmp_path, {}, tracked={"src/config.ts"})[0]


class _NonceServer:
    """A loopback app whose CSP nonce is fixed, or random per response."""

    def __init__(self, fixed: bool):
        counter = itertools.count()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                nonce = "static-abc" if fixed else f"random-{next(counter)}"
                self.send_response(200)
                self.send_header("Content-Security-Policy", f"script-src 'nonce-{nonce}'")
                self.end_headers()
                self.wfile.write(f'<script nonce="{nonce}"></script>'.encode())

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.mark.parametrize(("fixed", "expected"), [(True, "CONFIRMED"), (False, "NOT REPRODUCED")])
def test_static_nonce_verification_against_a_local_app(fixed, expected):
    app = _NonceServer(fixed)
    try:
        result = evidence.verify_static_nonce(app.url)
    finally:
        app.close()
    assert result.startswith(expected)
    if fixed:
        assert "'nonce-static-abc'" in result and 'nonce="static-abc"' in result


def test_verification_refuses_non_loopback_targets():
    report = ScanReport(
        target_dir="/tmp/app",
        target_url="http://example.com/",
        findings=[SecurityFinding(tool_name="Semgrep", rule_id="x.csp-static-nonce")],
    )
    evidence.run_verification(report)
    assert report.findings[0].verification.startswith("Not verified: REFUSED")


def _nonce_report(url):
    findings = [
        SecurityFinding(
            tool_name="Semgrep",
            rule_id="rules.csp-static-nonce",
            severity="MEDIUM",
            file_path="vercel.json",
            line_number=5,
        ),
        SecurityFinding(
            tool_name="Semgrep", rule_id="spawn-shell-true", severity="HIGH", file_path="a.js"
        ),
    ]
    report = ScanReport(target_dir="/tmp/app", target_url=url, findings=findings)
    report.total_raw_findings = len(findings)
    evidence.run_verification(report)
    return report.recount()


def test_confirmed_nonce_leads_the_report_with_curated_cvss():
    app = _NonceServer(fixed=True)
    try:
        report = _nonce_report(app.url)
    finally:
        app.close()
    nonce = report.findings[0]
    assert nonce.cvss_score == 4.7 and nonce.cvss_source.startswith("curated rule vector")
    md = ar.to_markdown(report)
    # Confirmed first, even though the other group is HIGH.
    assert "### 1. Static CSP nonce" in md and "### 2. OS command injection" in md
    for text in (
        "## Confirmed findings",
        "**CONFIRMED**",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "Verified automatically (read-only, local instance only). CONFIRMED",
        "| Client-side security controls | 1 |",
        "| Authentication and session management | 0 | No automated findings",
        "two read-only GET requests",
    ):
        assert text in md, text
    page = ar.to_html(report)
    assert "CONFIRMED" in page and "Coverage of the PS-163 scope" in page


def test_nonce_without_url_is_not_claimed_as_confirmed():
    report = _nonce_report(None)
    md = ar.to_markdown(report)
    assert "Not verified automatically: no local URL" in md
    assert "## Confirmed findings" not in md and "**CONFIRMED**" not in md
    assert "two read-only GET requests" not in md


def test_every_rule_file_rule_has_a_matching_category():
    import yaml

    rules_dir = Path(__file__).resolve().parent.parent / "rules"
    for name in ("manual-lessons.yml", "coverage-extras.yml"):
        for rule in yaml.safe_load((rules_dir / name).read_text())["rules"]:
            f = SecurityFinding(tool_name="Semgrep", rule_id=rule["id"])
            assert ar.classify(f).name != "Security weakness", rule["id"]
