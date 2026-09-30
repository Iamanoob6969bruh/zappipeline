import pytest

import history
import triage_tier2
from models import ScanReport, SecurityFinding, TriageResult
from redaction import redact_data
from triage_tier1 import run_tier1, tree_sitter_available


def finding(**kwargs):
    return SecurityFinding(
        **{
            "tool_name": "Semgrep",
            "rule_id": "rule",
            "file_path": "src/a.ts",
            "line_number": 1,
            **kwargs,
        }
    )


def test_ast_comments_mixed_lines_and_strings(tmp_path):
    assert tree_sitter_available(), "Install the required JS/TS wheels"
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.ts").write_text(
        '// eval(input)\nconst x = "eval(input)"; // real code\neval(input); // call\n'
    )
    fs = [finding(line_number=i) for i in range(1, 4)]
    report = run_tier1(ScanReport(target_dir=str(tmp_path), findings=fs, total_raw_findings=3))
    assert [f.is_false_positive for f in report.findings] == [True, False, False]


@pytest.mark.parametrize(
    "extension,source",
    [
        ("js", "// only comment\n"),
        ("tsx", "const element = <div>hello</div>;\n"),
        ("ts", "const x: number = 1;\n"),
    ],
)
def test_language_grammars(tmp_path, extension, source):
    path = f"a.{extension}"
    (tmp_path / path).write_text(source)
    report = run_tier1(
        ScanReport(
            target_dir=str(tmp_path), findings=[finding(file_path=path)], total_raw_findings=1
        )
    )
    assert report.findings[0].is_false_positive == (extension == "js")


def test_test_scoping_never_hides_credentials(tmp_path):
    fs = [
        finding(file_path="tests/a.ts"),
        finding(tool_name="Gitleaks", file_path="tests/a.ts"),
        finding(tool_name="Trivy", file_path="tests/package-lock.json"),
    ]
    report = run_tier1(ScanReport(target_dir=str(tmp_path), findings=fs, total_raw_findings=3))
    assert [f.is_false_positive for f in fs] == [True, False, False]
    assert report.actionable_count == 2


def test_duplicate_counts_and_prior_run(tmp_path):
    f = finding()
    report = run_tier1(
        ScanReport(target_dir=str(tmp_path), total_raw_findings=2, findings=[f, f.model_copy()])
    )
    assert report.total_raw_findings == 2
    assert report.duplicate_count == 1
    history.save_report(report)
    assert history.prior_findings(str(tmp_path / "other")) == set()
    second = run_tier1(
        ScanReport(target_dir=str(tmp_path), total_raw_findings=1, findings=[finding()]),
        history.prior_findings(str(tmp_path)),
    )
    assert second.known_count == 1


def test_endpoints_get_distinct_fingerprints():
    assert (
        finding(file_path=None, endpoint_url="http://localhost/a").finding_id
        != finding(file_path=None, endpoint_url="http://localhost/b").finding_id
    )


def test_ai_cannot_silently_filter(monkeypatch):
    monkeypatch.setattr(triage_tier2, "llm_available", lambda: True)
    monkeypatch.setattr(
        triage_tier2,
        "_llm_triage",
        lambda *a: TriageResult(
            is_false_positive=True,
            reasoning="maybe noise",
            cvss_score=2.0,
            confidence_score=0.8,
            poc_command="rm -rf /",
        ),
    )
    f = triage_tier2.ai_triage_finding(finding(), allow_llm=True)
    assert f.advisory_false_positive and not f.is_false_positive
    assert f.status == "PENDING_REVIEW" and f.poc_command is None
    report = ScanReport(findings=[f]).recount()
    assert report.new_count == report.pending_review_count == 1


def test_llm_requires_explicit_opt_in(monkeypatch):
    def forbidden(*a):
        raise AssertionError("No external call allowed")

    monkeypatch.setattr(triage_tier2, "_llm_triage", forbidden)
    f = triage_tier2.ai_triage_finding(finding())
    assert f.advisory_mode == "offline" and f.suggested_patch is None


def test_redaction_across_fields():
    output = redact_data(
        {
            "description": 'password="correct horse battery staple"',
            "url": "http://localhost/?token=secretvalue",
            "snippet": "ghp_" + "a" * 30,
            "nested": ["Bearer abcdefghijklmnopqrstuvwxyz"],
        }
    )
    assert "correct horse" not in str(output)
    assert "secretvalue" not in str(output)
    assert "a" * 30 not in str(output)
    assert "abcdefghijklmnopqrstuvwxyz" not in str(output)


@pytest.mark.parametrize(
    "overrides",
    [
        {"cvss_score": 11.0},
        {"confidence_score": 2.0},
        {"is_false_positive": "false"},
        {"extra_command": "run this"},
    ],
)
def test_invalid_llm_schema(overrides):
    with pytest.raises(ValueError):
        TriageResult(
            **{
                "is_false_positive": False,
                "reasoning": "test",
                "cvss_score": 5.0,
                "confidence_score": 0.5,
                **overrides,
            }
        )


def test_every_llm_evidence_field_is_redacted(monkeypatch):
    import json
    import sys
    from types import SimpleNamespace

    calls = []

    def completion(**kwargs):
        calls.append(kwargs)
        return {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "is_false_positive": False,
                                "reasoning": "Needs review",
                                "cvss_score": 5.0,
                                "confidence_score": 0.5,
                                "poc_command": None,
                                "suggested_patch": None,
                            }
                        )
                    }
                }
            ]
        }

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=completion))
    triage_tier2._llm_triage(
        finding(
            raw_description='password="super-secret-value"',
            endpoint_url="http://localhost/?token=another-secret-value",
            code_snippet='api_key="very-secret-value"',
        ),
        "test-model",
    )
    payload = calls[0]["messages"][1]["content"]
    assert "super-secret-value" not in payload
    assert "another-secret-value" not in payload
    assert "very-secret-value" not in payload
    assert calls[0]["timeout"] == 45 and calls[0]["num_retries"] == 0


def test_gitleaks_sample_contexts_filtered_but_test_code_labeled(tmp_path):
    fs = [
        finding(tool_name="Gitleaks", file_path="docs/usage.mdx"),
        finding(tool_name="Gitleaks", file_path="src/config/products.generated.ts"),
        finding(tool_name="Gitleaks", file_path="public/webhook-sample.json"),
        finding(tool_name="Gitleaks", file_path="tests/a.ts"),
        finding(tool_name="Gitleaks", file_path="src/a.ts"),
    ]
    run_tier1(ScanReport(target_dir=str(tmp_path), findings=fs, total_raw_findings=5))
    assert [f.is_false_positive for f in fs] == [True, True, True, False, False]
    assert fs[3].filter_reason.startswith("Credential pattern in test code")
    assert fs[3].severity == "LOW"
    assert fs[4].filter_reason is None


def test_gitleaks_in_untracked_files_is_not_a_repository_leak(tmp_path):
    import subprocess

    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.ts").write_text("x")
    (tmp_path / ".env").write_text("x")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "src/a.ts"], check=True)
    fs = [
        finding(tool_name="Gitleaks", file_path="src/a.ts"),
        finding(tool_name="Gitleaks", file_path=".env"),
    ]
    run_tier1(ScanReport(target_dir=str(tmp_path), findings=fs, total_raw_findings=2))
    assert [f.is_false_positive for f in fs] == [False, True]
    assert "not tracked by git" in fs[1].filter_reason


def test_low_signal_rules_and_informational_zap_are_filtered(tmp_path):
    fs = [
        finding(rule_id="javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring"),
        finding(rule_id="javascript.lang.security.detect-eval.detect-eval", line_number=2),
        finding(
            tool_name="OWASP ZAP",
            rule_id="10027",
            severity="INFO",
            file_path=None,
            line_number=None,
            endpoint_url="http://127.0.0.1:3000/",
        ),
        finding(
            tool_name="OWASP ZAP",
            rule_id="10038",
            severity="MEDIUM",
            file_path=None,
            line_number=None,
            endpoint_url="http://127.0.0.1:3000/",
        ),
    ]
    run_tier1(ScanReport(target_dir=str(tmp_path), findings=fs, total_raw_findings=4))
    assert [f.is_false_positive for f in fs] == [True, False, True, False]


def test_gitleaks_in_dependencies_filtered_and_build_output_not_mislabeled(tmp_path):
    fs = [
        finding(tool_name="Gitleaks", file_path="node_modules/pkg/index.js"),
        finding(tool_name="Gitleaks", file_path=".venv/lib/site-packages/x/conf.py"),
        finding(tool_name="Gitleaks", file_path="dist/app.js"),
    ]
    run_tier1(ScanReport(target_dir=str(tmp_path), findings=fs, total_raw_findings=3))
    assert [f.is_false_positive for f in fs] == [True, True, False]
    # A secret in build output ships to users: actionable, and not called test code.
    assert fs[2].filter_reason is None
