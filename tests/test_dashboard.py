from unittest.mock import MagicMock

from streamlit.testing.v1 import AppTest

import github_sync
from models import ScannerResult, ScanReport, SecurityFinding


def dashboard():
    report = ScanReport(
        target_dir="/tmp/example",
        total_raw_findings=1,
        scanners=[ScannerResult(tool_name="Semgrep", status="completed")],
        findings=[
            SecurityFinding(
                tool_name="Semgrep",
                rule_id="test-rule",
                raw_description="Review this finding",
                file_path="src/a.js",
            )
        ],
    ).recount()
    app = AppTest.from_file("../app.py")
    app.session_state["report"] = report
    app.session_state["scan_repo"] = "me/repo"
    return app.run(timeout=20)


def test_dashboard_explicit_approval(monkeypatch):
    publish = MagicMock(
        return_value={"created": True, "url": "https://github.com/me/repo/issues/1"}
    )
    monkeypatch.setattr(github_sync, "publish_preview", publish)
    app = dashboard()
    assert not app.exception
    next(b for b in app.button if b.label == "Preview issue").click().run()
    assert not app.exception
    button = next(b for b in app.button if b.label == "Approve & Create Issue")
    assert button.disabled
    publish.assert_not_called()
    next(c for c in app.checkbox if c.label.startswith("I reviewed")).check().run()
    next(b for b in app.button if b.label == "Approve & Create Issue").click().run()
    assert not app.exception
    publish.assert_called_once()
    assert app.session_state["report"].findings[0].status == "APPROVED"


def test_dashboard_changed_destination_hides_approval():
    app = dashboard()
    next(b for b in app.button if b.label == "Preview issue").click().run()
    next(t for t in app.text_input if t.label == "Repository for this draft").set_value(
        "me/other"
    ).run()
    assert not app.exception
    assert not any(b.label == "Approve & Create Issue" for b in app.button)
