"""Streamlit review workflow. Preview -> inspect -> explicit approval -> draft PR."""

import asyncio
import json

import streamlit as st

import assessment_report
import github_sync
from models import ScanOptions
from pipeline import execute
from redaction import redact_secrets
from scope_guard import ScopeViolationError

st.set_page_config(page_title="Smart Security Pipeline", page_icon="🛡️", layout="wide")
st.title("Smart Security Pipeline")
st.caption(
    "Signal over Noise · World Monitor security assessment · Findings require human verification"
)

with st.sidebar:
    st.header("Scan configuration")
    source = st.text_input("Source directory", "./target-app")
    target = st.text_input("Local application URL (optional)", placeholder="http://localhost:3000")
    offline = st.checkbox("Offline mode (local rules and cached databases)", value=True)
    tier2 = st.checkbox("Enable advisory copilot", value=False)
    allow_llm = st.checkbox(
        "Allow redacted findings to be sent to the AI provider",
        value=False,
        disabled=offline or not tier2,
    )
    model = st.text_input("Model", "gpt-4o-mini", disabled=not tier2)
    rules = st.text_input("Semgrep rule file (optional)")
    repo = st.text_input("GitHub repository (owner/name)", disabled=offline)
    history = st.checkbox("Remember findings in local run history", value=True)
    go = st.button("Run pipeline", type="primary")
    st.caption(
        "Offline mode uses the downloaded rule pack (fetch_rules.py), the cached Trivy "
        "database and an already-pulled ZAP image."
    )

if go:
    try:
        options = ScanOptions(
            target_dir=source,
            target_url=target or None,
            repo_full_name=repo if repo and not offline else None,
            tier2=tier2,
            allow_llm=bool(allow_llm and tier2 and not offline),
            offline=offline,
            llm_model=model,
            semgrep_config=rules or None,
            use_history=history,
        )
        with st.spinner("Scanning and analyzing…"):
            report = asyncio.run(execute(options))
        st.session_state["report"] = report
        st.session_state["scan_repo"] = options.repo_full_name or ""
        st.session_state.pop("preview", None)
        st.session_state.pop("published", None)
    except ScopeViolationError as exc:
        st.error(str(exc))
    except Exception:
        st.error("Scan could not start. Check the source directory and configuration.")

report = st.session_state.get("report")
if report is None:
    st.info("Choose a source directory and run the pipeline.")
    st.stop()

metrics = st.columns(5)
metrics[0].metric("Total raw alerts", report.total_raw_findings)
metrics[1].metric("Filtered by policy", report.deterministic_filtered_count)
metrics[2].metric("Needs investigation", report.actionable_count)
metrics[3].metric("Known / New", f"{report.known_count} / {report.new_count}")
metrics[4].metric("Exact duplicates", report.duplicate_count)
if not report.scan_complete:
    st.warning(
        "Scanner coverage is incomplete. Missing or failed checks are not a clean security result."
    )
for warning in report.warnings:
    st.warning(warning)
with st.expander("Scanner execution details", expanded=not report.scan_complete):
    st.dataframe([s.model_dump() for s in report.scanners], hide_index=True, width="stretch")
downloads = st.columns(3)
downloads[0].download_button(
    "Download redacted report (JSON)",
    report.model_dump_json(indent=2),
    file_name=f"scan-{report.run_id}.json",
    mime="application/json",
)
downloads[1].download_button(
    "Download assessment report (Markdown)",
    assessment_report.to_markdown(report),
    file_name=f"assessment-{report.run_id}.md",
    mime="text/markdown",
)
downloads[2].download_button(
    "Download assessment report (HTML)",
    assessment_report.to_html(report),
    file_name=f"assessment-{report.run_id}.html",
    mime="text/html",
)
view = st.radio("View", ["Deterministic Summary View", "Advisory Copilot View"], horizontal=True)
show_filtered = st.checkbox("Include filtered findings", value=False)
findings = [f for f in report.findings if show_filtered or not f.is_false_positive]
if not findings:
    st.info("No findings in this view. Check scanner coverage above.")
    st.stop()

rows = [
    {
        "Tool": f.tool_name,
        "Severity": f.severity,
        "Rule": f.rule_id,
        "Location": f"{f.file_path or f.endpoint_url}:{f.line_number or ''}",
        "Status": f.status,
    }
    for f in findings
]
selection = st.dataframe(
    rows,
    hide_index=True,
    width="stretch",
    on_select="rerun",
    selection_mode="single-row",
    key=f"findings-{report.run_id}-{show_filtered}",
)
indices = selection.selection.rows
index = indices[0] if indices else 0
finding = findings[min(index, len(findings) - 1)]
st.subheader(finding.rule_id)
st.write(finding.raw_description)
if finding.filter_reason:
    st.info(finding.filter_reason)
if finding.code_snippet:
    st.code(redact_secrets(finding.code_snippet), language="typescript")
if finding.github_issue_url:
    st.link_button("Related GitHub issue", finding.github_issue_url)
if finding.is_false_positive:
    if st.button("Restore for investigation"):
        finding.is_false_positive = False
        finding.filtered_by = None
        finding.filter_reason = "Restored by human reviewer"
        finding.status = "PENDING_REVIEW"
        report.recount()
        st.rerun()
    st.stop()

if view == "Advisory Copilot View":
    st.write(f"Analysis mode: **{finding.advisory_mode or 'not run'}**")
    st.write(
        f"CVSS estimate: **{finding.cvss_score}** · Confidence: **{finding.confidence_score}**"
    )
    if finding.advisory_reasoning:
        st.write(finding.advisory_reasoning)
    if finding.advisory_false_positive:
        st.warning(
            "AI suggests this may be a false positive. It remains actionable until a person reviews it."
        )
    if finding.poc_command:
        st.caption("Suggested read-only probe — displayed, never executed")
        st.code(finding.poc_command, language="bash")
    if finding.suggested_patch:
        st.code(finding.suggested_patch, language="diff")

st.divider()
st.write("Review and publish")
publish_repo = st.text_input(
    "Repository for this draft",
    st.session_state.get("scan_repo", ""),
    key=f"publish-repo-{report.run_id}",
)
base = st.text_input("Base branch (blank uses repository default)")
patch = st.text_area(
    "Reviewed unified diff (optional for an issue)",
    value=finding.suggested_patch or "",
    height=180,
    key=f"patch-{report.run_id}-{finding.finding_id}",
)
proposal_finding = finding.model_copy(update={"suggested_patch": patch or None})
# Bind stored preview to the current selection and edited form as well as payload.
form_key = json.dumps([report.run_id, finding.finding_id, publish_repo, base, patch])
left, right = st.columns(2)
try:
    if left.button("Preview issue", disabled=not publish_repo):
        st.session_state["preview"] = (
            form_key,
            github_sync.prepare_issue(publish_repo, proposal_finding),
        )
    if right.button("Preview draft PR", disabled=not publish_repo or not patch):
        with st.spinner("Validating diff against the GitHub base revision…"):
            st.session_state["preview"] = (
                form_key,
                github_sync.prepare_pull_request(publish_repo, proposal_finding, base or None),
            )
except Exception as exc:
    st.session_state.pop("preview", None)
    st.error("Preview failed: " + redact_secrets(str(exc))[:500])

stored = st.session_state.get("preview")
if stored and stored[0] == form_key:
    preview = stored[1]
    digest = preview.digest()
    st.write(f"**Destination:** {preview.repo} · **Type:** {preview.kind}")
    st.code(preview.title)
    st.text(preview.body)
    if preview.diff:
        st.caption(f"Base revision: {preview.base_sha}")
        st.code(preview.diff, language="diff")
    st.caption(f"Preview fingerprint: {digest[:16]}")
    confirmation = st.checkbox(
        "I reviewed this exact proposal and authorize the GitHub write.", key="approve-" + digest
    )
    label = "Approve & Create Draft PR" if preview.kind == "pr" else "Approve & Create Issue"
    if preview.kind == "issue":
        st.caption(
            "GitHub issues have no draft state. Approval creates a visible issue in the selected repository."
        )
    if st.button(label, type="primary", disabled=not confirmation, key="publish-" + digest):
        try:
            with st.spinner("Creating the approved GitHub draft…"):
                result = github_sync.publish_preview(preview, approved_digest=digest)
            finding.status = "APPROVED"
            st.session_state["published"] = result
            st.session_state.pop("preview", None)
            st.rerun()
        except Exception as exc:
            st.error(redact_secrets(str(exc))[:600])
if st.session_state.get("published"):
    result = st.session_state["published"]
    st.success("Approved draft created.")
    st.link_button("Open on GitHub", result["url"])
