"""Read-only deduplication and explicit, content-bound GitHub approval.

Only the Streamlit workflow calls publish_preview. HTTP endpoints are previews.
A PR is built on an isolated remote branch; the user's checkout is never changed.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import PurePosixPath

from pydantic import BaseModel, ConfigDict, Field

import history
from models import SecurityFinding
from redaction import redact_data, redact_secrets


class FileChange(BaseModel):
    path: str
    old_sha: str
    content: str
    mode: str = "100644"


class DraftPreview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str
    repo: str
    finding_id: str
    title: str
    body: str
    base_branch: str = ""
    base_sha: str = ""
    diff: str = ""
    changes: list[FileChange] = Field(default_factory=list)

    def digest(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()


def _get_repo(repo_full_name: str):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo_full_name):
        raise ValueError("Use a GitHub repository in owner/name format")
    from github import Auth, Github

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN is required for GitHub access")
    return Github(auth=Auth.Token(token), timeout=20, retry=0).get_repo(repo_full_name)


def fetch_security_issues(repo_full_name: str):
    # Bound matching work and API consumption; no exception-to-empty conversion.
    repo = _get_repo(repo_full_name)
    issues = repo.get_issues(state="open", labels=["security"])
    from itertools import islice

    return [i for i in islice(issues, 500) if not i.pull_request]


def match_known(
    findings: list[SecurityFinding], repo_full_name: str, prior_hashes: set[str] | None = None
):
    from rapidfuzz.fuzz import partial_ratio

    issues = fetch_security_issues(repo_full_name)
    for finding in findings:
        if finding.is_false_positive:
            continue
        if finding.finding_id in (prior_hashes or set()):
            finding.status = "KNOWN"
            finding.known_source = "local history"
        text = (finding.rule_id + " " + finding.raw_description).lower()
        for issue in issues:
            exact = f"finding:{finding.finding_id}" in (issue.body or "")
            title = issue.title.lower()
            # partial_ratio scores a short title like "XSS" 100 against any text
            # containing it, so fuzzy matching needs a descriptive title.
            fuzzy = len(title.split()) >= 4 and partial_ratio(text, title) > 85
            if exact or fuzzy:
                finding.status = "KNOWN"
                finding.github_issue_id = issue.number
                finding.github_issue_url = issue.html_url
                finding.known_source = (
                    "GitHub exact fingerprint"
                    if exact
                    else "GitHub title similarity (verify manually)"
                )
                break
    return findings


def _body(finding: SecurityFinding):
    return redact_secrets(
        f"<!-- finding:{finding.finding_id} -->\n"
        f"**Tool:** {finding.tool_name}\n**Rule:** {finding.rule_id}\n"
        f"**Severity:** {finding.severity}\n**CVSS estimate:** {finding.cvss_score}\n"
        f"**Location:** {finding.file_path or finding.endpoint_url}:{finding.line_number or ''}\n\n"
        f"{finding.raw_description}\n\n{finding.advisory_reasoning or ''}\n\n"
        "Human-reviewed draft from Smart Security Pipeline. Exploitability and patch correctness require verification."
    )


def _safe_path(value: str) -> str:
    if not value.startswith(("a/", "b/")):
        raise ValueError("Diff paths must use a/ and b/ prefixes")
    path = value[2:]
    parts = PurePosixPath(path).parts
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or any(c.isspace() for c in path)
        or any(
            p in {".", "..", ".git", ".github", ".ssh", ".aws", ".codex", ".agents"} for p in parts
        )
        or any(p.startswith(".env") for p in parts)
    ):
        raise ValueError("Patch targets an unsupported or sensitive path")
    return path


def apply_reviewed_diff(diff: str, originals: dict[str, str]) -> dict[str, str]:
    """Strict contextual application in memory; no fuzzy matching or shell."""
    from unidiff import PatchSet

    if not diff or len(diff) > 100000 or "[REDACTED" in diff:
        raise ValueError("Patch is empty, too large, or contains redacted evidence")
    patches = PatchSet(diff)
    if not patches or len(patches) > 10:
        raise ValueError("A patch must edit between one and ten existing text files")
    result = {}
    for patch in patches:
        path = _safe_path(patch.source_file)
        if (
            path != _safe_path(patch.target_file)
            or patch.is_added_file
            or patch.is_removed_file
            or patch.is_binary_file
        ):
            raise ValueError("Only edits to existing text files are supported")
        if path in result or not patch:
            raise ValueError("Duplicate file or empty patch")
        source = originals[path].splitlines(keepends=True)
        output, cursor = [], 0
        for hunk in patch:
            start = hunk.source_start - 1 if hunk.source_length else hunk.source_start
            if start < cursor or start > len(source):
                raise ValueError("Overlapping or out-of-range diff hunks")
            output.extend(source[cursor:start])
            cursor = start
            # A no-newline marker adjusts the preceding line, not file contents.
            lines = list(hunk)
            for index, line in enumerate(lines):
                if line.line_type == "\\":
                    continue
                value = line.value
                if index + 1 < len(lines) and lines[index + 1].line_type == "\\":
                    value = value.rstrip("\n")
                if line.is_context or line.is_removed:
                    if cursor >= len(source) or source[cursor] != value:
                        raise ValueError(
                            "Patch context does not match the selected GitHub base revision"
                        )
                    cursor += 1
                if line.is_context or line.is_added:
                    output.append(value)
        output.extend(source[cursor:])
        result[path] = "".join(output)
        if result[path] == originals[path]:
            raise ValueError("Patch does not change file content")
    return result


def prepare_issue(repo_full_name: str, finding: SecurityFinding) -> DraftPreview:
    if finding.is_false_positive:
        raise ValueError("Restore the filtered finding before drafting an issue")
    return DraftPreview(
        kind="issue",
        repo=repo_full_name,
        finding_id=finding.finding_id,
        title=redact_secrets(f"[security] {finding.rule_id}: {finding.raw_description[:60]}"),
        body=_body(finding),
    )


def prepare_pull_request(
    repo_full_name: str, finding: SecurityFinding, base_branch: str | None = None
) -> DraftPreview:
    from unidiff import PatchSet

    if finding.is_false_positive or not finding.suggested_patch:
        raise ValueError("An actionable finding with a reviewed diff is required")
    diff = finding.suggested_patch
    if len(diff) > 100000 or "[REDACTED" in diff:
        raise ValueError("Patch is too large or contains redacted source; supply a corrected diff")
    patches = PatchSet(diff)
    if not patches or len(patches) > 10:
        raise ValueError("Patch must edit between one and ten existing files")
    paths = [_safe_path(p.source_file) for p in patches]
    for patch in patches:
        if _safe_path(patch.source_file) != _safe_path(patch.target_file):
            raise ValueError("Renames, additions and deletions require manual handling")
    repo = _get_repo(repo_full_name)
    branch = base_branch or repo.default_branch
    base = repo.get_branch(branch).commit.sha
    originals, blobs = {}, {}
    base_tree = repo.get_git_tree(base, recursive=True)
    if base_tree.truncated:
        raise ValueError("Repository tree is too large to validate safely")
    entries = {entry.path: entry for entry in base_tree.tree}
    for path in paths:
        blob = repo.get_contents(path, ref=base)
        if isinstance(blob, list) or blob.type != "file" or blob.size > 1_000_000:
            raise ValueError("Only regular text files up to 1 MB can be patched")
        # The tree is authoritative for symlink/submodule mode.
        entry = entries.get(path)
        if entry is None or entry.mode not in {"100644", "100755"} or entry.type != "blob":
            raise ValueError("Symlinks and submodules cannot be patched")
        originals[path] = blob.decoded_content.decode("utf-8")
        blobs[path] = (blob.sha, entry.mode)
    changes = apply_reviewed_diff(diff, originals)
    return DraftPreview(
        kind="pr",
        repo=repo_full_name,
        finding_id=finding.finding_id,
        title=f"fix(security): {finding.rule_id}",
        body=_body(finding),
        base_branch=branch,
        base_sha=base,
        diff=diff,
        changes=[
            FileChange(path=path, old_sha=blobs[path][0], content=content, mode=blobs[path][1])
            for path, content in changes.items()
        ],
    )


def publish_preview(preview: DraftPreview, *, approved_digest: str) -> dict:
    """Called only after the UI's explicit approval button; never from scan code."""
    if approved_digest != preview.digest():
        raise PermissionError("Approval does not match the exact preview")
    repo = _get_repo(preview.repo)
    if not (getattr(repo.permissions, "push", False) or getattr(repo.permissions, "admin", False)):
        raise PermissionError("Repository write access is required")
    if preview.kind not in {"issue", "pr"}:
        raise ValueError("Unsupported draft type")
    if preview.kind == "pr":
        if repo.get_branch(preview.base_branch).commit.sha != preview.base_sha:
            raise ValueError("Base branch changed. Generate and approve a fresh preview.")
        if not preview.changes:
            raise ValueError("No changes in preview")
    history.reserve_approval(approved_digest)
    branch = None
    try:
        if preview.kind == "issue":
            issue = repo.create_issue(title=preview.title, body=preview.body, labels=["security"])
            result = {"created": True, "number": issue.number, "url": issue.html_url}
        else:
            from github import InputGitTreeElement

            parent = repo.get_git_commit(preview.base_sha)
            elements = []
            for change in preview.changes:
                blob = repo.create_git_blob(change.content, "utf-8")
                elements.append(InputGitTreeElement(change.path, change.mode, "blob", sha=blob.sha))
            tree = repo.create_git_tree(elements, base_tree=parent.tree)
            commit = repo.create_git_commit(preview.title, tree, [parent])
            branch = "ssp/security-" + approved_digest[:20]
            repo.create_git_ref("refs/heads/" + branch, commit.sha)
            pr = repo.create_pull(
                title=preview.title,
                body=preview.body,
                base=preview.base_branch,
                head=branch,
                draft=True,
            )
            result = {"created": True, "number": pr.number, "url": pr.html_url, "branch": branch}
        history.finish_approval(approved_digest, "created", result)
        return result
    except Exception:
        # Never retry an uncertain external mutation automatically.
        history.finish_approval(approved_digest, "needs_inspection", {"branch": branch})
        raise RuntimeError(
            "GitHub creation did not finish cleanly. Inspect GitHub and the approval audit before retrying."
            + (f" Possible branch: {branch}" if branch else "")
        ) from None


def create_draft_issue(
    repo_full_name: str,
    finding: SecurityFinding,
    dry_run: bool = True,
    approved_digest: str | None = None,
) -> dict:
    preview = prepare_issue(repo_full_name, finding)
    if dry_run:
        return {
            "created": False,
            "dry_run": True,
            "digest": preview.digest(),
            **redact_data(preview.model_dump()),
        }
    if not approved_digest:
        raise PermissionError("Explicit approval of the preview is required")
    return publish_preview(preview, approved_digest=approved_digest)


def create_draft_pull_request(
    repo_full_name: str,
    finding: SecurityFinding,
    base_branch: str | None = None,
    dry_run: bool = True,
    approved_digest: str | None = None,
) -> dict:
    preview = prepare_pull_request(repo_full_name, finding, base_branch)
    if dry_run:
        # Do not expose full source contents; UI retains the preview server-side.
        return {
            "created": False,
            "dry_run": True,
            "digest": preview.digest(),
            **redact_data(preview.model_dump(exclude={"changes"})),
        }
    if not approved_digest:
        raise PermissionError("Explicit approval of the preview is required")
    return publish_preview(preview, approved_digest=approved_digest)
