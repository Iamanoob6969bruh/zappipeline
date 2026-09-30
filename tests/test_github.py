from types import SimpleNamespace as NS
from unittest.mock import MagicMock

import pytest

import github_sync as sync
from models import SecurityFinding

DIFF = "--- a/src/a.js\n+++ b/src/a.js\n@@ -1 +1 @@\n-eval(input);\n+safe(input);\n"


def finding():
    return SecurityFinding(
        tool_name="Semgrep", rule_id="eval", file_path="src/a.js", suggested_patch=DIFF
    )


def repository():
    repo = MagicMock()
    repo.default_branch = "main"
    repo.permissions = NS(push=True, admin=False)
    repo.get_branch.return_value = NS(commit=NS(sha="base123"))
    repo.get_git_tree.return_value = NS(
        truncated=False, tree=[NS(path="src/a.js", mode="100644", type="blob")]
    )
    repo.get_contents.return_value = NS(
        type="file", size=13, decoded_content=b"eval(input);\n", sha="old123"
    )
    repo.get_git_commit.return_value = NS(tree=NS(sha="tree123"))
    repo.create_git_blob.return_value = NS(sha="newblob")
    repo.create_git_commit.return_value = NS(sha="newcommit")
    repo.create_pull.return_value = NS(number=7, html_url="https://github.com/me/repo/pull/7")
    repo.create_issue.return_value = NS(number=8, html_url="https://github.com/me/repo/issues/8")
    return repo


def test_diff_context_strictness():
    assert sync.apply_reviewed_diff(DIFF, {"src/a.js": "eval(input);\n"}) == {
        "src/a.js": "safe(input);\n"
    }
    with pytest.raises(ValueError, match="context"):
        sync.apply_reviewed_diff(DIFF, {"src/a.js": "changed();\n"})


@pytest.mark.parametrize(
    "path", ["../escape.js", "/tmp/a.js", ".github/workflows/a.yml", ".env", ".git/config"]
)
def test_reject_unsafe_patch_paths(path):
    diff = DIFF.replace("src/a.js", path)
    with pytest.raises(ValueError):
        sync.apply_reviewed_diff(diff, {path: "eval(input);\n"})


def test_review_creates_only_draft_pr_without_local_edits(monkeypatch):
    repo = repository()
    monkeypatch.setattr(sync, "_get_repo", lambda _: repo)
    preview = sync.prepare_pull_request("me/repo", finding())
    repo.create_git_blob.assert_not_called()
    result = sync.publish_preview(preview, approved_digest=preview.digest())
    assert result["created"]
    assert repo.create_pull.call_args.kwargs["draft"] is True
    assert repo.create_pull.call_args.kwargs["base"] == "main"
    assert repo.create_git_ref.call_args.args[0].startswith("refs/heads/ssp/security-")
    with pytest.raises(ValueError, match="already used"):
        sync.publish_preview(preview, approved_digest=preview.digest())
    assert repo.create_pull.call_count == 1


def test_modified_preview_invalidates_approval(monkeypatch):
    repo = repository()
    monkeypatch.setattr(sync, "_get_repo", lambda _: repo)
    preview = sync.prepare_pull_request("me/repo", finding())
    digest = preview.digest()
    preview.repo = "someone/else"
    with pytest.raises(PermissionError):
        sync.publish_preview(preview, approved_digest=digest)
    repo.create_git_blob.assert_not_called()


def test_stale_base_rejected(monkeypatch):
    repo = repository()
    monkeypatch.setattr(sync, "_get_repo", lambda _: repo)
    preview = sync.prepare_pull_request("me/repo", finding())
    repo.get_branch.return_value.commit.sha = "changed"
    with pytest.raises(ValueError, match="Base branch changed"):
        sync.publish_preview(preview, approved_digest=preview.digest())
    repo.create_git_blob.assert_not_called()


def test_symlink_rejected(monkeypatch):
    repo = repository()
    repo.get_git_tree.return_value.tree[0].mode = "120000"
    monkeypatch.setattr(sync, "_get_repo", lambda _: repo)
    with pytest.raises(ValueError, match="Symlinks"):
        sync.prepare_pull_request("me/repo", finding())


def test_write_permission_required(monkeypatch):
    repo = repository()
    repo.permissions.push = False
    monkeypatch.setattr(sync, "_get_repo", lambda _: repo)
    preview = sync.prepare_issue("me/repo", finding())
    with pytest.raises(PermissionError):
        sync.publish_preview(preview, approved_digest=preview.digest())
    repo.create_issue.assert_not_called()


def test_uncertain_pr_creation_cannot_be_retried(monkeypatch):
    repo = repository()
    monkeypatch.setattr(sync, "_get_repo", lambda _: repo)
    preview = sync.prepare_pull_request("me/repo", finding())
    repo.create_pull.side_effect = TimeoutError("Unknown remote state")
    with pytest.raises(RuntimeError, match="Possible branch"):
        sync.publish_preview(preview, approved_digest=preview.digest())
    with pytest.raises(ValueError, match="already used"):
        sync.publish_preview(preview, approved_digest=preview.digest())


def test_issue_hash_matching(monkeypatch):
    f = finding()
    monkeypatch.setattr(
        sync,
        "fetch_security_issues",
        lambda _: [
            NS(
                title="Unrelated title",
                body=f"<!-- finding:{f.finding_id} -->",
                number=9,
                html_url="https://github.com/me/repo/issues/9",
            )
        ],
    )
    sync.match_known([f], "me/repo")
    assert f.status == "KNOWN" and f.github_issue_id == 9


def test_issue_preview_does_not_contact_github(monkeypatch):
    def forbidden(*args):
        raise AssertionError("Must not contact GitHub")

    monkeypatch.setattr(sync, "_get_repo", forbidden)
    assert sync.create_draft_issue("me/repo", finding())["created"] is False


def test_fuzzy_match_requires_descriptive_title(monkeypatch):
    issues = [NS(title="eval", body="", number=1, html_url="https://github.com/me/repo/issues/1")]
    monkeypatch.setattr(sync, "fetch_security_issues", lambda _: issues)
    f = finding()
    sync.match_known([f], "me/repo")
    assert f.status == "NEW"
    issues[:] = [
        NS(
            title="Unsafe eval of request input",
            body="",
            number=2,
            html_url="https://github.com/me/repo/issues/2",
        )
    ]
    sync.match_known([f], "me/repo")
    assert f.status == "KNOWN" and f.github_issue_id == 2
