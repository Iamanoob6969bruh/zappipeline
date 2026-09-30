"""Offline, explainable JS/TS triage. Uncertain evidence stays actionable."""

from __future__ import annotations

import re
import subprocess
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

from models import ScanReport, SecurityFinding

_NOISE_DIRS = {
    "test",
    "tests",
    "__tests__",
    "__mocks__",
    "mocks",
    "mock",
    "fixtures",
    "e2e",
    "coverage",
    "dist",
    "build",
    "out",
    "node_modules",
    "vendor",
    "generated",
    ".venv",
    "venv",
    "site-packages",
}
_TEST_DIRS = {"test", "tests", "__tests__", "__mocks__", "mocks", "mock", "fixtures", "e2e"}
# Installed dependency code: a secret here belongs to a package, not this project.
_THIRD_PARTY_DIRS = {
    "node_modules",
    "bower_components",
    "jspm_packages",
    "vendor",
    ".venv",
    "venv",
    "site-packages",
    ".yarn",
    ".pnpm-store",
}
_TEST_FILE = re.compile(r"\.(?:test|spec|mock|stories|d)\.[cm]?[jt]sx?$", re.I)
# Credential matches here are almost always documented example values.
_DOC_SUFFIXES = {".md", ".mdx", ".rst", ".adoc", ".txt"}
_SAMPLE_DIRS = {"docs", "doc", "examples", "example", "fixtures", "generated"}
_SAMPLE_NAME = re.compile(r"(?:^|[._-])(?:example|sample|dummy|generated)(?:[._-]|$)", re.I)
# Saved scanner output inside the target: it repeats other findings, not new code.
_SCAN_ARTIFACT = re.compile(
    r"^(?:(?:gitleaks|semgrep|trivy|zap)[\w.-]*\.(?:json|sarif)"
    r"|(?:scan|assessment)-[\w.-]+\.(?:json|md|html))$",
    re.I,
)


# Hygiene rules: useful context, but rarely a vulnerability on their own.
_LOW_SIGNAL_SEMGREP = {"unsafe-formatstring", "header-redefinition", "dependabot-missing-cooldown"}


def tracked_files(root: Path) -> set[str] | None:
    """Repository-relative paths tracked by git, or None when not a git checkout."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return {p for p in result.stdout.decode(errors="replace").split("\0") if p}


def _is_test_location(relative: Path) -> bool:
    """Test code specifically (not build output or dependencies)."""
    return any(part.lower() in _TEST_DIRS for part in relative.parts) or bool(
        _TEST_FILE.search(relative.name)
    )


def _in_test_code(relative: Path) -> bool:
    return any(part.lower() in _NOISE_DIRS for part in relative.parts) or bool(
        _TEST_FILE.search(relative.name)
    )


def _sample_credential_context(relative: Path) -> bool:
    return (
        relative.suffix.lower() in _DOC_SUFFIXES
        or any(part.lower() in _SAMPLE_DIRS for part in relative.parts[:-1])
        or bool(_SAMPLE_NAME.search(relative.name))
    )


_EXTENSIONS = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
}


@lru_cache(maxsize=3)
def _language(name):
    import tree_sitter_javascript as javascript
    import tree_sitter_typescript as typescript
    from tree_sitter import Language

    return Language(
        javascript.language()
        if name == "javascript"
        else typescript.language_tsx()
        if name == "tsx"
        else typescript.language_typescript()
    )


def tree_sitter_available() -> bool:
    try:
        from tree_sitter import Parser

        for name in ("javascript", "typescript", "tsx"):
            Parser(_language(name)).parse(b"const value = 1;")
        return True
    except (ImportError, TypeError, ValueError):
        return False


def _comment_only(tree, source: bytes, row: int) -> bool:
    lines = source.splitlines(keepends=True)
    if not 0 <= row < len(lines):
        return False
    start = sum(map(len, lines[:row]))
    end = start + len(lines[row])
    remaining = bytearray(lines[row])
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.end_byte <= start or node.start_byte >= end:
            continue
        if node.type == "comment":
            a, b = max(start, node.start_byte) - start, min(end, node.end_byte) - start
            remaining[a:b] = b" " * (b - a)
        else:
            stack.extend(node.children)
    # A mixed code/comment line, a string or a parse error is never discarded.
    return bool(lines[row].strip()) and not remaining.strip()


def check_ast_reachability(
    finding: SecurityFinding,
    root: Path,
    cache: dict | None = None,
    tracked: set[str] | None = None,
) -> tuple[bool, str]:
    if finding.tool_name == "OWASP ZAP" and finding.severity == "INFO":
        return True, "Policy: informational ZAP alert, not a vulnerability; restore to review"
    if not finding.file_path:
        return False, ""
    relative = Path(finding.file_path)
    untracked = tracked is not None and finding.file_path not in tracked
    if untracked and _SCAN_ARTIFACT.match(relative.name):
        return True, (
            "Policy: saved scanner output (not project code) that repeats other findings; "
            "restore to review"
        )
    # Dependency/configuration warnings matter even in tests.
    if finding.tool_name == "Trivy":
        if untracked and finding.code_snippet == "[REDACTED_SECRET_EVIDENCE]":
            return True, (
                "Policy: secret pattern in a file not tracked by git, so it is not a "
                "repository leak; restore to review"
            )
        return False, ""
    if finding.tool_name == "Gitleaks":
        if any(part in _THIRD_PARTY_DIRS for part in relative.parts[:-1]):
            return True, (
                "Policy: credential pattern in installed third-party dependency code, "
                "not this project's secret; restore to review"
            )
        if untracked:
            return True, (
                "Policy: file is not tracked by git (a local-only file such as .env or a "
                "saved report), so it is not a repository leak; restore to review"
            )
        # Test code can hold real secrets, so only documentation, generated and
        # sample files are filtered. Filtered findings stay restorable.
        if _sample_credential_context(relative):
            return True, (
                "Policy: credential pattern in documentation/generated/sample file "
                "(usually an example value); restore to review"
            )
        return False, ""
    if _in_test_code(relative):
        return True, "Policy: test/mock/generated/build path; retained for human inspection"
    if finding.tool_name == "Semgrep" and finding.rule_id.rsplit(".", 1)[-1] in _LOW_SIGNAL_SEMGREP:
        return True, "Policy: low-signal hygiene rule, rarely exploitable; restore to review"
    if finding.tool_name != "Semgrep" or not finding.line_number:
        return False, ""
    language = _EXTENSIONS.get(relative.suffix.lower())
    if not language:
        return False, ""
    try:
        path = (root / relative).resolve()
        path.relative_to(root)
        if path.stat().st_size > 2_000_000:
            return False, ""
        from tree_sitter import Parser

        cache = cache if cache is not None else {}
        if path not in cache:
            source = path.read_bytes()
            cache[path] = (Parser(_language(language)).parse(source), source)
        tree, source = cache[path]
        if not tree.root_node.has_error and _comment_only(tree, source, finding.line_number - 1):
            return True, "Tree-sitter: flagged line contains comments only"
    except (OSError, ValueError, ImportError, TypeError):
        pass
    return False, ""


def deduplicate(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    return list({f.finding_id: f for f in reversed(findings)}.values())[::-1]


def run_tier1(report: ScanReport, prior_hashes: set[str] | None = None) -> ScanReport:
    root = Path(report.target_dir).resolve()
    before = len(report.findings)
    report.findings = deduplicate(report.findings)
    report.duplicate_count += before - len(report.findings)
    cache = {}
    if not tree_sitter_available():
        report.warnings.append(
            "Tree-sitter unavailable: only path filtering was applied; no AST conclusions made."
        )
    tracked = tracked_files(root) if report.findings else None
    by_location = defaultdict(list)
    for finding in report.findings:
        filtered, reason = check_ast_reachability(finding, root, cache, tracked)
        if filtered:
            finding.is_false_positive = True
            finding.filter_reason = reason
            finding.filtered_by = "tier1"
            finding.status = "FILTERED"
        elif finding.finding_id in (prior_hashes or set()):
            finding.status = "KNOWN"
            finding.known_source = "local history (previously observed, not necessarily resolved)"
        if (
            not filtered
            and finding.tool_name == "Gitleaks"
            and finding.file_path
            and _is_test_location(Path(finding.file_path))
        ):
            # Usually a test fixture: keep it actionable, but don't let dozens of
            # fixtures outrank real HIGH findings.
            finding.severity = "LOW"
            finding.filter_reason = (
                "Credential pattern in test code (usually a fixture; downgraded to LOW): "
                "confirm whether it is real"
            )
        if not filtered:
            by_location[(finding.file_path or finding.endpoint_url, finding.line_number)].append(
                finding
            )
    for (location, _), group in by_location.items():
        tools = {f.tool_name for f in group}
        if location and len(tools) > 1:
            for finding in group:
                finding.filter_reason = (
                    "Same location flagged by "
                    + ", ".join(sorted(tools))
                    + "; not proof of the same vulnerability"
                )
    return report.recount()
