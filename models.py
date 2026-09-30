"""Validated contracts shared by scanners, triage, API and dashboard."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
Status = Literal["NEW", "KNOWN", "FILTERED", "PENDING_REVIEW", "APPROVED"]


def compute_finding_id(
    tool: str,
    rule_id: str,
    file_path: str | None,
    line_number: int | None,
    endpoint_url: str | None = None,
) -> str:
    # Include the endpoint for web alerts; otherwise unrelated URLs collide.
    basis = f"{tool}|{rule_id}|{file_path or endpoint_url or ''}|{line_number or 0}"
    return hashlib.sha256(basis.encode()).hexdigest()


class SecurityFinding(BaseModel):
    model_config = ConfigDict(validate_assignment=True)
    finding_id: str = ""
    tool_name: Literal["Semgrep", "Gitleaks", "OWASP ZAP", "Trivy"]
    rule_id: str
    severity: Severity = "INFO"
    file_path: str | None = None
    line_number: int | None = Field(default=None, ge=1)
    column_number: int | None = Field(default=None, ge=1)
    endpoint_url: str | None = None
    raw_description: str = ""
    code_snippet: str | None = None
    is_false_positive: bool = False
    filter_reason: str | None = None
    filtered_by: Literal["tier1", "tier2"] | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = None
    cvss_source: str | None = None
    poc_command: str | None = None
    suggested_patch: str | None = None
    confidence_score: float | None = Field(default=None, ge=0, le=1)
    advisory_reasoning: str | None = None
    advisory_false_positive: bool = False
    advisory_mode: Literal["llm", "offline"] | None = None
    github_issue_id: int | None = None
    github_issue_url: str | None = None
    known_source: str | None = None
    verification: str | None = None
    status: Status = "NEW"

    def model_post_init(self, _ctx) -> None:
        if not self.finding_id:
            self.finding_id = compute_finding_id(
                self.tool_name, self.rule_id, self.file_path, self.line_number, self.endpoint_url
            )


class TriageResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    is_false_positive: bool
    reasoning: str = Field(max_length=8000)
    cvss_score: float = Field(ge=0, le=10)
    poc_command: str | None = Field(default=None, max_length=4000)
    suggested_patch: str | None = Field(default=None, max_length=100000)
    confidence_score: float = Field(ge=0, le=1)


class ScannerResult(BaseModel):
    tool_name: str
    status: Literal["completed", "skipped", "failed", "timeout"]
    exit_code: int | None = None
    duration_seconds: float = 0
    finding_count: int = 0
    message: str = ""
    findings: list[SecurityFinding] = Field(default_factory=list, exclude=True)


class ScanReport(BaseModel):
    run_id: str = Field(default_factory=lambda: uuid4().hex)
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    target_dir: str = ""
    target_url: str | None = None
    scope_reason: str = ""
    total_raw_findings: int = 0
    duplicate_count: int = 0
    deterministic_filtered_count: int = 0
    advisory_filtered_count: int = 0
    actionable_count: int = 0
    known_count: int = 0
    new_count: int = 0
    pending_review_count: int = 0
    scan_complete: bool = False
    scanners: list[ScannerResult] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    findings: list[SecurityFinding] = Field(default_factory=list)

    def recount(self) -> ScanReport:
        # Preserve the collection count even after exact duplicates disappear.
        self.deterministic_filtered_count = sum(
            f.is_false_positive and f.filtered_by != "tier2" for f in self.findings
        )
        self.advisory_filtered_count = sum(
            f.is_false_positive and f.filtered_by == "tier2" for f in self.findings
        )
        actionable = [f for f in self.findings if not f.is_false_positive]
        self.actionable_count = len(actionable)
        self.known_count = sum(f.status == "KNOWN" or bool(f.known_source) for f in actionable)
        self.new_count = len(actionable) - self.known_count
        self.pending_review_count = sum(f.status == "PENDING_REVIEW" for f in actionable)
        self.scan_complete = bool(self.scanners) and all(
            s.status == "completed" for s in self.scanners
        )
        return self


class ScanOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_dir: str
    target_url: str | None = None
    repo_full_name: str | None = None
    tier2: bool = False
    allow_llm: bool = False
    llm_model: str = "gpt-4o-mini"
    offline: bool = True
    semgrep_config: str | None = None
    use_history: bool = True

    @model_validator(mode="after")
    def offline_contract(self):
        if self.offline and (self.allow_llm or self.repo_full_name):
            raise ValueError(
                "Offline mode cannot use external AI or GitHub; disable offline explicitly."
            )
        return self
