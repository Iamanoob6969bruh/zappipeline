"""Local FastAPI orchestration. GitHub HTTP endpoints are preview-only."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import github_sync
from models import ScanOptions, ScanReport, SecurityFinding
from pipeline import execute
from scope_guard import ScopeViolationError
from triage_tier1 import tree_sitter_available
from triage_tier2 import llm_available

app = FastAPI(title="Smart Security Pipeline", version="2.0.0")
_scan_lock = asyncio.Lock()
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _same_loopback_origin(request: Request, origin: str) -> bool:
    host = request.headers.get("host", "")
    hostname = urlsplit("//" + host).hostname
    return hostname in _LOOPBACK_HOSTS and origin == f"{request.url.scheme}://{host}"


@app.middleware("http")
async def local_access(request: Request, call_next):
    token = os.getenv("SSP_API_TOKEN")
    if token:
        supplied = request.headers.get("authorization", "")
        if not secrets.compare_digest(supplied, "Bearer " + token):
            return JSONResponse(status_code=401, content={"detail": "Valid bearer token required"})
    else:
        try:
            local = ipaddress.ip_address(request.client.host).is_loopback
        except (ValueError, AttributeError):
            local = False
        if not local:
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Local clients only; configure SSP_API_TOKEN for authenticated access"
                },
            )
    # A browser visiting an unrelated website must not trigger scans on localhost.
    # Same-origin requests (the /docs page) are allowed only when the Host is a
    # loopback name, so a DNS-rebinding page cannot pass as same-origin.
    origin = request.headers.get("origin")
    if origin and not _same_loopback_origin(request, origin):
        return JSONResponse(
            status_code=403, content={"detail": "Cross-origin browser requests are not supported"}
        )
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def root():
    return {
        "service": "Smart Security Pipeline",
        "docs": "/docs",
        "github_writes": "Streamlit approval only",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "tree_sitter": tree_sitter_available(),
        "llm_configured": llm_available(),
    }


def _check_source(options: ScanOptions):
    allowed = os.getenv("SSP_SOURCE_ROOT")
    if allowed:
        try:
            Path(options.target_dir).expanduser().resolve().relative_to(
                Path(allowed).expanduser().resolve()
            )
        except ValueError:
            raise HTTPException(403, "Source is outside SSP_SOURCE_ROOT") from None


async def _scan(options: ScanOptions):
    _check_source(options)
    if _scan_lock.locked():
        raise HTTPException(409, "A scan is already running in this API worker")
    async with _scan_lock:
        try:
            return await execute(options)
        except ScopeViolationError as exc:
            raise HTTPException(403, str(exc)) from exc
        except (OSError, ValueError):
            raise HTTPException(422, "Invalid source directory or scan configuration") from None


@app.post("/scan", response_model=ScanReport)
async def scan(options: ScanOptions):
    return await _scan(options.model_copy(update={"tier2": False, "allow_llm": False}))


@app.post("/scan/full", response_model=ScanReport)
async def scan_full(options: ScanOptions):
    return await _scan(options.model_copy(update={"tier2": True}))


class DraftRequest(BaseModel):
    repo_full_name: str
    finding: SecurityFinding
    dry_run: bool = True
    base_branch: str | None = None


@app.post("/github/draft-issue")
def draft_issue(request: DraftRequest):
    if not request.dry_run:
        raise HTTPException(
            403, "Approve GitHub writes through Streamlit; this endpoint is preview-only"
        )
    try:
        return github_sync.create_draft_issue(request.repo_full_name, request.finding)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/github/draft-pr")
def draft_pr(request: DraftRequest):
    if not request.dry_run:
        raise HTTPException(
            403, "Approve GitHub writes through Streamlit; this endpoint is preview-only"
        )
    try:
        return github_sync.create_draft_pull_request(
            request.repo_full_name, request.finding, request.base_branch
        )
    except Exception:
        raise HTTPException(
            422, "Could not prepare a PR. Check token, repository, base branch and patch context."
        ) from None
