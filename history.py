"""Local SQLite run history. Stores redacted reports, never credentials."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from models import ScanReport
from redaction import redact_data


@contextmanager
def _connect():
    directory = Path(os.getenv("SSP_STATE_DIR", str(Path(__file__).parent / ".ssp")))
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    connection = sqlite3.connect(directory / "history.sqlite3", timeout=15)
    os.chmod(directory / "history.sqlite3", 0o600)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, project TEXT, created_at TEXT, report TEXT)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS findings (project TEXT, finding_id TEXT, PRIMARY KEY(project, finding_id))"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS approvals (digest TEXT PRIMARY KEY, state TEXT, result TEXT)"
    )
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def project_key(target_dir: str) -> str:
    return hashlib.sha256(str(Path(target_dir).resolve()).encode()).hexdigest()


def prior_findings(target_dir: str) -> set[str]:
    with _connect() as db:
        return {
            r[0]
            for r in db.execute(
                "SELECT finding_id FROM findings WHERE project=?", (project_key(target_dir),)
            )
        }


def save_report(report: ScanReport):
    key = project_key(report.target_dir)
    with _connect() as db:
        db.execute(
            "INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?)",
            (report.run_id, key, report.created_at, json.dumps(redact_data(report.model_dump()))),
        )
        db.executemany(
            "INSERT OR IGNORE INTO findings VALUES (?, ?)",
            [(key, f.finding_id) for f in report.findings if not f.is_false_positive],
        )


def reserve_approval(digest: str):
    with _connect() as db:
        try:
            db.execute("INSERT INTO approvals VALUES (?, ?, ?)", (digest, "in_progress", "{}"))
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                "This approval was already used. Check GitHub and the local audit record before retrying."
            ) from exc


def finish_approval(digest: str, state: str, result: dict):
    with _connect() as db:
        db.execute(
            "UPDATE approvals SET state=?, result=? WHERE digest=?",
            (state, json.dumps(redact_data(result)), digest),
        )
