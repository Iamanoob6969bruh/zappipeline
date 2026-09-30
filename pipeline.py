"""One orchestration path for CLI, FastAPI and Streamlit."""

import asyncio

import github_sync
import history
from evidence import run_verification
from models import ScanOptions, ScanReport
from redaction import redact_data
from runner import run_scanners
from triage_tier1 import run_tier1
from triage_tier2 import run_tier2


async def execute(options: ScanOptions) -> ScanReport:
    report = await run_scanners(
        options.target_dir,
        options.target_url,
        offline=options.offline,
        semgrep_config=options.semgrep_config,
    )
    prior = set()
    if options.use_history:
        try:
            prior = await asyncio.to_thread(history.prior_findings, report.target_dir)
        except Exception:
            report.warnings.append(
                "Local history unavailable; prior-run matching was not performed."
            )
    run_tier1(report, prior)
    if options.tier2:
        await asyncio.to_thread(
            run_tier2, report.findings, options.llm_model, allow_llm=options.allow_llm
        )
    if options.repo_full_name:
        try:
            await asyncio.to_thread(
                github_sync.match_known, report.findings, options.repo_full_name
            )
        except Exception:
            report.warnings.append(
                "GitHub lookup unavailable; unmatched findings are not confirmed new upstream."
            )
    # After Tier 2, so curated vectors and local evidence outrank estimates.
    await asyncio.to_thread(run_verification, report)
    report.recount()
    # Defense in depth: API/CLI return exactly the sanitized persisted contract.
    clean = ScanReport.model_validate(redact_data(report.model_dump()))
    if options.use_history:
        try:
            await asyncio.to_thread(history.save_report, clean)
        except Exception:
            clean.warnings.append("Could not persist this run to local history.")
    return clean
