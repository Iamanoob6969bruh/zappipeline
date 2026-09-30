"""Terminal entrypoint: refusals exit 3; incomplete scanner coverage exits 2."""

import argparse
import asyncio
import json
import sys
from pathlib import Path

from assessment_report import write_report
from models import ScanOptions
from pipeline import execute
from scope_guard import ScopeViolationError


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Local security assessment with explicit coverage reporting"
    )
    parser.add_argument("--src", required=True)
    parser.add_argument("--url")
    parser.add_argument("--repo")
    parser.add_argument("--tier2", action="store_true")
    parser.add_argument(
        "--allow-llm",
        action="store_true",
        help="Explicit consent to send redacted findings to the model provider",
    )
    parser.add_argument(
        "--online", action="store_true", help="Allow scanner downloads, GitHub and configured AI"
    )
    parser.add_argument("--model", default="gpt-4o-mini")
    parser.add_argument("--semgrep-config")
    parser.add_argument("--no-history", action="store_true")
    parser.add_argument("--json", dest="output")
    parser.add_argument(
        "--report", help="Write an assessment report; .html for HTML, otherwise Markdown"
    )
    args = parser.parse_args(argv)
    # Reports are never overwritten; fail before a long scan, not after it.
    for path in (args.output, args.report):
        if path and Path(path).exists():
            print(f"Configuration error: {path} already exists", file=sys.stderr)
            return 1
    try:
        options = ScanOptions(
            target_dir=args.src,
            target_url=args.url,
            repo_full_name=args.repo,
            tier2=args.tier2,
            allow_llm=args.allow_llm,
            llm_model=args.model,
            offline=not args.online,
            semgrep_config=args.semgrep_config,
            use_history=not args.no_history,
        )
        report = asyncio.run(execute(options))
    except ScopeViolationError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except (ValueError, OSError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1
    print(
        f"raw={report.total_raw_findings} duplicates={report.duplicate_count} "
        f"filtered={report.deterministic_filtered_count} actionable={report.actionable_count} "
        f"known={report.known_count} new={report.new_count}"
    )
    for scanner in report.scanners:
        print(
            f"{scanner.tool_name}: {scanner.status} ({scanner.finding_count} findings) {scanner.message}"
        )
    for warning in report.warnings:
        print(f"Warning: {warning}", file=sys.stderr)
    if args.output:
        # Exclusive create prevents accidentally overwriting source files/reports.
        with Path(args.output).open("x") as handle:
            json.dump(report.model_dump(), handle, indent=2)
    if args.report:
        write_report(report, args.report)
        print(f"Assessment report written to {args.report}")
    return 0 if report.scan_complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
