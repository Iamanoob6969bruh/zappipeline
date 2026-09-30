"""Curated CVSS vectors and safe, automatic verification for our own rules.

Verification is read-only: at most two GET requests to a URL that the scope
guard has resolved to loopback, over a connection pinned to the checked IP,
without following redirects. Nothing is sent that changes application state.
"""

from __future__ import annotations

import http.client
import re
import ssl
from urllib.parse import urlsplit

import cvss
from models import ScanReport, SecurityFinding
from scope_guard import ScopeViolationError, resolve_target

# Default vectors for the bug classes our own rules target. Each is a starting
# point for that class; the analyst adjusts it to the specific deployment.
RULE_CVSS: dict[str, tuple[str, str]] = {
    "csp-static-nonce": (
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "needs a separate HTML injection point (AC:H) and a victim visit (UI:R); "
        "script runs in the victim's browser (S:C)",
    ),
    "nginx-injects-internal-credential": (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "unauthenticated clients reach routes meant to require the internal credential; "
        "raise C/I if those routes expose sensitive data or actions",
    ),
    "xml-feed-unescaped-interpolation": (
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "needs attacker-influenced upstream data (AC:H) and a feed consumer (UI:R)",
    ),
}

_NONCE_HEADER = re.compile(r"'nonce-([^']+)'")
_NONCE_ATTR = re.compile(r"""\bnonce=["']([^"']+)["']""", re.I)
_USER_AGENT = "smart-security-pipeline-verifier/1.0 (authorized local testing)"
_MAX_BODY = 512 * 1024


def short_rule(rule_id: str) -> str:
    return rule_id.rsplit(".", 1)[-1]


def apply_curated_cvss(findings: list[SecurityFinding]) -> None:
    for finding in findings:
        curated = RULE_CVSS.get(short_rule(finding.rule_id))
        if curated and not finding.is_false_positive:
            vector, rationale = curated
            finding.cvss_vector = vector
            finding.cvss_score = cvss.base_score(vector)
            finding.cvss_source = f"curated rule vector: {rationale}"


def _get(url: str) -> tuple[int, list[str], str]:
    """One read-only GET, pinned to the IP the scope guard approved."""
    target = resolve_target(url)
    parts = urlsplit(target.url)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    if target.scheme == "https":
        # Loopback targets usually have self-signed certificates. The connection
        # is pinned to a checked loopback IP and only collects evidence.
        context = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(target.ip, target.port, timeout=10, context=context)
    else:
        conn = http.client.HTTPConnection(target.ip, target.port, timeout=10)
    default_port = 443 if target.scheme == "https" else 80
    name = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
    host = name if target.port == default_port else f"{name}:{target.port}"
    try:
        conn.request(
            "GET", path, headers={"Host": host, "User-Agent": _USER_AGENT, "Accept": "text/html"}
        )
        response = conn.getresponse()
        csp = response.headers.get_all("Content-Security-Policy") or []
        body = response.read(_MAX_BODY).decode("utf-8", errors="replace")
        return response.status, csp, body
    finally:
        conn.close()


def verify_static_nonce(url: str) -> str:
    """Evidence text: the CSP nonce is (or is not) the same across two responses."""
    seen = []
    for _ in range(2):
        status, csp, body = _get(url)
        header_nonces = sorted({n for value in csp for n in _NONCE_HEADER.findall(value)})
        page_nonces = sorted(set(_NONCE_ATTR.findall(body)))
        seen.append((status, header_nonces, page_nonces))
    (status1, first, page1), (status2, second, _) = seen
    if not first and not second:
        return (
            f"NOT REPRODUCED on {url}: HTTP {status1}/{status2}, no nonce in the "
            "Content-Security-Policy header. The flagged config may not be served at this path."
        )
    if first != second:
        return (
            f"NOT REPRODUCED on {url}: the CSP nonce changed between two requests "
            "(random per response, as intended)."
        )
    values = ", ".join(f"'nonce-{n}'" for n in first)
    in_page = [n for n in first if n in page1]
    page_note = (
        f' The same value is visible in the page source (nonce="{in_page[0]}").' if in_page else ""
    )
    return (
        f"CONFIRMED on {url}: two separate requests (HTTP {status1}, {status2}) returned the "
        f"identical CSP nonce {values}. A nonce must be random for every response; this one "
        f"is fixed and public.{page_note}"
    )


def run_verification(report: ScanReport) -> None:
    """Attach automatic evidence to findings our verifiers support."""
    apply_curated_cvss(report.findings)
    nonce_findings = [
        f
        for f in report.findings
        if not f.is_false_positive and short_rule(f.rule_id) == "csp-static-nonce"
    ]
    if not nonce_findings:
        return
    if not report.target_url:
        note = (
            "Not verified automatically: no local URL was given. Rerun with the app's "
            "localhost URL to confirm the nonce is served unchanged."
        )
    else:
        try:
            note = verify_static_nonce(report.target_url)
        except ScopeViolationError as exc:
            note = f"Not verified: {exc}"
        except (OSError, http.client.HTTPException) as exc:
            note = f"Not verified: the local app did not respond ({type(exc).__name__})."
    for finding in nonce_findings:
        finding.verification = note
