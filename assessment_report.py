"""Turn a ScanReport into an assessment report in the SIH PS-163 template.

For each finding group: title, description, affected component, severity with a
CVSS 3.1 score (and where it came from), steps to reproduce, proof of concept,
business impact and remediation. Findings sharing a rule are grouped so a large
scan stays readable, and each group is mapped to a PS-163 scope area.

Everything here is derived from scanner output, fixed guidance text and the
read-only verification in evidence.py. Only automatically verified findings are
marked confirmed; the rest are leads until a person reproduces them. Markdown
and HTML are generated; HTML escapes every value.
"""

from __future__ import annotations

import html
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import cvss
from evidence import short_rule
from models import ScanReport, SecurityFinding
from redaction import redact_secrets
from triage_tier2 import _SEV_CVSS, _safe_probe

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_MAX_LOCATIONS = 15

# The PS-163 assessment scope, in the order the problem statement lists it.
AUTH = "Authentication and session management"
AUTHZ = "Authorization and access control"
INPUT = "Input validation and data handling"
API = "API security"
CLIENT = "Client-side security controls"
COMMS = "Secure communication mechanisms"
DATA = "Data storage and privacy protections"
INFRA = "Supporting infrastructure and supply chain"
SCOPE_AREAS = [AUTH, AUTHZ, INPUT, API, CLIENT, COMMS, DATA, INFRA]


@dataclass(frozen=True)
class Guidance:
    name: str
    owasp: str
    scope: str
    impact: str
    remediation: str
    # Optional class-specific reproduction steps; "{loc}" is the first location.
    steps: tuple[str, ...] = field(default=())


# Ordered: the first matching pattern wins. The rule ID is matched first.
_CATEGORIES: list[tuple[str, Guidance]] = [
    (
        r"nosql|\$where",
        Guidance(
            "NoSQL / database code injection",
            "A03:2021 Injection",
            INPUT,
            "An attacker may read or modify database records or run code on the database server.",
            "Never build $where or query operators from strings; use typed query objects "
            "and validate input types.",
        ),
    ),
    (
        r"sql|sequelize|knex-raw|tainted-sql",
        Guidance(
            "SQL injection",
            "A03:2021 Injection",
            INPUT,
            "An attacker may read, change or delete data, or bypass login.",
            "Use parameterized queries or the ORM's bound parameters; never concatenate "
            "input into SQL.",
        ),
    ),
    (
        r"eval|dynamic-function|code-string-concat|code-injection|vm-|10110|dangerous-js",
        Guidance(
            "Code injection",
            "A03:2021 Injection",
            INPUT,
            "An attacker may execute arbitrary code on the server or in the browser.",
            "Remove eval/new Function on data; use a parser or an allowlist of operations.",
        ),
    ),
    (
        r"xml-feed|xml-injection|xxe",
        Guidance(
            "XML injection",
            "A03:2021 Injection",
            INPUT,
            "Upstream text containing '<' or '&' can break the feed for every subscriber or "
            "inject markup that feed readers may render.",
            "Escape values for XML (&, <, >, quotes) before interpolating, or build the "
            "document with an XML library.",
            (
                "Open `{loc}` and note which upstream field is interpolated without escaping.",
                "On a local instance, give that field a test value containing `&` or `<`.",
                "Validate the generated feed (for example with `xmllint --noout`): it fails to "
                "parse or contains the injected element.",
            ),
        ),
    ),
    (
        r"postmessage",
        Guidance(
            "Unrestricted postMessage",
            "A05:2021 Security Misconfiguration",
            CLIENT,
            "Another website could receive data posted to a frame, or send messages that the "
            "page trusts, if other checks fail.",
            "Pass an exact target origin to postMessage, and check event.origin against an "
            "allowlist before acting on a message.",
        ),
    ),
    (
        r"incomplete-sanitization|incomplete-escap",
        Guidance(
            "Incomplete escaping",
            "A03:2021 Injection",
            INPUT,
            "Replacing only the first match leaves later special characters in place, which "
            "can break the escaping it was meant to provide.",
            "Use replaceAll or a global regular expression, or a vetted escaping function.",
        ),
    ),
    (
        r"xss|bypass-?security-?trust|innerhtml|script-tag|unescaped|document-write|raw-html|"
        r"sanitiz",
        Guidance(
            "Cross-site scripting / HTML injection",
            "A03:2021 Injection",
            CLIENT,
            "An attacker may run script in users' browsers, steal sessions or deface pages.",
            "Escape output for its context, keep framework sanitization on, and use a "
            "strict nonce- or hash-based CSP.",
        ),
    ),
    (
        r"ssrf|request-forgery|urllib|tainted-url",
        Guidance(
            "Server-side request forgery",
            "A10:2021 Server-Side Request Forgery",
            API,
            "The server can be made to call internal services or send data to attacker URLs.",
            "Allowlist destination hosts, block private address ranges, and never let input "
            "choose the full URL.",
        ),
    ),
    (
        r"open-redirect",
        Guidance(
            "Open redirect",
            "A01:2021 Broken Access Control",
            CLIENT,
            "Attackers can use a trusted domain to redirect victims to phishing pages.",
            "Redirect only to an allowlist of paths or hosts.",
        ),
    ),
    (
        r"traversal|sendfile|directory-listing|path-join",
        Guidance(
            "Path traversal / file exposure",
            "A01:2021 Broken Access Control",
            AUTHZ,
            "An attacker may read files outside the intended directory or browse files.",
            "Resolve paths and check they stay inside the base directory; disable listings.",
        ),
    ),
    (
        r"nonce",
        Guidance(
            "Static CSP nonce",
            "A05:2021 Security Misconfiguration",
            CLIENT,
            "The nonce is fixed and public, so any HTML injection point can carry it and the "
            "browser will run the injected script. CSP no longer stops XSS: one injection bug "
            "becomes script execution in users' browsers.",
            "Generate a fresh random nonce (at least 128 bits) for every response and add it "
            "to both the header and the script tags, or use hash-based CSP for static pages.",
            (
                "Open `{loc}`: the Content-Security-Policy contains a literal 'nonce-…' value.",
                "Request the page twice from the local instance and compare the "
                "Content-Security-Policy headers.",
                "The nonce is identical on both responses and visible in the page source, so "
                "it is not a secret.",
            ),
        ),
    ),
    (
        r"injects-internal-credential|local-token",
        Guidance(
            "Internal credential injected by proxy",
            "A07:2021 Identification and Authentication Failures",
            AUTH,
            "The proxy attaches an internal credential to every forwarded request, so any "
            "client that can reach it passes the upstream's authentication check.",
            "Authenticate clients at the proxy instead of injecting a shared secret, or keep "
            "the upstream reachable only by trusted internal callers.",
            (
                "Open `{loc}`: the proxy sets a credential header from a secret variable.",
                "On a local instance, request a protected upstream route directly: it is "
                "refused (for example HTTP 401).",
                "Request the same route through the proxy without any credential: it succeeds "
                "(HTTP 200), because the proxy authenticated on the client's behalf.",
            ),
        ),
    ),
    (
        r"gcm",
        Guidance(
            "AES-GCM without a fixed tag length",
            "A02:2021 Cryptographic Failures",
            DATA,
            "Accepting a shortened authentication tag weakens integrity checks, making forged "
            "ciphertexts easier to get accepted.",
            "Pass authTagLength: 16 to createDecipheriv and reject tags of any other length.",
        ),
    ),
    (
        r"weak-hash|md5|sha1|cipher|insecure-random|pseudo-random|weak-crypto",
        Guidance(
            "Weak or misused cryptography",
            "A02:2021 Cryptographic Failures",
            DATA,
            "Protected data, passwords or tokens can be decrypted, cracked or forged.",
            "Use bcrypt/scrypt/argon2 for passwords, SHA-256+ or HMAC for tokens, and "
            "authenticated encryption with full-length tags.",
        ),
    ),
    (
        r"publishable",
        Guidance(
            "Publishable key (public by design)",
            "A07:2021 Identification and Authentication Failures",
            DATA,
            "Low: publishable keys are meant to appear in client code. The risk is only if a "
            "secret key was committed in its place.",
            "Confirm it is a publishable key, not a secret key; no change is needed otherwise.",
        ),
    ),
    (
        r"jwt|hmac|private-key|secret|api-key|password|credential|token|generic-api-key",
        Guidance(
            "Hardcoded secret or credential",
            "A07:2021 Identification and Authentication Failures",
            DATA,
            "If the value is a live credential, anyone with the code can impersonate the "
            "service or access linked accounts.",
            "Remove it from the code and history, rotate it, and load secrets from a vault "
            "or environment.",
            (
                "Open `{loc}` (the value is redacted in this report).",
                "Decide whether it is a real, live credential or a placeholder/test value.",
                "If real, check git history for other copies and which service it unlocks.",
            ),
        ),
    ),
    (
        r"cors|cross-domain|10098",
        Guidance(
            "Permissive cross-origin policy",
            "A05:2021 Security Misconfiguration",
            API,
            "Other websites may read responses that should be same-origin only.",
            "Allow only trusted origins; never reflect arbitrary origins with credentials.",
        ),
    ),
    (
        r"bypass-tls|reject-?unauthorized|tls-verification",
        Guidance(
            "TLS certificate verification disabled",
            "A02:2021 Cryptographic Failures",
            COMMS,
            "Anyone on the network path can impersonate the server and read or change the traffic.",
            "Keep certificate verification on (rejectUnauthorized: true) and supply the "
            "server's CA certificate instead.",
        ),
    ),
    (
        r"insecure-websocket|insecure-transport|http-not-https|cleartext|tls-|ssl-",
        Guidance(
            "Insecure transport",
            "A02:2021 Cryptographic Failures",
            COMMS,
            "Traffic can be read or modified by anyone on the network path.",
            "Use TLS (https://, wss://) for all connections and reject downgrades.",
        ),
    ),
    (
        r"csp|header|hsts|nosniff|permissions-policy|cross-origin|x-frame|10038|10055|10063|"
        r"10021|10035|90004|10020",
        Guidance(
            "Missing or weak security header",
            "A05:2021 Security Misconfiguration",
            CLIENT,
            "Browser protections against XSS, clickjacking and MIME sniffing are weaker.",
            "Set CSP, HSTS, X-Content-Type-Options, frame-ancestors and related headers.",
        ),
    ),
    (
        r"version|banner|10036|10009|10096|disclos",
        Guidance(
            "Information disclosure",
            "A05:2021 Security Misconfiguration",
            DATA,
            "Version numbers, timestamps and other internal details help attackers map the "
            "system and pick known exploits.",
            "Remove version banners and internal details from responses and error pages.",
        ),
    ),
    (
        r"integrity|90003|10017",
        Guidance(
            "Third-party script without integrity check",
            "A08:2021 Software and Data Integrity Failures",
            CLIENT,
            "If the third-party host is compromised, its script runs with full page access.",
            "Add Subresource Integrity (integrity=) or self-host the script.",
        ),
    ),
    (
        r"allerrors|resource-exhaustion",
        Guidance(
            "Unbounded validation errors (resource exhaustion)",
            "A04:2021 Insecure Design",
            INPUT,
            "Crafted input can produce very large error lists that exhaust memory and CPU.",
            "Set allErrors: false when validating untrusted input, and limit request size.",
        ),
    ),
    (
        r"regexp|redos",
        Guidance(
            "Regular expression denial of service (ReDoS)",
            "A04:2021 Insecure Design",
            INPUT,
            "If outside input shapes the pattern or is matched by a slow one, the regex engine "
            "can hang and exhaust CPU.",
            "Use fixed patterns, escape any input placed in a pattern, and bound input sizes.",
        ),
    ),
    (
        r"github-actions|gha-|run-shell-injection|workflow",
        Guidance(
            "CI workflow script injection",
            "A08:2021 Software and Data Integrity Failures",
            INFRA,
            "If a ${{ }} value is attacker-controlled (for example a PR title), it runs as "
            "shell code in CI with access to CI secrets. Values from secrets.* are not "
            "attacker-controlled.",
            "Pass ${{ }} values through env: and quote them in the script; pin third-party "
            "actions to commit SHAs.",
        ),
    ),
    (
        r"npm-|minimum-release|dependabot",
        Guidance(
            "Package manager hardening",
            "A08:2021 Software and Data Integrity Failures",
            INFRA,
            "A freshly published malicious package version could be installed before anyone "
            "notices.",
            "Set a minimum release age in .npmrc (for example min-release-age=7), keep "
            "lockfiles committed, and review new dependencies.",
        ),
    ),
    (
        r"command-injection|spawn-shell|shell-true|child-process|exec-|detect-child",
        Guidance(
            "OS command injection",
            "A03:2021 Injection",
            INPUT,
            "If outside input reaches the command, an attacker may run operating-system commands.",
            "Call processes with an argument list (no shell) and never pass input to a shell.",
        ),
    ),
    (
        r"prototype-pollution|object-assign|mass-assign|remote-property-injection|"
        r"data-exfiltration",
        Guidance(
            "Prototype pollution / mass assignment",
            "A08:2021 Software and Data Integrity Failures",
            INPUT,
            "Attackers may inject object properties that change logic or security checks.",
            "Copy only allowlisted keys, reject __proto__/constructor, or use Object.create(null).",
        ),
    ),
    (
        r"^ds-0002$|missing-user|run-as-root",
        Guidance(
            "Container runs as root",
            "A05:2021 Security Misconfiguration",
            INFRA,
            "If the app in the container is compromised, the attacker has root inside it, "
            "which makes escaping the container or tampering with it easier.",
            "Create a dedicated user and add `USER <name>` before CMD in the Dockerfile.",
        ),
    ),
    (
        r"^ds-0026$|healthcheck",
        Guidance(
            "Container has no health check",
            "A05:2021 Security Misconfiguration",
            INFRA,
            "A hung service is not detected or restarted automatically, which hurts availability.",
            "Add a HEALTHCHECK instruction that probes the service.",
        ),
    ),
    (
        r"missing-internal",
        Guidance(
            "Proxy location reachable from outside",
            "A05:2021 Security Misconfiguration",
            API,
            "Any client can use this proxy location; if it forwards to internal services, "
            "they become reachable from outside.",
            "Add `internal;` if the location should only serve internal redirects; otherwise "
            "restrict it with authentication or allow/deny rules.",
        ),
    ),
    (
        r"^(ds|ksv|avd)-|docker|dockerfile|container|aws-|terraform|k8s|misconfig|nginx|"
        r"request-host",
        Guidance(
            "Infrastructure or container misconfiguration",
            "A05:2021 Security Misconfiguration",
            INFRA,
            "Infrastructure is exposed or privileged more than intended, which makes a "
            "compromise easier to extend.",
            "Apply the scanner's fix note shown in the description, then rebuild and retest.",
        ),
    ),
]

_DEPENDENCY = Guidance(
    "Vulnerable dependency",
    "A06:2021 Vulnerable and Outdated Components",
    INFRA,
    "A published vulnerability in this package may be exploitable if the app uses the "
    "affected feature.",
    "Upgrade to a fixed version shown in the evidence, then rerun tests and this scan.",
)
_GENERIC = Guidance(
    "Security weakness",
    "Unclassified",
    INPUT,
    "Depends on whether untrusted input reaches the flagged code.",
    "Review the flagged code against the rule description and fix or document the risk.",
)


def classify(finding: SecurityFinding) -> Guidance:
    if finding.tool_name == "Trivy" and re.match(r"(CVE|GHSA)-", finding.rule_id):
        return _DEPENDENCY
    # The rule ID is the stronger signal; descriptions can mention other classes.
    for text in (finding.rule_id.lower(), finding.raw_description[:200].lower()):
        for pattern, guidance in _CATEGORIES:
            if re.search(pattern, text):
                return guidance
    return _GENERIC


def _location(f: SecurityFinding) -> str:
    if f.endpoint_url:
        return f.endpoint_url
    return f"{f.file_path or '?'}" + (f":{f.line_number}" if f.line_number else "")


def _steps(f: SecurityFinding, guidance: Guidance) -> list[str]:
    if guidance.steps:
        return [step.format(loc=_location(f)) for step in guidance.steps]
    if f.tool_name == "OWASP ZAP":
        return [
            "Start the application locally (loopback only).",
            f"Request `{f.endpoint_url}` and inspect the response headers and body.",
            "Confirm the condition described above is present.",
        ]
    if guidance is _DEPENDENCY:
        package = f.rule_id.split(":", 1)[-1]
        return [
            f"Open `{f.file_path}`: {f.code_snippet or package}.",
            f"Find what pulls it in, for example `npm ls {package}` for npm projects.",
            "Read the advisory: the risk is real only if the app uses the affected feature.",
        ]
    if f.tool_name == "Trivy":
        return [
            f"Open `{_location(f)}`.",
            f"Confirm the setting: {f.code_snippet or f.raw_description}.",
            "Apply the fix note in the description, rebuild locally and rescan.",
        ]
    return [
        f"Open `{_location(f)}` and read the flagged code.",
        "Trace where the value comes from: the finding is real only if outside input "
        "(request data, URL, upstream feed) can reach it.",
        "If it can, confirm with a harmless test input on a local instance.",
    ]


@dataclass
class Group:
    guidance: Guidance
    tool: str
    rule_id: str
    severity: str
    findings: list[SecurityFinding]

    @property
    def verification(self) -> str | None:
        return next((f.verification for f in self.findings if f.verification), None)

    @property
    def confirmed(self) -> bool:
        return (self.verification or "").startswith("CONFIRMED")


def build_groups(report: ScanReport) -> list[Group]:
    # Severity is part of the key so downgraded test fixtures never inflate a
    # HIGH group of the same rule.
    buckets: dict[tuple[str, str, str], list[SecurityFinding]] = defaultdict(list)
    for f in report.findings:
        if not f.is_false_positive:
            buckets[(f.tool_name, f.rule_id, f.severity)].append(f)
    groups = []
    for (tool, rule_id, severity), items in buckets.items():
        groups.append(Group(classify(items[0]), tool, rule_id, severity, items))
    # Automatically confirmed findings first, then by severity and size.
    groups.sort(
        key=lambda g: (
            not g.confirmed,
            _SEVERITY_ORDER.index(g.severity),
            -len(g.findings),
            g.rule_id,
        )
    )
    return groups


def _cvss(group: Group) -> tuple[float, str | None, str]:
    """Score, vector and where they came from, for the group's highest score."""
    scored = [f for f in group.findings if f.cvss_score is not None]
    if not scored:
        return _SEV_CVSS[group.severity], None, "estimate from scanner severity"
    best = max(scored, key=lambda f: f.cvss_score)
    return best.cvss_score, best.cvss_vector, best.cvss_source or "estimate"


def _cvss_text(group: Group) -> str:
    score, vector, source = _cvss(group)
    text = f"{score:.1f} {cvss.rating(score)}"
    if vector:
        text += f" · `{vector}`"
    text += f" · source: {source}"
    if not vector:
        text += " (no vector: confirm with a CVSS 3.1 calculator)"
    return text


def _poc(group: Group, report: ScanReport) -> str:
    first = group.findings[0]
    if group.verification:
        return "Verified automatically (read-only, local instance only). " + group.verification
    rule = short_rule(group.rule_id)
    if rule == "nginx-injects-internal-credential":
        return (
            "Read-only comparison on a local instance, not executed by the tool: "
            "`curl -s -o /dev/null -w '%{http_code}' http://localhost:<upstream-port>/<route>` "
            "(expect 401) against the same route through the proxy port (200)."
        )
    if rule == "xml-feed-unescaped-interpolation":
        return (
            "On a local instance, not executed by the tool: generate the feed with a test item "
            "whose link contains `&`, then run `xmllint --noout feed.xml` (it reports a parse "
            "error)."
        )
    probe = first.poc_command or _safe_probe(first)
    if probe:
        return f"Read-only probe, not executed by the tool: `{probe}`"
    if group.guidance is _DEPENDENCY:
        return (
            "Not needed: the evidence is the installed version against the advisory's fixed "
            "version, shown above."
        )
    if first.tool_name == "Trivy":
        return (
            "Not needed: the configuration shown in the evidence is the proof; no request to "
            "the app is required."
        )
    if first.tool_name == "Gitleaks" or group.guidance.name.startswith("Hardcoded"):
        return (
            "Intentionally not attempted: using a possibly live credential is outside a safe "
            "proof of concept. Confirm with the owner and rotate it if real."
        )
    return "Not generated automatically; confirm manually with the steps above on a local instance."


def _scope_rows(groups: list[Group]) -> list[tuple[str, str, str]]:
    rows = []
    for area in SCOPE_AREAS:
        items = [g for g in groups if g.guidance.scope == area]
        if not items:
            rows.append((area, "0", "No automated findings; needs manual testing."))
            continue
        top = min(items, key=lambda g: _SEVERITY_ORDER.index(g.severity))
        confirmed = sum(g.confirmed for g in items)
        note = f"highest: {top.severity} ({top.guidance.name})"
        if confirmed:
            note += f"; {confirmed} confirmed automatically"
        rows.append((area, str(len(items)), note))
    return rows


def _constraints(report: ScanReport, verified: bool) -> list[str]:
    lines = [
        "Authorized local testing only: any URL is resolved first, and every address must "
        "be loopback (127.0.0.0/8 or ::1) or the scan is refused.",
        "Static analysis reads source files only; nothing in the target is modified.",
    ]
    if report.target_url:
        lines.append(
            "The running app was scanned with the OWASP ZAP baseline (passive, GET only, "
            "form submission disabled) through a proxy pinned to the approved address."
        )
    if verified:
        lines.append(
            "Automatic verification sent at most two read-only GET requests to the local "
            "target. No exploit payloads were sent."
        )
    lines.append("No production system, production user or production data was touched.")
    return lines


def to_markdown(report: ScanReport, title: str = "Security Assessment Report") -> str:
    groups = build_groups(report)
    raw = report.total_raw_findings or 1
    confirmed = [g for g in groups if g.confirmed]
    verified = any(g.verification for g in groups) and bool(report.target_url)
    out = [f"# {title}", ""]
    out += [
        f"- **Target source:** `{report.target_dir}`",
        f"- **Target URL:** {report.target_url or 'none (static scan only)'}",
        f"- **Scan ID / time:** `{report.run_id}` · {report.created_at}",
        f"- **Coverage complete:** {'yes' if report.scan_complete else 'NO, see below'}",
        "",
        "> Only findings marked CONFIRMED were reproduced automatically; the rest are leads "
        "to confirm. CVSS 3.1 scores come from published advisories, curated vectors for our "
        "own rules, or (marked as such) an estimate from scanner severity.",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Raw alerts | {report.total_raw_findings} |",
        f"| Exact duplicates | {report.duplicate_count} |",
        f"| Filtered by policy | {report.deterministic_filtered_count} |",
        f"| Actionable | {report.actionable_count} ({report.actionable_count / raw:.0%} of raw) |",
        f"| Known / new | {report.known_count} / {report.new_count} |",
        f"| Finding groups | {len(groups)} |",
        f"| Confirmed automatically | {len(confirmed)} |",
        "",
    ]
    if confirmed:
        out += ["## Confirmed findings", ""]
        out += [
            f"- **{g.guidance.name}** (`{short_rule(g.rule_id)}`), CVSS {_cvss(g)[0]:.1f}: "
            f"{_text(g.verification)}"
            for g in confirmed
        ]
        out.append("")
    out += [
        "## Testing constraints",
        "",
        *[f"- {line}" for line in _constraints(report, verified)],
        "",
        "## Coverage of the PS-163 scope",
        "",
        "| Scope area | Finding groups | Notes |",
        "|---|---|---|",
    ]
    out += [f"| {a} | {n} | {_cell(note)} |" for a, n, note in _scope_rows(groups)]
    out += [
        "",
        "## Scanner coverage",
        "",
        "| Scanner | Status | Findings | Notes |",
        "|---|---|---|---|",
    ]
    for s in report.scanners:
        out.append(f"| {s.tool_name} | {s.status} | {s.finding_count} | {_cell(s.message)} |")
    out += ["", "## Findings by severity", ""]
    sev = Counter(g.severity for g in groups)
    out.append(", ".join(f"{k}: {sev[k]}" for k in _SEVERITY_ORDER if sev[k]) or "None")
    out.append("")
    for i, g in enumerate(groups, 1):
        first = g.findings[0]
        badge = " · **CONFIRMED**" if g.confirmed else ""
        out += [
            f"### {i}. {g.guidance.name}: `{short_rule(g.rule_id)}`",
            "",
            f"- **Severity:** {g.severity}{badge}",
            f"- **CVSS 3.1:** {_cvss_text(g)}",
            f"- **OWASP:** {g.guidance.owasp} · **Scope area:** {g.guidance.scope}",
            f"- **Source:** {g.tool} · **Occurrences:** {len(g.findings)} · "
            f"**Status:** {first.status}"
            + (f" ({first.known_source})" if first.known_source else ""),
            "",
            f"**Description.** {_text(first.raw_description) or g.guidance.name}",
            "",
            "**Affected components:**",
            "",
        ]
        for f in g.findings[:_MAX_LOCATIONS]:
            out.append(f"- `{_location(f)}`")
        if len(g.findings) > _MAX_LOCATIONS:
            out.append(f"- …and {len(g.findings) - _MAX_LOCATIONS} more (see JSON report)")
        out += ["", "**Steps to reproduce:**", ""]
        out += [f"{n}. {step}" for n, step in enumerate(_steps(first, g.guidance), 1)]
        if first.code_snippet and first.tool_name != "Gitleaks":
            out += ["", "**Evidence:**", "", _fence(redact_secrets(first.code_snippet))]
        out += [
            "",
            f"**Proof of concept.** {_poc(g, report)}",
            "",
            f"**Business impact.** {g.guidance.impact}",
            "",
            f"**Remediation.** {g.guidance.remediation}",
            "",
        ]
        if first.filter_reason:
            out += [f"_Triage note: {_text(first.filter_reason)}_", ""]
    out += ["## Filtered by policy", "", "| Reason | Count |", "|---|---|"]
    reasons = Counter(
        (f.filter_reason or "unspecified") for f in report.findings if f.is_false_positive
    )
    for reason, count in reasons.most_common():
        out.append(f"| {_cell(reason)} | {count} |")
    if report.warnings:
        out += ["", "## Warnings", ""] + [f"- {_text(w)}" for w in report.warnings]
    out.append("")
    return redact_secrets("\n".join(out))


def _text(value: str | None) -> str:
    return re.sub(r"\s+", " ", redact_secrets(value or "")).strip()


def _cell(value: str | None) -> str:
    return _text(value).replace("|", "\\|")


def _fence(code: str) -> str:
    fence = "~~~~" if "```" in code else "```"
    return f"{fence}\n{code.rstrip()}\n{fence}"


def _inline(text: str) -> str:
    """Escape for HTML, then turn `code` spans into <code> elements."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", html.escape(text))


def write_report(report: ScanReport, path: str) -> None:
    """Write Markdown or HTML by extension. Never overwrites an existing file."""
    body = to_html(report) if path.lower().endswith((".html", ".htm")) else to_markdown(report)
    with open(path, "x", encoding="utf-8") as handle:
        handle.write(body)


def main(argv: list[str] | None = None) -> int:
    """Build a report from a saved scan: python assessment_report.py scan.json out.md"""
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Assessment report from a saved scan JSON")
    parser.add_argument("scan_json")
    parser.add_argument("output", help=".html for HTML, otherwise Markdown")
    args = parser.parse_args(argv)
    try:
        with open(args.scan_json, encoding="utf-8") as handle:
            report = ScanReport.model_validate_json(handle.read())
        write_report(report, args.output)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Assessment report written to {args.output}")
    return 0


def to_html(report: ScanReport, title: str = "Security Assessment Report") -> str:
    """Standalone HTML version. Every value is escaped."""
    groups = build_groups(report)
    e = html.escape
    confirmed = [g for g in groups if g.confirmed]
    verified = any(g.verification for g in groups) and bool(report.target_url)
    rows = "".join(
        f"<tr><td>{e(s.tool_name)}</td><td>{e(s.status)}</td><td>{s.finding_count}</td>"
        f"<td>{e(_text(s.message))}</td></tr>"
        for s in report.scanners
    )
    scope = "".join(
        f"<tr><td>{e(a)}</td><td>{n}</td><td>{e(note)}</td></tr>"
        for a, n, note in _scope_rows(groups)
    )
    constraints = "".join(f"<li>{e(line)}</li>" for line in _constraints(report, verified))
    confirmed_html = "".join(
        f"<li><b>{e(g.guidance.name)}</b> (<code>{e(short_rule(g.rule_id))}</code>), "
        f"CVSS {_cvss(g)[0]:.1f}: {e(_text(g.verification))}</li>"
        for g in confirmed
    )
    cards = []
    for i, g in enumerate(groups, 1):
        first = g.findings[0]
        locs = "".join(
            f"<li><code>{e(_location(f))}</code></li>" for f in g.findings[:_MAX_LOCATIONS]
        )
        extra = len(g.findings) - _MAX_LOCATIONS
        more = f"<li>…and {extra} more</li>" if extra > 0 else ""
        steps = "".join(f"<li>{_inline(s)}</li>" for s in _steps(first, g.guidance))
        evidence = (
            f"<h4>Evidence</h4><pre>{e(redact_secrets(first.code_snippet))}</pre>"
            if first.code_snippet and first.tool_name != "Gitleaks"
            else ""
        )
        badge = ' <span class="ok">CONFIRMED</span>' if g.confirmed else ""
        cards.append(
            f'<section class="card sev-{e(g.severity.lower())}">'
            f"<h3>{i}. {e(g.guidance.name)}: <code>{e(short_rule(g.rule_id))}</code>{badge}</h3>"
            f'<p class="meta"><b>{e(g.severity)}</b> · CVSS 3.1 {_inline(_cvss_text(g))}</p>'
            f'<p class="meta">{e(g.guidance.owasp)} · {e(g.guidance.scope)} · {e(g.tool)} · '
            f"{len(g.findings)} occurrence(s) · {e(first.status)}</p>"
            f"<h4>Description</h4><p>{e(_text(first.raw_description))}</p>"
            f"<h4>Affected components</h4><ul>{locs}{more}</ul>"
            f"<h4>Steps to reproduce</h4><ol>{steps}</ol>{evidence}"
            f"<h4>Proof of concept</h4><p>{_inline(_text(_poc(g, report)))}</p>"
            f"<h4>Business impact</h4><p>{e(g.guidance.impact)}</p>"
            f"<h4>Remediation</h4><p>{_inline(g.guidance.remediation)}</p></section>"
        )
    raw = report.total_raw_findings or 1
    confirmed_section = (
        f"<h2>Confirmed findings</h2><ul>{confirmed_html}</ul>" if confirmed_html else ""
    )
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<style>
:root {{ --bg:#fff; --fg:#1d1d1f; --muted:#5f6368; --line:#e2e2e2; --card:#fafafa;
  --crit:#b3261e; --high:#c5531b; --med:#9a6b00; --low:#2f6fb0; --info:#6b6b6b; --ok:#1e7e34; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#141414; --fg:#ececec; --muted:#a0a0a0;
  --line:#333; --card:#1d1d1d; --ok:#5cc26f; }} }}
body {{ background:var(--bg); color:var(--fg); font:15px/1.55 system-ui, sans-serif;
  max-width:980px; margin:0 auto; padding:24px 16px; }}
h1 {{ font-size:26px; }} h3 {{ margin:0 0 6px; font-size:17px; }} h4 {{ margin:14px 0 4px; }}
table {{ border-collapse:collapse; width:100%; }} td,th {{ border:1px solid var(--line);
  padding:6px 8px; text-align:left; vertical-align:top; }}
.card {{ background:var(--card); border:1px solid var(--line); border-left:5px solid var(--info);
  border-radius:8px; padding:14px 16px; margin:14px 0; overflow-wrap:anywhere; }}
.sev-critical {{ border-left-color:var(--crit); }} .sev-high {{ border-left-color:var(--high); }}
.sev-medium {{ border-left-color:var(--med); }} .sev-low {{ border-left-color:var(--low); }}
.meta {{ color:var(--muted); margin:0 0 4px; }} pre {{ overflow-x:auto; padding:8px;
  border:1px solid var(--line); border-radius:6px; }} .note {{ color:var(--muted); }}
.ok {{ color:var(--ok); border:1px solid var(--ok); border-radius:4px; padding:0 6px;
  font-size:12px; vertical-align:middle; }}
</style></head><body>
<h1>{e(title)}</h1>
<p class="note">Source <code>{e(report.target_dir)}</code> · URL {e(report.target_url or "none")}
· scan <code>{e(report.run_id)}</code> · {e(report.created_at)}</p>
<p class="note">Only findings marked CONFIRMED were reproduced automatically; the rest are leads
to confirm. CVSS 3.1 scores come from published advisories, curated vectors for our own rules,
or (marked as such) an estimate from scanner severity.</p>
<h2>Summary</h2>
<table><tr><th>Raw alerts</th><td>{report.total_raw_findings}</td></tr>
<tr><th>Filtered by policy</th><td>{report.deterministic_filtered_count}</td></tr>
<tr><th>Actionable</th><td>{report.actionable_count} ({report.actionable_count / raw:.0%})</td></tr>
<tr><th>Finding groups</th><td>{len(groups)}</td></tr>
<tr><th>Confirmed automatically</th><td>{len(confirmed)}</td></tr>
<tr><th>Coverage complete</th><td>{"yes" if report.scan_complete else "NO"}</td></tr></table>
{confirmed_section}
<h2>Testing constraints</h2><ul>{constraints}</ul>
<h2>Coverage of the PS-163 scope</h2>
<table><tr><th>Scope area</th><th>Finding groups</th><th>Notes</th></tr>{scope}</table>
<h2>Scanner coverage</h2>
<table><tr><th>Scanner</th><th>Status</th><th>Findings</th><th>Notes</th></tr>{rows}</table>
<h2>Findings</h2>
{"".join(cards) or "<p>No actionable findings.</p>"}
</body></html>
"""
    return redact_secrets(doc)


if __name__ == "__main__":
    raise SystemExit(main())
