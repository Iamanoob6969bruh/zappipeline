"""Best-effort redaction at every persistence/display/external boundary."""

import re
from typing import Any

_PATTERNS = [
    (
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "[REDACTED_PRIVATE_KEY]",
    ),
    (r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "[REDACTED_AWS_KEY]"),
    (r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]"),
    (r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED_JWT]"),
    (r"\b(?:sk|rk|pk|ghp|gho|ghs|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{10,}", "[REDACTED_KEY]"),
    (
        r"""(?i)(["']?(?:api[_-]?key|access[_-]?key|client[_-]?secret|secret|token|password|passwd|pwd|authorization)["']?\s*[:=]\s*)(["'])([^"'\r\n]+)\2""",
        r"\1\2[REDACTED]\2",
    ),
    (
        r'(?i)((?:api[_-]?key|secret|token|password|passwd|pwd|authorization)\s*[:=]\s*)(?![\["\'])[\w./+~%=-]{4,}',
        r"\1[REDACTED]",
    ),
    (r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1[REDACTED]@"),
    (
        r"(?i)([?&](?:[^=&\s]*(?:token|key|secret|password|signature)[^=&\s]*)=)[^&#\s]+",
        r"\1[REDACTED]",
    ),
]
_COMPILED = [(re.compile(p), replacement) for p, replacement in _PATTERNS]


def redact_secrets(snippet: str) -> str:
    for pattern, replacement in _COMPILED:
        snippet = pattern.sub(replacement, snippet)
    return snippet


def redact_data(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, list):
        return [redact_data(v) for v in value]
    if isinstance(value, dict):
        return {k: redact_data(v) for k, v in value.items()}
    return value
