import re
from typing import Any

REDACTION_PLACEHOLDER = "[redacted]"
TRUNCATION_MARKER = "…[truncated]"

_PATTERNS: tuple[re.Pattern[str], ...] = (
    # PEM-encoded private key blocks, including the armour lines.
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    # Olympus enrollment tokens.
    re.compile(r"olynode_[A-Za-z0-9_-]+"),
    # HTTP bearer credentials.
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    # JSON web tokens.
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    # Well-known provider credential shapes.
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
)

# Keyword-anchored assignments such as ``password=hunter2`` or ``"api_key": "abc"``.
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(pass|passwd|password|secret|token|api[_-]?key|apikey|access[_-]?key"
    r"|private[_-]?key|credential|authorization)\b"
    r'(\s*["\']?\s*[:=]\s*["\']?)'
    r"([^\s\"',;}\]]{3,})"
)

_MAX_REDACTION_DEPTH = 8


def redact_text(value: str) -> str:
    """Mask credential-shaped substrings before text is logged, audited, or returned."""
    redacted = value
    for pattern in _PATTERNS:
        redacted = pattern.sub(REDACTION_PLACEHOLDER, redacted)
    return _ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTION_PLACEHOLDER}", redacted
    )


def redact_value(value: Any, *, depth: int = 0) -> Any:
    """Recursively redact strings inside JSON-shaped data."""
    if depth >= _MAX_REDACTION_DEPTH:
        return REDACTION_PLACEHOLDER
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {
            str(key): redact_value(item, depth=depth + 1) for key, item in list(value.items())[:64]
        }
    if isinstance(value, (list, tuple)):
        return [redact_value(item, depth=depth + 1) for item in list(value)[:64]]
    return value


def bound_text(value: str, max_bytes: int) -> tuple[str, bool]:
    """Truncate ``value`` to ``max_bytes`` UTF-8 bytes, reporting whether it was cut."""
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value, False
    kept = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return f"{kept}{TRUNCATION_MARKER}", True


def redact_and_bound(value: str, max_bytes: int) -> tuple[str, bool]:
    """Redact first, then bound, so truncation can never split a secret open."""
    return bound_text(redact_text(value), max_bytes)
