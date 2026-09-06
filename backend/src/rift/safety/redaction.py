"""Recursive secret redaction for logs, audits, APIs, and evidence."""

import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "[REDACTED]"
SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "proxy_authorization",
        "cookie",
        "set_cookie",
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "x_api_key",
        "encrypted_bearer_token",
    }
)
INLINE_PATTERNS = (
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(api[_-]?key|token|password|secret)=([^&\s]+)"),
    re.compile(r"""(?i)(["'](?:api[_-]?key|token|password|secret)["']\s*:\s*["'])([^"']+)"""),
    re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?"
        r"-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
)


def redact_text(value: str, configured_patterns: Sequence[str] = ()) -> str:
    result = value
    for compiled_pattern in INLINE_PATTERNS:
        result = compiled_pattern.sub(REDACTED, result)
    for configured_pattern in configured_patterns:
        result = re.sub(configured_pattern, REDACTED, result)
    return result


def redact(value: Any, configured_patterns: Sequence[str] = ()) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED
            if str(key).lower().replace("-", "_") in SENSITIVE_KEYS
            else redact(item, configured_patterns)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(redact(item, configured_patterns) for item in value)
    if isinstance(value, list):
        return [redact(item, configured_patterns) for item in value]
    if isinstance(value, str):
        return redact_text(value, configured_patterns)
    return value


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        key: REDACTED if key.lower().replace("-", "_") in SENSITIVE_KEYS else redact_text(value)
        for key, value in headers.items()
    }
