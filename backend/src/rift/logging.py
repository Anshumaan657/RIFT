"""Structured logging with recursive secret redaction."""

import logging
from collections.abc import Mapping, MutableMapping
from typing import Any

import structlog

_SENSITIVE_PARTS = ("authorization", "cookie", "password", "secret", "token", "api_key")
_REDACTED = "[REDACTED]"


def _sanitize(value: Any, key: str = "") -> Any:
    if any(part in key.lower() for part in _SENSITIVE_PARTS):
        return _REDACTED
    if isinstance(value, Mapping):
        return {str(k): _sanitize(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize(item) for item in value)
    return value


def redact_secrets(
    _logger: Any, _method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Redact values whose field names indicate sensitive material."""

    return {key: _sanitize(value, key) for key, value in event_dict.items()}


def configure_logging(level: str) -> None:
    """Configure JSON logs for the process."""

    logging.basicConfig(level=level, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            redact_secrets,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level)),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
