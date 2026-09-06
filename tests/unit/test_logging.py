from rift.logging import redact_secrets


def test_recursive_redaction() -> None:
    event = {
        "event": "request",
        "authorization": "Bearer canary",
        "nested": {"api_key": "canary", "safe": "visible"},
        "items": [{"session_token": "canary"}],
    }
    sanitized = redact_secrets(None, "info", event)
    assert sanitized == {
        "event": "request",
        "authorization": "[REDACTED]",
        "nested": {"api_key": "[REDACTED]", "safe": "visible"},
        "items": [{"session_token": "[REDACTED]"}],
    }
