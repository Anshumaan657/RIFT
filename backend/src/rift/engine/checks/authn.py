"""RIFT-AUTHN-001: missing-authentication validation."""

from datetime import UTC, datetime

from rift.domain.models import CheckOutcome
from rift.engine.checks.common import body_contains, result
from rift.engine.contracts import CheckResult, ControlledClient, EvidenceCapture, ResourceInput

IDENTIFIER = "RIFT-AUTHN-001"
VERSION = "1.0"


async def run(client: ControlledClient, resource: ResourceInput | None) -> CheckResult:
    started = datetime.now(UTC)
    if resource is None:
        return result(
            IDENTIFIER,
            started,
            CheckOutcome.SKIPPED,
            "PRIVATE_RESOURCE_MISSING",
            "No private synthetic resource was configured.",
        )
    response = await client.request("GET", resource.path)
    capture = EvidenceCapture("GET", response.path, {}, response)
    marker = body_contains(response.body, resource.marker)
    if 200 <= response.status_code < 300 and marker:
        return result(
            IDENTIFIER,
            started,
            CheckOutcome.FINDING,
            "ANONYMOUS_MARKER_EXPOSED",
            "An anonymous request exposed the configured synthetic marker.",
            capture,
        )
    if response.status_code in {401, 403}:
        return result(
            IDENTIFIER,
            started,
            CheckOutcome.PASSED,
            "ANONYMOUS_ACCESS_DENIED",
            "The endpoint denied the anonymous request.",
            capture,
        )
    if (300 <= response.status_code < 400 or response.redirect_history) and not marker:
        return result(
            IDENTIFIER,
            started,
            CheckOutcome.PASSED,
            "LOGIN_REDIRECT",
            "The anonymous request redirected without exposing the marker.",
            capture,
        )
    if 200 <= response.status_code < 300:
        return result(
            IDENTIFIER,
            started,
            CheckOutcome.INCONCLUSIVE,
            "SUCCESS_WITHOUT_MARKER",
            "The endpoint returned success without the expected marker.",
            capture,
        )
    if response.status_code in {404, 410}:
        reason = "RESOURCE_NOT_FOUND" if response.status_code == 404 else "RESOURCE_GONE"
        return result(
            IDENTIFIER,
            started,
            CheckOutcome.INCONCLUSIVE,
            reason,
            "The configured synthetic resource was unavailable.",
            capture,
        )
    if 400 <= response.status_code < 500:
        return result(
            IDENTIFIER,
            started,
            CheckOutcome.INCONCLUSIVE,
            "OTHER_CLIENT_RESPONSE",
            "The endpoint returned an ambiguous client response.",
            capture,
        )
    return result(
        IDENTIFIER,
        started,
        CheckOutcome.ERROR,
        "SERVER_ERROR",
        "The endpoint returned a server error.",
        capture,
    )
