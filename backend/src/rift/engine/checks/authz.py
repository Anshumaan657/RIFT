"""RIFT-AUTHZ-001: declared cross-user resource validation."""

from datetime import UTC, datetime

from rift.domain.models import CheckOutcome
from rift.engine.checks.common import body_contains, result
from rift.engine.contracts import CheckResult, ControlledClient, EvidenceCapture, ResourceInput

IDENTIFIER = "RIFT-AUTHZ-001"
VERSION = "1.0"


async def run(client: ControlledClient, resource: ResourceInput | None) -> CheckResult:
    started = datetime.now(UTC)
    if resource is None or not resource.owner_token or not resource.alternate_token:
        return result(
            IDENTIFIER, started, CheckOutcome.SKIPPED, "CROSS_USER_PREREQUISITES_MISSING",
            "Two identities and an owned synthetic resource are required."
        )
    owner_headers = {"Authorization": f"Bearer {resource.owner_token}"}
    owner = await client.request("GET", resource.path, headers=owner_headers)
    owner_capture = EvidenceCapture("GET", owner.path, owner_headers, owner)
    if not (200 <= owner.status_code < 300 and body_contains(owner.body, resource.marker)):
        return result(
            IDENTIFIER, started, CheckOutcome.INCONCLUSIVE, "OWNER_VERIFICATION_FAILED",
            "The owner could not retrieve the configured marker; cross-user testing stopped.",
            owner_capture
        )
    alternate_headers = {"Authorization": f"Bearer {resource.alternate_token}"}
    alternate = await client.request("GET", resource.path, headers=alternate_headers)
    alternate_capture = EvidenceCapture("GET", alternate.path, alternate_headers, alternate)
    if 200 <= alternate.status_code < 300 and body_contains(alternate.body, resource.marker):
        return result(
            IDENTIFIER, started, CheckOutcome.FINDING, "CROSS_USER_MARKER_EXPOSED",
            "A different synthetic identity exposed the owner's configured marker.",
            owner_capture, alternate_capture
        )
    if alternate.status_code in {401, 403, 404} and not body_contains(
        alternate.body, resource.marker
    ):
        return result(
            IDENTIFIER, started, CheckOutcome.PASSED, "CROSS_USER_ACCESS_DENIED",
            "The cross-user request did not expose the owner's marker.",
            owner_capture, alternate_capture
        )
    if 200 <= alternate.status_code < 300:
        return result(
            IDENTIFIER, started, CheckOutcome.INCONCLUSIVE, "SUCCESS_WITHOUT_OWNER_MARKER",
            "The cross-user request succeeded without the owner's expected marker.",
            owner_capture, alternate_capture
        )
    if alternate.status_code >= 500:
        outcome, reason = CheckOutcome.ERROR, "SERVER_ERROR"
    else:
        outcome, reason = CheckOutcome.INCONCLUSIVE, "AMBIGUOUS_CROSS_USER_RESPONSE"
    return result(
        IDENTIFIER, started, outcome, reason,
        "The cross-user response did not establish the expected access behavior.",
        owner_capture, alternate_capture
    )
