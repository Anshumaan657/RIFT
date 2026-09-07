from hashlib import sha256

import pytest

from rift.domain.models import CheckOutcome
from rift.engine.checks import authn, authz, config
from rift.engine.contracts import ResourceInput
from rift.engine.runner import run_check
from rift.safety.http_client import (
    BudgetExceededError,
    CancellationError,
    SafeResponse,
)
from rift.worker.service import retryable_transport_error

pytestmark = pytest.mark.asyncio


def response(
    status: int,
    body: bytes = b"",
    *,
    headers: dict[str, str] | None = None,
    redirects: tuple[int, ...] = (),
    security_metadata: dict[str, object] | None = None,
) -> SafeResponse:
    return SafeResponse(
        status,
        headers or {},
        body,
        sha256(body).hexdigest(),
        "/api/records/synthetic-record-b",
        redirects,
        security_metadata or {},
    )


class FakeClient:
    def __init__(self, *responses: SafeResponse, error: BaseException | None = None):
        self.responses = list(responses)
        self.error = error
        self.calls: list[tuple[str, str, dict[str, str]]] = []

    async def request(self, method: str, path: str, *, headers=None):
        self.calls.append((method, path, headers or {}))
        if self.error:
            raise self.error
        return self.responses.pop(0)


RESOURCE = ResourceInput(
    "/api/records/synthetic-record-b",
    "RIFT_SYNTHETIC_RECORD_B_7F2A",
    "owner-token",
    "alternate-token",
)


@pytest.mark.parametrize(
    ("upstream", "outcome", "reason"),
    [
        (
            response(200, b"RIFT_SYNTHETIC_RECORD_B_7F2A"),
            CheckOutcome.FINDING,
            "ANONYMOUS_MARKER_EXPOSED",
        ),
        (response(401), CheckOutcome.PASSED, "ANONYMOUS_ACCESS_DENIED"),
        (
            response(200, b"different"),
            CheckOutcome.INCONCLUSIVE,
            "SUCCESS_WITHOUT_MARKER",
        ),
        (response(404), CheckOutcome.INCONCLUSIVE, "RESOURCE_NOT_FOUND"),
        (response(500), CheckOutcome.ERROR, "SERVER_ERROR"),
        (response(200, redirects=(302,)), CheckOutcome.PASSED, "LOGIN_REDIRECT"),
    ],
)
async def test_authn_exact_classification(upstream, outcome, reason):
    result = await authn.run(FakeClient(upstream), RESOURCE)
    assert result.outcome == outcome
    assert result.reason_code == reason


async def test_authn_skips_without_declared_private_resource():
    result = await authn.run(FakeClient(), None)
    assert result.outcome == CheckOutcome.SKIPPED


async def test_authz_verifies_owner_before_alternate_and_detects_vulnerable_case():
    client = FakeClient(
        response(200, b"RIFT_SYNTHETIC_RECORD_B_7F2A"),
        response(200, b"RIFT_SYNTHETIC_RECORD_B_7F2A"),
    )
    result = await authz.run(client, RESOURCE)
    assert result.outcome == CheckOutcome.FINDING
    assert client.calls[0][2]["Authorization"] == "Bearer owner-token"
    assert client.calls[1][2]["Authorization"] == "Bearer alternate-token"


async def test_authz_fixed_case_is_not_a_finding():
    result = await authz.run(
        FakeClient(response(200, RESOURCE.marker.encode()), response(403)), RESOURCE
    )
    assert result.outcome == CheckOutcome.PASSED


async def test_authz_stops_when_owner_prerequisite_is_ambiguous():
    client = FakeClient(response(200, b"wrong marker"))
    result = await authz.run(client, RESOURCE)
    assert result.outcome == CheckOutcome.INCONCLUSIVE
    assert result.reason_code == "OWNER_VERIFICATION_FAILED"
    assert len(client.calls) == 1


async def test_config_falls_back_to_get_only_for_method_not_supported():
    client = FakeClient(response(405), response(200, headers={"x-content-type-options": "nosniff"}))
    result = await config.run(client, is_https=True)
    assert [call[0] for call in client.calls] == ["HEAD", "GET"]
    assert result.reason_code == "CONFIG_OBSERVATIONS_RECORDED"


async def test_config_records_each_missing_cookie_attribute_as_an_observation():
    upstream = response(
        200,
        headers={
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
        },
        security_metadata={
            "cookie_flags": [{"secure": False, "httponly": False, "samesite": False}]
        },
    )
    check_result = await config.run(FakeClient(upstream), is_https=True)
    assert "cookie[0].secure" in check_result.observations["missing"]
    assert "cookie[0].httponly" in check_result.observations["missing"]
    assert "cookie[0].samesite" in check_result.observations["missing"]


@pytest.mark.parametrize(
    ("error", "reason", "outcome"),
    [
        (CancellationError(), "ASSESSMENT_CANCELLED", CheckOutcome.CANCELLED),
        (BudgetExceededError(), "REQUEST_BUDGET_EXHAUSTED", CheckOutcome.ERROR),
    ],
)
async def test_runner_preserves_terminal_safety_outcomes(error, reason, outcome):
    result = await run_check(
        authn.IDENTIFIER, FakeClient(error=error), resource=RESOURCE, is_https=True
    )
    assert result.reason_code == reason
    assert result.outcome == outcome


async def test_only_repeatable_transport_failures_are_retryable():
    assert retryable_transport_error(TimeoutError())
    assert retryable_transport_error(OSError())
    assert not retryable_transport_error(BudgetExceededError())
    assert not retryable_transport_error(RuntimeError("unfavorable result"))
