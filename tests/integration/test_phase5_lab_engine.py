"""End-to-end check classification against the isolated synthetic lab."""

import hashlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "lab" / "src"))

from lab_app.main import create_app  # noqa: E402
from rift.domain.models import CheckOutcome  # noqa: E402
from rift.engine.checks import authn, authz  # noqa: E402
from rift.engine.contracts import ResourceInput  # noqa: E402
from rift.safety.http_client import SafeResponse  # noqa: E402
from rift.safety.redaction import redact_headers  # noqa: E402

pytestmark = pytest.mark.asyncio


class LabControlledClient:
    """Test-only adapter with the same narrow interface checks receive in production."""

    def __init__(self, mode: str) -> None:
        self.client = TestClient(create_app(mode))  # type: ignore[arg-type]

    async def request(self, method: str, path: str, *, headers=None) -> SafeResponse:
        upstream = self.client.request(method, path, headers=headers or {}, follow_redirects=True)
        body = upstream.content
        return SafeResponse(
            upstream.status_code,
            redact_headers(dict(upstream.headers)),
            body,
            hashlib.sha256(body).hexdigest(),
            path,
        )


RESOURCE = ResourceInput(
    path="/api/records/synthetic-record-b",
    marker="RIFT_SYNTHETIC_RECORD_B_7F2A",
    owner_token="rift-lab-user-b-token",
    alternate_token="rift-lab-user-a-token",
)


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("vulnerable", CheckOutcome.FINDING), ("fixed", CheckOutcome.PASSED)],
)
async def test_authn_lab_variants(mode: str, expected: CheckOutcome) -> None:
    check_result = await authn.run(LabControlledClient(mode), RESOURCE)
    assert check_result.outcome == expected


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("vulnerable", CheckOutcome.FINDING), ("fixed", CheckOutcome.PASSED)],
)
async def test_authz_lab_variants(mode: str, expected: CheckOutcome) -> None:
    check_result = await authz.run(LabControlledClient(mode), RESOURCE)
    assert check_result.outcome == expected
