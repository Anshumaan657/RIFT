import hashlib
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "lab" / "src"))

from lab_app.main import create_app  # noqa: E402

FIXTURE_PATH = ROOT / "lab" / "fixtures" / "seed.json"
MARKER_B = "RIFT_SYNTHETIC_RECORD_B_7F2A"
TOKENS = {
    "a": "rift-lab-user-a-token",
    "b": "rift-lab-user-b-token",
    "expired": "rift-lab-expired-token",
}


@pytest.fixture(params=["vulnerable", "fixed"])
def lab(request: pytest.FixtureRequest) -> tuple[str, TestClient]:
    mode = str(request.param)
    return mode, TestClient(create_app(mode))  # type: ignore[arg-type]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_authentication_and_owner_boundaries() -> None:
    vulnerable = TestClient(create_app("vulnerable"))
    fixed = TestClient(create_app("fixed"))
    path = "/api/records/synthetic-record-b"

    anonymous_vulnerable = vulnerable.get(path)
    assert anonymous_vulnerable.status_code == 200
    assert MARKER_B in anonymous_vulnerable.text

    anonymous_fixed = fixed.get(path)
    assert anonymous_fixed.status_code == 401
    assert MARKER_B not in anonymous_fixed.text

    for client in (vulnerable, fixed):
        owner = client.get(path, headers=auth(TOKENS["b"]))
        assert owner.status_code == 200
        assert MARKER_B in owner.text

    cross_user_vulnerable = vulnerable.get(path, headers=auth(TOKENS["a"]))
    assert cross_user_vulnerable.status_code == 200
    assert MARKER_B in cross_user_vulnerable.text

    cross_user_fixed = fixed.get(path, headers=auth(TOKENS["a"]))
    assert cross_user_fixed.status_code == 403
    assert MARKER_B not in cross_user_fixed.text


def test_common_failure_and_public_contract(lab: tuple[str, TestClient]) -> None:
    mode, client = lab
    assert client.get("/api/public/synthetic-public").status_code == 200
    assert client.get("/api/missing").status_code == 404
    assert client.get("/api/denied", headers=auth(TOKENS["a"])).status_code == 403
    assert client.get("/api/auth-required").status_code == 401
    assert client.get("/api/auth-required", headers=auth(TOKENS["expired"])).status_code == 401
    assert client.get("/api/error").status_code == 500
    response = client.get("/api/redirect", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/api/status"
    assert client.get("/health").json()["mode"] == mode


def test_slow_and_oversized_contract(lab: tuple[str, TestClient]) -> None:
    _, client = lab
    assert client.get("/api/slow", params={"delay_seconds": 0}).status_code == 200
    response = client.get("/api/oversized")
    assert response.status_code == 200
    assert len(response.content) > 1_048_576


def test_configuration_profiles() -> None:
    vulnerable = TestClient(create_app("vulnerable")).get("/api/config")
    fixed = TestClient(create_app("fixed")).get("/api/config")
    assert "strict-transport-security" not in vulnerable.headers
    assert "secure" not in vulnerable.headers["set-cookie"].lower()
    assert fixed.headers["x-content-type-options"] == "nosniff"
    fixed_cookie = fixed.headers["set-cookie"].lower()
    assert all(attribute in fixed_cookie for attribute in ("secure", "httponly", "samesite=strict"))


def test_seed_is_deterministic_and_synthetic() -> None:
    first = FIXTURE_PATH.read_bytes()
    second = FIXTURE_PATH.read_bytes()
    assert hashlib.sha256(first).digest() == hashlib.sha256(second).digest()
    parsed = json.loads(first)
    assert {user["id"] for user in parsed["users"]} == {
        "user-a",
        "user-b",
        "expired-user",
    }
    assert all(user["token"].startswith("rift-lab-") for user in parsed["users"])
