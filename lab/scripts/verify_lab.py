"""Manually verify only the loopback-hosted RIFT synthetic lab."""

import argparse
import json
from dataclasses import dataclass
from urllib.error import HTTPError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

MARKER_B = "RIFT_SYNTHETIC_RECORD_B_7F2A"
USER_A_TOKEN = "rift-lab-user-a-token"
USER_B_TOKEN = "rift-lab-user-b-token"
EXPIRED_TOKEN = "rift-lab-expired-token"


@dataclass(frozen=True)
class Result:
    status: int
    body: str


def validate_base_url(value: str, *, allow_compose_network: bool = False) -> str:
    parsed = urlparse(value)
    allowed_hosts = {"localhost", "127.0.0.1", "::1"}
    if allow_compose_network:
        allowed_hosts.update({"lab-vulnerable", "lab-fixed"})
    if parsed.scheme != "http" or parsed.hostname not in allowed_hosts:
        raise ValueError("Verification is restricted to approved HTTP lab URLs")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(
            "Lab base URL must not contain credentials, query, or fragment"
        )
    return value.rstrip("/") + "/"


def get(base_url: str, path: str, token: str | None = None) -> Result:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = Request(urljoin(base_url, path), headers=headers, method="GET")
    try:
        with urlopen(request, timeout=12) as response:  # noqa: S310 - loopback URL is validated above
            return Result(response.status, response.read(1_048_576).decode())
    except HTTPError as error:
        return Result(error.code, error.read(1_048_576).decode())


def assert_lab_contract(vulnerable: str, fixed: str) -> None:
    private_path = "api/records/synthetic-record-b"
    cases = [
        ("anonymous vulnerable", get(vulnerable, private_path), 200, True),
        ("anonymous fixed", get(fixed, private_path), 401, False),
        ("owner vulnerable", get(vulnerable, private_path, USER_B_TOKEN), 200, True),
        ("owner fixed", get(fixed, private_path, USER_B_TOKEN), 200, True),
        (
            "cross-user vulnerable",
            get(vulnerable, private_path, USER_A_TOKEN),
            200,
            True,
        ),
        ("cross-user fixed", get(fixed, private_path, USER_A_TOKEN), 403, False),
        (
            "expired vulnerable",
            get(vulnerable, "api/auth-required", EXPIRED_TOKEN),
            401,
            False,
        ),
        ("expired fixed", get(fixed, "api/auth-required", EXPIRED_TOKEN), 401, False),
        (
            "public vulnerable",
            get(vulnerable, "api/public/synthetic-public"),
            200,
            False,
        ),
        ("public fixed", get(fixed, "api/public/synthetic-public"), 200, False),
    ]
    failures: list[dict[str, object]] = []
    for label, result, expected_status, marker_expected in cases:
        marker_present = MARKER_B in result.body
        if result.status != expected_status or marker_present != marker_expected:
            failures.append(
                {
                    "case": label,
                    "expected_status": expected_status,
                    "actual_status": result.status,
                    "expected_private_marker": marker_expected,
                    "actual_private_marker": marker_present,
                }
            )
        print(f"{label}: status={result.status} private_marker={marker_present}")
    if failures:
        raise RuntimeError(json.dumps(failures, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vulnerable-base", default="http://127.0.0.1:8081/")
    parser.add_argument("--fixed-base", default="http://127.0.0.1:8082/")
    parser.add_argument("--allow-compose-network", action="store_true")
    args = parser.parse_args()
    assert_lab_contract(
        validate_base_url(
            args.vulnerable_base, allow_compose_network=args.allow_compose_network
        ),
        validate_base_url(
            args.fixed_base, allow_compose_network=args.allow_compose_network
        ),
    )
    print("RIFT synthetic lab contract verified.")


if __name__ == "__main__":
    main()
