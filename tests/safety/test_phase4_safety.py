import asyncio
import ipaddress
import os
from pathlib import Path
from typing import Any

import pytest

from rift.safety.audit import AuditChain
from rift.safety.http_client import (
    BudgetExceededError,
    CancellationError,
    DnsChangeError,
    PolicyError,
    RedirectLimitError,
    ResponseTooLargeError,
    RuntimeExceededError,
    SafeHttpClient,
    TransportResponse,
)
from rift.safety.policy import RequestedLimits, SafetyPolicy
from rift.safety.redaction import REDACTED, redact
from rift.safety.scope import NormalizedTarget, ScopeViolation


class FakeTransport:
    def __init__(self, responses: list[TransportResponse] | None = None) -> None:
        self.responses = responses or [TransportResponse(200, {}, b"ok")]
        self.calls: list[dict[str, Any]] = []

    async def request(self, **kwargs: Any) -> TransportResponse:
        self.calls.append(kwargs)
        return self.responses.pop(0)


def target(ip: str = "8.8.8.8", base: str = "/api/") -> NormalizedTarget:
    return NormalizedTarget.create("https", "example.test", 443, base, [ip])


def policy(**changes: Any) -> SafetyPolicy:
    values = {
        "max_requests": 100,
        "concurrency": 2,
        "requests_per_second": 2.0,
        "connect_timeout_seconds": 10.0,
        "total_timeout_seconds": 20.0,
        "response_body_bytes": 1_048_576,
        "runtime_seconds": 900,
    }
    values.update(changes)
    return SafetyPolicy(**values)


def resolver_for(value: str):
    async def resolve(_hostname: str, _port: int):
        return frozenset({ipaddress.ip_address(value)})

    return resolve


def client(**kwargs: Any) -> SafeHttpClient:
    return SafeHttpClient(
        assessment_id="assessment",
        target=kwargs.pop("target", target()),
        policy=kwargs.pop("policy", policy()),
        cancellation_check=kwargs.pop("cancellation_check", lambda: False),
        audit=kwargs.pop("audit", AuditChain()),
        resolver=kwargs.pop("resolver", resolver_for("8.8.8.8")),
        transport=kwargs.pop("transport", FakeTransport()),
        sleep=kwargs.pop("sleep", asyncio.sleep),
        **kwargs,
    )


@pytest.mark.parametrize(
    "scheme,host",
    [
        ("file", "example.test"),
        ("ftp", "example.test"),
        ("https", "user@example.test"),
        ("https", "*.example.test"),
        ("https", "2130706433"),
        ("https", "0x7f000001"),
        ("https", "example%2etest"),
    ],
)
def test_prohibited_schemes_and_host_tricks(scheme: str, host: str) -> None:
    with pytest.raises(ScopeViolation):
        NormalizedTarget.create(scheme, host, 443, "/", ["8.8.8.8"])


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",  # noqa: S104 - unsafe address is the test subject
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "ff00::1",
        "2001:db8::1",
    ],
)
@pytest.mark.asyncio
async def test_non_global_addresses_are_blocked(value: str) -> None:
    current_target = target(value)
    with pytest.raises(PolicyError):
        await client(target=current_target, resolver=resolver_for(value)).request("GET", "/api/")


@pytest.mark.asyncio
async def test_local_lab_allows_loopback_only() -> None:
    lab_policy = policy(local_lab_mode=True)
    loopback_target = NormalizedTarget.create("http", "localhost", 8080, "/", ["127.0.0.1"])
    response = await client(
        target=loopback_target,
        policy=lab_policy,
        resolver=resolver_for("127.0.0.1"),
    ).request("GET", "/")
    assert response.status_code == 200
    private_target = NormalizedTarget.create("http", "lab", 8080, "/", ["172.18.0.2"])
    with pytest.raises(PolicyError):
        await client(
            target=private_target,
            policy=lab_policy,
            resolver=resolver_for("172.18.0.2"),
        ).request("GET", "/")


@pytest.mark.asyncio
async def test_dns_is_checked_every_request_and_changes_are_rejected() -> None:
    answers = iter(["8.8.8.8", "1.1.1.1"])

    async def changing(_hostname: str, _port: int):
        return frozenset({ipaddress.ip_address(next(answers))})

    current = client(resolver=changing)
    await current.request("GET", "/api/a")
    with pytest.raises(DnsChangeError):
        await current.request("GET", "/api/b")


@pytest.mark.parametrize(
    "path",
    [
        "/admin",
        "/apiary",
        "/api/../admin",
        "/api/%2e%2e/admin",
        "//evil.test/api",
        "https://evil.test/api",
        "/api/item#fragment",
    ],
)
def test_base_path_escapes_are_rejected(path: str) -> None:
    with pytest.raises(ScopeViolation):
        target().normalize_relative_path(path)


@pytest.mark.asyncio
async def test_redirects_stay_in_exact_scope_and_are_limited() -> None:
    outside = FakeTransport([TransportResponse(302, {"location": "https://evil.test/api"}, b"")])
    with pytest.raises(ScopeViolation):
        await client(transport=outside).request("GET", "/api/")

    looping = FakeTransport(
        [TransportResponse(302, {"location": "/api/next"}, b"") for _ in range(3)]
    )
    with pytest.raises(RedirectLimitError):
        await client(transport=looping, sleep=no_sleep).request("GET", "/api/")


async def no_sleep(_delay: float) -> None:
    return None


@pytest.mark.asyncio
async def test_methods_bodies_and_hop_headers_are_rejected() -> None:
    current = client()
    for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
        with pytest.raises(PolicyError):
            await current.request(method, "/api/")
    with pytest.raises(PolicyError):
        await current.request("GET", "/api/", body=b"x")
    for header in ("Host", "Connection", "Proxy-Authorization", "Transfer-Encoding"):
        with pytest.raises(PolicyError):
            await current.request("GET", "/api/", headers={header: "unsafe"})


@pytest.mark.asyncio
async def test_proxy_environment_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    transport = FakeTransport()
    await client(transport=transport).request("GET", "/api/")
    assert transport.calls[0]["ip"] == ipaddress.ip_address("8.8.8.8")
    assert os.environ["HTTPS_PROXY"] == "http://127.0.0.1:9999"


@pytest.mark.asyncio
async def test_budget_runtime_response_limit_timeout_and_cancellation() -> None:
    budget_client = client(policy=policy(max_requests=1), sleep=no_sleep)
    await budget_client.request("GET", "/api/")
    with pytest.raises(BudgetExceededError):
        await budget_client.request("GET", "/api/")

    times = iter([0.0, 2.0])
    runtime_client = client(policy=policy(runtime_seconds=1), clock=lambda: next(times))
    with pytest.raises(RuntimeExceededError):
        await runtime_client.request("GET", "/api/")

    oversized = FakeTransport([TransportResponse(200, {}, b"x" * 11)])
    with pytest.raises(ResponseTooLargeError):
        await client(policy=policy(response_body_bytes=10), transport=oversized).request(
            "GET", "/api/"
        )

    class SlowTransport(FakeTransport):
        async def request(self, **kwargs: Any) -> TransportResponse:
            await asyncio.sleep(0.1)
            return TransportResponse(200, {}, b"ok")

    with pytest.raises(TimeoutError):
        await client(policy=policy(total_timeout_seconds=0.01), transport=SlowTransport()).request(
            "GET", "/api/"
        )

    with pytest.raises(CancellationError):
        await client(cancellation_check=lambda: True).request("GET", "/api/")


@pytest.mark.asyncio
async def test_cancellation_rechecked_after_dns_before_transport() -> None:
    cancelled = False

    async def resolve(_hostname: str, _port: int):
        nonlocal cancelled
        cancelled = True
        return frozenset({ipaddress.ip_address("8.8.8.8")})

    with pytest.raises(CancellationError):
        await client(cancellation_check=lambda: cancelled, resolver=resolve).request("GET", "/api/")


@pytest.mark.asyncio
async def test_tokens_are_redacted_from_response_headers_body_and_audit() -> None:
    secret = "very-secret-token"  # noqa: S105 - synthetic redaction fixture
    audit = AuditChain()
    transport = FakeTransport(
        [
            TransportResponse(
                200,
                {"set-cookie": f"session={secret}", "x-safe": "ok"},
                f'{{"token":"{secret}"}}'.encode(),
            )
        ]
    )
    response = await client(audit=audit, transport=transport).request(
        "GET", "/api/", headers={"Authorization": f"Bearer {secret}"}
    )
    serialized = repr((response, audit.records("assessment")))
    assert secret not in serialized
    assert REDACTED in serialized
    assert AuditChain.verify(audit.records("assessment"))


def test_recursive_redaction_covers_metadata_and_evidence() -> None:
    secret = "secret-value"  # noqa: S105 - synthetic redaction fixture
    value = {
        "authorization": f"Bearer {secret}",
        "nested": [{"api_key": secret}, f"token={secret}"],
    }
    assert secret not in repr(redact(value))


def test_policy_inputs_can_lower_but_never_raise_server_limits(
    settings_factory,
) -> None:
    settings = settings_factory(max_requests_per_assessment=80)
    lowered = SafetyPolicy.from_settings(settings, RequestedLimits(requests=10))
    raised = SafetyPolicy.from_settings(settings, RequestedLimits(requests=100))
    assert lowered.max_requests == 10
    assert raised.max_requests == 80


def test_checks_cannot_import_network_clients_or_sockets() -> None:
    import ast

    root = Path(__file__).parents[2] / "backend" / "src" / "rift" / "engine"
    forbidden = {"httpx", "requests", "aiohttp", "socket", "urllib", "http.client"}
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text())
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports |= {
            node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        }
        assert not any(
            imported == name or imported.startswith(name + ".")
            for imported in imports
            for name in forbidden
        ), f"{path} bypasses the controlled client"
