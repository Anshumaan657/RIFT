import asyncio
import ipaddress
from collections.abc import Mapping

import pytest

from rift.safety.audit import AuditChain
from rift.safety.http_client import PolicyError, SafeHttpClient, TransportResponse
from rift.safety.policy import SafetyPolicy
from rift.safety.scope import NormalizedTarget


class NoNetworkTransport:
    async def request(
        self,
        *,
        scheme: str,
        hostname: str,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
        port: int,
        method: str,
        path: str,
        headers: Mapping[str, str],
        connect_timeout: float,
        response_limit: int,
    ) -> TransportResponse:
        return TransportResponse(200, {}, b"synthetic")


def configured_client(address: str, allowed: str) -> SafeHttpClient:
    parsed_address = ipaddress.ip_address(address)

    async def resolver(_hostname: str, _port: int):
        return frozenset({parsed_address})

    return SafeHttpClient(
        assessment_id="phase8-egress-test",
        target=NormalizedTarget.create("https", "staging.example.test", 443, "/", [address]),
        policy=SafetyPolicy(
            max_requests=1,
            concurrency=1,
            requests_per_second=1,
            connect_timeout_seconds=1,
            total_timeout_seconds=1,
            response_body_bytes=1024,
            runtime_seconds=10,
            allowed_target_networks=(ipaddress.ip_network(allowed),),
        ),
        cancellation_check=lambda: False,
        audit=AuditChain(),
        resolver=resolver,
        transport=NoNetworkTransport(),
        sleep=asyncio.sleep,
    )


@pytest.mark.asyncio
async def test_deployment_allowlist_blocks_global_address_outside_partner_cidr() -> None:
    with pytest.raises(PolicyError, match="deployment egress allowlist"):
        await configured_client("8.8.8.8", "1.1.1.0/24").request("GET", "/")


@pytest.mark.asyncio
async def test_deployment_allowlist_permits_verified_address_inside_partner_cidr() -> None:
    response = await configured_client("8.8.8.8", "8.8.8.0/24").request("HEAD", "/")
    assert response.status_code == 200
