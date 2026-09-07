"""Server-owned V1 ceilings and customer-requested lower limits."""

import ipaddress
from dataclasses import dataclass

from rift.settings import Settings

HARD_MAX_REQUESTS = 100
HARD_MAX_CONCURRENCY = 2
HARD_MAX_RATE = 2.0
HARD_MAX_CONNECT_TIMEOUT = 10.0
HARD_MAX_TOTAL_TIMEOUT = 20.0
HARD_MAX_RESPONSE_BYTES = 1_048_576
HARD_MAX_RUNTIME = 900


@dataclass(frozen=True)
class RequestedLimits:
    requests: int | None = None
    concurrency: int | None = None
    requests_per_second: float | None = None
    connect_timeout_seconds: float | None = None
    total_timeout_seconds: float | None = None
    response_body_bytes: int | None = None
    runtime_seconds: int | None = None


@dataclass(frozen=True)
class SafetyPolicy:
    max_requests: int
    concurrency: int
    requests_per_second: float
    connect_timeout_seconds: float
    total_timeout_seconds: float
    response_body_bytes: int
    runtime_seconds: int
    local_lab_mode: bool = False
    user_agent: str = "RIFT-V1/1.0"
    allowed_target_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()

    @classmethod
    def from_settings(
        cls, settings: Settings, requested: RequestedLimits | None = None
    ) -> "SafetyPolicy":
        request = requested or RequestedLimits()

        def bounded(
            value: int | float | None, configured: int | float, hard: int | float
        ) -> int | float:
            selected = configured if value is None else value
            if selected <= 0:
                raise ValueError("safety limits must be positive")
            return min(selected, configured, hard)

        return cls(
            max_requests=int(
                bounded(
                    request.requests,
                    settings.max_requests_per_assessment,
                    HARD_MAX_REQUESTS,
                )
            ),
            concurrency=int(
                bounded(request.concurrency, settings.max_concurrent_requests, HARD_MAX_CONCURRENCY)
            ),
            requests_per_second=float(
                bounded(
                    request.requests_per_second,
                    settings.max_requests_per_second_per_host,
                    HARD_MAX_RATE,
                )
            ),
            connect_timeout_seconds=float(
                bounded(
                    request.connect_timeout_seconds,
                    settings.connect_timeout_seconds,
                    HARD_MAX_CONNECT_TIMEOUT,
                )
            ),
            total_timeout_seconds=float(
                bounded(
                    request.total_timeout_seconds,
                    settings.request_timeout_seconds,
                    HARD_MAX_TOTAL_TIMEOUT,
                )
            ),
            response_body_bytes=int(
                bounded(
                    request.response_body_bytes,
                    settings.max_response_body_bytes,
                    HARD_MAX_RESPONSE_BYTES,
                )
            ),
            runtime_seconds=int(
                bounded(
                    request.runtime_seconds,
                    settings.max_assessment_runtime_seconds,
                    HARD_MAX_RUNTIME,
                )
            ),
            local_lab_mode=settings.local_lab_mode,
            allowed_target_networks=settings.allowed_target_networks,
        )
