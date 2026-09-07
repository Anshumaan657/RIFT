"""Versioned check contracts. Checks can only use the controlled client."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from rift.domain.models import CheckOutcome
from rift.safety.http_client import SafeResponse


class ControlledClient(Protocol):
    async def request(
        self, method: str, relative_path: str, *, headers: dict[str, str] | None = None
    ) -> SafeResponse: ...


@dataclass(frozen=True)
class EvidenceCapture:
    method: str
    path: str
    request_headers: dict[str, str]
    response: SafeResponse


@dataclass(frozen=True)
class CheckResult:
    check_identifier: str
    check_version: str
    outcome: CheckOutcome
    reason_code: str
    summary: str
    started_at: datetime
    completed_at: datetime
    evidence: tuple[EvidenceCapture, ...] = ()
    observations: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ResourceInput:
    path: str
    marker: str
    owner_token: str | None = None
    alternate_token: str | None = None
