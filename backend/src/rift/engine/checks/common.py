"""Shared deterministic check classification."""

from datetime import UTC, datetime

from rift.domain.models import CheckOutcome
from rift.engine.contracts import CheckResult, EvidenceCapture


def result(
    identifier: str,
    started_at: datetime,
    outcome: CheckOutcome,
    reason: str,
    summary: str,
    *evidence: EvidenceCapture,
    observations: dict[str, object] | None = None,
) -> CheckResult:
    return CheckResult(
        check_identifier=identifier,
        check_version="1.0",
        outcome=outcome,
        reason_code=reason,
        summary=summary,
        started_at=started_at,
        completed_at=datetime.now(UTC),
        evidence=evidence,
        observations=observations or {},
    )


def body_contains(body: bytes, marker: str) -> bool:
    return marker.encode() in body
