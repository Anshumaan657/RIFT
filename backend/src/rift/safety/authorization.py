"""Authorization-window checks and immutable assessment snapshot construction."""

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from rift.domain.models import (
    AuthorizationRecord,
    AuthorizationStatus,
    Target,
    TargetEnabledState,
    TargetVerificationState,
)
from rift.safety.policy import SafetyPolicy


class AuthorizationDenied(ValueError):
    pass


def require_active_authorization(
    record: AuthorizationRecord,
    target: Target,
    *,
    now: datetime | None = None,
) -> None:
    timestamp = now or datetime.now(UTC)
    if record.application_id != target.application_id:
        raise AuthorizationDenied("authorization does not own target")
    if record.status != AuthorizationStatus.VALID:
        raise AuthorizationDenied("authorization is not active")
    if not record.operator_review:
        raise AuthorizationDenied("authorization has not passed operator review")
    if not (record.valid_from <= timestamp < record.valid_until):
        raise AuthorizationDenied("authorization is outside its validity window")
    if target.verification_state != TargetVerificationState.VERIFIED:
        raise AuthorizationDenied("target has not passed HTTP challenge verification")
    if target.enabled_state != TargetEnabledState.ENABLED:
        raise AuthorizationDenied("target is disabled")
    approved = json.loads(record.approved_scope)
    exact_scope = {
        "scheme": target.scheme,
        "hostname": target.hostname,
        "port": target.port,
        "base_path": target.base_path_prefix,
    }
    if exact_scope not in approved.get("targets", []):
        raise AuthorizationDenied("target is outside approved scope")


def build_assessment_snapshot(
    *,
    record: AuthorizationRecord,
    target: Target,
    selected_checks: Sequence[str],
    resource_expectations: Sequence[Mapping[str, Any]],
    identity_ids: Sequence[str],
    policy: SafetyPolicy,
) -> Mapping[str, Any]:
    require_active_authorization(record, target)
    return {
        "authorization_record_id": str(record.id),
        "authorization_valid_until": record.valid_until.astimezone(UTC).isoformat(),
        "target": {
            "id": str(target.id),
            "scheme": target.scheme,
            "hostname": target.hostname,
            "port": target.port,
            "base_path": target.base_path_prefix,
            "validated_ips": sorted(json.loads(target.validated_ips)),
        },
        "selected_checks": sorted(set(selected_checks)),
        "resource_expectations": list(resource_expectations),
        "identity_ids": sorted(identity_ids),
        "limits": {
            "max_requests": policy.max_requests,
            "concurrency": policy.concurrency,
            "requests_per_second": policy.requests_per_second,
            "connect_timeout_seconds": policy.connect_timeout_seconds,
            "total_timeout_seconds": policy.total_timeout_seconds,
            "response_body_bytes": policy.response_body_bytes,
            "runtime_seconds": policy.runtime_seconds,
        },
    }
