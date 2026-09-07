"""Create immutable reports from stored outcomes, findings, and sanitized evidence."""

import hashlib
import json
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from rift.domain.models import (
    Application,
    Assessment,
    AuthorizationRecord,
    CheckExecution,
    Evidence,
    Finding,
    ReportFormat,
    Target,
)
from rift.engine.persistence import canonical_json
from rift.reports.evidence import sanitized_record
from rift.reports.findings import materialize_findings
from rift.reports.models import ReportArtifact, ReportVariant
from rift.reports.render import render_report


async def create_report(
    session: AsyncSession,
    assessment_id: UUID,
    *,
    format: ReportFormat,
    variant: ReportVariant,
    idempotency_key: str | None,
) -> ReportArtifact:
    if idempotency_key:
        existing = await session.scalar(
            select(ReportArtifact).where(ReportArtifact.idempotency_key == idempotency_key)
        )
        if existing is not None:
            if (
                existing.assessment_id != assessment_id
                or existing.format != format
                or existing.variant != variant
            ):
                raise ValueError("idempotency key was already used for a different report")
            return existing
    assessment = await session.get(Assessment, assessment_id)
    if assessment is None:
        raise LookupError("assessment not found")
    terminal_states = {
        "completed",
        "completed_with_errors",
        "failed",
        "cancelled",
    }
    if assessment.state.value not in terminal_states:
        raise ValueError("reports can only be generated for a terminal assessment")
    target = await session.get(Target, assessment.target_id)
    application = await session.get(Application, assessment.application_id)
    if target is None or application is None:
        raise LookupError("assessment ownership is incomplete")
    configuration = json.loads(assessment.configuration_snapshot)
    authorization = await session.get(
        AuthorizationRecord, UUID(configuration["authorization_record_id"])
    )
    if authorization is None:
        raise LookupError("authorization snapshot source not found")
    await materialize_findings(session, assessment_id)
    checks = (
        await session.scalars(
            select(CheckExecution)
            .where(CheckExecution.assessment_id == assessment_id)
            .order_by(CheckExecution.check_identifier)
        )
    ).all()
    findings = (
        await session.scalars(
            select(Finding)
            .where(Finding.assessment_id == assessment_id)
            .order_by(Finding.check_identifier)
        )
    ).all()
    if any(item.operator_reviewed_at is None for item in findings):
        raise ValueError("all findings must receive operator review before report generation")
    evidence = (
        await session.scalars(
            select(Evidence)
            .where(Evidence.assessment_id == assessment_id)
            .order_by(Evidence.check_identifier, Evidence.capture_time, Evidence.id)
        )
    ).all()
    snapshot = {
        "schema_version": 1,
        "tool_version": "0.1.0",
        "assessment": {
            "id": str(assessment.id),
            "state": assessment.state.value,
            "selected_checks": json.loads(assessment.selected_checks),
            "created_at": assessment.created_at.isoformat(),
            "started_at": assessment.started_at.isoformat() if assessment.started_at else None,
            "completed_at": (
                assessment.completed_at.isoformat() if assessment.completed_at else None
            ),
            "terminal_reason": assessment.terminal_reason,
        },
        "target": {
            "scheme": target.scheme,
            "hostname": target.hostname,
            "port": target.port,
            "base_path": target.base_path_prefix,
        },
        "authorization": {
            "valid_from": authorization.valid_from.isoformat(),
            "valid_until": authorization.valid_until.isoformat(),
            "operator_review": authorization.operator_review,
        },
        "checks": [
            {
                "check_identifier": item.check_identifier,
                "check_version": item.check_version,
                "outcome": item.outcome.value,
                "reason_code": item.reason_code,
                "summary": item.summary,
                "observations": json.loads(item.observations),
            }
            for item in checks
        ],
        "coverage": {
            "tested": [
                item.check_identifier
                for item in checks
                if item.outcome.value in {"passed", "finding", "inconclusive"}
            ],
            "skipped": [
                item.check_identifier for item in checks if item.outcome.value == "skipped"
            ],
            "failed": [
                item.check_identifier
                for item in checks
                if item.outcome.value in {"error", "cancelled"}
            ],
        },
        "findings": [
            {
                "id": str(item.id),
                "check_identifier": item.check_identifier,
                "check_version": item.check_version,
                "title": item.title,
                "validation_state": item.validation_state.value,
                "severity": item.severity.value,
                "severity_rationale": item.severity_rationale,
                "expected_behavior": item.expected_behavior,
                "observed_behavior": item.observed_behavior,
                "impact": item.impact,
                "remediation_guidance": item.remediation_guidance,
                "reproduction_guidance": item.reproduction_guidance,
                "evidence_refs": json.loads(item.evidence_refs),
                "operator_reviewed_by": item.operator_reviewed_by,
                "operator_reviewed_at": (
                    item.operator_reviewed_at.isoformat()
                    if item.operator_reviewed_at
                    else None
                ),
            }
            for item in findings
        ],
        "evidence": [sanitized_record(item) for item in evidence],
        "limitations": (
            "Only declared synthetic resources and the selected V1 checks were tested. "
            "Inconclusive, skipped, cancelled, and error outcomes are not clean results."
        ),
    }
    snapshot_digest = hashlib.sha256(canonical_json(snapshot).encode()).hexdigest()
    content = render_report(
        snapshot, format=format, variant=variant, snapshot_digest=snapshot_digest,
        review_status="draft"
    )
    artifact = ReportArtifact(
        assessment_id=assessment_id,
        organization_id=application.organization_id,
        format=format,
        variant=variant,
        content=content,
        file_digest=hashlib.sha256(content).hexdigest(),
        snapshot_digest=snapshot_digest,
        snapshot=canonical_json(snapshot),
        source_artifact_id=None,
        idempotency_key=idempotency_key,
    )
    session.add(artifact)
    await session.commit()
    await session.refresh(artifact)
    return artifact
