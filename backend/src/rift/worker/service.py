"""Assessment orchestration for a claimed durable job."""

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from rift.domain.encryption import EncryptionService
from rift.domain.models import (
    Assessment,
    AssessmentState,
    AuditEventType,
    CheckExecution,
    CheckOutcome,
    Job,
    JobState,
    ResourceExpectation,
    Target,
    TestIdentity,
)
from rift.engine.checks.common import result
from rift.engine.contracts import ResourceInput
from rift.engine.persistence import append_audit_event, persist_network_audit, persist_result
from rift.engine.runner import run_check
from rift.safety.audit import AuditChain
from rift.safety.http_client import SafeHttpClient
from rift.safety.policy import RequestedLimits, SafetyPolicy
from rift.safety.scope import NormalizedTarget
from rift.settings import get_settings


async def execute_job(
    session: AsyncSession,
    job: Job,
    *,
    cancellation_check: Callable[[], bool] = lambda: False,
) -> None:
    assessment = await session.get(Assessment, job.assessment_id)
    if assessment is None:
        raise RuntimeError("assessment disappeared")
    if assessment.state in {AssessmentState.CANCELLING, AssessmentState.CANCELLED}:
        job.state = JobState.CANCELLED
        await session.commit()
        return
    if assessment.state == AssessmentState.QUEUED:
        assessment.state = AssessmentState.RUNNING
        assessment.started_at = datetime.now(UTC)
    snapshot = json.loads(assessment.configuration_snapshot)
    authorization_deadline = datetime.fromisoformat(snapshot["authorization_valid_until"])
    settings = get_settings()
    expired_reason: str | None = None
    if authorization_deadline <= datetime.now(UTC):
        expired_reason = "AUTHORIZATION_EXPIRED"
    elif (
        assessment.started_at
        and (datetime.now(UTC) - assessment.started_at).total_seconds()
        >= settings.max_assessment_runtime_seconds
    ):
        expired_reason = "RUNTIME_EXPIRED"
    if expired_reason:
        terminal = result(
            job.check_identifier,
            datetime.now(UTC),
            CheckOutcome.ERROR,
            expired_reason,
            "Execution stopped before a request because a safety deadline expired.",
        )
        await persist_result(session, assessment.id, terminal, EncryptionService())
        await session.commit()
        return

    target = await session.get(Target, assessment.target_id)
    if target is None:
        raise RuntimeError("target disappeared")
    normalized = NormalizedTarget.create(
        target.scheme,
        target.hostname,
        target.port,
        target.base_path_prefix,
        json.loads(target.validated_ips),
    )
    audit = AuditChain()
    client = SafeHttpClient(
        assessment_id=str(assessment.id),
        target=normalized,
        policy=SafetyPolicy.from_settings(
            settings, RequestedLimits(requests=assessment.request_budget)
        ),
        cancellation_check=lambda: cancellation_check()
        or assessment.state in {AssessmentState.CANCELLING, AssessmentState.CANCELLED},
        audit=audit,
    )
    resource = await _resource_input(session, assessment.application_id)
    await append_audit_event(
        session,
        assessment.id,
        AuditEventType.CHECK_STARTED,
        {"check_identifier": job.check_identifier, "check_version": job.check_version},
    )
    try:
        check_result = await run_check(
            job.check_identifier,
            client,
            resource=resource,
            is_https=target.scheme == "https",
        )
    finally:
        await persist_network_audit(session, assessment.id, audit.records(str(assessment.id)))
        await session.commit()
    if check_result.outcome == CheckOutcome.CANCELLED:
        assessment.state = AssessmentState.CANCELLING
    await persist_result(session, assessment.id, check_result, EncryptionService())
    await session.commit()


async def persist_terminal_failure(session: AsyncSession, job: Job, error_code: str) -> None:
    terminal = result(
        job.check_identifier,
        datetime.now(UTC),
        CheckOutcome.ERROR,
        "TRANSPORT_FAILURE",
        f"The controlled transport failed after safe retry handling ({error_code}).",
    )
    await persist_result(session, job.assessment_id, terminal, EncryptionService())
    await session.commit()


async def finalize_assessment(session: AsyncSession, assessment_id: UUID) -> None:
    assessment = await session.get(Assessment, assessment_id)
    if assessment is None:
        return
    jobs = (await session.scalars(select(Job).where(Job.assessment_id == assessment_id))).all()
    if any(job.state in {JobState.PENDING, JobState.CLAIMED, JobState.RUNNING} for job in jobs):
        return
    executions = (
        await session.scalars(
            select(CheckExecution).where(CheckExecution.assessment_id == assessment_id)
        )
    ).all()
    if assessment.state == AssessmentState.CANCELLING or any(
        job.state == JobState.CANCELLED for job in jobs
    ):
        assessment.state = AssessmentState.CANCELLED
    elif any(job.state == JobState.FAILED for job in jobs) or any(
        item.outcome in {CheckOutcome.ERROR, CheckOutcome.SKIPPED, CheckOutcome.CANCELLED}
        for item in executions
    ):
        assessment.state = AssessmentState.COMPLETED_WITH_ERRORS
    elif len(executions) != len(jobs):
        assessment.state = AssessmentState.FAILED
        assessment.terminal_reason = "missing check execution records"
    else:
        assessment.state = AssessmentState.COMPLETED
    assessment.completed_at = datetime.now(UTC)
    await append_audit_event(
        session,
        assessment.id,
        (
            AuditEventType.ASSESSMENT_CANCELLED
            if assessment.state == AssessmentState.CANCELLED
            else AuditEventType.ASSESSMENT_FAILED
            if assessment.state == AssessmentState.FAILED
            else AuditEventType.ASSESSMENT_COMPLETED
        ),
        {"state": assessment.state.value, "terminal_reason": assessment.terminal_reason},
    )
    await session.commit()


async def _resource_input(session: AsyncSession, application_id: UUID) -> ResourceInput | None:
    expectation = await session.scalar(
        select(ResourceExpectation)
        .where(
            ResourceExpectation.application_id == application_id,
            ResourceExpectation.is_public.is_(False),
        )
        .order_by(ResourceExpectation.created_at)
    )
    if expectation is None:
        return None
    identities = (
        await session.scalars(
            select(TestIdentity).where(TestIdentity.application_id == application_id)
        )
    ).all()
    owner = next((item for item in identities if item.label == expectation.owner_identity), None)
    alternate = next(
        (item for item in identities if item.label != expectation.owner_identity), None
    )
    encryption = EncryptionService()
    owner_token = (
        encryption.decrypt_token(owner.encrypted_bearer_token, str(owner.id)) if owner else None
    )
    alternate_token = (
        encryption.decrypt_token(alternate.encrypted_bearer_token, str(alternate.id))
        if alternate
        else None
    )
    path = expectation.endpoint_template.replace("{resource_id}", expectation.synthetic_resource_id)
    return ResourceInput(path, expectation.content_marker, owner_token, alternate_token)


def retryable_transport_error(exc: BaseException) -> bool:
    return isinstance(exc, TimeoutError | OSError | asyncio.IncompleteReadError)
