"""Phase 4 operator authentication and onboarding API."""

import json
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from rift.api.auth import SESSION_COOKIE, AuthService, RateLimitedError
from rift.api.dependencies import current_operator, get_auth_service, require_csrf
from rift.api.schemas import (
    ApplicationCreate,
    AssessmentCreate,
    AuthorizationRecordCreate,
    LoginRequest,
    OrganizationCreate,
    ResourceExpectationCreate,
    TargetCreate,
    TestIdentityCreate,
)
from rift.db.session import get_session
from rift.domain.encryption import EncryptionService
from rift.domain.models import (
    Application,
    Assessment,
    AssessmentState,
    AuditEvent,
    AuthorizationRecord,
    CheckExecution,
    Job,
    JobState,
    Organization,
    ResourceExpectation,
    Target,
    TargetVerificationState,
    TestIdentity,
)
from rift.domain.repositories import AssessmentRepository, OwnershipError
from rift.domain.state import InvalidStateTransition, transition_assessment
from rift.safety.audit import AuditChain
from rift.safety.authorization import (
    AuthorizationDenied,
    build_assessment_snapshot,
    require_active_authorization,
)
from rift.safety.http_client import SafeHttpClient
from rift.safety.policy import RequestedLimits, SafetyPolicy
from rift.safety.scope import (
    NormalizedTarget,
    normalize_base_path,
    normalize_hostname,
    resolve_hostname,
)
from rift.safety.verification import challenge_digest, verify_http_challenge
from rift.settings import get_settings

router = APIRouter(prefix="/api/v1")


@router.post("/login")
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    auth: AuthService = Depends(get_auth_service),
) -> dict[str, str]:
    settings = get_settings()
    client = request.client.host if request.client else "unknown"
    key = f"{client}:{payload.username}"
    try:
        valid = auth.authenticate(
            payload.username,
            payload.password,
            expected_username=settings.operator_username,
            password_hash=settings.operator_password_hash.get_secret_value(),
            key=key,
        )
    except RateLimitedError as exc:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many login attempts") from exc
    if not valid:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    cookie, csrf_token = auth.create_session(settings.operator_username)
    response.set_cookie(
        SESSION_COOKIE,
        cookie,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    return {"csrf_token": csrf_token}


@router.post("/logout", dependencies=[Depends(require_csrf)])
async def logout(response: Response) -> dict[str, str]:
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return {"status": "logged_out"}


@router.post("/organizations", dependencies=[Depends(require_csrf)], status_code=201)
async def create_organization(
    payload: OrganizationCreate,
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    organization = Organization(name=payload.name)
    session.add(organization)
    await session.commit()
    await session.refresh(organization)
    return {"id": organization.id, "name": organization.name, "status": organization.status}


@router.post("/applications", dependencies=[Depends(require_csrf)], status_code=201)
async def create_application(
    payload: ApplicationCreate,
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    if await session.get(Organization, payload.organization_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "organization not found")
    application = Application(**payload.model_dump())
    session.add(application)
    await session.commit()
    await session.refresh(application)
    return {"id": application.id, "application_id": application.organization_id}


@router.post("/authorization-records", dependencies=[Depends(require_csrf)], status_code=201)
async def create_authorization(
    payload: AuthorizationRecordCreate,
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    if await session.get(Application, payload.application_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "application not found")
    record = AuthorizationRecord(
        application_id=payload.application_id,
        approver_identity=payload.approver_identity,
        authorization_statement=payload.authorization_statement,
        valid_from=payload.valid_from,
        valid_until=payload.valid_until,
        approved_scope=json.dumps(payload.approved_scope, sort_keys=True),
        prohibited_actions=json.dumps(payload.prohibited_actions, sort_keys=True),
        operator_review=payload.operator_review,
    )
    session.add(record)
    await session.commit()
    await session.refresh(record)
    return {"id": record.id, "operator_review": record.operator_review}


@router.post("/targets", dependencies=[Depends(require_csrf)], status_code=201)
async def create_target(
    payload: TargetCreate,
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    settings = get_settings()
    if await session.get(Application, payload.application_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "application not found")
    if payload.scheme == "http" and not settings.local_lab_mode:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "HTTP requires local lab mode")
    hostname = normalize_hostname(payload.hostname)
    base_path = normalize_base_path(payload.base_path_prefix)
    addresses = await resolve_hostname(hostname, payload.port)
    policy = SafetyPolicy.from_settings(settings)
    probe = NormalizedTarget.create(
        payload.scheme, hostname, payload.port, base_path, [str(address) for address in addresses]
    )
    for address in probe.validated_ips:
        if policy.local_lab_mode and not address.is_loopback:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "lab targets must resolve to loopback")
        if not policy.local_lab_mode and not address.is_global:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "target resolves to a prohibited address"
            )
    token = secrets.token_urlsafe(32)
    target = Target(
        application_id=payload.application_id,
        scheme=payload.scheme,
        hostname=hostname,
        port=payload.port,
        base_path_prefix=base_path,
        verification_token=challenge_digest(token),
        verification_token_expires_at=datetime.now(UTC) + timedelta(minutes=30),
        validated_ips=json.dumps(sorted(str(address) for address in addresses)),
    )
    session.add(target)
    await session.commit()
    await session.refresh(target)
    challenge_path = f"{base_path.rstrip('/')}/.well-known/rift-challenge.txt"
    return {"id": target.id, "challenge_token": token, "challenge_path": challenge_path}


@router.post("/targets/{target_id}/verify", dependencies=[Depends(require_csrf)])
async def verify_target(
    target_id: UUID,
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    target = await session.get(Target, target_id)
    if target is None or target.verification_token is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "pending target verification not found")
    if (
        target.verification_token_expires_at is None
        or target.verification_token_expires_at <= datetime.now(UTC)
    ):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "verification challenge expired")
    normalized = NormalizedTarget.create(
        target.scheme,
        target.hostname,
        target.port,
        target.base_path_prefix,
        json.loads(target.validated_ips),
    )
    client = SafeHttpClient(
        assessment_id=f"target-verification:{target.id}",
        target=normalized,
        policy=SafetyPolicy.from_settings(get_settings(), RequestedLimits(requests=1)),
        cancellation_check=lambda: False,
        audit=AuditChain(),
    )
    if not await verify_http_challenge(client, target.verification_token):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "HTTP challenge did not match")
    target.verification_state = TargetVerificationState.VERIFIED
    target.verification_token = None
    target.verification_token_expires_at = None
    await session.commit()
    return {"id": target.id, "verification_state": target.verification_state}


@router.post("/test-identities", dependencies=[Depends(require_csrf)], status_code=201)
async def create_identity(
    payload: TestIdentityCreate,
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    identity_id = uuid4()
    encrypted = EncryptionService().encrypt_token(payload.bearer_token, str(identity_id))
    identity = TestIdentity(
        id=identity_id,
        application_id=payload.application_id,
        label=payload.label,
        encrypted_bearer_token=encrypted,
        token_expiry=payload.token_expiry,
    )
    session.add(identity)
    await session.commit()
    await session.refresh(identity)
    return {"id": identity.id, "label": identity.label, "token_expiry": identity.token_expiry}


@router.post("/resource-expectations", dependencies=[Depends(require_csrf)], status_code=201)
async def create_resource_expectation(
    payload: ResourceExpectationCreate,
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    if payload.owner_identity is not None:
        identity = await session.scalar(
            select(TestIdentity).where(
                TestIdentity.application_id == payload.application_id,
                TestIdentity.label == payload.owner_identity,
            )
        )
        if identity is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "owner identity does not exist")
    expectation = ResourceExpectation(**payload.model_dump())
    session.add(expectation)
    await session.commit()
    await session.refresh(expectation)
    return {"id": expectation.id}


@router.post("/assessments", dependencies=[Depends(require_csrf)], status_code=201)
async def create_assessment(
    payload: AssessmentCreate,
    session: AsyncSession = Depends(get_session),
    _operator: str = Depends(current_operator),
) -> dict[str, object]:
    target = await session.get(Target, payload.target_id)
    record = await session.get(AuthorizationRecord, payload.authorization_record_id)
    if target is None or record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target or authorization not found")
    try:
        require_active_authorization(record, target)
    except AuthorizationDenied as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    expectations = (
        await session.scalars(
            select(ResourceExpectation).where(
                ResourceExpectation.application_id == payload.application_id
            )
        )
    ).all()
    identities = (
        await session.scalars(
            select(TestIdentity).where(TestIdentity.application_id == payload.application_id)
        )
    ).all()
    policy = SafetyPolicy.from_settings(
        get_settings(), RequestedLimits(requests=payload.request_budget)
    )
    snapshot = build_assessment_snapshot(
        record=record,
        target=target,
        selected_checks=payload.selected_checks,
        resource_expectations=[
            {
                "endpoint_template": item.endpoint_template,
                "synthetic_resource_id": item.synthetic_resource_id,
                "owner_identity": item.owner_identity,
                "is_public": item.is_public,
                "expected_access": item.expected_access,
                "content_marker": item.content_marker,
            }
            for item in expectations
        ],
        identity_ids=[str(item.id) for item in identities],
        policy=policy,
    )
    try:
        assessment = await AssessmentRepository(session).create(
            application_id=payload.application_id,
            target_id=payload.target_id,
            selected_checks=payload.selected_checks,
            configuration=snapshot,
            request_budget=policy.max_requests,
            idempotency_key=payload.idempotency_key,
        )
    except OwnershipError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    await session.commit()
    return {"id": assessment.id, "state": assessment.state, "request_budget": policy.max_requests}


@router.post("/assessments/{assessment_id}/cancel", dependencies=[Depends(require_csrf)])
async def cancel_assessment(
    assessment_id: UUID,
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    assessment = await session.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "assessment not found")
    if assessment.state in {
        AssessmentState.CANCELLING,
        AssessmentState.CANCELLED,
    }:
        return {"id": assessment.id, "state": assessment.state}
    destination = (
        AssessmentState.CANCELLED
        if assessment.state in {AssessmentState.DRAFT, AssessmentState.QUEUED}
        else AssessmentState.CANCELLING
    )
    try:
        transition_assessment(assessment, destination, reason="operator requested cancellation")
    except InvalidStateTransition as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    for job in (
        await session.scalars(
            select(Job).where(
                Job.assessment_id == assessment.id,
                Job.state.in_([JobState.PENDING, JobState.CLAIMED]),
            )
        )
    ).all():
        job.state = JobState.CANCELLED
        job.lease_owner = None
        job.lease_expires_at = None
    await session.commit()
    return {"id": assessment.id, "state": assessment.state}


@router.get("/assessments/{assessment_id}")
async def get_assessment(
    assessment_id: UUID,
    session: AsyncSession = Depends(get_session),
    _operator: str = Depends(current_operator),
) -> dict[str, object]:
    assessment = await session.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "assessment not found")
    executions = (
        await session.scalars(
            select(CheckExecution)
            .where(CheckExecution.assessment_id == assessment_id)
            .order_by(CheckExecution.check_identifier)
        )
    ).all()
    return {
        "id": assessment.id,
        "application_id": assessment.application_id,
        "target_id": assessment.target_id,
        "state": assessment.state,
        "selected_checks": json.loads(assessment.selected_checks),
        "request_budget": assessment.request_budget,
        "started_at": assessment.started_at,
        "completed_at": assessment.completed_at,
        "terminal_reason": assessment.terminal_reason,
        "checks": [
            {
                "check_identifier": item.check_identifier,
                "check_version": item.check_version,
                "outcome": item.outcome,
                "reason_code": item.reason_code,
                "summary": item.summary,
            }
            for item in executions
        ],
    }


@router.get("/assessments/{assessment_id}/audit-events")
async def get_audit_events(
    assessment_id: UUID,
    session: AsyncSession = Depends(get_session),
    _operator: str = Depends(current_operator),
) -> list[dict[str, object]]:
    if await session.get(Assessment, assessment_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "assessment not found")
    events = (
        await session.scalars(
            select(AuditEvent)
            .where(AuditEvent.assessment_id == assessment_id)
            .order_by(AuditEvent.timestamp, AuditEvent.id)
        )
    ).all()
    return [
        {
            "id": event.id,
            "event_type": event.event_type,
            "timestamp": event.timestamp,
            "actor": event.actor,
            "metadata": json.loads(event.sanitized_metadata),
            "previous_hash": event.previous_hash,
            "event_hash": event.event_hash,
        }
        for event in events
    ]
