"""Read models and credential lifecycle endpoints used by the operator console."""

import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from rift.api.dependencies import current_operator, require_csrf
from rift.api.schemas import TestIdentityUpdate
from rift.db.session import get_session
from rift.domain.encryption import EncryptionService
from rift.domain.models import (
    Application,
    Assessment,
    AuthorizationRecord,
    Evidence,
    Organization,
    ResourceExpectation,
    Target,
    TestIdentity,
)
from rift.reports.evidence import sanitized_record
from rift.reports.models import ReportArtifact

router = APIRouter(prefix="/api/v1", dependencies=[Depends(current_operator)])


@router.get("/organizations")
async def list_organizations(
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, object]]:
    rows = (await session.scalars(select(Organization).order_by(Organization.created_at))).all()
    return [{"id": row.id, "name": row.name, "status": row.status} for row in rows]


@router.get("/organizations/{organization_id}")
async def get_organization(
    organization_id: UUID,
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    row = await session.get(Organization, organization_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "organization not found")
    return {"id": row.id, "name": row.name, "status": row.status}


@router.get("/applications/{application_id}")
async def get_application(
    application_id: UUID,
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    application = await session.get(Application, application_id)
    if application is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "application not found")
    authorizations = (
        await session.scalars(
            select(AuthorizationRecord)
            .where(AuthorizationRecord.application_id == application_id)
            .order_by(AuthorizationRecord.created_at.desc())
        )
    ).all()
    targets = (
        await session.scalars(
            select(Target)
            .where(Target.application_id == application_id)
            .order_by(Target.created_at)
        )
    ).all()
    identities = (
        await session.scalars(
            select(TestIdentity)
            .where(TestIdentity.application_id == application_id)
            .order_by(TestIdentity.created_at)
        )
    ).all()
    resources = (
        await session.scalars(
            select(ResourceExpectation)
            .where(ResourceExpectation.application_id == application_id)
            .order_by(ResourceExpectation.created_at)
        )
    ).all()
    return {
        "id": application.id,
        "organization_id": application.organization_id,
        "display_name": application.display_name,
        "environment_type": application.environment_type,
        "lifecycle_status": application.lifecycle_status,
        "authorization_records": [
            {
                "id": row.id,
                "approver_identity": row.approver_identity,
                "valid_from": row.valid_from,
                "valid_until": row.valid_until,
                "operator_review": row.operator_review,
                "status": row.status,
                "approved_scope": json.loads(row.approved_scope),
            }
            for row in authorizations
        ],
        "targets": [
            {
                "id": row.id,
                "scheme": row.scheme,
                "hostname": row.hostname,
                "port": row.port,
                "base_path_prefix": row.base_path_prefix,
                "verification_state": row.verification_state,
                "enabled_state": row.enabled_state,
            }
            for row in targets
        ],
        "test_identities": [
            {
                "id": row.id,
                "label": row.label,
                "token_expiry": row.token_expiry,
                "credential_state": "stored",
            }
            for row in identities
        ],
        "resource_expectations": [
            {
                "id": row.id,
                "endpoint_template": row.endpoint_template,
                "synthetic_resource_id": row.synthetic_resource_id,
                "owner_identity": row.owner_identity,
                "is_public": row.is_public,
                "expected_access": row.expected_access,
                "content_marker": row.content_marker,
            }
            for row in resources
        ],
    }


@router.get("/applications/{application_id}/assessments")
async def list_assessments(
    application_id: UUID,
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, object]]:
    if await session.get(Application, application_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "application not found")
    rows = (
        await session.scalars(
            select(Assessment)
            .where(Assessment.application_id == application_id)
            .order_by(Assessment.created_at.desc())
        )
    ).all()
    return [
        {
            "id": row.id,
            "target_id": row.target_id,
            "state": row.state,
            "selected_checks": json.loads(row.selected_checks),
            "created_at": row.created_at,
            "started_at": row.started_at,
            "completed_at": row.completed_at,
            "terminal_reason": row.terminal_reason,
        }
        for row in rows
    ]


@router.put(
    "/test-identities/{identity_id}",
    dependencies=[Depends(require_csrf)],
)
async def replace_test_identity(
    identity_id: UUID,
    payload: TestIdentityUpdate,
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    identity = await session.get(TestIdentity, identity_id)
    if identity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "test identity not found")
    identity.label = payload.label or identity.label
    identity.encrypted_bearer_token = EncryptionService().encrypt_token(
        payload.bearer_token, str(identity.id)
    )
    identity.token_expiry = payload.token_expiry
    await session.commit()
    return {
        "id": identity.id,
        "label": identity.label,
        "token_expiry": identity.token_expiry,
        "credential_state": "stored",
    }


@router.delete(
    "/test-identities/{identity_id}",
    dependencies=[Depends(require_csrf)],
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_test_identity(
    identity_id: UUID,
    session: AsyncSession = Depends(get_session),
) -> Response:
    identity = await session.get(TestIdentity, identity_id)
    if identity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "test identity not found")
    await session.delete(identity)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/assessments/{assessment_id}/evidence")
async def list_evidence(
    assessment_id: UUID,
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, object]]:
    if await session.get(Assessment, assessment_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "assessment not found")
    rows = (
        await session.scalars(
            select(Evidence)
            .where(Evidence.assessment_id == assessment_id)
            .order_by(Evidence.capture_time, Evidence.id)
        )
    ).all()
    return [sanitized_record(row) for row in rows]


@router.get("/assessments/{assessment_id}/reports")
async def list_reports(
    assessment_id: UUID,
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, object]]:
    if await session.get(Assessment, assessment_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "assessment not found")
    rows = (
        await session.scalars(
            select(ReportArtifact)
            .where(ReportArtifact.assessment_id == assessment_id)
            .order_by(ReportArtifact.created_at.desc())
        )
    ).all()
    return [
        {
            "id": row.id,
            "format": row.format,
            "variant": row.variant,
            "review_status": row.review_status,
            "file_digest": row.file_digest,
            "created_at": row.created_at,
        }
        for row in rows
    ]
