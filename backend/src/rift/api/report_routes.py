"""Evidence-backed finding and immutable report endpoints."""

import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from rift.api.dependencies import current_operator, require_csrf
from rift.api.schemas import ReportCreate
from rift.db.session import get_session
from rift.domain.models import Assessment, Finding, ReportFormat
from rift.reports.findings import materialize_findings
from rift.reports.models import ReportArtifact, ReviewStatus
from rift.reports.render import render_report
from rift.reports.service import create_report

router = APIRouter(prefix="/api/v1")


def finding_view(item: Finding) -> dict[str, object]:
    return {
        "id": item.id,
        "assessment_id": item.assessment_id,
        "check_identifier": item.check_identifier,
        "check_version": item.check_version,
        "title": item.title,
        "validation_state": item.validation_state,
        "severity": item.severity,
        "severity_rationale": item.severity_rationale,
        "expected_behavior": item.expected_behavior,
        "observed_behavior": item.observed_behavior,
        "impact": item.impact,
        "reproduction_guidance": item.reproduction_guidance,
        "remediation_guidance": item.remediation_guidance,
        "evidence_refs": json.loads(item.evidence_refs),
        "operator_reviewed_by": item.operator_reviewed_by,
        "operator_reviewed_at": item.operator_reviewed_at,
    }


@router.get("/assessments/{assessment_id}/findings")
async def list_findings(
    assessment_id: UUID,
    session: AsyncSession = Depends(get_session),
    _operator: str = Depends(current_operator),
) -> list[dict[str, object]]:
    if await session.get(Assessment, assessment_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "assessment not found")
    await materialize_findings(session, assessment_id)
    await session.commit()
    rows = (
        await session.scalars(
            select(Finding)
            .where(Finding.assessment_id == assessment_id)
            .order_by(Finding.check_identifier)
        )
    ).all()
    return [finding_view(item) for item in rows]


@router.get("/findings/{finding_id}")
async def get_finding(
    finding_id: UUID,
    session: AsyncSession = Depends(get_session),
    _operator: str = Depends(current_operator),
) -> dict[str, object]:
    item = await session.get(Finding, finding_id)
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return finding_view(item)


@router.post("/findings/{finding_id}/review", dependencies=[Depends(require_csrf)])
async def review_finding(
    finding_id: UUID,
    session: AsyncSession = Depends(get_session),
    operator: str = Depends(current_operator),
) -> dict[str, object]:
    item = await session.get(Finding, finding_id)
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    item.operator_reviewed_by = operator
    item.operator_reviewed_at = item.operator_reviewed_at or datetime.now(UTC)
    await session.commit()
    return finding_view(item)


@router.post(
    "/assessments/{assessment_id}/reports",
    dependencies=[Depends(require_csrf)],
    status_code=201,
)
async def generate_report(
    assessment_id: UUID,
    payload: ReportCreate,
    session: AsyncSession = Depends(get_session),
    _operator: str = Depends(current_operator),
) -> dict[str, object]:
    try:
        artifact = await create_report(
            session,
            assessment_id,
            format=payload.format,
            variant=payload.variant,
            idempotency_key=payload.idempotency_key,
        )
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return {
        "id": artifact.id,
        "format": artifact.format,
        "variant": artifact.variant,
        "review_status": artifact.review_status,
        "file_digest": artifact.file_digest,
        "snapshot_digest": artifact.snapshot_digest,
    }


@router.post("/reports/{report_id}/review", dependencies=[Depends(require_csrf)], status_code=201)
async def review_report(
    report_id: UUID,
    session: AsyncSession = Depends(get_session),
    operator: str = Depends(current_operator),
) -> dict[str, object]:
    source = await session.get(ReportArtifact, report_id)
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    if source.review_status == ReviewStatus.REVIEWED:
        return {"id": source.id, "review_status": source.review_status}
    existing = await session.scalar(
        select(ReportArtifact).where(ReportArtifact.source_artifact_id == source.id)
    )
    if existing is not None:
        return {"id": existing.id, "review_status": existing.review_status}
    unreviewed_finding = await session.scalar(
        select(Finding.id)
        .where(
            Finding.assessment_id == source.assessment_id,
            Finding.operator_reviewed_at.is_(None),
        )
        .limit(1)
    )
    if unreviewed_finding is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "all findings must receive operator review before report approval",
        )
    snapshot = json.loads(source.snapshot)
    if any(item.get("operator_reviewed_at") is None for item in snapshot.get("findings", [])):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "draft predates finding review; generate a new draft before approval",
        )
    content = render_report(
        snapshot,
        format=source.format,
        variant=source.variant,
        snapshot_digest=source.snapshot_digest,
        review_status="reviewed",
    )
    reviewed = ReportArtifact(
        assessment_id=source.assessment_id,
        organization_id=source.organization_id,
        format=source.format,
        variant=source.variant,
        review_status=ReviewStatus.REVIEWED,
        content=content,
        file_digest=hashlib.sha256(content).hexdigest(),
        snapshot_digest=source.snapshot_digest,
        snapshot=source.snapshot,
        source_artifact_id=source.id,
        reviewed_by=operator,
        reviewed_at=datetime.now(UTC),
    )
    session.add(reviewed)
    await session.commit()
    await session.refresh(reviewed)
    return {"id": reviewed.id, "review_status": reviewed.review_status}


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: UUID,
    session: AsyncSession = Depends(get_session),
    _operator: str = Depends(current_operator),
) -> Response:
    artifact = await session.get(ReportArtifact, report_id)
    if artifact is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    media_types = {
        ReportFormat.HTML: "text/html; charset=utf-8",
        ReportFormat.JSON: "application/json",
        ReportFormat.PDF: "application/pdf",
    }
    return Response(
        artifact.content,
        media_type=media_types[artifact.format],
        headers={
            "Content-Disposition": (
                f'attachment; filename="rift-{artifact.variant.value}-{artifact.id}.'
                f'{artifact.format.value}"'
            ),
            "Digest": f"sha-256={artifact.file_digest}",
            "X-RIFT-Review-Status": artifact.review_status.value,
        },
    )
