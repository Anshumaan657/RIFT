"""Phase 8 maintenance controls with deterministic, testable behavior."""

import hashlib
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from rift.domain.encryption import EncryptionService
from rift.domain.models import Assessment, AuditEvent, Evidence, TestIdentity
from rift.engine.persistence import canonical_json
from rift.reports.models import ReportArtifact
from rift.settings import Settings

PURGED_RAW_EVIDENCE = "purged:v1"


@dataclass(frozen=True)
class RetentionResult:
    raw_evidence_purged: int
    credentials_deleted: int
    reports_deleted: int


def retention_cutoffs(now: datetime, settings: Settings) -> tuple[datetime, datetime, datetime]:
    return (
        now - timedelta(days=settings.raw_evidence_retention_days),
        now - timedelta(days=settings.credential_retention_days),
        now - timedelta(days=settings.report_retention_days),
    )


async def apply_retention(
    session: AsyncSession, settings: Settings, *, now: datetime | None = None
) -> RetentionResult:
    timestamp = now or datetime.now(UTC)
    raw_cutoff, credential_cutoff, report_cutoff = retention_cutoffs(timestamp, settings)
    stale_raw_assessments = select(Assessment.id).where(
        Assessment.completed_at.is_not(None), Assessment.completed_at < raw_cutoff
    )
    raw_result = await session.execute(
        update(Evidence)
        .where(
            Evidence.assessment_id.in_(stale_raw_assessments),
            Evidence.encrypted_raw_blob_ref != PURGED_RAW_EVIDENCE,
        )
        .values(encrypted_raw_blob_ref=PURGED_RAW_EVIDENCE)
    )

    stale_applications = (
        select(Assessment.application_id)
        .where(Assessment.completed_at.is_not(None))
        .group_by(Assessment.application_id)
        .having(func.max(Assessment.completed_at) < credential_cutoff)
    )
    credential_result = await session.execute(
        delete(TestIdentity).where(TestIdentity.application_id.in_(stale_applications))
    )

    stale_report_assessments = select(Assessment.id).where(
        Assessment.completed_at.is_not(None), Assessment.completed_at < report_cutoff
    )
    reviewed_result = await session.execute(
        delete(ReportArtifact).where(
            ReportArtifact.assessment_id.in_(stale_report_assessments),
            ReportArtifact.source_artifact_id.is_not(None),
        )
    )
    draft_result = await session.execute(
        delete(ReportArtifact).where(
            ReportArtifact.assessment_id.in_(stale_report_assessments),
            ReportArtifact.source_artifact_id.is_(None),
        )
    )
    await session.commit()
    return RetentionResult(
        raw_evidence_purged=int(raw_result.rowcount or 0),
        credentials_deleted=int(credential_result.rowcount or 0),
        reports_deleted=int(reviewed_result.rowcount or 0) + int(draft_result.rowcount or 0),
    )


def audit_event_digest(previous_hash: str | None, event: AuditEvent) -> str:
    return hashlib.sha256(
        (
            f"{previous_hash or ''}|{event.event_type.value}|"
            f"{event.actor}|{event.sanitized_metadata}"
        ).encode()
    ).hexdigest()


async def find_invalid_audit_chains(session: AsyncSession) -> list[UUID]:
    assessment_ids = (await session.scalars(select(AuditEvent.assessment_id).distinct())).all()
    invalid: list[UUID] = []
    for assessment_id in assessment_ids:
        events = (
            await session.scalars(
                select(AuditEvent).where(AuditEvent.assessment_id == assessment_id)
            )
        ).all()
        children: dict[str | None, list[AuditEvent]] = {}
        for event in events:
            children.setdefault(event.previous_hash, []).append(event)
        previous_hash: str | None = None
        visited = 0
        while visited < len(events):
            candidates = children.get(previous_hash, [])
            if len(candidates) != 1:
                invalid.append(assessment_id)
                break
            event = candidates[0]
            if event.event_hash != audit_event_digest(previous_hash, event):
                invalid.append(assessment_id)
                break
            previous_hash = event.event_hash
            visited += 1
        if visited == len(events) and children.get(previous_hash):
            invalid.append(assessment_id)
    return invalid


async def database_size_bytes(session: AsyncSession) -> int:
    value = await session.scalar(text("SELECT pg_database_size(current_database())"))
    return int(value or 0)


def disk_free_bytes(path: str | Path | None = None) -> int:
    import shutil

    return shutil.disk_usage(path or tempfile.gettempdir()).free


async def rotate_encryption_key(
    session: AsyncSession,
    old: EncryptionService,
    new: EncryptionService,
) -> tuple[int, int]:
    identities = (await session.scalars(select(TestIdentity).with_for_update())).all()
    evidence = (
        await session.scalars(
            select(Evidence)
            .where(Evidence.encrypted_raw_blob_ref != PURGED_RAW_EVIDENCE)
            .with_for_update()
        )
    ).all()
    for identity in identities:
        plaintext = old.decrypt_token(identity.encrypted_bearer_token, str(identity.id))
        identity.encrypted_bearer_token = new.encrypt_token(plaintext, str(identity.id))
    for row in evidence:
        plaintext = old.decrypt(
            row.encrypted_raw_blob_ref, purpose="raw-evidence", record_id=str(row.id)
        )
        row.encrypted_raw_blob_ref = new.encrypt(
            plaintext, purpose="raw-evidence", record_id=str(row.id)
        )
    await session.commit()
    return len(identities), len(evidence)


def sanitized_maintenance_result(result: RetentionResult) -> str:
    return canonical_json(
        {
            "credentials_deleted": result.credentials_deleted,
            "raw_evidence_purged": result.raw_evidence_purged,
            "reports_deleted": result.reports_deleted,
        }
    )
