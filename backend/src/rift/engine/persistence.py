"""Transactional persistence for terminal check results and their evidence."""

import hashlib
import json
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from rift.domain.encryption import EncryptionService
from rift.domain.models import Assessment, AuditEvent, AuditEventType, CheckExecution, Evidence
from rift.engine.contracts import CheckResult
from rift.safety.audit import AuditRecord
from rift.safety.redaction import redact_headers, redact_text


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


async def persist_network_audit(
    session: AsyncSession, assessment_id: UUID, records: tuple[AuditRecord, ...]
) -> None:
    event_types = {
        "http_request_intent": AuditEventType.REQUEST_SENT,
        "http_request_outcome": AuditEventType.REQUEST_RESPONSE,
    }
    for record in records:
        event_type = event_types.get(record.event_type)
        if event_type is not None:
            await append_audit_event(session, assessment_id, event_type, record.metadata)


async def persist_result(
    session: AsyncSession,
    assessment_id: UUID,
    result: CheckResult,
    encryption: EncryptionService,
) -> CheckExecution:
    existing = await session.scalar(
        select(CheckExecution).where(
            CheckExecution.assessment_id == assessment_id,
            CheckExecution.check_identifier == result.check_identifier,
            CheckExecution.check_version == result.check_version,
        )
    )
    if existing is not None:
        return existing

    evidence_ids: list[str] = []
    for capture in result.evidence:
        evidence_id = uuid4()
        raw = canonical_json(
            {
                "method": capture.method,
                "path": capture.path,
                "request_headers": capture.request_headers,
                "status_code": capture.response.status_code,
                "response_headers": dict(
                    capture.response.raw_headers or capture.response.headers
                ),
                "body": (capture.response.raw_body or capture.response.body).decode(
                    "utf-8", errors="replace"
                ),
            }
        )
        row = Evidence(
            id=evidence_id,
            assessment_id=assessment_id,
            check_identifier=result.check_identifier,
            check_version=result.check_version,
            encrypted_raw_blob_ref=encryption.encrypt(
                raw, purpose="raw-evidence", record_id=str(evidence_id)
            ),
            sanitized_request=canonical_json(
                {
                    "method": capture.method,
                    "path": redact_text(capture.path),
                    "headers": redact_headers(capture.request_headers),
                }
            ),
            sanitized_response=canonical_json(
                {
                    "status_code": capture.response.status_code,
                    "headers": redact_headers(capture.response.headers),
                    "excerpt": redact_text(
                        capture.response.body.decode("utf-8", errors="replace")[:2048]
                    ),
                }
            ),
            body_digest=capture.response.body_digest,
            redaction_version=1,
        )
        session.add(row)
        evidence_ids.append(str(evidence_id))

    execution = CheckExecution(
        assessment_id=assessment_id,
        check_identifier=result.check_identifier,
        check_version=result.check_version,
        outcome=result.outcome,
        reason_code=result.reason_code,
        summary=result.summary,
        evidence_refs=canonical_json(evidence_ids),
        observations=canonical_json(result.observations),
        started_at=result.started_at,
        completed_at=result.completed_at,
    )
    session.add(execution)
    await append_audit_event(
        session,
        assessment_id,
        AuditEventType.CHECK_COMPLETED,
        {
            "check_identifier": result.check_identifier,
            "check_version": result.check_version,
            "outcome": result.outcome.value,
            "reason_code": result.reason_code,
            "evidence_refs": evidence_ids,
        },
    )
    await session.flush()
    return execution


async def append_audit_event(
    session: AsyncSession,
    assessment_id: UUID,
    event_type: AuditEventType,
    metadata: object,
) -> None:
    await session.scalar(
        select(Assessment.id).where(Assessment.id == assessment_id).with_for_update()
    )
    previous = await session.scalar(
        select(AuditEvent)
        .where(AuditEvent.assessment_id == assessment_id)
        .order_by(AuditEvent.timestamp.desc(), AuditEvent.id.desc())
        .limit(1)
        .with_for_update()
    )
    previous_hash = previous.event_hash if previous else None
    serialized = canonical_json(metadata)
    event_hash = hashlib.sha256(
        f"{previous_hash or ''}|{event_type.value}|system|{serialized}".encode()
    ).hexdigest()
    session.add(
        AuditEvent(
            assessment_id=assessment_id,
            event_type=event_type,
            actor="system",
            sanitized_metadata=serialized,
            previous_hash=previous_hash,
            event_hash=event_hash,
        )
    )
