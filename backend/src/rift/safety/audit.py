"""Deterministic, sanitized, append-only audit hash chains."""

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from rift.safety.redaction import redact

ZERO_HASH = "0" * 64


@dataclass(frozen=True)
class AuditRecord:
    assessment_id: str
    sequence: int
    event_type: str
    timestamp: str
    actor: str
    metadata: Mapping[str, Any]
    previous_hash: str
    event_hash: str


class AuditChain:
    def __init__(self, sink: Callable[[AuditRecord], None] | None = None) -> None:
        self._records: dict[str, list[AuditRecord]] = {}
        self._sink = sink

    def append(
        self,
        assessment_id: str,
        event_type: str,
        actor: str,
        metadata: Mapping[str, Any],
        *,
        timestamp: datetime | None = None,
        configured_patterns: tuple[str, ...] = (),
    ) -> AuditRecord:
        existing = self._records.setdefault(assessment_id, [])
        previous_hash = existing[-1].event_hash if existing else ZERO_HASH
        safe_metadata = redact(metadata, configured_patterns)
        event_time = (timestamp or datetime.now(UTC)).astimezone(UTC).isoformat()
        payload = {
            "assessment_id": assessment_id,
            "sequence": len(existing) + 1,
            "event_type": event_type,
            "timestamp": event_time,
            "actor": actor,
            "metadata": safe_metadata,
            "previous_hash": previous_hash,
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        record = AuditRecord(**payload, event_hash=digest)
        existing.append(record)
        if self._sink is not None:
            self._sink(record)
        return record

    def records(self, assessment_id: str) -> tuple[AuditRecord, ...]:
        return tuple(self._records.get(assessment_id, ()))

    @staticmethod
    def verify(records: tuple[AuditRecord, ...]) -> bool:
        previous_hash = ZERO_HASH
        for expected_sequence, record in enumerate(records, start=1):
            if record.sequence != expected_sequence or record.previous_hash != previous_hash:
                return False
            payload = {
                "assessment_id": record.assessment_id,
                "sequence": record.sequence,
                "event_type": record.event_type,
                "timestamp": record.timestamp,
                "actor": record.actor,
                "metadata": record.metadata,
                "previous_hash": record.previous_hash,
            }
            digest = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if not __import__("hmac").compare_digest(digest, record.event_hash):
                return False
            previous_hash = record.event_hash
        return True
