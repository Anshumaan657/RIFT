"""Versioned raw-evidence access and deterministic report-safe representations."""

import json

from rift.domain.encryption import EncryptionService
from rift.domain.models import Evidence
from rift.engine.persistence import canonical_json

RAW_EVIDENCE_VERSION = 1
SANITIZED_EVIDENCE_VERSION = 1
MAX_EXCERPT_CHARS = 2048


def decrypt_raw(row: Evidence, encryption: EncryptionService) -> dict[str, object]:
    value = encryption.decrypt(
        row.encrypted_raw_blob_ref, purpose="raw-evidence", record_id=str(row.id)
    )
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError("raw evidence must be an object")
    return parsed


def sanitized_record(row: Evidence) -> dict[str, object]:
    request = json.loads(row.sanitized_request)
    response = json.loads(row.sanitized_response)
    response["excerpt"] = str(response.get("excerpt", ""))[:MAX_EXCERPT_CHARS]
    return {
        "id": str(row.id),
        "check_identifier": row.check_identifier,
        "check_version": row.check_version,
        "request": request,
        "response": response,
        "body_digest": row.body_digest,
        "capture_time": row.capture_time.isoformat(),
        "redaction_version": row.redaction_version,
        "schema_version": SANITIZED_EVIDENCE_VERSION,
    }


def deterministic_sanitized_json(row: Evidence) -> str:
    return canonical_json(sanitized_record(row))
