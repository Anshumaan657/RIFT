import base64
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from starlette.responses import Response

from rift.api.security_headers import apply_security_headers
from rift.domain.encryption import EncryptionService
from rift.domain.models import AuditEvent, AuditEventType, Evidence
from rift.domain.models import TestIdentity as StoredTestIdentity
from rift.maintenance.backup import decrypt_backup, encrypt_backup
from rift.maintenance.service import (
    audit_event_digest,
    find_invalid_audit_chains,
    retention_cutoffs,
    rotate_encryption_key,
)
from rift.settings import Settings
from rift.worker.health import heartbeat_is_fresh, touch_heartbeat


def settings(**changes: object) -> Settings:
    values: dict[str, object] = {
        "database_url": "postgresql+asyncpg://u:p@db/rift",
        "master_key_b64": base64.urlsafe_b64encode(b"k" * 32).decode(),
        "session_secret": "s" * 32,
        "operator_password_hash": "$argon2id$development-placeholder",
    }
    values.update(changes)
    return Settings(**values)


def test_production_configuration_requires_tls_real_secrets_and_egress_scope() -> None:
    common = {
        "environment": "pilot",
        "frontend_origin": "https://rift.example.test",
        "database_url": "postgresql+asyncpg://u:p@db/rift?ssl=verify-full",
        "master_key_b64": base64.urlsafe_b64encode(b"k" * 32).decode(),
        "session_secret": "s" * 32,
        "operator_password_hash": "$argon2id$v=19$m=65536,t=3,p=4$hash",
        "allowed_target_cidrs": "8.8.8.0/24",
    }
    configured = Settings(**common)
    assert str(configured.allowed_target_networks[0]) == "8.8.8.0/24"
    for change in (
        {"frontend_origin": "http://rift.example.test"},
        {"frontend_origin": "https://rift.example.test/unexpected-path"},
        {"database_url": "postgresql+asyncpg://u:p@db/rift"},
        {"database_url": "postgresql+asyncpg://u:p@db/rift?ssl=require"},
        {"allowed_target_cidrs": ""},
        {"allowed_target_cidrs": "10.0.0.0/8"},
        {"operator_password_hash": "not-argon"},
        {"session_secret": "REPLACE_WITH_REAL_SESSION_SECRET_123"},
    ):
        with pytest.raises(ValueError):
            Settings(**(common | change))


def test_retention_defaults_and_hard_maxima() -> None:
    configured = settings()
    now = datetime(2026, 9, 7, tzinfo=UTC)
    assert retention_cutoffs(now, configured) == (
        now - timedelta(days=30),
        now - timedelta(days=30),
        now - timedelta(days=180),
    )
    with pytest.raises(ValueError):
        settings(raw_evidence_retention_days=31)
    with pytest.raises(ValueError):
        settings(report_retention_days=181)


def test_backup_envelope_round_trip_and_tamper_detection() -> None:
    key = base64.urlsafe_b64encode(b"b" * 32).decode()
    encrypted = encrypt_backup(b"synthetic-postgres-archive", key)
    assert b"synthetic-postgres-archive" not in encrypted
    assert decrypt_backup(encrypted, key) == b"synthetic-postgres-archive"
    damaged = encrypted.replace(b"ciphertext", b"ciphertexu", 1)
    with pytest.raises((KeyError, ValueError)):
        decrypt_backup(damaged, key)


@pytest.mark.asyncio
async def test_encryption_key_rotation_reencrypts_credentials_and_evidence() -> None:
    old_key = base64.urlsafe_b64encode(b"o" * 32).decode()
    new_key = base64.urlsafe_b64encode(b"n" * 32).decode()
    old = EncryptionService(old_key)
    new = EncryptionService(new_key)
    identity_id = uuid4()
    evidence_id = uuid4()
    identity = StoredTestIdentity(
        id=identity_id,
        application_id=uuid4(),
        label="synthetic-owner",
        encrypted_bearer_token=old.encrypt_token("synthetic-token", str(identity_id)),
    )
    evidence = Evidence(
        id=evidence_id,
        assessment_id=uuid4(),
        check_identifier="phase8.rehearsal",
        check_version="1",
        encrypted_raw_blob_ref=old.encrypt(
            "synthetic-evidence", purpose="raw-evidence", record_id=str(evidence_id)
        ),
        sanitized_request="{}",
        sanitized_response="{}",
        body_digest="0" * 64,
    )

    class ScalarRows:
        def __init__(self, rows: list[object]) -> None:
            self.rows = rows

        def all(self) -> list[object]:
            return self.rows

    session = AsyncMock()
    session.scalars.side_effect = [ScalarRows([identity]), ScalarRows([evidence])]

    assert await rotate_encryption_key(session, old, new) == (1, 1)
    assert new.decrypt_token(identity.encrypted_bearer_token, str(identity_id)) == "synthetic-token"
    assert (
        new.decrypt(
            evidence.encrypted_raw_blob_ref,
            purpose="raw-evidence",
            record_id=str(evidence_id),
        )
        == "synthetic-evidence"
    )
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_audit_monitor_detects_tampered_metadata() -> None:
    assessment_id = uuid4()
    event = AuditEvent(
        assessment_id=assessment_id,
        event_type=AuditEventType.CHECK_COMPLETED,
        actor="system",
        sanitized_metadata='{"outcome":"passed"}',
        previous_hash=None,
        event_hash="",
    )
    event.event_hash = audit_event_digest(None, event)

    class ScalarRows:
        def __init__(self, rows: list[object]) -> None:
            self.rows = rows

        def all(self) -> list[object]:
            return self.rows

    valid_session = AsyncMock()
    valid_session.scalars.side_effect = [ScalarRows([assessment_id]), ScalarRows([event])]
    assert await find_invalid_audit_chains(valid_session) == []

    event.sanitized_metadata = '{"outcome":"finding"}'
    tampered_session = AsyncMock()
    tampered_session.scalars.side_effect = [ScalarRows([assessment_id]), ScalarRows([event])]
    assert await find_invalid_audit_chains(tampered_session) == [assessment_id]


def test_worker_heartbeat_detects_missing_stale_and_fresh_files(tmp_path) -> None:
    heartbeat = tmp_path / "worker-heartbeat"
    assert not heartbeat_is_fresh(heartbeat, max_age_seconds=30, timestamp=100)
    touch_heartbeat(heartbeat, timestamp=80)
    assert not heartbeat_is_fresh(heartbeat, max_age_seconds=10, timestamp=100)
    touch_heartbeat(heartbeat, timestamp=95)
    assert heartbeat_is_fresh(heartbeat, max_age_seconds=10, timestamp=100)


def test_security_headers_are_strict_and_hsts_is_environment_gated() -> None:
    response = Response()
    apply_security_headers(response, enable_hsts=False)
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "strict-transport-security" not in response.headers
    apply_security_headers(response, enable_hsts=True)
    assert response.headers["strict-transport-security"].startswith("max-age=31536000")
