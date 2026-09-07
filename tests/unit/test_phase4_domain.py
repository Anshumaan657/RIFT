import base64
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from argon2 import Type
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from rift.api.auth import (
    AuthService,
    LoginThrottle,
    RateLimitedError,
    SessionExpiredError,
)
from rift.domain.encryption import EncryptionError, EncryptionService
from rift.domain.models import (
    Assessment,
    AssessmentState,
    AuditEvent,
    AuthorizationStatus,
    Job,
    JobState,
    TargetEnabledState,
    TargetVerificationState,
)
from rift.domain.state import (
    InvalidStateTransition,
    transition_assessment,
    transition_job,
)
from rift.settings import Settings


def test_argon2id_auth_sessions_csrf_and_throttle() -> None:
    auth = AuthService("s" * 32, session_ttl_seconds=600, throttle=LoginThrottle(2, 60))
    password_hash = auth.hash_password("correct horse battery staple")
    assert "$argon2id$" in password_hash
    assert auth._password_hasher.type is Type.ID
    assert auth.authenticate(
        "operator",
        "correct horse battery staple",
        expected_username="operator",
        password_hash=password_hash,
        key="client",
    )
    cookie, csrf = auth.create_session("operator", now=100)
    session = auth.validate_session(cookie, now=101)
    assert auth.validate_csrf(session, csrf)
    assert not auth.validate_csrf(session, "wrong")
    with pytest.raises(SessionExpiredError):
        auth.validate_session(cookie, now=700)
    assert not auth.authenticate(
        "operator",
        "wrong",
        expected_username="operator",
        password_hash=password_hash,
        key="bad",
    )
    assert not auth.authenticate(
        "operator",
        "wrong",
        expected_username="operator",
        password_hash=password_hash,
        key="bad",
    )
    with pytest.raises(RateLimitedError):
        auth.authenticate(
            "operator",
            "wrong",
            expected_username="operator",
            password_hash=password_hash,
            key="bad",
        )


def test_login_sets_secure_strict_http_only_cookie(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rift.api.dependencies import get_auth_service
    from rift.api.routes import router
    from rift.settings import get_settings

    auth = AuthService("s" * 32)
    monkeypatch.setenv("RIFT_DATABASE_URL", "postgresql+asyncpg://u:p@localhost/rift")
    monkeypatch.setenv("RIFT_MASTER_KEY_B64", base64.urlsafe_b64encode(b"k" * 32).decode())
    monkeypatch.setenv("RIFT_SESSION_SECRET", "s" * 32)
    monkeypatch.setenv("RIFT_OPERATOR_PASSWORD_HASH", auth.hash_password("operator-password"))
    get_settings.cache_clear()
    get_auth_service.cache_clear()
    app = FastAPI()
    app.include_router(router)
    response = TestClient(app).post(
        "/api/v1/login",
        json={"username": "operator", "password": "operator-password"},
    )
    cookie = response.headers["set-cookie"].lower()
    assert response.status_code == 200
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=strict" in cookie
    get_settings.cache_clear()
    get_auth_service.cache_clear()


def test_authenticated_encryption_binds_ciphertext_to_record() -> None:
    key = base64.urlsafe_b64encode(b"k" * 32).decode().rstrip("=")
    service = EncryptionService(key)
    encrypted = service.encrypt_token("raw-secret-token", "identity-a")
    assert "raw-secret-token" not in encrypted
    assert service.decrypt_token(encrypted, "identity-a") == "raw-secret-token"
    with pytest.raises(EncryptionError):
        service.decrypt_token(encrypted, "identity-b")


def test_assessment_and_job_state_transitions() -> None:
    assessment = Assessment(
        application_id=uuid4(),
        target_id=uuid4(),
        selected_checks='["RIFT-AUTHN-001"]',
        configuration_snapshot="{}",
        state=AssessmentState.DRAFT,
        request_budget=10,
    )
    transition_assessment(assessment, AssessmentState.QUEUED)
    transition_assessment(assessment, AssessmentState.RUNNING)
    transition_assessment(assessment, AssessmentState.CANCELLING)
    transition_assessment(assessment, AssessmentState.CANCELLED, reason="operator")
    assert assessment.cancelled_at is not None
    assert assessment.completed_at is not None
    with pytest.raises(InvalidStateTransition):
        transition_assessment(assessment, AssessmentState.RUNNING)

    job = Job(
        assessment_id=uuid4(),
        check_identifier="RIFT-AUTHN-001",
        check_version="1",
        state=JobState.PENDING,
    )
    transition_job(job, JobState.CLAIMED)
    transition_job(job, JobState.RUNNING)
    transition_job(job, JobState.SUCCEEDED)
    with pytest.raises(InvalidStateTransition):
        transition_job(job, JobState.RUNNING)


def test_models_expose_required_constraints_and_timestamps() -> None:
    metadata = inspect(Assessment).local_table
    constraint_names = {constraint.name for constraint in metadata.constraints}
    assert "ck_assessment_budget" in constraint_names
    assert {"created_at", "updated_at"} <= set(metadata.columns.keys())
    assert {"previous_hash", "event_hash"} <= set(inspect(AuditEvent).local_table.columns.keys())


def test_settings_reject_ceiling_increases_and_non_dev_lab_mode() -> None:
    common = {
        "database_url": "postgresql+asyncpg://u:p@localhost/rift",
        "master_key_b64": base64.urlsafe_b64encode(b"k" * 32).decode(),
        "session_secret": "s" * 32,
        "operator_password_hash": "$argon2id$placeholder",
    }
    with pytest.raises(ValueError):
        Settings(**common, max_requests_per_assessment=101)
    with pytest.raises(ValueError):
        Settings(**common, environment="pilot", local_lab_mode=True)


def test_authorization_window_is_half_open() -> None:
    from rift.domain.models import AuthorizationRecord, Target
    from rift.safety.authorization import (
        AuthorizationDenied,
        require_active_authorization,
    )

    app_id = uuid4()
    now = datetime.now(UTC)
    target = Target(
        application_id=app_id,
        scheme="https",
        hostname="example.test",
        port=443,
        base_path_prefix="/api/",
        validated_ips='["203.0.113.10"]',
        verification_state=TargetVerificationState.VERIFIED,
        enabled_state=TargetEnabledState.ENABLED,
    )
    record = AuthorizationRecord(
        application_id=app_id,
        approver_identity="owner@example.test",
        authorization_statement="Authorized staging validation",
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(minutes=1),
        approved_scope=(
            '{"targets":[{"base_path":"/api/","hostname":"example.test",'
            '"port":443,"scheme":"https"}]}'
        ),
        prohibited_actions="[]",
        operator_review=True,
        status=AuthorizationStatus.VALID,
    )
    require_active_authorization(record, target, now=now)
    with pytest.raises(AuthorizationDenied):
        require_active_authorization(record, target, now=record.valid_until)
