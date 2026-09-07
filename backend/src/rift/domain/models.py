import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    event,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from rift.db.base import Base


def enum_values(enum_class: type[enum.Enum]) -> list[str]:
    return [str(member.value) for member in enum_class]


class EnvironmentType(str, enum.Enum):
    STAGING = "staging"
    PRODUCTION = "production"


class ApplicationStatus(str, enum.Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"


class AuthorizationStatus(str, enum.Enum):
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"


class TargetVerificationState(str, enum.Enum):
    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    FAILED = "failed"


class TargetEnabledState(str, enum.Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"


class AssessmentState(str, enum.Enum):
    DRAFT = "draft"
    QUEUED = "queued"
    RUNNING = "running"
    CANCELLING = "cancelling"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingValidationState(str, enum.Enum):
    SUSPECTED = "suspected"
    REPRODUCED = "reproduced"
    NEEDS_REVIEW = "needs_review"


class Severity(str, enum.Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class JobState(str, enum.Enum):
    PENDING = "pending"
    CLAIMED = "claimed"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CheckOutcome(str, enum.Enum):
    PASSED = "passed"
    FINDING = "finding"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class AuditEventType(str, enum.Enum):
    ASSESSMENT_CREATED = "assessment_created"
    ASSESSMENT_QUEUED = "assessment_queued"
    ASSESSMENT_STARTED = "assessment_started"
    ASSESSMENT_CANCELLED = "assessment_cancelled"
    ASSESSMENT_COMPLETED = "assessment_completed"
    ASSESSMENT_FAILED = "assessment_failed"
    CHECK_STARTED = "check_started"
    CHECK_COMPLETED = "check_completed"
    CHECK_FAILED = "check_failed"
    REQUEST_SENT = "request_sent"
    REQUEST_RESPONSE = "request_response"
    SCOPE_VIOLATION = "scope_violation"
    CANCELLATION_CHECKED = "cancellation_checked"
    TARGET_VERIFIED = "target_verified"
    AUTHORIZATION_CHECKED = "authorization_checked"


class ReportFormat(str, enum.Enum):
    HTML = "html"
    PDF = "pdf"
    JSON = "json"


class ReportState(str, enum.Enum):
    GENERATING = "generating"
    READY = "ready"
    FAILED = "failed"


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[ApplicationStatus] = mapped_column(
        Enum(ApplicationStatus, values_callable=enum_values),
        nullable=False,
        default=ApplicationStatus.ACTIVE,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    applications: Mapped[list["Application"]] = relationship(
        back_populates="organization", lazy="selectin"
    )


class Application(Base):
    __tablename__ = "applications"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    environment_type: Mapped[EnvironmentType] = mapped_column(
        Enum(EnvironmentType, values_callable=enum_values), nullable=False
    )
    lifecycle_status: Mapped[ApplicationStatus] = mapped_column(
        Enum(ApplicationStatus, values_callable=enum_values),
        nullable=False,
        default=ApplicationStatus.ACTIVE,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    organization: Mapped["Organization"] = relationship(
        back_populates="applications", lazy="selectin"
    )
    authorization_records: Mapped[list["AuthorizationRecord"]] = relationship(
        back_populates="application", lazy="selectin"
    )
    targets: Mapped[list["Target"]] = relationship(back_populates="application", lazy="selectin")
    test_identities: Mapped[list["TestIdentity"]] = relationship(
        back_populates="application", lazy="selectin"
    )
    resource_expectations: Mapped[list["ResourceExpectation"]] = relationship(
        back_populates="application", lazy="selectin"
    )
    assessments: Mapped[list["Assessment"]] = relationship(
        back_populates="application", lazy="selectin"
    )


class AuthorizationRecord(Base):
    __tablename__ = "authorization_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )
    approver_identity: Mapped[str] = mapped_column(String(255), nullable=False)
    authorization_statement: Mapped[str] = mapped_column(Text, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_scope: Mapped[str] = mapped_column(Text, nullable=False)
    prohibited_actions: Mapped[str] = mapped_column(Text, nullable=False, default="")
    operator_review: Mapped[bool] = mapped_column(nullable=False, default=False)
    status: Mapped[AuthorizationStatus] = mapped_column(
        Enum(AuthorizationStatus, values_callable=enum_values),
        nullable=False,
        default=AuthorizationStatus.VALID,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    application: Mapped["Application"] = relationship(
        back_populates="authorization_records", lazy="selectin"
    )

    __table_args__ = (
        CheckConstraint("valid_until > valid_from", name="ck_authorization_valid_window"),
        Index(
            "ix_authorization_records_application_valid",
            "application_id",
            "valid_from",
            "valid_until",
        ),
    )


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )
    scheme: Mapped[str] = mapped_column(String(10), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(nullable=False)
    base_path_prefix: Mapped[str] = mapped_column(String(500), nullable=False, default="/")
    verification_state: Mapped[TargetVerificationState] = mapped_column(
        Enum(TargetVerificationState, values_callable=enum_values),
        nullable=False,
        default=TargetVerificationState.UNVERIFIED,
    )
    enabled_state: Mapped[TargetEnabledState] = mapped_column(
        Enum(TargetEnabledState, values_callable=enum_values),
        nullable=False,
        default=TargetEnabledState.ENABLED,
    )
    verification_token: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verification_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    validated_ips: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    application: Mapped["Application"] = relationship(back_populates="targets", lazy="selectin")
    assessments: Mapped[list["Assessment"]] = relationship(back_populates="target", lazy="selectin")

    __table_args__ = (
        CheckConstraint("scheme IN ('http', 'https')", name="ck_target_scheme"),
        CheckConstraint("port BETWEEN 1 AND 65535", name="ck_target_port"),
        CheckConstraint("base_path_prefix LIKE '/%'", name="ck_target_base_path"),
        UniqueConstraint(
            "application_id",
            "scheme",
            "hostname",
            "port",
            "base_path_prefix",
            name="uq_target_scope",
        ),
        Index("ix_targets_application_enabled", "application_id", "enabled_state"),
    )


class TestIdentity(Base):
    __tablename__ = "test_identities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )
    label: Mapped[str] = mapped_column(String(100), nullable=False)
    encrypted_bearer_token: Mapped[str] = mapped_column(Text, nullable=False)
    token_expiry: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    application: Mapped["Application"] = relationship(
        back_populates="test_identities", lazy="selectin"
    )

    __table_args__ = (UniqueConstraint("application_id", "label", name="uq_test_identity_label"),)


class ResourceExpectation(Base):
    __tablename__ = "resource_expectations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )
    endpoint_template: Mapped[str] = mapped_column(String(500), nullable=False)
    synthetic_resource_id: Mapped[str] = mapped_column(String(255), nullable=False)
    owner_identity: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_public: Mapped[bool] = mapped_column(nullable=False, default=False)
    expected_access: Mapped[str] = mapped_column(String(50), nullable=False)
    content_marker: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    application: Mapped["Application"] = relationship(
        back_populates="resource_expectations", lazy="selectin"
    )

    __table_args__ = (
        CheckConstraint(
            "(is_public AND owner_identity IS NULL) OR "
            "(NOT is_public AND owner_identity IS NOT NULL)",
            name="ck_resource_owner_or_public",
        ),
        UniqueConstraint(
            "application_id",
            "endpoint_template",
            "synthetic_resource_id",
            name="uq_resource_expectation",
        ),
    )


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="RESTRICT"), nullable=False
    )
    selected_checks: Mapped[str] = mapped_column(Text, nullable=False)
    configuration_snapshot: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[AssessmentState] = mapped_column(
        Enum(AssessmentState, values_callable=enum_values),
        nullable=False,
        default=AssessmentState.DRAFT,
    )
    request_budget: Mapped[int] = mapped_column(nullable=False, default=100)
    idempotency_key: Mapped[str | None] = mapped_column(String(255), nullable=True, unique=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    terminal_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    application: Mapped["Application"] = relationship(back_populates="assessments", lazy="selectin")
    target: Mapped["Target"] = relationship(back_populates="assessments", lazy="selectin")
    jobs: Mapped[list["Job"]] = relationship(back_populates="assessment", lazy="selectin")
    audit_events: Mapped[list["AuditEvent"]] = relationship(
        back_populates="assessment", lazy="selectin"
    )
    evidence: Mapped[list["Evidence"]] = relationship(back_populates="assessment", lazy="selectin")
    findings: Mapped[list["Finding"]] = relationship(back_populates="assessment", lazy="selectin")
    reports: Mapped[list["Report"]] = relationship(back_populates="assessment", lazy="selectin")
    check_executions: Mapped[list["CheckExecution"]] = relationship(
        back_populates="assessment", lazy="selectin"
    )

    __table_args__ = (
        CheckConstraint("request_budget BETWEEN 1 AND 100", name="ck_assessment_budget"),
        Index("ix_assessments_application_state", "application_id", "state"),
        Index("ix_assessments_idempotency_key", "idempotency_key"),
    )


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    check_identifier: Mapped[str] = mapped_column(String(100), nullable=False)
    check_version: Mapped[str] = mapped_column(String(20), nullable=False)
    state: Mapped[JobState] = mapped_column(
        Enum(JobState, values_callable=enum_values), nullable=False, default=JobState.PENDING
    )
    attempt_count: Mapped[int] = mapped_column(nullable=False, default=0)
    lease_owner: Mapped[str | None] = mapped_column(String(100), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    assessment: Mapped["Assessment"] = relationship(back_populates="jobs", lazy="selectin")

    __table_args__ = (
        CheckConstraint("attempt_count BETWEEN 0 AND 2", name="ck_job_attempt_count"),
        UniqueConstraint(
            "assessment_id", "check_identifier", "check_version", name="uq_job_assessment_check"
        ),
        Index("ix_jobs_assessment_state", "assessment_id", "state"),
        Index("ix_jobs_lease", "lease_owner", "lease_expires_at"),
    )


class CheckExecution(Base):
    """One immutable terminal outcome for a versioned check."""

    __tablename__ = "check_executions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    check_identifier: Mapped[str] = mapped_column(String(100), nullable=False)
    check_version: Mapped[str] = mapped_column(String(20), nullable=False)
    outcome: Mapped[CheckOutcome] = mapped_column(
        Enum(CheckOutcome, values_callable=enum_values), nullable=False
    )
    reason_code: Mapped[str] = mapped_column(String(100), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_refs: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    observations: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    assessment: Mapped["Assessment"] = relationship(
        back_populates="check_executions", lazy="selectin"
    )

    __table_args__ = (
        UniqueConstraint(
            "assessment_id",
            "check_identifier",
            "check_version",
            name="uq_check_execution_assessment_check",
        ),
        Index("ix_check_executions_assessment_outcome", "assessment_id", "outcome"),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[AuditEventType] = mapped_column(
        Enum(AuditEventType, values_callable=enum_values), nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    sanitized_metadata: Mapped[str] = mapped_column(Text, nullable=False)
    previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    assessment: Mapped["Assessment"] = relationship(back_populates="audit_events", lazy="selectin")

    __table_args__ = (Index("ix_audit_events_assessment_timestamp", "assessment_id", "timestamp"),)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    check_identifier: Mapped[str] = mapped_column(String(100), nullable=False)
    check_version: Mapped[str] = mapped_column(String(20), nullable=False)
    encrypted_raw_blob_ref: Mapped[str] = mapped_column(Text, nullable=False)
    sanitized_request: Mapped[str] = mapped_column(Text, nullable=False)
    sanitized_response: Mapped[str] = mapped_column(Text, nullable=False)
    body_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    capture_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    redaction_version: Mapped[int] = mapped_column(nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    assessment: Mapped["Assessment"] = relationship(back_populates="evidence", lazy="selectin")

    __table_args__ = (
        Index("ix_evidence_assessment_check", "assessment_id", "check_identifier", "check_version"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    check_identifier: Mapped[str] = mapped_column(String(100), nullable=False)
    check_version: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    validation_state: Mapped[FindingValidationState] = mapped_column(
        Enum(FindingValidationState, values_callable=enum_values),
        nullable=False,
        default=FindingValidationState.SUSPECTED,
    )
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, values_callable=enum_values), nullable=False
    )
    severity_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    expected_behavior: Mapped[str] = mapped_column(Text, nullable=False)
    observed_behavior: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    reproduction_guidance: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_guidance: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_refs: Mapped[str] = mapped_column(Text, nullable=False)
    operator_reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    operator_reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    assessment: Mapped["Assessment"] = relationship(back_populates="findings", lazy="selectin")

    __table_args__ = (
        Index("ix_findings_assessment_validation", "assessment_id", "validation_state"),
    )


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    format: Mapped[ReportFormat] = mapped_column(
        Enum(ReportFormat, values_callable=enum_values), nullable=False
    )
    generation_state: Mapped[ReportState] = mapped_column(
        Enum(ReportState, values_callable=enum_values),
        nullable=False,
        default=ReportState.GENERATING,
    )
    finding_snapshot: Mapped[str] = mapped_column(Text, nullable=False)
    file_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    assessment: Mapped["Assessment"] = relationship(back_populates="reports", lazy="selectin")

    __table_args__ = (Index("ix_reports_assessment_format", "assessment_id", "format"),)


_ASSESSMENT_SNAPSHOT_FIELDS = frozenset(
    {"application_id", "target_id", "selected_checks", "configuration_snapshot", "request_budget"}
)


@event.listens_for(Assessment, "before_update")
def prevent_assessment_snapshot_mutation(
    _mapper: object, _connection: object, target: Assessment
) -> None:
    """Keep the scope and execution inputs immutable after assessment creation."""
    from sqlalchemy import inspect

    state = inspect(target)
    changed = [
        name for name in _ASSESSMENT_SNAPSHOT_FIELDS if state.attrs[name].history.has_changes()
    ]
    if changed:
        raise ValueError(f"immutable assessment fields changed: {', '.join(sorted(changed))}")


@event.listens_for(AuditEvent, "before_update")
def prevent_audit_update(_mapper: object, _connection: object, _target: AuditEvent) -> None:
    raise ValueError("audit events are append-only")


@event.listens_for(CheckExecution, "before_update")
def prevent_check_execution_update(
    _mapper: object, _connection: object, _target: CheckExecution
) -> None:
    raise ValueError("check executions are immutable")
