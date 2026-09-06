"""Create the Phase 4 persistence model.

Revision ID: 20260906_0002
Revises: 20260906_0001
"""

import sqlalchemy as sa

from alembic import op

revision: str = "20260906_0002"
down_revision: str | None = "20260906_0001"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "status", sa.Enum("active", "archived", name="applicationstatus"), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "applications",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column(
            "environment_type",
            sa.Enum("staging", "production", name="environmenttype"),
            nullable=False,
        ),
        sa.Column(
            "lifecycle_status",
            sa.Enum("active", "archived", name="applicationstatus"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "authorization_records",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("application_id", sa.UUID(), nullable=False),
        sa.Column("approver_identity", sa.String(length=255), nullable=False),
        sa.Column("authorization_statement", sa.Text(), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_scope", sa.Text(), nullable=False),
        sa.Column("prohibited_actions", sa.Text(), nullable=False),
        sa.Column("operator_review", sa.Boolean(), nullable=False),
        sa.Column(
            "status",
            sa.Enum("valid", "expired", "revoked", name="authorizationstatus"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("valid_until > valid_from", name="ck_authorization_valid_window"),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_authorization_records_application_valid",
        "authorization_records",
        ["application_id", "valid_from", "valid_until"],
        unique=False,
    )
    op.create_table(
        "resource_expectations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("application_id", sa.UUID(), nullable=False),
        sa.Column("endpoint_template", sa.String(length=500), nullable=False),
        sa.Column("synthetic_resource_id", sa.String(length=255), nullable=False),
        sa.Column("owner_identity", sa.String(length=100), nullable=True),
        sa.Column("is_public", sa.Boolean(), nullable=False),
        sa.Column("expected_access", sa.String(length=50), nullable=False),
        sa.Column("content_marker", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(is_public AND owner_identity IS NULL) OR "
            "(NOT is_public AND owner_identity IS NOT NULL)",
            name="ck_resource_owner_or_public",
        ),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "application_id",
            "endpoint_template",
            "synthetic_resource_id",
            name="uq_resource_expectation",
        ),
    )
    op.create_table(
        "targets",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("application_id", sa.UUID(), nullable=False),
        sa.Column("scheme", sa.String(length=10), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("base_path_prefix", sa.String(length=500), nullable=False),
        sa.Column(
            "verification_state",
            sa.Enum("unverified", "verified", "failed", name="targetverificationstate"),
            nullable=False,
        ),
        sa.Column(
            "enabled_state",
            sa.Enum("enabled", "disabled", name="targetenabledstate"),
            nullable=False,
        ),
        sa.Column("verification_token", sa.String(length=255), nullable=True),
        sa.Column("verification_token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("validated_ips", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("base_path_prefix LIKE '/%'", name="ck_target_base_path"),
        sa.CheckConstraint("scheme IN ('http', 'https')", name="ck_target_scheme"),
        sa.CheckConstraint("port BETWEEN 1 AND 65535", name="ck_target_port"),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "application_id",
            "scheme",
            "hostname",
            "port",
            "base_path_prefix",
            name="uq_target_scope",
        ),
    )
    op.create_index(
        "ix_targets_application_enabled",
        "targets",
        ["application_id", "enabled_state"],
        unique=False,
    )
    op.create_table(
        "test_identities",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("application_id", sa.UUID(), nullable=False),
        sa.Column("label", sa.String(length=100), nullable=False),
        sa.Column("encrypted_bearer_token", sa.Text(), nullable=False),
        sa.Column("token_expiry", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("application_id", "label", name="uq_test_identity_label"),
    )
    op.create_table(
        "assessments",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("application_id", sa.UUID(), nullable=False),
        sa.Column("target_id", sa.UUID(), nullable=False),
        sa.Column("selected_checks", sa.Text(), nullable=False),
        sa.Column("configuration_snapshot", sa.Text(), nullable=False),
        sa.Column(
            "state",
            sa.Enum(
                "draft",
                "queued",
                "running",
                "cancelling",
                "completed",
                "completed_with_errors",
                "failed",
                "cancelled",
                name="assessmentstate",
            ),
            nullable=False,
        ),
        sa.Column("request_budget", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("terminal_reason", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("request_budget BETWEEN 1 AND 100", name="ck_assessment_budget"),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key"),
    )
    op.create_index(
        "ix_assessments_application_state", "assessments", ["application_id", "state"], unique=False
    )
    op.create_index(
        "ix_assessments_idempotency_key", "assessments", ["idempotency_key"], unique=False
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("assessment_id", sa.UUID(), nullable=False),
        sa.Column(
            "event_type",
            sa.Enum(
                "assessment_created",
                "assessment_queued",
                "assessment_started",
                "assessment_cancelled",
                "assessment_completed",
                "assessment_failed",
                "check_started",
                "check_completed",
                "check_failed",
                "request_sent",
                "request_response",
                "scope_violation",
                "cancellation_checked",
                "target_verified",
                "authorization_checked",
                name="auditeventtype",
            ),
            nullable=False,
        ),
        sa.Column(
            "timestamp", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("sanitized_metadata", sa.Text(), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_audit_events_assessment_timestamp",
        "audit_events",
        ["assessment_id", "timestamp"],
        unique=False,
    )
    op.create_table(
        "evidence",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("assessment_id", sa.UUID(), nullable=False),
        sa.Column("check_identifier", sa.String(length=100), nullable=False),
        sa.Column("check_version", sa.String(length=20), nullable=False),
        sa.Column("encrypted_raw_blob_ref", sa.Text(), nullable=False),
        sa.Column("sanitized_request", sa.Text(), nullable=False),
        sa.Column("sanitized_response", sa.Text(), nullable=False),
        sa.Column("body_digest", sa.String(length=64), nullable=False),
        sa.Column(
            "capture_time",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("redaction_version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_evidence_assessment_check",
        "evidence",
        ["assessment_id", "check_identifier", "check_version"],
        unique=False,
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("assessment_id", sa.UUID(), nullable=False),
        sa.Column("check_identifier", sa.String(length=100), nullable=False),
        sa.Column("check_version", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column(
            "validation_state",
            sa.Enum("suspected", "reproduced", "needs_review", name="findingvalidationstate"),
            nullable=False,
        ),
        sa.Column(
            "severity",
            sa.Enum("informational", "low", "medium", "high", "critical", name="severity"),
            nullable=False,
        ),
        sa.Column("severity_rationale", sa.Text(), nullable=False),
        sa.Column("expected_behavior", sa.Text(), nullable=False),
        sa.Column("observed_behavior", sa.Text(), nullable=False),
        sa.Column("impact", sa.Text(), nullable=False),
        sa.Column("reproduction_guidance", sa.Text(), nullable=False),
        sa.Column("remediation_guidance", sa.Text(), nullable=False),
        sa.Column("evidence_refs", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_findings_assessment_validation",
        "findings",
        ["assessment_id", "validation_state"],
        unique=False,
    )
    op.create_table(
        "jobs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("assessment_id", sa.UUID(), nullable=False),
        sa.Column("check_identifier", sa.String(length=100), nullable=False),
        sa.Column("check_version", sa.String(length=20), nullable=False),
        sa.Column(
            "state",
            sa.Enum(
                "pending", "claimed", "running", "succeeded", "failed", "cancelled", name="jobstate"
            ),
            nullable=False,
        ),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("lease_owner", sa.String(length=100), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=100), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("attempt_count >= 0", name="ck_job_attempt_count"),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_jobs_assessment_state", "jobs", ["assessment_id", "state"], unique=False)
    op.create_index("ix_jobs_lease", "jobs", ["lease_owner", "lease_expires_at"], unique=False)
    op.create_table(
        "reports",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("assessment_id", sa.UUID(), nullable=False),
        sa.Column("format", sa.Enum("html", "pdf", "json", name="reportformat"), nullable=False),
        sa.Column(
            "generation_state",
            sa.Enum("generating", "ready", "failed", name="reportstate"),
            nullable=False,
        ),
        sa.Column("finding_snapshot", sa.Text(), nullable=False),
        sa.Column("file_digest", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_reports_assessment_format", "reports", ["assessment_id", "format"], unique=False
    )
    op.execute(
        """
        CREATE FUNCTION rift_prevent_assessment_snapshot_update()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.application_id IS DISTINCT FROM OLD.application_id
             OR NEW.target_id IS DISTINCT FROM OLD.target_id
             OR NEW.selected_checks IS DISTINCT FROM OLD.selected_checks
             OR NEW.configuration_snapshot IS DISTINCT FROM OLD.configuration_snapshot
             OR NEW.request_budget IS DISTINCT FROM OLD.request_budget THEN
            RAISE EXCEPTION 'assessment snapshot fields are immutable';
          END IF;
          RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER assessments_immutable_snapshot
        BEFORE UPDATE ON assessments
        FOR EACH ROW EXECUTE FUNCTION rift_prevent_assessment_snapshot_update()
        """
    )
    op.execute(
        """
        CREATE FUNCTION rift_prevent_audit_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'audit events are append-only';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_append_only
        BEFORE UPDATE OR DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION rift_prevent_audit_mutation()
        """
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS rift_prevent_audit_mutation()")
    op.execute("DROP TRIGGER IF EXISTS assessments_immutable_snapshot ON assessments")
    op.execute("DROP FUNCTION IF EXISTS rift_prevent_assessment_snapshot_update()")
    op.drop_index("ix_reports_assessment_format", table_name="reports")
    op.drop_table("reports")
    op.drop_index("ix_jobs_lease", table_name="jobs")
    op.drop_index("ix_jobs_assessment_state", table_name="jobs")
    op.drop_table("jobs")
    op.drop_index("ix_findings_assessment_validation", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_evidence_assessment_check", table_name="evidence")
    op.drop_table("evidence")
    op.drop_index("ix_audit_events_assessment_timestamp", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index("ix_assessments_idempotency_key", table_name="assessments")
    op.drop_index("ix_assessments_application_state", table_name="assessments")
    op.drop_table("assessments")
    op.drop_table("test_identities")
    op.drop_index("ix_targets_application_enabled", table_name="targets")
    op.drop_table("targets")
    op.drop_table("resource_expectations")
    op.drop_index("ix_authorization_records_application_valid", table_name="authorization_records")
    op.drop_table("authorization_records")
    op.drop_table("applications")
    op.drop_table("organizations")
    for enum_name in (
        "reportstate",
        "reportformat",
        "jobstate",
        "severity",
        "findingvalidationstate",
        "auditeventtype",
        "assessmentstate",
        "targetenabledstate",
        "targetverificationstate",
        "authorizationstatus",
        "environmenttype",
        "applicationstatus",
    ):
        op.execute(sa.text(f'DROP TYPE IF EXISTS "{enum_name}"'))
