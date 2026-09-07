"""Add immutable Phase 6 report artifacts.

Revision ID: 20260907_0004
Revises: 20260907_0003
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260907_0004"
down_revision: str | None = "20260907_0003"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    report_variant = sa.Enum("founder_summary", "technical_detail", name="reportvariant")
    review_status = sa.Enum("draft", "reviewed", name="reviewstatus")
    op.create_table(
        "report_artifacts",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("assessment_id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "format",
            postgresql.ENUM("html", "pdf", "json", name="reportformat", create_type=False),
            nullable=False,
        ),
        sa.Column("variant", report_variant, nullable=False),
        sa.Column("review_status", review_status, nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("file_digest", sa.String(64), nullable=False),
        sa.Column("snapshot_digest", sa.String(64), nullable=False),
        sa.Column("snapshot", sa.Text(), nullable=False),
        sa.Column("source_artifact_id", sa.UUID(), nullable=True),
        sa.Column("idempotency_key", sa.String(255), nullable=True),
        sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["source_artifact_id"], ["report_artifacts.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key"),
        sa.UniqueConstraint("source_artifact_id", name="uq_report_artifact_review_source"),
    )
    op.create_index(
        "ix_report_artifacts_assessment",
        "report_artifacts",
        ["assessment_id", "format", "variant"],
    )
    op.execute(
        """
        CREATE FUNCTION rift_prevent_report_artifact_content_update()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.assessment_id IS DISTINCT FROM OLD.assessment_id
             OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
             OR NEW.format IS DISTINCT FROM OLD.format
             OR NEW.variant IS DISTINCT FROM OLD.variant
             OR NEW.content IS DISTINCT FROM OLD.content
             OR NEW.file_digest IS DISTINCT FROM OLD.file_digest
             OR NEW.snapshot_digest IS DISTINCT FROM OLD.snapshot_digest
             OR NEW.snapshot IS DISTINCT FROM OLD.snapshot
             OR NEW.source_artifact_id IS DISTINCT FROM OLD.source_artifact_id THEN
            RAISE EXCEPTION 'generated report artifacts are immutable';
          END IF;
          RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER report_artifact_content_immutable
        BEFORE UPDATE ON report_artifacts
        FOR EACH ROW EXECUTE FUNCTION rift_prevent_report_artifact_content_update()
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS report_artifact_content_immutable ON report_artifacts"
    )
    op.execute("DROP FUNCTION IF EXISTS rift_prevent_report_artifact_content_update()")
    op.drop_index("ix_report_artifacts_assessment", table_name="report_artifacts")
    op.drop_table("report_artifacts")
    sa.Enum(name="reviewstatus").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="reportvariant").drop(op.get_bind(), checkfirst=True)
