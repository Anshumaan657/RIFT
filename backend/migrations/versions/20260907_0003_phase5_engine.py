"""Add durable Phase 5 check execution state.

Revision ID: 20260907_0003
Revises: 20260906_0002
"""

import sqlalchemy as sa
from alembic import op

revision: str = "20260907_0003"
down_revision: str | None = "20260906_0002"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    check_outcome = sa.Enum(
        "passed", "finding", "inconclusive", "error", "skipped", "cancelled",
        name="checkoutcome",
    )
    op.add_column(
        "jobs",
        sa.Column(
            "available_at", sa.DateTime(timezone=True), server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.add_column("jobs", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.drop_constraint("ck_job_attempt_count", "jobs", type_="check")
    op.create_check_constraint("ck_job_attempt_count", "jobs", "attempt_count BETWEEN 0 AND 2")
    op.create_unique_constraint(
        "uq_job_assessment_check",
        "jobs",
        ["assessment_id", "check_identifier", "check_version"],
    )
    op.create_table(
        "check_executions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("assessment_id", sa.UUID(), nullable=False),
        sa.Column("check_identifier", sa.String(100), nullable=False),
        sa.Column("check_version", sa.String(20), nullable=False),
        sa.Column("outcome", check_outcome, nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("evidence_refs", sa.Text(), nullable=False),
        sa.Column("observations", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "assessment_id", "check_identifier", "check_version",
            name="uq_check_execution_assessment_check",
        ),
    )
    op.create_index(
        "ix_check_executions_assessment_outcome",
        "check_executions",
        ["assessment_id", "outcome"],
    )
    op.execute(
        """
        CREATE FUNCTION rift_prevent_check_execution_update()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'check executions are immutable';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER check_executions_immutable
        BEFORE UPDATE ON check_executions
        FOR EACH ROW EXECUTE FUNCTION rift_prevent_check_execution_update()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS check_executions_immutable ON check_executions")
    op.execute("DROP FUNCTION IF EXISTS rift_prevent_check_execution_update()")
    op.drop_index("ix_check_executions_assessment_outcome", table_name="check_executions")
    op.drop_table("check_executions")
    op.drop_constraint("uq_job_assessment_check", "jobs", type_="unique")
    op.drop_constraint("ck_job_attempt_count", "jobs", type_="check")
    op.create_check_constraint("ck_job_attempt_count", "jobs", "attempt_count >= 0")
    op.drop_column("jobs", "heartbeat_at")
    op.drop_column("jobs", "available_at")
    sa.Enum(name="checkoutcome").drop(op.get_bind(), checkfirst=True)
