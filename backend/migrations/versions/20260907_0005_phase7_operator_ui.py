"""Add operator finding review metadata.

Revision ID: 20260907_0005
Revises: 20260907_0004
"""

import sqlalchemy as sa
from alembic import op

revision: str = "20260907_0005"
down_revision: str | None = "20260907_0004"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("operator_reviewed_by", sa.String(255), nullable=True))
    op.add_column(
        "findings", sa.Column("operator_reviewed_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("findings", "operator_reviewed_at")
    op.drop_column("findings", "operator_reviewed_by")
