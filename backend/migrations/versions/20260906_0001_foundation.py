"""Record the Phase 2 migration baseline."""

revision: str = "20260906_0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Phase 4 introduces persistent domain tables."""


def downgrade() -> None:
    """The baseline has no database objects to remove."""
