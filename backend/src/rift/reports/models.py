"""Immutable generated report artifacts."""

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    event,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from rift.db.base import Base
from rift.domain.models import ReportFormat, enum_values


class ReportVariant(str, enum.Enum):
    FOUNDER_SUMMARY = "founder_summary"
    TECHNICAL_DETAIL = "technical_detail"


class ReviewStatus(str, enum.Enum):
    DRAFT = "draft"
    REVIEWED = "reviewed"


class ReportArtifact(Base):
    __tablename__ = "report_artifacts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    format: Mapped[ReportFormat] = mapped_column(
        Enum(ReportFormat, values_callable=enum_values), nullable=False
    )
    variant: Mapped[ReportVariant] = mapped_column(
        Enum(ReportVariant, values_callable=enum_values), nullable=False
    )
    review_status: Mapped[ReviewStatus] = mapped_column(
        Enum(ReviewStatus, values_callable=enum_values),
        nullable=False,
        default=ReviewStatus.DRAFT,
    )
    content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    file_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot: Mapped[str] = mapped_column(Text, nullable=False)
    source_artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("report_artifacts.id", ondelete="RESTRICT"), nullable=True
    )
    idempotency_key: Mapped[str | None] = mapped_column(String(255), nullable=True, unique=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        Index("ix_report_artifacts_assessment", "assessment_id", "format", "variant"),
        UniqueConstraint("source_artifact_id", name="uq_report_artifact_review_source"),
    )


@event.listens_for(ReportArtifact, "before_update")
def protect_report_content(_mapper: object, _connection: object, target: ReportArtifact) -> None:
    from sqlalchemy import inspect

    state = inspect(target)
    immutable = ("assessment_id", "organization_id", "format", "variant", "content",
                 "file_digest", "snapshot_digest", "snapshot", "source_artifact_id",
                 "idempotency_key")
    if any(state.attrs[name].history.has_changes() for name in immutable):
        raise ValueError("generated report content and snapshot are immutable")
