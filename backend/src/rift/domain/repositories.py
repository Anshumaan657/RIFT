"""Persistence operations that preserve ownership and immutable snapshots."""

import json
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from rift.domain.models import Assessment, AssessmentState, Job, Target


class OwnershipError(ValueError):
    pass


class AssessmentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        *,
        application_id: UUID,
        target_id: UUID,
        selected_checks: Sequence[str],
        configuration: Mapping[str, Any],
        request_budget: int,
        idempotency_key: str | None = None,
    ) -> Assessment:
        canonical_checks = json.dumps(sorted(set(selected_checks)), separators=(",", ":"))
        canonical_snapshot = json.dumps(configuration, sort_keys=True, separators=(",", ":"))
        if idempotency_key:
            existing = await self.session.scalar(
                select(Assessment).where(Assessment.idempotency_key == idempotency_key)
            )
            if existing is not None:
                if (
                    existing.application_id != application_id
                    or existing.target_id != target_id
                    or existing.selected_checks != canonical_checks
                    or existing.configuration_snapshot != canonical_snapshot
                    or existing.request_budget != request_budget
                ):
                    raise OwnershipError(
                        "idempotency key was already used for a different assessment"
                    )
                return existing
        target = await self.session.scalar(
            select(Target).where(
                Target.id == target_id,
                Target.application_id == application_id,
            )
        )
        if target is None:
            raise OwnershipError("target does not belong to application")
        assessment = Assessment(
            application_id=application_id,
            target_id=target_id,
            selected_checks=canonical_checks,
            configuration_snapshot=canonical_snapshot,
            request_budget=request_budget,
            idempotency_key=idempotency_key,
        )
        self.session.add(assessment)
        await self.session.flush()
        for check_identifier in sorted(set(selected_checks)):
            self.session.add(
                Job(
                    assessment_id=assessment.id,
                    check_identifier=check_identifier,
                    check_version="1.0",
                )
            )
        assessment.state = AssessmentState.QUEUED
        return assessment

    async def get(self, assessment_id: UUID) -> Assessment | None:
        return await self.session.get(Assessment, assessment_id)
