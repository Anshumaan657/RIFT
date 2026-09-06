"""Persistence operations that preserve ownership and immutable snapshots."""

import json
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from rift.domain.models import Assessment, Target


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
        target = await self.session.scalar(
            select(Target).where(
                Target.id == target_id,
                Target.application_id == application_id,
            )
        )
        if target is None:
            raise OwnershipError("target does not belong to application")
        canonical_checks = json.dumps(sorted(set(selected_checks)), separators=(",", ":"))
        canonical_snapshot = json.dumps(configuration, sort_keys=True, separators=(",", ":"))
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
        return assessment

    async def get(self, assessment_id: UUID) -> Assessment | None:
        return await self.session.get(Assessment, assessment_id)
