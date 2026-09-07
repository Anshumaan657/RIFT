"""PostgreSQL-backed job queue with leases and restart recovery."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from rift.domain.models import Job, JobState

MAX_ATTEMPTS = 2


class JobRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def claim(self, worker_id: str, lease_seconds: int = 30) -> Job | None:
        now = datetime.now(UTC)
        job = await self.session.scalar(
            select(Job)
            .where(
                Job.attempt_count < MAX_ATTEMPTS,
                Job.available_at <= now,
                or_(
                    Job.state == JobState.PENDING,
                    (Job.state.in_([JobState.CLAIMED, JobState.RUNNING]))
                    & (Job.lease_expires_at < now),
                ),
            )
            .order_by(Job.created_at, Job.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if job is None:
            return None
        job.state = JobState.CLAIMED
        job.attempt_count += 1
        job.lease_owner = worker_id
        job.heartbeat_at = now
        job.lease_expires_at = now + timedelta(seconds=lease_seconds)
        await self.session.commit()
        return job

    async def start(self, job: Job) -> None:
        job.state = JobState.RUNNING
        await self.session.commit()

    async def heartbeat(self, job_id: UUID, worker_id: str, lease_seconds: int = 30) -> bool:
        now = datetime.now(UTC)
        result = await self.session.execute(
            update(Job)
            .where(
                Job.id == job_id,
                Job.lease_owner == worker_id,
                Job.state.in_([JobState.CLAIMED, JobState.RUNNING]),
            )
            .values(heartbeat_at=now, lease_expires_at=now + timedelta(seconds=lease_seconds))
        )
        await self.session.commit()
        return bool(result.rowcount)

    async def succeed(self, job: Job) -> None:
        job.state = JobState.SUCCEEDED
        job.lease_owner = None
        job.lease_expires_at = None
        await self.session.commit()

    async def fail(self, job: Job, code: str, *, retryable: bool) -> None:
        job.error_code = code
        job.lease_owner = None
        job.lease_expires_at = None
        if retryable and job.attempt_count < MAX_ATTEMPTS:
            job.state = JobState.PENDING
            job.available_at = datetime.now(UTC) + timedelta(seconds=2**job.attempt_count)
        else:
            job.state = JobState.FAILED
        await self.session.commit()

    async def cancel_pending(self, assessment_id: UUID) -> None:
        await self.session.execute(
            update(Job)
            .where(
                Job.assessment_id == assessment_id,
                Job.state.in_([JobState.PENDING, JobState.CLAIMED]),
            )
            .values(state=JobState.CANCELLED, lease_owner=None, lease_expires_at=None)
        )
        await self.session.commit()
