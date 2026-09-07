"""Durable PostgreSQL worker process."""

import asyncio
import signal
import socket
from uuid import UUID, uuid4

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from rift.db.session import create_engine, create_session_factory, database_is_ready
from rift.domain.models import Assessment, AssessmentState, JobState
from rift.logging import configure_logging
from rift.settings import get_settings
from rift.worker.health import touch_heartbeat
from rift.worker.repository import MAX_ATTEMPTS, JobRepository
from rift.worker.service import (
    execute_job,
    finalize_assessment,
    persist_terminal_failure,
    retryable_transport_error,
)


async def run() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    logger = structlog.get_logger("rift.worker")
    engine = create_engine(settings)
    factory = create_session_factory(engine)
    worker_id = f"{socket.gethostname()}:{uuid4()}"
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stopping.set)
    logger.info(
        "worker_started", database_ready=await database_is_ready(engine), worker_id=worker_id
    )
    while not stopping.is_set():
        touch_heartbeat(settings.worker_heartbeat_path)
        async with factory() as session:
            repository = JobRepository(session)
            job = await repository.claim(worker_id)
            if job is None:
                try:
                    await asyncio.wait_for(stopping.wait(), timeout=1)
                except TimeoutError:
                    pass
                continue
            await repository.start(job)
            lease_stop = asyncio.Event()
            cancelled = asyncio.Event()
            lease_task = asyncio.create_task(
                maintain_lease(
                    factory,
                    job.id,
                    job.assessment_id,
                    worker_id,
                    lease_stop,
                    cancelled,
                )
            )
            try:
                await execute_job(session, job, cancellation_check=cancelled.is_set)
            except Exception as exc:
                retryable = retryable_transport_error(exc)
                if not retryable or job.attempt_count >= MAX_ATTEMPTS:
                    await persist_terminal_failure(session, job, type(exc).__name__.upper())
                await repository.fail(job, type(exc).__name__.upper(), retryable=retryable)
                logger.warning("job_failed", job_id=str(job.id), retryable=retryable)
            else:
                if job.state != JobState.CANCELLED:
                    await repository.succeed(job)
            finally:
                lease_stop.set()
                await lease_task
            await finalize_assessment(session, job.assessment_id)
    await engine.dispose()
    logger.info("worker_stopped")


async def maintain_lease(
    factory: async_sessionmaker[AsyncSession],
    job_id: UUID,
    assessment_id: UUID,
    worker_id: str,
    stop: asyncio.Event,
    cancelled: asyncio.Event,
) -> None:
    """Renew a running lease and relay cancellation between requests."""
    while not stop.is_set():
        async with factory() as heartbeat_session:
            touch_heartbeat(get_settings().worker_heartbeat_path)
            assessment = await heartbeat_session.get(Assessment, assessment_id)
            if assessment is None or assessment.state in {
                AssessmentState.CANCELLING,
                AssessmentState.CANCELLED,
            }:
                cancelled.set()
            await JobRepository(heartbeat_session).heartbeat(job_id, worker_id)
        try:
            await asyncio.wait_for(stop.wait(), timeout=10)
        except TimeoutError:
            pass


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
