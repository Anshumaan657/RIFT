"""Phase 2 worker placeholder with database readiness."""

import asyncio
import signal

import structlog

from rift.db.session import create_engine, database_is_ready
from rift.logging import configure_logging
from rift.settings import get_settings


async def run() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    logger = structlog.get_logger("rift.worker")
    engine = create_engine(settings)
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stopping.set)
    logger.info("worker_started", database_ready=await database_is_ready(engine))
    await stopping.wait()
    await engine.dispose()
    logger.info("worker_stopped")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
