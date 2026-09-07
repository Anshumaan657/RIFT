"""Operator-only maintenance command entrypoint."""

import argparse
import asyncio
import os

import structlog

from rift.db.session import create_engine, create_session_factory
from rift.domain.encryption import EncryptionService
from rift.logging import configure_logging
from rift.maintenance.service import (
    apply_retention,
    database_size_bytes,
    disk_free_bytes,
    find_invalid_audit_chains,
    rotate_encryption_key,
    sanitized_maintenance_result,
)
from rift.settings import get_settings


async def run_once(command: str) -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    logger = structlog.get_logger("rift.maintenance")
    engine = create_engine(settings)
    factory = create_session_factory(engine)
    try:
        async with factory() as session:
            if command == "retention":
                result = await apply_retention(session, settings)
                logger.info("retention_complete", result=sanitized_maintenance_result(result))
            elif command == "monitor":
                invalid = await find_invalid_audit_chains(session)
                database_bytes = await database_size_bytes(session)
                free_bytes = disk_free_bytes()
                logger_method = logger.warning if invalid else logger.info
                logger_method(
                    "operational_monitor",
                    audit_chain_valid=not invalid,
                    invalid_assessment_count=len(invalid),
                    database_bytes=database_bytes,
                    database_capacity_warning=(
                        database_bytes >= settings.database_capacity_warning_bytes
                    ),
                    disk_free_bytes=free_bytes,
                    disk_capacity_warning=free_bytes <= settings.disk_free_warning_bytes,
                )
                if invalid:
                    raise RuntimeError("audit integrity validation failed")
            elif command == "rotate-key":
                previous = os.environ.get("RIFT_PREVIOUS_MASTER_KEY_B64")
                if not previous:
                    raise RuntimeError("RIFT_PREVIOUS_MASTER_KEY_B64 is required")
                identities, evidence = await rotate_encryption_key(
                    session,
                    EncryptionService(previous),
                    EncryptionService(settings.master_key_b64.get_secret_value()),
                )
                logger.info(
                    "encryption_key_rotation_complete",
                    identities_rotated=identities,
                    evidence_rotated=evidence,
                )
    finally:
        await engine.dispose()


async def daemon(interval_seconds: int) -> None:
    while True:
        await run_once("retention")
        await run_once("monitor")
        await asyncio.sleep(interval_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description="RIFT maintenance controls")
    parser.add_argument("command", choices=("retention", "monitor", "rotate-key", "daemon"))
    parser.add_argument("--interval-seconds", type=int, default=3600)
    args = parser.parse_args()
    if args.command == "daemon":
        if args.interval_seconds < 300:
            parser.error("daemon interval must be at least 300 seconds")
        asyncio.run(daemon(args.interval_seconds))
    else:
        asyncio.run(run_once(args.command))


if __name__ == "__main__":
    main()
