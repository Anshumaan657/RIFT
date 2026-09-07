#!/usr/bin/env python3
"""Create, verify, and restore encrypted PostgreSQL backups without printing secrets."""

import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from rift.maintenance.backup import decrypt_backup, encrypt_backup


def postgres_environment(name: str) -> tuple[dict[str, str], str]:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} is required")
    parsed = urlsplit(value.replace("postgresql+asyncpg://", "postgresql://", 1))
    database = parsed.path.removeprefix("/")
    if not all((parsed.hostname, parsed.username, parsed.password, database)):
        raise SystemExit(f"{name} must include host, user, password, and database")
    ssl_mode = parse_qs(parsed.query).get("ssl", ["verify-full"])[0]
    environment = {
        "PGDATABASE": database,
        "PGHOST": parsed.hostname or "",
        "PGPASSWORD": unquote(parsed.password or ""),
        "PGPORT": str(parsed.port or 5432),
        "PGSSLMODE": ssl_mode,
        "PGUSER": unquote(parsed.username or ""),
    }
    if root_certificate := os.environ.get("PGSSLROOTCERT"):
        environment["PGSSLROOTCERT"] = root_certificate
    return environment, database


def backup_key() -> str:
    value = os.environ.get("RIFT_BACKUP_KEY_B64")
    if not value:
        raise SystemExit("RIFT_BACKUP_KEY_B64 is required")
    return value


def executable(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise SystemExit(f"required executable is unavailable: {name}")
    return path


def create(output: Path) -> None:
    environment, _database = postgres_environment("RIFT_DATABASE_URL")
    archive = subprocess.run(  # noqa: S603 - fixed executable and argument vector
        [
            executable("pg_dump"),
            "--format=custom",
            "--no-owner",
            "--no-acl",
        ],
        check=True,
        capture_output=True,
        env=environment,
    ).stdout
    encrypted = encrypt_backup(archive, backup_key())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(encrypted)
    output.chmod(0o600)


def verify(source: Path) -> None:
    archive = decrypt_backup(source.read_bytes(), backup_key())
    with tempfile.NamedTemporaryFile() as temporary:
        temporary.write(archive)
        temporary.flush()
        subprocess.run(  # noqa: S603 - fixed executable and argument vector
            [executable("pg_restore"), "--list", temporary.name],
            check=True,
            stdout=subprocess.DEVNULL,
        )


def restore(source: Path, confirmation: str) -> None:
    environment, actual_name = postgres_environment("RIFT_RESTORE_DATABASE_URL")
    if not actual_name or confirmation != actual_name:
        raise SystemExit("--confirm-database must exactly match the restore database name")
    archive = decrypt_backup(source.read_bytes(), backup_key())
    with tempfile.NamedTemporaryFile() as temporary:
        temporary.write(archive)
        temporary.flush()
        subprocess.run(  # noqa: S603 - fixed executable and argument vector
            [
                executable("pg_restore"),
                "--clean",
                "--if-exists",
                "--no-owner",
                "--no-acl",
                "--dbname",
                actual_name,
                temporary.name,
            ],
            check=True,
            env=environment,
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("create", "verify"):
        action = subparsers.add_parser(command)
        action.add_argument("path", type=Path)
    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("path", type=Path)
    restore_parser.add_argument("--confirm-database", required=True)
    args = parser.parse_args()
    if args.command == "create":
        create(args.path)
    elif args.command == "verify":
        verify(args.path)
    else:
        restore(args.path, args.confirm_database)


if __name__ == "__main__":
    main()
