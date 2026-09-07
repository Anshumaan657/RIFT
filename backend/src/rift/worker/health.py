"""File heartbeat used by the container health check."""

import argparse
import os
import time
from pathlib import Path

from rift.settings import get_settings


def touch_heartbeat(path: str | Path, *, timestamp: float | None = None) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".tmp")
    temporary.write_text(str(timestamp if timestamp is not None else time.time()))
    os.replace(temporary, target)


def heartbeat_is_fresh(
    path: str | Path, *, max_age_seconds: int, timestamp: float | None = None
) -> bool:
    try:
        recorded = float(Path(path).read_text())
    except (OSError, ValueError):
        return False
    now = timestamp if timestamp is not None else time.time()
    return 0 <= now - recorded <= max_age_seconds


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "touch"))
    args = parser.parse_args()
    settings = get_settings()
    if args.command == "touch":
        touch_heartbeat(settings.worker_heartbeat_path)
        return
    if not heartbeat_is_fresh(
        settings.worker_heartbeat_path,
        max_age_seconds=settings.worker_heartbeat_max_age_seconds,
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
