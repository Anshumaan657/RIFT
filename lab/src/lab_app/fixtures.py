"""Immutable synthetic fixtures."""

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

FIXTURE_PATH = Path(__file__).parents[2] / "fixtures" / "seed.json"


@lru_cache
def load_fixtures() -> dict[str, Any]:
    """Load a defensive copy of committed deterministic fixtures."""

    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
