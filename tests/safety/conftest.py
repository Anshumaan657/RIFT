import base64
from collections.abc import Callable
from typing import Any

import pytest

from rift.settings import Settings


@pytest.fixture
def settings_factory() -> Callable[..., Settings]:
    def factory(**overrides: Any) -> Settings:
        values = {
            "database_url": "postgresql+asyncpg://u:p@localhost/rift",
            "master_key_b64": base64.urlsafe_b64encode(b"k" * 32).decode(),
            "session_secret": "s" * 32,
            "operator_password_hash": "$argon2id$placeholder",
            "environment": "test",
        }
        values.update(overrides)
        return Settings(**values)

    return factory
