"""Validated runtime configuration."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """RIFT settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="RIFT_",
        extra="ignore",
        case_sensitive=False,
    )

    environment: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    database_url: SecretStr
    master_key_b64: SecretStr = Field(min_length=43)
    frontend_origin: str = "http://localhost:5173"


@lru_cache
def get_settings() -> Settings:
    """Return one validated settings object per process."""

    return Settings()
