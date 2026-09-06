"""Validated runtime configuration with hard V1 safety ceilings."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="RIFT_", extra="ignore", case_sensitive=False
    )

    environment: Literal["development", "test", "pilot", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    database_url: SecretStr
    master_key_b64: SecretStr = Field(min_length=43)
    frontend_origin: str = "http://localhost:5173"
    session_secret: SecretStr = Field(min_length=32)
    operator_username: str = "operator"
    operator_password_hash: SecretStr
    session_ttl_seconds: int = Field(default=3600, ge=300, le=43_200)
    login_attempts: int = Field(default=5, ge=1, le=10)
    login_window_seconds: int = Field(default=900, ge=60, le=3600)
    local_lab_mode: bool = False

    max_requests_per_assessment: int = Field(default=100, ge=1, le=100)
    max_concurrent_requests: int = Field(default=2, ge=1, le=2)
    max_requests_per_second_per_host: float = Field(default=2.0, gt=0, le=2.0)
    connect_timeout_seconds: float = Field(default=10.0, gt=0, le=10.0)
    request_timeout_seconds: float = Field(default=20.0, gt=0, le=20.0)
    max_response_body_bytes: int = Field(default=1_048_576, ge=1024, le=1_048_576)
    max_assessment_runtime_seconds: int = Field(default=900, ge=1, le=900)

    @model_validator(mode="after")
    def prevent_lab_mode_outside_development(self) -> "Settings":
        if self.local_lab_mode and self.environment != "development":
            raise ValueError("local lab mode is permitted only in development")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
