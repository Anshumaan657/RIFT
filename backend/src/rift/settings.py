"""Validated runtime configuration with hard V1 safety ceilings."""

import ipaddress
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qs, urlsplit

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
    allowed_target_cidrs: str = ""
    raw_evidence_retention_days: int = Field(default=30, ge=1, le=30)
    credential_retention_days: int = Field(default=30, ge=1, le=30)
    report_retention_days: int = Field(default=180, ge=1, le=180)
    database_capacity_warning_bytes: int = Field(default=5_368_709_120, ge=1_048_576)
    disk_free_warning_bytes: int = Field(default=1_073_741_824, ge=1_048_576)
    worker_heartbeat_path: str = Field(
        default_factory=lambda: str(Path(tempfile.gettempdir()) / "rift-worker-heartbeat")
    )
    worker_heartbeat_max_age_seconds: int = Field(default=30, ge=10, le=120)

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
        if self.environment in {"pilot", "production"}:
            origin = urlsplit(self.frontend_origin)
            if (
                origin.scheme != "https"
                or not origin.hostname
                or origin.username is not None
                or origin.password is not None
                or origin.path not in {"", "/"}
                or origin.query
                or origin.fragment
            ):
                raise ValueError("pilot and production require an HTTPS frontend origin")
            database_url = self.database_url.get_secret_value()
            database = urlsplit(database_url)
            ssl_mode = parse_qs(database.query).get("ssl", [])
            if database.scheme != "postgresql+asyncpg" or ssl_mode != ["verify-full"]:
                raise ValueError(
                    "pilot and production require certificate-validated PostgreSQL TLS"
                )
            secret_values = (
                self.master_key_b64.get_secret_value(),
                self.session_secret.get_secret_value(),
            )
            if any(
                marker in value.lower()
                for value in secret_values
                for marker in ("replace", "placeholder", "change-me")
            ):
                raise ValueError("placeholder secrets are prohibited outside development")
            if secret_values[0] == secret_values[1]:
                raise ValueError("encryption and session keys must be distinct")
            if not self.operator_password_hash.get_secret_value().startswith("$argon2id$"):
                raise ValueError("pilot and production require an Argon2id operator hash")
            if not self.allowed_target_networks:
                raise ValueError("pilot and production require explicit target CIDRs")
        return self

    @property
    def allowed_target_networks(
        self,
    ) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for value in filter(None, (part.strip() for part in self.allowed_target_cidrs.split(","))):
            network = ipaddress.ip_network(value, strict=True)
            if network.version != 4 or not network.is_global or network.prefixlen == 0:
                raise ValueError("target CIDRs must be explicit globally routable IPv4 networks")
            networks.append(network)
        return tuple(networks)


@lru_cache
def get_settings() -> Settings:
    return Settings()
