"""Validated operator API inputs. Secret fields never appear in response models."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from rift.domain.models import EnvironmentType, ReportFormat
from rift.reports.models import ReportVariant


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)


class ApplicationCreate(BaseModel):
    organization_id: UUID
    display_name: str = Field(min_length=1, max_length=255)
    environment_type: EnvironmentType


class AuthorizationRecordCreate(BaseModel):
    application_id: UUID
    approver_identity: str = Field(min_length=1, max_length=255)
    authorization_statement: str = Field(min_length=1, max_length=10_000)
    valid_from: datetime
    valid_until: datetime
    approved_scope: dict[str, Any]
    prohibited_actions: list[str] = Field(default_factory=list)
    operator_review: bool = False

    @model_validator(mode="after")
    def valid_window(self) -> "AuthorizationRecordCreate":
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self


class TargetCreate(BaseModel):
    application_id: UUID
    scheme: Literal["http", "https"]
    hostname: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65_535)
    base_path_prefix: str = Field(default="/", max_length=500)


class TestIdentityCreate(BaseModel):
    application_id: UUID
    label: str = Field(min_length=1, max_length=100)
    bearer_token: str = Field(min_length=1, max_length=16_384)
    token_expiry: datetime | None = None


class TestIdentityUpdate(BaseModel):
    label: str | None = Field(default=None, min_length=1, max_length=100)
    bearer_token: str = Field(min_length=1, max_length=16_384)
    token_expiry: datetime | None = None


class ResourceExpectationCreate(BaseModel):
    application_id: UUID
    endpoint_template: str = Field(min_length=1, max_length=500)
    synthetic_resource_id: str = Field(min_length=1, max_length=255)
    owner_identity: str | None = Field(default=None, max_length=100)
    is_public: bool = False
    expected_access: Literal["allow", "deny"]
    content_marker: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def owner_or_public(self) -> "ResourceExpectationCreate":
        if self.is_public == (self.owner_identity is not None):
            raise ValueError("resource must be public or have exactly one owner identity")
        return self


class AssessmentCreate(BaseModel):
    application_id: UUID
    target_id: UUID
    authorization_record_id: UUID
    selected_checks: list[str] = Field(min_length=1, max_length=3)
    request_budget: int = Field(default=100, ge=1, le=100)
    idempotency_key: str | None = Field(default=None, max_length=255)

    @field_validator("selected_checks")
    @classmethod
    def approved_checks_only(cls, values: list[str]) -> list[str]:
        approved = {"RIFT-AUTHN-001", "RIFT-AUTHZ-001", "RIFT-CONFIG-001"}
        if not values or set(values) - approved:
            raise ValueError("selected_checks contains an unapproved V1 check")
        return values


class ReportCreate(BaseModel):
    format: ReportFormat
    variant: ReportVariant
    idempotency_key: str | None = Field(default=None, max_length=255)


class ORMResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ObjectResponse(ORMResponse):
    id: UUID
    created_at: datetime
    updated_at: datetime


class ErrorResponse(BaseModel):
    detail: str
