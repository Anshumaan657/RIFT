"""Strict Phase 1 contract schemas."""

from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CheckOutcome(StrEnum):
    PASSED = "passed"
    FINDING = "finding"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class ValidationState(StrEnum):
    SUSPECTED = "suspected"
    REPRODUCED = "reproduced"
    NEEDS_REVIEW = "needs_review"


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TargetSnapshot(StrictModel):
    scheme: Literal["http", "https"]
    hostname: str = Field(min_length=1, max_length=253)
    port: Annotated[int, Field(ge=1, le=65535)]
    base_path: str = Field(pattern=r"^/.*")


class CheckSelection(StrictModel):
    check_id: Literal["RIFT-AUTHN-001", "RIFT-AUTHZ-001", "RIFT-CONFIG-001"]
    check_version: Literal[1]


class IdentityReference(StrictModel):
    identity_id: UUID
    label: str = Field(min_length=1, max_length=100)


class ResourceExpectationInput(StrictModel):
    resource_expectation_id: UUID
    endpoint_template: str = Field(min_length=1)
    resource_id: str = Field(min_length=1, max_length=200)
    access: Literal["private", "public"]
    owner_identity_id: UUID | None
    content_marker_ref: str = Field(min_length=1, max_length=200)
    content_marker: str = Field(min_length=8, max_length=500)

    @model_validator(mode="after")
    def validate_template_and_owner(self) -> "ResourceExpectationInput":
        if (
            self.endpoint_template.startswith("/")
            or self.endpoint_template.count("{resource_id}") != 1
        ):
            raise ValueError("endpoint_template must be relative and contain one {resource_id}")
        if self.access == "private" and self.owner_identity_id is None:
            raise ValueError("private resources require owner_identity_id")
        return self


class AssessmentLimits(StrictModel):
    max_requests: Annotated[int, Field(ge=1, le=100)]
    max_concurrency: Annotated[int, Field(ge=1, le=2)]
    requests_per_second: Annotated[int, Field(ge=1, le=2)]
    connect_timeout_seconds: Annotated[int, Field(ge=1, le=10)]
    request_timeout_seconds: Annotated[int, Field(ge=1, le=20)]
    max_response_bytes: Annotated[int, Field(ge=1, le=1_048_576)]
    assessment_timeout_seconds: Annotated[int, Field(ge=1, le=900)]


class AuthorizationSnapshot(StrictModel):
    valid_from: AwareDatetime
    valid_until: AwareDatetime
    allowed_methods: list[Literal["GET", "HEAD"]]

    @model_validator(mode="after")
    def validate_window(self) -> "AuthorizationSnapshot":
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        if not self.allowed_methods:
            raise ValueError("at least one allowed method is required")
        return self


class AssessmentConfiguration(StrictModel):
    schema_version: Literal[1]
    organization_id: UUID
    application_id: UUID
    authorization_record_id: UUID
    target_id: UUID
    target: TargetSnapshot
    local_lab_mode: bool
    selected_checks: list[CheckSelection] = Field(min_length=1)
    identity_refs: list[IdentityReference]
    resource_expectations: list[ResourceExpectationInput]
    configuration_path: str = Field(min_length=1)
    limits: AssessmentLimits
    authorization: AuthorizationSnapshot

    @model_validator(mode="after")
    def validate_references(self) -> "AssessmentConfiguration":
        if self.configuration_path.startswith("/"):
            raise ValueError("configuration_path must be relative")
        check_keys = [(item.check_id, item.check_version) for item in self.selected_checks]
        if len(check_keys) != len(set(check_keys)):
            raise ValueError("selected_checks must be unique")
        identities = [item.identity_id for item in self.identity_refs]
        if len(identities) != len(set(identities)):
            raise ValueError("identity_refs must be unique")
        identity_set = set(identities)
        if any(
            item.owner_identity_id is not None and item.owner_identity_id not in identity_set
            for item in self.resource_expectations
        ):
            raise ValueError("resource owner must reference a configured identity")
        if self.local_lab_mode and self.target.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("local_lab_mode is restricted to loopback hostnames")
        if not self.local_lab_mode and self.target.scheme != "https":
            raise ValueError("non-lab targets require HTTPS")
        return self


class FindingProposal(StrictModel):
    validation_state: ValidationState
    severity: Severity
    title: str
    severity_rationale: str
    expected_behavior: str
    observed_behavior: str
    evidence_refs: list[UUID] = Field(min_length=1)


class CheckResult(StrictModel):
    schema_version: Literal[1]
    check_id: Literal["RIFT-AUTHN-001", "RIFT-AUTHZ-001", "RIFT-CONFIG-001"]
    check_version: Literal[1]
    outcome: CheckOutcome
    reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]+$")
    target_id: UUID
    resource_expectation_id: UUID | None
    identity_ids: list[UUID]
    started_at: AwareDatetime
    finished_at: AwareDatetime
    request_count: Annotated[int, Field(ge=0, le=100)]
    evidence_refs: list[UUID]
    summary: str
    limitations: list[str]
    finding_proposals: list[FindingProposal]

    @model_validator(mode="after")
    def validate_result(self) -> "CheckResult":
        if self.finished_at < self.started_at:
            raise ValueError("finished_at must not precede started_at")
        if self.outcome == CheckOutcome.FINDING and not self.finding_proposals:
            raise ValueError("finding outcome requires finding_proposals")
        if self.outcome != CheckOutcome.FINDING and self.finding_proposals:
            raise ValueError("only finding outcomes may contain finding_proposals")
        evidence_ids = set(self.evidence_refs)
        if any(not set(item.evidence_refs) <= evidence_ids for item in self.finding_proposals):
            raise ValueError("finding evidence must belong to the result")
        return self
