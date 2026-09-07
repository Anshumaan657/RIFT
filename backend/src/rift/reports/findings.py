"""Evidence-gated finding creation."""

import json
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from rift.domain.models import (
    CheckExecution,
    CheckOutcome,
    Evidence,
    Finding,
    FindingValidationState,
    Severity,
)

GUIDANCE = {
    "RIFT-AUTHN-001": {
        "title": "Private synthetic resource accessible without authentication",
        "severity": Severity.HIGH,
        "rationale": "The configured private marker was returned without credentials.",
        "expected": "Anonymous requests must be denied without returning private content.",
        "impact": "An unauthenticated party could read resources with the same access path.",
        "remediation": "Require authentication before loading or serializing the resource.",
        "retest": "Repeat one anonymous GET for the same synthetic resource and verify denial.",
    },
    "RIFT-AUTHZ-001": {
        "title": "Synthetic resource accessible across user boundary",
        "severity": Severity.HIGH,
        "rationale": "A non-owner identity received the owner's unique synthetic marker.",
        "expected": "The server must verify resource ownership for every object request.",
        "impact": "One authenticated user could read another user's resources.",
        "remediation": "Enforce an ownership check in the server-side resource query.",
        "retest": "Repeat the owner request, then one non-owner GET for that exact resource.",
    },
    "RIFT-CONFIG-001": {
        "title": "HTTP security configuration observations",
        "severity": Severity.INFORMATIONAL,
        "rationale": "One or more contextual transport or response-header controls were absent.",
        "expected": "Review applicable transport, browser, and cookie hardening controls.",
        "impact": "The observation may reduce defense in depth depending on endpoint context.",
        "remediation": "Add only the recorded controls that apply to this endpoint and client.",
        "retest": "Repeat HEAD on the same endpoint and compare the listed response headers.",
    },
}

CONFIG_LABELS = {
    "https": ("HTTPS was not used", Severity.LOW),
    "hsts": ("HSTS header was not observed", Severity.LOW),
    "csp": ("CSP header was not observed on HTML", Severity.INFORMATIONAL),
    "x_content_type_options": (
        "X-Content-Type-Options nosniff was not observed",
        Severity.INFORMATIONAL,
    ),
    "referrer_policy": ("Referrer-Policy header was not observed", Severity.INFORMATIONAL),
}


async def materialize_findings(
    session: AsyncSession, assessment_id: UUID
) -> list[Finding]:
    executions = (
        await session.scalars(
            select(CheckExecution).where(
                CheckExecution.assessment_id == assessment_id,
                CheckExecution.outcome == CheckOutcome.FINDING,
            )
        )
    ).all()
    created: list[Finding] = []
    for execution in executions:
        evidence_refs = [UUID(value) for value in json.loads(execution.evidence_refs)]
        evidence_count = await session.scalar(
            select(func.count())
            .select_from(Evidence)
            .where(Evidence.assessment_id == assessment_id, Evidence.id.in_(evidence_refs))
        )
        if not evidence_refs or evidence_count != len(evidence_refs):
            continue
        guide = GUIDANCE[execution.check_identifier]
        items = [(str(guide["title"]), guide["severity"], execution.summary)]
        if execution.check_identifier == "RIFT-CONFIG-001":
            missing = json.loads(execution.observations).get("missing", [])
            items = [
                (
                    CONFIG_LABELS.get(
                        key.split(".")[-1],
                        (f"Cookie attribute was not observed: {key}", Severity.INFORMATIONAL),
                    )[0],
                    CONFIG_LABELS.get(
                        key.split(".")[-1],
                        ("", Severity.INFORMATIONAL),
                    )[1],
                    f"The stored response observation recorded {key} as absent.",
                )
                for key in missing
            ]
        for title, severity, observed in items:
            existing = await session.scalar(
                select(Finding).where(
                    Finding.assessment_id == assessment_id,
                    Finding.check_identifier == execution.check_identifier,
                    Finding.check_version == execution.check_version,
                    Finding.title == title,
                )
            )
            if existing is not None:
                created.append(existing)
                continue
            finding = Finding(
                assessment_id=assessment_id,
                check_identifier=execution.check_identifier,
                check_version=execution.check_version,
                title=title,
                validation_state=(
                    FindingValidationState.NEEDS_REVIEW
                    if execution.check_identifier == "RIFT-CONFIG-001"
                    else FindingValidationState.REPRODUCED
                ),
                severity=severity,
                severity_rationale=str(guide["rationale"]),
                expected_behavior=str(guide["expected"]),
                observed_behavior=observed,
                impact=str(guide["impact"]),
                reproduction_guidance=str(guide["retest"]),
                remediation_guidance=str(guide["remediation"]),
                evidence_refs=execution.evidence_refs,
            )
            session.add(finding)
            created.append(finding)
    await session.flush()
    return created
