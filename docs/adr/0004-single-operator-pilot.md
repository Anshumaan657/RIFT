# ADR 0004: Assisted single-operator pilot

- Status: Accepted
- Date: 2026-09-06

## Context

V1 must validate useful assessments and customer trust before investing in
self-service onboarding, organization roles, collaboration, or billing.

## Decision

Deploy one RIFT instance with one internal operator account. The operator records
authorization, configures synthetic targets and identities, starts/cancels runs,
reviews all findings, and exports reports to design partners. Partners do not log
in to RIFT during V1.

All customer-owned records still carry `organization_id`, and the application
validates relationships so future tenant boundaries are not lost. Protect the
operator login with Argon2id, secure expiring cookies, CSRF defense, throttling,
TLS, and an additional deployment access control. MFA and customer roles are
deferred.

## Consequences

Human review remains an explicit safety and quality control. The operator can
access every pilot organization's data and is therefore a trusted role. This
model cannot scale broadly, but it avoids prematurely building account, billing,
and support systems. Self-service access requires a new threat-model review and ADR.
