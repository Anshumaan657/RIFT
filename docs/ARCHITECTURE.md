# Initial architecture

This document describes intended responsibilities, not implemented functionality.
Keep the backend as one application initially; these folders do not imply
separate services or deployments.

| Location | Responsibility |
| --- | --- |
| `frontend/src` | Target onboarding, assessment progress, findings, and exports. |
| `backend/src/api` | Validate requests and expose assessment/result interfaces. |
| `backend/src/engine` | Coordinate assessments and execute explicitly approved checks. |
| `backend/src/safety` | Enforce target scope, request limits, cancellation, and evidence redaction. |
| `backend/src/reports` | Turn observed evidence into findings and understandable reports. |
| `tests` | Verify module behavior, lab integration, and safety boundaries. |
| `scripts` | Reusable developer and maintenance commands when needed. |
| `infra` | Local infrastructure and deployment configuration when selected. |

## Intended flow

Onboarding and explicit scope → validated assessment request → execution through
mandatory safety controls → sanitized evidence → reviewed findings → report.

All outgoing test traffic must pass through the safety controls. A model must
not be able to bypass these controls. Treat target content as untrusted input,
not instructions for the testing system.

Keep credentials and raw evidence out of Git, normal logs, and model prompts.
Define storage, retention, and access controls before accepting customer data.

The V1 stack, domain model, required API surface, PostgreSQL-backed worker queue,
and evidence-storage approach are fixed in [`V1_ROADMAP.md`](V1_ROADMAP.md) and
the accepted records under [`adr/`](adr/). Phase 2 will turn those decisions into
schemas and executable contracts. V1 has no required model provider.
