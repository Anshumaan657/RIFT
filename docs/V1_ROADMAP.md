# RIFT V1 implementation roadmap

## 1. Purpose of this document

This is the execution specification for RIFT V1. Implement Phases 0–9 in order.
A phase is complete only when its deliverables exist and all of its exit checks
pass. Do not silently change product scope, security boundaries, public APIs, or
the selected stack. Record necessary implementation-level choices in an ADR
under `docs/adr/`. Stop and request a decision if a change would alter this
specification.

RIFT V1 is an assisted security-validation pilot for explicitly authorized
staging applications containing synthetic data. It performs a small set of
controlled web/API checks, records sanitized evidence, and produces reviewed
reports. It is not a general penetration-testing agent.

## 2. Fixed V1 decisions

### 2.1 Product boundary

V1 supports only:

- staging targets that the operator has reviewed and approved;
- `HTTPS` targets, except loopback-only local lab targets may use `HTTP`;
- exact hosts and ports, with no wildcard domains;
- `GET` and `HEAD` requests;
- customer-provided synthetic resource identifiers;
- public endpoints or bearer-token authentication;
- the three check families defined in Section 5;
- assisted onboarding and human review before report delivery.

V1 does not support production targets, browser automation, form login, cookie
sessions, OAuth flows, crawling, fuzzing, payload generation, state-changing
requests, vulnerability chaining, business-logic discovery, cloud/mobile
assessment, automatic fixes, continuous deployment hooks, arbitrary plug-ins,
or unrestricted model-generated commands.

### 2.2 Technology stack

Use these technologies unless this document is amended by the project owner:

- Backend and worker: Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic,
  HTTPX, and PostgreSQL 16.
- Job execution: a separate Python worker process using a PostgreSQL-backed job
  table and `SELECT ... FOR UPDATE SKIP LOCKED`. Do not add Redis or a message
  broker in V1.
- Frontend: Node.js 22 LTS, TypeScript, React, Vite, React Router, and TanStack
  Query. Use plain CSS with project-owned design tokens; do not add a component
  library initially.
- Tests: pytest for backend/unit/integration/safety tests, Vitest and React
  Testing Library for frontend tests, and Playwright for the single critical UI
  journey.
- Local environment: Docker Compose for PostgreSQL, the RIFT backend, worker,
  frontend, and the synthetic lab.
- Quality tools: Ruff for Python formatting/linting, mypy for Python type checks,
  ESLint and Prettier for TypeScript.
- Reports: Jinja2 HTML templates and WeasyPrint for PDF generation.
- AI: no model dependency is required for V1. If an evidence-grounded summary is
  added after Phase 6, it must be optional and have a deterministic fallback.

Pin direct dependencies. Commit lock files. Do not place secrets in source,
fixtures, Git history, logs, reports, screenshots, or model prompts.

### 2.3 Deployment and tenancy

V1 is a single RIFT deployment with one internal operator account. Design
partners do not receive self-service accounts. The operator performs assisted
onboarding and shares reviewed exported reports. Keep `organization_id` on all
application, assessment, credential, finding, evidence, and report records so
future tenant isolation is possible, but do not build team management or billing.

Use PostgreSQL for structured data. Store encrypted credential values and raw
evidence payloads outside normal application logs. For the pilot, store encrypted
blobs in PostgreSQL using application-level envelope encryption; store only key
identifiers in rows. Load the master encryption key from the runtime secret store
or environment during local development. Never store it in the database.
Sanitized evidence used in reports is a separate representation.

## 3. Required domain model

Use UUID primary keys and UTC timestamps. Every mutable record needs
`created_at` and `updated_at`. Use database constraints for enums and ownership
relationships.

- `Organization`: name and status.
- `Application`: organization, display name, environment type, and lifecycle status.
- `AuthorizationRecord`: application, approver identity, authorization statement,
  valid-from/valid-until, approved scope, prohibited actions, and operator review.
- `Target`: application, scheme, exact hostname, explicit port, base-path prefix,
  verification state, and enabled state.
- `TestIdentity`: application, label, encrypted bearer token, and token expiry.
- `ResourceExpectation`: application, endpoint template, synthetic resource ID,
  owner identity or public designation, expected access, and content marker.
- `Assessment`: application, selected checks, immutable configuration snapshot,
  state, request budget, timestamps, cancellation timestamp, and terminal reason.
- `Job`: assessment, state, attempt count, lease owner, lease expiry, and error code.
- `AuditEvent`: assessment, event type, timestamp, actor, sanitized metadata, and
  hash-chain fields `previous_hash` and `event_hash`.
- `Evidence`: assessment, check identifier/version, encrypted raw blob reference,
  sanitized request/response representation, body digest, capture time, and
  redaction version.
- `Finding`: assessment, check identifier/version, title, validation state,
  severity, severity rationale, expected behavior, observed behavior, impact,
  reproduction guidance, remediation guidance, and evidence references.
- `Report`: assessment, format, generation state, immutable finding snapshot,
  file digest, and creation time.

Assessment states are `draft`, `queued`, `running`, `cancelling`, `completed`,
`completed_with_errors`, `failed`, and `cancelled`. Finding validation states are
`suspected`, `reproduced`, and `needs_review`. Severity values are `informational`,
`low`, `medium`, `high`, and `critical`. Do not expose numeric confidence scores.

## 4. Required safety invariants

All network traffic from checks must go through one controlled HTTP client in
`backend/src/safety/`. Checks must not instantiate HTTP clients or sockets.

The controlled client must:

1. Accept only a normalized target and relative path already present in the
   immutable assessment snapshot.
2. Reject URL user-info, fragments, encoded host tricks, non-HTTP(S) schemes,
   wildcard targets, and paths outside the configured base-path prefix.
3. Resolve DNS before every connection and reject loopback, private, link-local,
   multicast, unspecified, reserved, carrier-grade NAT, and cloud-metadata
   destinations. The explicit local-lab mode may allow loopback only and must be
   impossible in a pilot/customer deployment.
4. Connect only to the validated IP set while preserving the authorized hostname
   for TLS/SNI and certificate validation. Re-resolve and revalidate on every
   redirect. Allow at most two redirects.
5. Ignore ambient proxy environment variables and block proxy configuration in
   assessment input.
6. Permit only `GET` and `HEAD`, with a fixed RIFT user agent. Reject request
   bodies, custom Host headers, and customer-supplied hop-by-hop headers.
7. Apply per-request timeout, response-size limit, per-host rate limit, concurrency
   limit, and total-request budget from server-owned policy. Customer input may
   lower limits but cannot raise policy maxima.
8. Check cancellation before queueing and immediately before every request.
9. Redact authorization headers, tokens, cookies, API keys, and configured content
   patterns before logging or producing report evidence.
10. Emit an audit event for request intent and outcome without logging secrets or
    full raw response bodies.

Initial server-owned maximums are: 100 requests per assessment, 2 concurrent
requests, 2 requests/second per host, 10-second connect timeout, 20-second total
request timeout, 1 MiB response body, and 15-minute assessment runtime. Make these
settings configurable by the operator while enforcing these values as hard V1
ceilings.

The worker must stop scheduling work after cancellation, authorization expiry,
request-budget exhaustion, or runtime expiry. A completed assessment must never
mean that every selected check succeeded: retain per-check outcomes and use
`completed_with_errors` when any selected check failed or could not run.

## 5. V1 check catalogue

Each check has a stable identifier and version. Checks compare a declared access
expectation with observed behavior; an HTTP status alone is never sufficient to
claim unauthorized data access.

### 5.1 `RIFT-AUTHN-001` — missing authentication

For a resource declared private, request the configured path without an
Authorization header. Mark `reproduced` only if the response is successful and
contains the configured unique synthetic content marker. A redirect to login,
`401`, `403`, absent marker, ambiguous response, or network error is not a
reproduced finding. Ambiguous success becomes `needs_review`.

### 5.2 `RIFT-AUTHZ-001` — cross-user resource access

Use identity A to retrieve identity B's declared synthetic resource. First verify
that B can retrieve the resource and that the response contains B's unique
marker. Then perform the same request with A. Mark `reproduced` only if A's
response successfully exposes B's marker. Do not enumerate or guess identifiers.
Use only identifiers supplied in `ResourceExpectation` records.

### 5.3 `RIFT-CONFIG-001` — basic transport/header observations

Issue `HEAD`, falling back to `GET` only when required, and record observable
configuration for HTTPS, HSTS, CSP, `X-Content-Type-Options`, `Referrer-Policy`,
and response cookies' `Secure`, `HttpOnly`, and `SameSite` attributes. These are
individual informational/low observations based on endpoint context. Missing
headers must not be described as independently exploitable vulnerabilities.
Never send exploit payloads for this check.

Every check result must be one of `passed`, `finding`, `inconclusive`, `error`,
`skipped`, or `cancelled`, with a machine-readable reason code.

## 6. Required operator API

Use `/api/v1`. Generate and publish an OpenAPI document from FastAPI. Return a
consistent error object with `code`, `message`, and optional field `details`.
Never return secrets or raw evidence blobs.

Required endpoints:

- `POST /organizations` and `GET /organizations/{id}`
- `POST /applications` and `GET /applications/{id}`
- `POST /applications/{id}/authorization-records`
- `POST /applications/{id}/targets`
- `POST /targets/{id}/verify` using an operator-reviewed HTTP challenge token;
  verification proves target control but does not replace written authorization
- `POST /applications/{id}/test-identities`
- `POST /applications/{id}/resource-expectations`
- `POST /assessments`, `GET /assessments/{id}`, and
  `POST /assessments/{id}/cancel`
- `GET /assessments/{id}/audit-events`
- `GET /assessments/{id}/findings` and `GET /findings/{id}`
- `POST /assessments/{id}/reports` and `GET /reports/{id}/download`

Use idempotency keys for assessment creation, cancellation, target verification,
and report generation. Validate ownership across every relationship. Reject an
assessment unless authorization is currently valid, its target is verified and
enabled, its scope is nonempty, all selected checks are supported, and required
synthetic expectations are present.

## 7. Repository target structure

Retain the existing top-level folders and evolve them to:

```text
RIFT/
├── backend/
│   ├── pyproject.toml
│   ├── alembic.ini
│   ├── migrations/
│   └── src/rift/
│       ├── api/
│       ├── engine/
│       │   └── checks/
│       ├── safety/
│       ├── reports/
│       ├── db/
│       ├── domain/
│       ├── worker/
│       └── settings.py
├── frontend/
│   ├── package.json
│   └── src/
├── lab/
│   ├── vulnerable/
│   ├── fixed/
│   └── fixtures/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── safety/
│   └── fixtures/
├── docs/
│   ├── adr/
│   ├── threat-model.md
│   ├── check-catalogue.md
│   ├── operations.md
│   └── V1_ROADMAP.md
├── infra/
│   └── compose.yaml
└── scripts/
```

Keep the backend as one codebase with separate API and worker processes. Do not
create microservices in V1.

## 8. Phase roadmap

### Phase 0 — repository scaffold (complete)

Deliverables:

- Existing project folders, `.gitignore`, `.editorconfig`, README, scope,
  architecture, and initial Git history.
- This roadmap added to `docs/V1_ROADMAP.md`.

Exit checks:

- Working tree contains no credentials, evidence, or generated reports.
- Documentation links resolve.
- Repository is on `main` and tracks `origin/main`.

Suggested commit: `docs: add decision-complete V1 roadmap`

### Phase 1 — specifications and threat model

Deliverables:

- Add `docs/check-catalogue.md` with the exact request, prerequisite, positive
  signal, negative signal, inconclusive conditions, severity guidance, and
  evidence fields for all three checks in Section 5.
- Add `docs/threat-model.md` covering assets, actors, trust boundaries, target
  content as hostile input, SSRF/DNS rebinding, credential exposure, tenant data
  mixing, evidence tampering, resource exhaustion, and worker compromise.
- Add ADRs confirming the fixed stack, PostgreSQL worker queue, encrypted evidence
  model, and single-operator pilot.
- Add JSON examples for assessment configuration and each check result under
  `docs/examples/`. Examples must contain synthetic placeholders only.

Exit checks:

- Every check has an unambiguous expected signal and stop condition.
- Every threat has a preventive control or explicitly accepted V1 limitation.
- Examples include explicit field definitions that Phase 2 can encode as Pydantic/JSON schemas.

Suggested commit: `docs: define V1 checks and threat model`

### Phase 2 — development foundation

Deliverables:

- Initialize the pinned Python and Node projects with the tools from Section 2.2.
- Add typed settings, structured logging with redaction, database session handling,
  migrations, health/readiness endpoints, and the initial domain schemas.
- Add the React shell, API client, router, error boundary, and accessible base
  layout. Do not implement polished product screens yet.
- Add Dockerfiles and `infra/compose.yaml` for local development.
- Add `.env.example` containing names and safe placeholder values only.
- Add CI that runs formatting checks, lint, type checks, unit tests, frontend
  tests, and secret scanning. CI must not run network tests against external hosts.
- Update README with exact install, start, migration, test, and lint commands.

Exit checks:

- A fresh clone can start PostgreSQL, API, worker, frontend, and lab placeholders
  using documented commands.
- Health/readiness endpoints correctly reflect database availability.
- All static checks and tests pass from clean environments.

Suggested commit: `build: initialize RIFT application stack`

### Phase 3 — synthetic security lab

Deliverables:

- Build isolated vulnerable and fixed FastAPI lab variants with identical
  contracts and synthetic fixture data.
- Create user A and user B bearer tokens, private records with unique markers,
  a public record, missing/expired-token cases, denied access, missing record,
  redirect, slow response, oversized response, and server-error endpoints.
- Implement a deterministic reset/seed command. Never use customer data.
- Bind the lab to loopback/private Docker networking and document that it is
  intentionally vulnerable and must never be publicly deployed.
- Add manual verification scripts using only lab endpoints.

Exit checks:

- Manual checks demonstrate `RIFT-AUTHN-001` and `RIFT-AUTHZ-001` against the
  vulnerable variant.
- Equivalent checks do not reproduce against the fixed variant.
- Resetting the lab produces identical IDs, markers, and expected results.

Suggested commit: `test: add isolated vulnerable and fixed security lab`

### Phase 4 — persistence, onboarding, and safety layer

Deliverables:

- Implement the Section 3 models, migrations, repositories, and immutable
  assessment snapshots.
- Implement operator authentication with one bootstrapped operator account,
  Argon2id password hashing, secure `HttpOnly`/`SameSite=Strict` session cookies,
  CSRF protection for mutations, login throttling, and session expiry.
- Implement authorization records, exact target scope, HTTP challenge verification,
  encrypted bearer-token storage, and resource expectations.
- Implement the sole controlled HTTP client and every invariant in Section 4.
- Implement cancellation state transitions, audit hash chaining, secret redaction,
  and policy-owned ceilings.

Exit checks:

- Unit tests cover model constraints and state transitions.
- Safety tests cover prohibited schemes/IP ranges, alternate numeric IP forms,
  redirects, DNS changes, base-path escapes, proxy variables, forbidden methods,
  budgets, response limits, timeouts, cancellation, and redaction.
- Tests prove check modules cannot perform network access outside the controlled
  client through dependency and architecture checks.
- Raw tokens never appear in logs, API responses, audit metadata, or sanitized
  evidence snapshots.

Suggested commit: `feat: enforce authorized target scope and execution safety`

### Phase 5 — durable assessment engine

Deliverables:

- Implement PostgreSQL job claiming, leases, heartbeat, retry, recovery after
  worker restart, and terminal failure handling. Maximum job attempts: two.
  Retry only transport failures that are safe to repeat; never retry policy
  rejection or a completed request merely because its result is unfavorable.
- Implement the assessment state machine and per-check outcomes.
- Implement the three versioned checks exactly as specified in Section 5.
- Enforce prerequisite ordering for owner verification before cross-user testing.
- Persist evidence and audit events transactionally enough that a crash cannot
  produce a finding with missing evidence.

Exit checks:

- Integration tests pass for vulnerable, fixed, ambiguous, error, skipped,
  cancelled, budget-exhausted, and worker-restart cases.
- The vulnerable lab is detected and the fixed lab is not falsely reported.
- An incomplete run never appears as a clean or fully completed assessment.
- Replaying an idempotent request does not duplicate assessments or reports.

Suggested commit: `feat: execute controlled V1 security assessments`

### Phase 6 — findings, evidence, and reports

Deliverables:

- Implement versioned raw-evidence encryption and deterministic sanitized evidence.
- Create findings only from stored check results and evidence. Do not infer facts
  absent from evidence.
- Implement severity rationale, validation states, remediation guidance, and
  minimal retest instructions.
- Produce immutable founder-summary and technical-detail HTML reports, JSON export,
  and PDF output. Include target, authorization window, selected checks, per-check
  outcomes, tested/skipped/failed areas, timestamps, tool/check versions,
  limitations, and file digest.
- Render request examples with secrets replaced by stable redaction labels. Limit
  response excerpts and escape all target-controlled content.
- Add an operator review status so exports are visibly `DRAFT` until reviewed.

Exit checks:

- Reports render correctly for zero findings, mixed results, cancellation,
  partial failure, and multiple findings.
- HTML/PDF injection tests prove target content cannot execute markup or scripts.
- Snapshot tests contain no credentials and another developer can reproduce each
  lab finding from the sanitized instructions.
- An experienced security reviewer approves check claims and report language
  before any design-partner report is delivered.

Suggested commit: `feat: generate evidence-backed assessment reports`

### Phase 7 — operator interface

Deliverables:

- Build screens for login; organizations/applications; authorization record;
  target scope and verification; test identities; resource expectations;
  assessment configuration; progress and cancellation; findings/evidence;
  assessment history; review; and report download.
- Show precise states for draft, queued, running, cancelling, completed with
  errors, failed, and cancelled assessments.
- Require a final scope/authorization review before queueing an assessment.
- Do not expose raw bearer tokens after creation. Permit replacement and deletion.
- Meet keyboard-navigation, label, focus, error-message, and color-contrast needs.

Exit checks:

- The Playwright critical journey creates a lab application, configures scope and
  identities, runs an assessment, reviews a finding, and downloads a report.
- UI tests cover expired authorization, invalid scope, failed target verification,
  cancellation, empty results, partial results, and unavailable report generation.
- The complete assisted workflow requires no direct database or terminal access.

Suggested commit: `feat: add assisted V1 assessment workflow`

### Phase 8 — hardening and pilot deployment

Status: engineering and internal rehearsals complete; pilot release remains gated
on the independent application-security sign-off recorded in
`docs/phase8-security-review.md`.

Deliverables:

- Add production configuration validation, TLS termination, restrictive network
  egress, security headers, encrypted backups, key rotation procedure, retention
  and deletion jobs, disk/DB capacity alerts, worker health, and audit monitoring.
- Add `docs/operations.md` with deployment, rollback, backup restore, incident
  response, emergency cancellation, credential rotation, evidence deletion, and
  disaster-recovery procedures.
- Define default retention: raw evidence and target credentials 30 days after the
  assessment; sanitized reports 180 days. Allow earlier operator deletion.
- Run dependency, container, secret, and application security scans. Triage every
  high/critical result rather than accepting scanner output automatically.
- Obtain an independent application-security review of RIFT and resolve all
  findings that could make pilot operation unsafe.

Exit checks:

- Restore is tested from an encrypted backup.
- Egress tests prove the deployment cannot reach prohibited address ranges.
- Emergency cancellation and key rotation are rehearsed and documented.
- No unresolved review finding permits scope escape, secret disclosure, cross-
  organization access, evidence tampering, or unauthorized assessment execution.

Suggested commit: `ops: harden RIFT for an assisted staging pilot`

### Phase 9 — controlled design-partner pilot

Deliverables:

- Onboard one design partner first using a signed authorization record, staging
  target, synthetic accounts/data, agreed testing window, escalation contact,
  and explicit stop procedure.
- Perform a preflight check, run the assessment, manually review every finding,
  deliver the reviewed report, collect developer feedback, and record corrections.
- Expand gradually to at most five design partners only after resolving safety or
  reliability issues from the prior assessment.
- Track accepted reproduced findings, false positives, false negatives in known
  lab cases, inconclusive rate, assessment completion, runtime, request count,
  report review time, operating cost, repeat-assessment interest, and willingness
  to pay.
- Maintain a pilot issue log separating product defects, check limitations,
  onboarding friction, and requested future features.

Exit checks:

- All pilot assessments stayed inside scope and left complete sanitized audit trails.
- Developers could independently reproduce accepted findings.
- Known lab regression tests still pass after every pilot-driven change.
- Product evidence identifies whether customers value and would repeat/pay for
  the assessment. Payment is a business validation metric, not a condition for
  declaring the software technically complete.

Suggested commit: `docs: record V1 pilot outcomes and release decision`

## 9. Global definition of done

RIFT V1 is complete only when:

- Phases 0–9 meet their exit checks.
- The three V1 checks work against vulnerable and fixed lab targets.
- Authorization, exact scope enforcement, safety budgets, cancellation,
  redaction, evidence, reports, history, and audit logs work together.
- Tests cover expected, fixed, ambiguous, failure, cancellation, and scope-escape
  scenarios, and CI passes on a clean checkout.
- An independent security reviewer has approved pilot safety and reporting claims.
- Pilot findings are manually reviewed before delivery.
- Documentation states exactly what was tested, skipped, or unsupported and never
  presents "no findings" as proof that a target is secure.

## 10. Instructions for an implementation agent

For each phase:

1. Read `README.md`, `docs/V1_SCOPE.md`, `docs/ARCHITECTURE.md`, this roadmap,
   applicable ADRs, and the current Git status before editing.
2. Work only on the current phase. Do not implement later-phase features unless
   they are a small prerequisite explicitly named by this document.
3. Preserve all Section 4 safety invariants. Never probe a public or customer
   target while developing or testing; use only the local synthetic lab.
4. Add meaningful tests for security boundaries and behavior. Do not create tests
   that merely mirror implementation details.
5. Run the phase's format, lint, type, unit, integration, safety, and UI checks as
   applicable. Report commands and results honestly; never claim unrun checks.
6. Update documentation whenever commands, schemas, or behavior change.
7. Review `git diff` for credentials, raw evidence, generated artifacts, and
   unrelated edits before committing.
8. Use the suggested phase commit message or a small series of conventional
   commits. Do not push, deploy, onboard a partner, or test an external target
   without explicit project-owner authorization.
9. At phase completion, report deliverables, validation evidence, remaining risks,
   and the next phase. Stop if any exit check is unmet.

When ambiguity remains, choose the safer behavior only for reversible internal
implementation details. Ask the project owner before changing supported checks,
limits, target types, authentication methods, retention, deployment model, data
model semantics, API contracts, or acceptance criteria.
