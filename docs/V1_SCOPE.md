# V1 scope — working direction

## Goal

Build an assisted pilot for a few design partners. Prove that a defined set of
security checks can produce useful, reproducible findings within an authorized
scope. Validate willingness to pay through customer feedback and repeat use.

## Intended capabilities

- Manual onboarding with explicit authorization and a staging-only target scope.
- A small set of reviewed web/API checks, to be selected before implementation.
- Basic authenticated testing using supplied test accounts and synthetic data.
- Technically enforced scope, request limits, cancellation, and audit events.
- Sanitized evidence, a technical report, and a founder-friendly summary.
- Basic assessment history and exportable reports.
- Human review of pilot reports, with experienced security review before customer delivery.

## Boundaries

- No production testing in the initial pilot.
- No automatic fixes, deployments, or infrastructure modifications.
- No destructive tests, load testing, or access to unrelated customer records.
- No unrestricted AI-generated commands or tests.
- Defer attack graphs, general business-logic discovery, cloud/mobile testing,
  continuous integrations, and multi-agent orchestration.

## Evidence and safety

Separate suspected findings, reproduced findings, and items needing review.
A reproduced finding needs observed evidence and an expected behavior against
which to compare it. Do not publish uncalibrated confidence percentages or
imply that a clean report means the application is secure.

Report tested and skipped areas. Enforce safety controls outside the model.
Define allowed state changes before testing: no automatic fixes does not mean
that an active assessment is incapable of changing application state.

## First implementation acceptance criteria

1. A local synthetic lab demonstrates one known vulnerability and its fixed counterpart.
2. The assessment identifies the vulnerable case without flagging the fixed case.
3. Scope boundaries and cancellation are verified using controlled local tests.
4. Evidence supports independent reproduction without exposing credentials.
5. The report states coverage limitations and distinguishes incomplete runs.

## Decisions fixed for V1

The check catalogue, local-lab requirements, bearer-token authentication,
technology stack, and encrypted evidence-storage approach are fixed in
[`V1_ROADMAP.md`](V1_ROADMAP.md). Phase 1 specifications are recorded in
[`check-catalogue.md`](check-catalogue.md), [`threat-model.md`](threat-model.md),
and the accepted architecture decisions under [`adr/`](adr/).
