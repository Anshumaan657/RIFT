# RIFT

An authorized security validation platform for web applications and APIs.

RIFT aims to run controlled security checks and produce reproducible evidence
and clear reports. It does not automatically fix or deploy changes to a target.

## Current status

Initial project scaffold only. No application, scanner, API, or executable tests
have been implemented. Frameworks and dependencies have not been selected.

## V1 direction

Start with an assisted design-partner pilot for explicitly authorized staging
environments and synthetic data. Focus on a small, defined set of checks,
strict scope enforcement, and findings a developer can independently reproduce.

See [V1 scope](docs/V1_SCOPE.md) and [architecture](docs/ARCHITECTURE.md).

## Folder structure

```text
RIFT/
├── backend/
│   └── src/
│       ├── api/           # Assessment and result interfaces
│       ├── engine/        # Approved checks and assessment execution
│       ├── safety/        # Scope, request limits, cancellation, redaction
│       └── reports/       # Evidence-backed findings and report generation
├── frontend/
│   └── src/               # Onboarding, assessment progress, results
├── tests/
│   ├── unit/              # Individual module behavior
│   ├── integration/       # End-to-end assessment flow in a local lab
│   ├── safety/            # Scope, cancellation, and secret-handling checks
│   └── fixtures/          # Synthetic test data and local lab fixtures
├── docs/                  # Product scope and technical decisions
├── scripts/               # Future development and maintenance helpers
└── infra/                 # Future local environment and deployment config
```

## Development

Runtime setup and run commands will be added when the initial technology stack
is chosen. Empty implementation folders contain `.gitkeep` files so Git tracks
them. There is no install, run, or test command yet.

## Safety

Only test systems with explicit permission and a defined scope. Use staging
and synthetic data for the initial pilot. Active tests can affect application
state even when no source code is changed.

Never commit credentials, session tokens, customer data, or assessment evidence.
Future evidence storage must be separate from generated source code and Git.

## Initial Git setup

See [first commit commands](docs/FIRST_COMMIT.md).
