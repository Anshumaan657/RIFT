# RIFT

An authorized security validation platform for web applications and APIs.

RIFT aims to run controlled security checks and produce reproducible evidence
and clear reports. It does not automatically fix or deploy changes to a target.

## Current status

Phase 4 provides the persistent onboarding model, single-operator authentication,
authorization and target verification records, immutable assessment snapshots,
and the mandatory controlled HTTP safety boundary. Security check execution and
report generation remain for later phases.

## V1 direction

Start with an assisted design-partner pilot for explicitly authorized staging
environments and synthetic data. Focus on a small, defined set of checks,
strict scope enforcement, and findings a developer can independently reproduce.

See [V1 scope](docs/V1_SCOPE.md) and [architecture](docs/ARCHITECTURE.md).
Phase 4 operation and invariants are documented in [Phase 4](docs/PHASE4.md).

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

Requirements: Python 3.12, Node.js 22, and Docker with Compose.

Create local configuration and replace every placeholder before starting:

```sh
cp .env.example .env
python3 -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Put the generated value in `RIFT_MASTER_KEY_B64` and choose a local PostgreSQL
password. Generate the bootstrapped operator's Argon2id password hash without
putting the password in shell history:

```sh
PYTHONPATH=backend/src .venv/bin/python scripts/bootstrap_operator.py
```

Put the resulting hash in `RIFT_OPERATOR_PASSWORD_HASH`, set a random
`RIFT_SESSION_SECRET`, and then start the application:

```sh
docker compose --env-file .env -f infra/compose.yaml up --build
```

By default the operator shell is at `http://localhost:15173`; liveness and
readiness are at `http://localhost:18000/api/v1/health/live` and
`/api/v1/health/ready`. Host ports can be changed in `.env`.

For host-based development:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --requirement backend/requirements.lock
python -m pip install --no-deps --editable backend
cd frontend && npm ci && cd ..
```

Run validation from the repository root:

```sh
ruff format --check backend/src tests/unit tests/safety scripts
ruff check backend/src tests/unit tests/safety scripts
(cd backend && mypy && pytest)
(cd frontend && npm run format:check && npm run lint && npm test && npm run build)
docker compose --env-file .env -f infra/compose.yaml config --quiet
```

Run migrations inside the API container:

```sh
docker compose --env-file .env -f infra/compose.yaml run --rm api alembic upgrade head
```

## Safety

Only test systems with explicit permission and a defined scope. Use staging
and synthetic data for the initial pilot. Active tests can affect application
state even when no source code is changed.

Never commit credentials, session tokens, customer data, or assessment evidence.
Future evidence storage must be separate from generated source code and Git.

## Initial Git setup

See [first commit commands](docs/FIRST_COMMIT.md).
