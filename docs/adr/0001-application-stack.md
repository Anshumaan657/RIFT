# ADR 0001: V1 application stack

- Status: Accepted
- Date: 2026-09-06

## Context

RIFT needs an API, durable assessment worker, operator UI, synthetic lab, and
repeatable local environment. A solo builder needs a small number of well-supported
technologies without splitting the backend into services.

## Decision

Use Python 3.12 with FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, HTTPX, and
PostgreSQL 16 for the backend and worker. Use the Python `cryptography` package
for the encrypted-blob format defined by ADR 0003. Use Node.js 22 LTS, TypeScript, React,
Vite, React Router, and TanStack Query for the UI. Use Docker Compose locally,
pytest/Vitest/React Testing Library/Playwright for tests, Ruff/mypy and
ESLint/Prettier for quality checks, and Jinja2/WeasyPrint for reports.

Keep one backend codebase with separate API and worker processes. AI is not a V1
runtime dependency. Pin direct dependencies and commit lock files.

## Consequences

The project has two language toolchains but uses common, documented components.
The backend remains simple to deploy and test. PDF generation and native packages
must be represented in container builds. Adding a framework, message broker,
model provider, or microservice requires a new ADR and owner approval.
