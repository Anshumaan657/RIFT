# ADR 0002: PostgreSQL-backed assessment queue

- Status: Accepted
- Date: 2026-09-06

## Context

Assessments must survive process restarts and be cancellable, but V1 volume does
not justify operating a separate broker.

## Decision

Use a `Job` table in PostgreSQL. A separate Python worker claims available jobs
inside a short transaction with `SELECT ... FOR UPDATE SKIP LOCKED`, records a
lease owner/expiry, and commits before executing checks. The worker heartbeats the
lease and records terminal state. Expired leases may be reclaimed. Attempt count
is capped at two, and only safe transport failures are retryable. API idempotency
keys prevent duplicate assessment creation and cancellation effects.

## Consequences

PostgreSQL is both system of record and queue, reducing V1 operations. Workers
must implement careful leases, state transitions, and crash tests. At-least-once
execution is possible, which is acceptable only because V1 supports bounded
GET/HEAD requests and idempotent result persistence. Redis or another broker is
out of scope unless load evidence justifies a later ADR.
