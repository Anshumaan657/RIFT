# Phase 4: persistence, onboarding, and safety

Phase 4 establishes the boundary that every later check and worker must use.

## Operator authentication

RIFT V1 has one operator configured through `RIFT_OPERATOR_USERNAME` and
`RIFT_OPERATOR_PASSWORD_HASH`. Generate the Argon2id hash with
`scripts/bootstrap_operator.py`. Sessions are signed, expire on the configured
TTL, and use a `Secure`, `HttpOnly`, `SameSite=Strict` cookie. Every mutation
except login requires the session cookie and the matching `X-CSRF-Token`.

Failed logins are limited by client address and username. The in-memory
throttle is suitable for the single API process in V1; a multi-process
deployment must replace it with a shared store before scaling.

## Onboarding sequence

1. Create the organization and staging application.
2. Record authorization dates, exact approved target scopes, prohibited
   actions, and operator review.
3. Create an exact target. RIFT normalizes its hostname and base path, resolves
   it, rejects prohibited addresses, and returns a one-time HTTP challenge.
4. Serve that challenge at the returned path and invoke target verification.
5. Add encrypted bearer-token identities and synthetic resource expectations.
6. Create an assessment. RIFT builds the configuration snapshot on the server;
   clients cannot supply proxy or network configuration.

Raw bearer tokens are encrypted with AES-256-GCM. The record ID and purpose are
authenticated as associated data, so ciphertext cannot be moved between
identity records.

## Controlled HTTP boundary

Checks receive `SafeHttpClient`; they do not create sockets or third-party HTTP
clients. The boundary accepts only `GET` and `HEAD` relative paths under the
snapshot base path. It resolves DNS before each connection and requires the
answer to equal the verified IP set. The transport connects to a selected
validated IP while preserving the authorized hostname for TLS SNI and
certificate validation.

Redirects must retain the exact scheme, hostname, effective port, and base
path. The client permits two redirects. It uses no ambient proxy configuration
and rejects caller-supplied host, proxy, framing, and hop-by-hop headers.

Server settings cannot exceed the V1 ceilings. Assessment input may only lower
request count, concurrency, rate, timeouts, response size, and runtime.
Cancellation is checked before queueing and immediately before transport.
Request intent and outcome enter a sanitized SHA-256 audit chain; full raw
response bodies do not.

Local lab mode can be enabled only in `development` and permits loopback
destinations only. It cannot be enabled in test, pilot, or production.
