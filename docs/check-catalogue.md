# RIFT V1 check catalogue

## Contract shared by every check

Checks operate only on the immutable assessment snapshot and send traffic only
through the controlled client defined in `V1_ROADMAP.md`. They never discover,
guess, crawl, mutate, or broaden scope. Version every implementation and persist
the version with its result and evidence.

Every result contains:

- `check_id`, `check_version`, `outcome`, `reason_code`, and a safe summary;
- the IDs of the target, resource expectation, and test identities used;
- start/end UTC timestamps and request count;
- sanitized evidence references and limitations;
- an optional finding proposal only when the outcome is `finding`.

Allowed outcomes are `passed`, `finding`, `inconclusive`, `error`, `skipped`, and
`cancelled`. A result may not claim that an application is secure. A `passed`
result means only that the configured signal was not reproduced for the supplied
synthetic resource during this run.

Before and immediately before every request, stop with the relevant outcome if
authorization expired, cancellation was requested, scope validation fails, the
request budget is unavailable, or the assessment deadline passed. Never continue
after obtaining the minimum proof required by a check.

## RIFT-AUTHN-001 v1 — missing authentication

### Purpose

Test whether one declared private synthetic resource can be read without a bearer
token. This is not endpoint discovery and does not test bypass payloads.

### Required input and prerequisite

- One verified, enabled target and a relative endpoint template.
- A `private` resource expectation with a caller-supplied synthetic resource ID.
- A unique, non-secret content marker expected in that resource.
- No identity is attached to the test request.

The final relative path is produced by replacing exactly one documented
`{resource_id}` placeholder. Reject extra placeholders, traversal, query/fragment
content in the ID, or a resulting path outside the approved base path.

### Request

Send one `GET` request without `Authorization`, cookies, or caller-defined headers.
Follow at most two redirects through the controlled client. Each hop must remain
in the exact approved scope.

### Decision table

| Signal | Outcome | Reason code |
| --- | --- | --- |
| `2xx` and decoded body contains the exact marker | `finding` with `reproduced` proposal | `PRIVATE_MARKER_EXPOSED_WITHOUT_AUTH` |
| `401` or `403` | `passed` | `ANONYMOUS_ACCESS_DENIED` |
| Redirect ending at a login/authentication response without marker | `passed` | `ANONYMOUS_REDIRECTED_TO_AUTH` |
| `2xx` without marker, or marker check cannot safely decode body | `inconclusive` | `SUCCESS_RESPONSE_WITHOUT_PROOF` |
| `404` or `410` | `inconclusive` | `RESOURCE_NOT_AVAILABLE` |
| Other `4xx` | `inconclusive` | `UNEXPECTED_CLIENT_RESPONSE` |
| `5xx` | `error` | `TARGET_SERVER_ERROR` |
| Network/timeout/size/TLS failure | `error` | matching controlled-client error code |
| Prerequisite absent | `skipped` | `MISSING_PRIVATE_RESOURCE_EXPECTATION` |
| Cancellation observed | `cancelled` | `ASSESSMENT_CANCELLED` |

Stop after the first terminal response or controlled-client failure. Do not try
alternative paths, tokens, encodings, or methods.

### Finding and severity guidance

Title: `Private synthetic resource accessible without authentication`.
Default severity is `high` only when the exact private marker is exposed. A human
reviewer may lower severity using documented application context, but may not
raise it to `critical` without separately documented impact outside this check.
Explain that only the supplied resource and endpoint were tested.

### Required evidence

Store request method, sanitized URL, absence of authentication, status, selected
safe response headers, redirect chain, body digest, bounded escaped excerpt around
the synthetic marker, marker match result, timestamps, target/check versions, and
redaction version. Never include the complete body or the marker if it was marked
confidential by the operator.

## RIFT-AUTHZ-001 v1 — cross-user resource access

### Purpose

Test whether identity A can read one declared private synthetic resource owned by
identity B. RIFT uses only supplied IDs and performs no enumeration.

### Required input and prerequisite

- One verified, enabled target and relative endpoint template.
- Distinct, unexpired bearer-token identities A and B in the same application.
- A private resource expectation owned by B, with supplied ID and exact marker.
- Authorization remains valid for both the owner verification and cross-user test.

### Requests and ordering

1. Send `GET` as B to the configured resource.
2. Continue only if B receives `2xx` and the exact marker is present.
3. Send the identical request as A, changing only the bearer credential.
4. Stop. Do not test other identities or identifiers.

### Decision table

| Signal | Outcome | Reason code |
| --- | --- | --- |
| B proves ownership; A gets `2xx` with B's marker | `finding` with `reproduced` proposal | `CROSS_USER_PRIVATE_MARKER_EXPOSED` |
| B proves ownership; A gets `401`, `403`, or `404` without marker | `passed` | `CROSS_USER_ACCESS_DENIED` |
| B cannot get `2xx` with marker | `inconclusive`; do not request as A | `OWNER_BASELINE_NOT_PROVEN` |
| A gets `2xx` without marker | `inconclusive` | `SUCCESS_RESPONSE_WITHOUT_OWNER_PROOF` |
| A gets another `4xx` or redirect without marker | `inconclusive` | `UNEXPECTED_ACCESS_RESPONSE` |
| Either request gets `5xx` | `error` | `TARGET_SERVER_ERROR` |
| Network/timeout/size/TLS failure | `error` | matching controlled-client error code |
| Identity/expectation missing or identities identical | `skipped` | `INVALID_AUTHZ_PREREQUISITE` |
| Cancellation before either request | `cancelled` | `ASSESSMENT_CANCELLED` |

If cancellation or authorization expiry occurs after the owner request, do not
send the cross-user request.

### Finding and severity guidance

Title: `Synthetic resource exposed across test-user boundary`. Default severity is
`high`. A reviewer may lower it based on the synthetic resource's declared impact.
Do not claim broad account compromise, privilege escalation, or access to records
that were not tested.

### Required evidence

Record two separately sanitized request/response summaries, stable identity labels
(never tokens), identical normalized path, statuses, safe response headers, body
digests, bounded escaped marker excerpts, marker results, timestamps, target/check
versions, and redaction version. Evidence must show that B's baseline succeeded
before A's request.

## RIFT-CONFIG-001 v1 — transport and header observations

### Purpose

Record a bounded set of observable HTTPS, response-header, and response-cookie
properties. These observations are not exploit validation.

### Required input and prerequisite

- One verified, enabled target and one approved relative path.
- No resource marker or identity is required.

### Requests and rules

Send `HEAD`. If the target returns `405` or `501`, send one `GET` to the same path.
Do not fall back for any other response. Inspect only the final in-scope response.
Record HTTPS use, HSTS, CSP, `X-Content-Type-Options`, `Referrer-Policy`, and every
response `Set-Cookie` value's `Secure`, `HttpOnly`, and `SameSite` attributes.
Persist cookie names but redact cookie values.

### Decision table

| Signal | Outcome | Reason code |
| --- | --- | --- |
| Response inspected and one or more properties absent/weak | `finding` with `needs_review` proposal(s) | `CONFIG_OBSERVATIONS_RECORDED` |
| Response inspected and no catalogue observation applies | `passed` | `NO_CONFIG_OBSERVATION` |
| Redirect leaves scope or response cannot be inspected | `inconclusive` | `CONFIG_RESPONSE_NOT_INSPECTABLE` |
| `HEAD` gets `405`/`501` and fallback cannot complete | `error` | `CONFIG_FALLBACK_FAILED` |
| Network/timeout/size/TLS/`5xx` failure | `error` | matching error code |
| Cancellation observed | `cancelled` | `ASSESSMENT_CANCELLED` |

Create separate observations for: non-HTTPS transport; absent HSTS on HTTPS;
absent CSP on an HTML response; absent/nonsensical `X-Content-Type-Options`;
absent `Referrer-Policy`; and missing `Secure`, `HttpOnly`, or `SameSite` on a
response cookie where the attribute is applicable. Contextual checks belong in
Phase 6 reporting and operator review.

### Severity guidance

Default to `informational`. A reviewer may set `low` when endpoint context supports
the impact. Never label a missing header or cookie attribute as independently
exploitable, and never raise these observations above `low` in V1.

### Required evidence

Store method(s), sanitized URL, status, redirect chain, HTTPS/TLS observation,
the inspected security-header names and sanitized values, cookie names and boolean
attribute presence, timestamps, target/check versions, and redaction version. Do
not store cookie values or the response body for this check.

## Common error and policy reason codes

The controlled client owns stable codes including `SCOPE_REJECTED`,
`PROHIBITED_DESTINATION`, `REDIRECT_REJECTED`, `METHOD_REJECTED`,
`REQUEST_BUDGET_EXHAUSTED`, `ASSESSMENT_DEADLINE_EXCEEDED`, `CONNECT_TIMEOUT`,
`REQUEST_TIMEOUT`, `TLS_VALIDATION_FAILED`, `DNS_RESOLUTION_FAILED`,
`RESPONSE_TOO_LARGE`, and `NETWORK_ERROR`. Checks propagate these codes and do not
translate them into findings.

## Versioning rule

Any change to request count, prerequisite, positive signal, negative signal,
severity ceiling, or evidence meaning creates a new check version. Editorial text
or remediation-link changes may retain the version. Historical results always use
the catalogue version persisted with the assessment snapshot.
