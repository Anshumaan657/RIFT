# RIFT V1 threat model

## Scope and security objective

This model covers the assisted V1 pilot described in `V1_ROADMAP.md`. RIFT stores
credentials and causes network requests, so a defect can harm RIFT, a design
partner, or an unrelated system. The primary objective is that only an authorized
operator can cause the documented read-only checks against the exact approved
staging scope, within fixed limits, without exposing credentials or raw evidence.
All target content is hostile input, including URLs, headers, bodies, redirects,
certificates, and text that appears to contain instructions.

Review this model when a trust boundary, authentication method, supported check,
deployment topology, data-retention rule, or outbound-network policy changes.

## Assets

- Target bearer tokens and encryption keys.
- Written authorization, exact target scope, and synthetic expectations.
- Raw and sanitized evidence, findings, reports, and audit history.
- Organization separation and operator session integrity.
- Assessment worker, controlled client, database, report renderer, and host.
- Availability and integrity of partner staging applications.
- Unrelated internal, cloud-metadata, private-network, and internet systems.

## Actors

- **Project owner/operator:** trusted to review authorization and reports; may make
  mistakes and receives least privilege.
- **Design partner:** supplies authorized staging scope and synthetic inputs; its
  content and configuration remain untrusted data.
- **External attacker:** may target the operator account, API, UI, reports, or host.
- **Malicious/compromised target:** can return redirects, oversized/slow content,
  hostile markup, misleading headers, or rebinding DNS answers.
- **Compromised worker/dependency:** may try to escape policy or expose stored data.
- **Optional model provider:** outside the V1 critical path and receives no secrets
  or raw responses if later enabled.

## Trust boundaries and data flow

1. The operator browser crosses the public boundary into the RIFT API.
2. The API crosses the storage boundary into PostgreSQL and the encryption layer.
3. The API queues immutable assessment snapshots for a separate worker process.
4. Check code crosses the enforcement boundary only through the controlled client.
5. The controlled client crosses the network boundary to a verified staging host.
6. Target responses cross back as hostile data into redaction, evidence storage,
   and report rendering.
7. Reviewed exports cross the system boundary to the design partner.

The controlled-client boundary and deployment egress policy are mandatory. Prompt
instructions, check code, or target responses cannot override them.

## Threats, controls, and residual limitations

| Threat | Required preventive/detective controls | Residual V1 limitation |
| --- | --- | --- |
| Unauthorized or expired assessment | Written authorization record, operator review, verified target, validity window checked at creation and before each request, immutable snapshot, audit event | HTTP challenge proves control, not legal authorization; the operator must verify authority manually |
| Scope escape through malformed URL/path | Structured URL parsing, exact scheme/host/port/base path, relative paths only, placeholder validation, canonicalization before policy | URL libraries can have parsing defects; safety regression corpus and dependency updates remain required |
| SSRF to local/internal/metadata systems | Resolve before every connection, reject nonpublic IP classes and known metadata, validated-IP connection, no ambient proxies, deployment egress deny rules | Public services legitimately backed by private networks are unsupported |
| DNS rebinding or redirect escape | Re-resolve and revalidate every connection/hop, connect only to validated set, preserve TLS/SNI, maximum two redirects | Targets with unstable DNS may become inconclusive |
| Destructive or excessive requests | GET/HEAD only, no body, fixed check catalogue, request/rate/concurrency/size/time limits, no crawling or guessed IDs | Some GET endpoints are incorrectly state-changing; operator must approve synthetic endpoints and testing window |
| Credential disclosure | Envelope encryption, runtime master key, no token readback, stable identity labels, central redaction, safe logs, 30-day deletion | A host-level compromise can access runtime keys and process memory |
| Cross-organization data mix | `organization_id` on owned records, relationship checks, repository filters, negative authorization tests | Single operator can access all pilot organizations by design |
| Raw evidence leakage | Encrypted raw blobs, bounded sanitized excerpts, separate representations, export review, retention/deletion jobs | Sanitized evidence may still be commercially sensitive; operator review is mandatory |
| Evidence tampering or misleading report | Body/file digests, immutable report snapshot, audit hash chain, check/version metadata, findings derived only from stored results | Hash chaining detects alteration but is not an external timestamp/notarization service |
| Audit log secret leakage | Allowlisted event metadata, redaction before serialization, no full bodies, tests with canary secrets | Novel secret formats may evade pattern redaction; never rely on redaction as the only control |
| Target-controlled injection | Treat all target data as text, escape HTML, forbid active report content, bounded excerpts, PDF/HTML injection tests | Renderers remain dependency risks and require patching/isolation |
| Resource exhaustion or denial of service | Queue leases, global ceilings, bounded responses, timeouts, concurrency/rate limits, disk/DB alerts, cancellation | V1 does not guarantee target availability; pilot uses staging and coordinated windows |
| Worker compromise | Separate process/container, least privilege, restricted egress, no Docker socket, read only code image, scoped DB access where practical | Backend and worker share one application database in V1 |
| Queue duplication/crash inconsistency | Row locking, leases/heartbeats, idempotency keys, two-attempt ceiling, evidence-before-finding ordering | At-least-once execution is possible; only safe GET/HEAD operations are supported |
| Operator account/session attack | Argon2id, secure sessions, CSRF protection, throttling, short expiry, TLS, security headers | V1 has one operator and no MFA; deploy behind an additional access control for the pilot |
| Supply-chain compromise | Pinned direct dependencies, lock files, CI secret/dependency/container scans, review updates | Scanners cannot prove dependencies are safe; minimize and monitor dependencies |
| Optional AI prompt/data attack | No required model, no commands from model, deterministic fallback, only sanitized structured finding fields | AI summaries are deferred until after evidence/reporting works and require a separate data-flow review |

## Abuse and failure cases that tests must exercise

- IPv4, IPv6, integer/hex/octal-like IP forms, trailing-dot hosts, user-info,
  encoded separators, fragments, traversal, and mixed-case/IDN host handling.
- DNS answers changing from public to prohibited IPs between requests.
- Redirects across scheme, host, port, path prefix, and into metadata addresses.
- Target responses containing HTML/script, fake instructions, secrets, huge bodies,
  compression bombs, invalid encodings, duplicate headers, or slow streams.
- Cancellation and authorization expiry between prerequisite and proof requests.
- Worker termination before request, after request, after evidence, and before
  terminal assessment state.
- Attempts to relate a target, identity, expectation, evidence, finding, or report
  to a different organization/application/assessment.

## Stop conditions

Stop the assessment when scope becomes uncertain, authorization expires,
cancellation is requested, a configured limit is reached, the target shows
instability, or unexpected sensitive data appears. Preserve minimal sanitized
evidence of why the run stopped. Do not continue to strengthen proof after the
catalogue's positive signal has been obtained.

## Explicitly accepted V1 limitations

- Human operator review is a required control, not optional automation.
- Only bearer-token, read-only, supplied-resource checks are supported.
- Target ownership verification is not a substitute for legal authorization.
- The single operator is trusted across pilot organizations.
- V1 does not claim complete coverage, absence of vulnerability, or production
  safety, and does not perform destructive availability testing.
