# Phase 8 security review packet

Date: 2026-09-07

Scope: RIFT V1 source, pilot Compose topology, operator API, worker, controlled HTTP
boundary, encryption, evidence/report lifecycle, and operational procedures. No
public or partner target was scanned.

## Internal review and remediation

| Boundary | Review result | Control or disposition |
| --- | --- | --- |
| Scope escape and SSRF | No open code finding | DNS/IP revalidation, exact immutable scope, global-address checks, CIDR allowlist, and egress firewall regression tests |
| Secret disclosure | No open code finding | AEAD storage, redaction tests, hidden UI values, `no-store`, backup encryption, and documented rotation |
| Unauthorized execution | No open code finding | Single operator authentication, strict CSRF cookie, authorization window, verified target, and final operator review |
| Cross-organization mixing | Review required before pilot | V1 is single operator; ownership constraints exist. An independent reviewer must trace every endpoint before launch. |
| Evidence tampering | No open code finding | AEAD raw blobs, deterministic digests, immutable report artifacts, audit hash monitoring, and restore verification |
| Worker compromise | Risk reduced; external review required | Unprivileged/read-only worker plus network-namespace firewall. Only approved CIDRs on 443 and PostgreSQL are allowed. |
| Resource exhaustion | No open code finding | Fixed request, concurrency, rate, timeout, response, runtime, DB, and disk ceilings |

## Scan plan and triage rules

Run `scripts/security_scan.sh` from a clean checkout. Save machine-readable output in
the private operations evidence store, never Git. The scan covers Python and npm
dependencies, source/application rules, filesystem/container configuration, images,
and Git history secrets. A high or critical item must be reproduced or shown
unreachable, assigned an owner, and resolved before pilot launch. Scanner silence is
not security approval.

### Implementer scan record

The implementer ran the following checks on 2026-09-07 from the working tree that
contains the Phase 8 changes:

| Check | Result |
| --- | --- |
| Ruff security/application rules | Passed |
| pip-audit 2.10.1 against `backend/requirements.lock` | Passed; no known vulnerabilities after upgrading FastAPI/Starlette, cryptography, WeasyPrint, pytest, and pytest-asyncio |
| npm production dependency audit | Passed; zero vulnerabilities |
| Gitleaks 8.30.1 Git-history and working-tree scans, plus Trivy 0.74.0 working-tree secret scan | Passed; zero detected secrets |
| Trivy configuration scan | Passed with the single reviewed exception below |
| Backend production image | Passed; zero fixed high/critical findings |
| Frontend production image | Passed; zero fixed high/critical findings |
| Egress production image | Passed; zero fixed high/critical findings |
| nginx TLS image | Passed; zero fixed high/critical findings |

The scans initially found vulnerable dependency pins and outdated container bases.
Those pins and bases were upgraded, rebuilt, and rescanned. Results are point-in-time
evidence and CI repeats the audits on every push and pull request.

### Time-bounded configuration exception

Trivy rule `AVD-DS-0002` is ignored only for `infra/egress/Dockerfile` until
2026-12-01. The initializer must start with UID 0 and the single `NET_ADMIN`
capability to install default-deny rules in its isolated network namespace. After
the rules are installed, `su-exec` changes the long-running process to UID 10001.
The pilot Compose overlay also uses a read-only root filesystem, a small no-exec
`/tmp`, and `no-new-privileges`. A runtime rehearsal confirmed UID 10001 and an
OUTPUT default policy of `DROP`, with only loopback, established traffic, the exact
database CIDR on TCP 5432, and exact target CIDRs on TCP 443 allowed. Re-review or
replace this design before the exception expires.

## Exit-check rehearsal record

- Encrypted backup/restore: passed against disposable PostgreSQL 16 databases. The
  AES-256-GCM backup was mode `0600`, verification passed, and the restored database
  returned the expected synthetic marker.
- Egress: safety tests passed without making network requests; the container runtime
  rehearsal confirmed the default-deny rules and post-initialization privilege drop.
- Emergency cancellation: the controlled-client cancellation-before-request and
  cancellation-after-DNS tests passed.
- Key rotation: a transactional rehearsal re-encrypted a synthetic credential and
  raw-evidence envelope; both decrypted only through the new key path and the commit
  completed once.

## Independent review gate

An independent application-security reviewer must sign this section before the
first design-partner assessment. The implementer cannot self-certify this gate.

- Reviewer and organization:
- Review date and source commit:
- Tools and manual paths reviewed:
- High/critical findings and resolutions:
- Scope escape verdict:
- Secret disclosure verdict:
- Cross-organization access verdict:
- Evidence/audit integrity verdict:
- Unauthorized execution verdict:
- Approval or rejection:

Pilot deployment remains blocked until every verdict above is explicit and every
unsafe finding is resolved and retested.
