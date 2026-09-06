# ADR 0003: Encrypted credentials and evidence in PostgreSQL

- Status: Accepted
- Date: 2026-09-06

## Context

RIFT needs enough evidence to reproduce findings while protecting bearer tokens
and potentially sensitive target responses. Normal logs and Git are not evidence
stores.

## Decision

Store structured metadata and application-encrypted credential/raw-evidence blobs
in PostgreSQL. Use envelope encryption with a runtime master key loaded from the
deployment secret store, or a local environment variable during development.
Persist key identifiers and versioned ciphertext, never the master key. Produce a
separate deterministic sanitized representation for findings and reports.

Use the Python `cryptography` package and AES-256-GCM. Generate a random 256-bit
data-encryption key and 96-bit nonce for every blob. Encrypt the blob with the data
key, then wrap that data key with the current 256-bit master key using AES-256-GCM
and a separate random 96-bit nonce. Authenticate the schema version, organization
ID, record type, record ID, and master-key ID as associated data. Store ciphertext,
both nonces, wrapped data key, algorithm, schema version, and master-key ID. Never
reuse a nonce with the same key. Decryption must fail closed on authentication-tag
failure. Rotation rewraps data keys under a new master key without decrypting and
reencrypting the evidence blob.

Do not return raw tokens or raw evidence through the V1 API. Default deletion is
30 days for target credentials and raw evidence and 180 days for sanitized
reports, with earlier operator deletion supported. Audit creation, access,
rotation, and deletion without logging contents.

## Consequences

Database compromise alone should not reveal blob contents, while compromise of
the running host may expose keys. Key rotation, backup encryption, restore, and
redaction tests are required before the pilot. Large binary evidence and object
storage are deferred because V1 bounds every response to 1 MiB and stores minimal
proof.
