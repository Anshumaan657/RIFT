# Phase 1 JSON examples

These files define synthetic contract examples for Phase 2 Pydantic and JSON
schemas. They are documentation, not executable assessment inputs. Hostnames use
the reserved `.test` domain and credential fields contain references, never tokens.

## Assessment configuration fields

- `schema_version`: configuration contract version (`1`).
- `organization_id`, `application_id`, `authorization_record_id`, `target_id`:
  UUID ownership chain.
- `target`: exact scheme, hostname, port, and normalized base path.
- `local_lab_mode`: false for customer/pilot configurations.
- `selected_checks`: stable check IDs and versions.
- `identity_refs`: stable IDs and labels; no credentials.
- `resource_expectations`: endpoint template, supplied synthetic ID, access class,
  owner reference, marker reference, and non-secret marker used for the example.
- `limits`: requested limits, all at or below server maxima.
- `authorization`: validity window and explicit allowed methods.

At assessment creation, the backend validates these inputs and stores an immutable
snapshot. The real schema also derives target verification/enabled state from
server records rather than trusting the client example.

## Check-result fields

- `schema_version`, `check_id`, and `check_version` identify the result contract.
- `outcome` and `reason_code` use the catalogue values.
- `target_id`, `resource_expectation_id`, and `identity_ids` identify sanitized
  prerequisites.
- `started_at`, `finished_at`, and `request_count` describe execution.
- `evidence_refs` point to stored sanitized evidence.
- `summary` and `limitations` are safe report text.
- `finding_proposals` is empty unless the check proposes findings; each item
  contains only validation state, severity, title, rationale, expected/observed
  behavior, and evidence references. The array permits one configuration request
  to produce separate observations. Human review is still required.

Phase 2 must encode these fields with strict Pydantic models that reject unknown
fields, validate UUIDs/timestamps/enums, and preserve the ownership rules in the
roadmap. Phase 5 may extend results only through a new schema version.
