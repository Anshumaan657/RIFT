# Pilot preflight checklist

Copy this checklist into the operator's secure run record. Replace placeholders
outside Git; never add real hosts, credentials, evidence, or contact details to
this repository.

## Authorization and scope

- [ ] Partner approval reference: `<SIGNED_AUTHORIZATION_REFERENCE>`
- [ ] Testing window: `<UTC_START>` to `<UTC_END>`
- [ ] Escalation contact confirmed: `<SECURE_CONTACT_REFERENCE>`
- [ ] Target is staging or synthetic and explicitly owned by the partner.
- [ ] Exact hostname, port, and base path are recorded in the secure run record.
- [ ] Prohibited actions and stop procedure are agreed.
- [ ] Synthetic resource IDs and unique content markers are confirmed.

## RIFT controls

- [ ] Pilot configuration validation passes with `RIFT_ENVIRONMENT=pilot`.
- [ ] Frontend origin is HTTPS and certificate files are supplied by the secret store.
- [ ] PostgreSQL URL uses certificate verification (`ssl=verify-full`).
- [ ] Target CIDRs and database CIDRs are exact and approved.
- [ ] Target challenge verification is complete and enabled.
- [ ] Required bearer tokens are stored through the operator UI and not copied into notes.
- [ ] Cancellation procedure has been rehearsed against the local lab.
- [ ] Latest encrypted backup exists and its restore verification passed.
- [ ] Worker heartbeat, audit monitoring, and capacity alerts are healthy.

## Execution and closeout

- [ ] Final scope and authorization review completed immediately before queueing.
- [ ] Assessment ID and start/end times recorded in the secure run record.
- [ ] Every finding is manually reviewed; draft reports are not delivered.
- [ ] Report states tested, skipped, failed, and unsupported areas.
- [ ] Report digest and delivery reference are recorded securely.
- [ ] Credentials and raw evidence retention/deletion dates are scheduled.
- [ ] Any issue is recorded using the sanitized issue-log template.
- [ ] Stop the run immediately if scope, authorization, availability, or data sensitivity changes.

