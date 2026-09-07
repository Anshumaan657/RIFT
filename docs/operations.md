# RIFT V1 pilot operations

This runbook applies only to the assisted V1 pilot. The operator must have written
authorization for each staging target, synthetic fixtures, an agreed window, and an
emergency contact. Production application targets remain prohibited.

## Deployment boundary

Use a dedicated host and a dedicated managed PostgreSQL database with certificate-
validated TLS. Copy
`.env.pilot.example` to a secret-managed environment file outside Git. Replace every
placeholder. `RIFT_ALLOWED_TARGET_CIDRS` must contain the partner's exact public
IPv4 CIDRs, normally `/32`; broad networks and non-global ranges are rejected.

The pilot overlay provides:

- unprivileged nginx TLS termination with an operator-supplied certificate and HSTS;
- an unprivileged static frontend and unprivileged API/worker containers;
- read-only root filesystems, dropped capabilities, and `no-new-privileges`;
- internal database and UI networks;
- a shared worker/egress network namespace whose firewall permits PostgreSQL and
  approved target CIDRs on TCP 443 and managed database CIDRs on TCP 5432, then
  drops all other outbound traffic;
- worker heartbeat health checks and an hourly maintenance process.

Validate configuration before starting:

```sh
docker compose --env-file /secure/path/rift-pilot.env \
  -f infra/compose.yaml -f infra/compose.pilot.yaml config --quiet
docker compose --env-file /secure/path/rift-pilot.env \
  -f infra/compose.yaml -f infra/compose.pilot.yaml up --build -d
docker compose --env-file /secure/path/rift-pilot.env \
  -f infra/compose.yaml -f infra/compose.pilot.yaml ps
```

The pilot overlay disables the local PostgreSQL service; `RIFT_DATABASE_URL` and
`RIFT_DATABASE_CIDRS` must name the managed database. Do not expose API, worker,
maintenance, or frontend container ports. Only the TLS service publishes port 443.

## Preflight and monitoring

Before an assessment, confirm the authorization window, escalation contact,
verified DNS/IP set, exact CIDR firewall value, synthetic identities, unique content
markers, request budget, free capacity, worker health, and backup age.

Run the monitor on demand:

```sh
docker compose --env-file /secure/path/rift-pilot.env \
  -f infra/compose.yaml -f infra/compose.pilot.yaml exec maintenance \
  python -m rift.maintenance.main monitor
```

Treat any invalid audit chain as a security incident. Capacity warnings fire when
the database reaches 5 GiB or free container disk falls to 1 GiB by default. Change
thresholds to match the host, while keeping alerting conservative.

## Emergency cancellation

1. Use **Cancel assessment** in the operator console.
2. Confirm the state moves through `cancelling` to `cancelled` and worker requests stop.
3. If the console is unavailable, stop the worker container immediately:

   ```sh
   docker compose --env-file /secure/path/rift-pilot.env \
     -f infra/compose.yaml -f infra/compose.pilot.yaml stop worker
   ```

4. Preserve API, worker, egress, and database logs. Do not delete evidence.
5. Contact the partner and record the time, assessment ID, request count, reason,
   and operator. Restart only after the cause is understood and authorization is
   reconfirmed.

Rehearse cancellation against the local synthetic lab before every pilot window.

## Encrypted backup and restore

Keep `RIFT_BACKUP_KEY_B64` distinct from the application master key and outside the
database host. The backup command uses PostgreSQL custom format and AES-256-GCM,
writes mode `0600`, and never prints keys.

```sh
PYTHONPATH=backend/src backend/.venv/bin/python scripts/database_backup.py create \
  /secure/backups/rift-$(date -u +%Y%m%dT%H%M%SZ).dump.enc
PYTHONPATH=backend/src backend/.venv/bin/python scripts/database_backup.py verify \
  /secure/backups/rift-YYYYMMDDTHHMMSSZ.dump.enc
```

Test restore only into an empty, isolated rehearsal database. Set
`RIFT_RESTORE_DATABASE_URL`, then provide its database name explicitly:

```sh
PYTHONPATH=backend/src backend/.venv/bin/python scripts/database_backup.py restore \
  /secure/backups/rift-YYYYMMDDTHHMMSSZ.dump.enc \
  --confirm-database rift_restore_rehearsal
```

After restore, run migrations, compare row counts, verify audit chains with the
monitor command, open one sanitized report, and delete the rehearsal database.
Record the backup digest, timestamps, operator, source/restore PostgreSQL versions,
and outcome in the operations log. Perform this rehearsal before pilot launch and
monthly during the pilot.

## Rollback

Never roll back the database by running Alembic downgrade on pilot data. Stop new
assessments, stop the worker and maintenance containers, preserve logs, deploy the
last reviewed application image, and run its forward-compatible migrations. Restore
the encrypted pre-deployment backup into a new database only when forward recovery
is impossible. Point the stack at that new database after integrity verification.

## Key and credential rotation

For an application master-key rotation, stop API, worker, and maintenance; back up
the database; set the new `RIFT_MASTER_KEY_B64` and supply the old key temporarily as
`RIFT_PREVIOUS_MASTER_KEY_B64`; then run:

```sh
python -m rift.maintenance.main rotate-key
```

Unset and destroy the old key, restart services, verify one synthetic credential in
the local lab, and run the audit monitor. The rotation is transactional: any failed
decrypt aborts without committing partial ciphertext changes.

Replace a target bearer token in the operator console and revoke the prior token at
the target. Rotate the operator password by generating a new Argon2id hash, updating
the secret, and restarting API/worker; existing signed sessions must be treated as
revoked by also rotating the session secret.

## Retention and early deletion

The fixed V1 maximums are:

- encrypted raw evidence: 30 days after assessment completion;
- target bearer credentials: 30 days after the application's last completed assessment;
- sanitized generated reports: 180 days after assessment completion.

The maintenance service applies these every hour. Operators may delete credentials,
raw evidence, or reports earlier through the authenticated API. Raw purge keeps the
sanitized representation and digest while replacing the encrypted blob with a purge
marker. Report source drafts cannot be deleted before reviewed derivatives.

Run retention manually after an approved early-deletion request:

```sh
python -m rift.maintenance.main retention
```

Record the organization, assessment IDs, requestor, legal basis, timestamp, and
returned deletion counts. Never place those records in Git.

## Incident response

Stop scheduling assessments when scope escape, unexpected traffic, secret exposure,
audit failure, target instability, or sensitive real data is suspected. Stop the
worker, preserve logs and encrypted evidence, rotate affected credentials and keys,
notify the partner contact, determine the first/last affected events, and document
containment. Restore service only after the smallest relevant local regression test
and independent security approval pass.

For suspected database compromise, rotate database, application, backup, session,
operator, and target credentials. Restore into a new host from the last verified
encrypted backup, validate audit chains, and compare assessment/report digests.

## Disaster recovery

Recovery order is secrets and TLS certificate, PostgreSQL, migrations, API,
maintenance, egress firewall, worker, frontend, then TLS proxy. Validate database and
worker readiness, audit integrity, retention status, and an end-to-end run against
the local fixed lab before reopening a partner window. Recovery is unsuccessful if
any audit chain or reviewed report digest cannot be verified.
