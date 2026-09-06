# RIFT synthetic security lab

The lab is intentionally vulnerable and uses synthetic data only. It must never be
deployed to a public host or pointed at customer systems. The vulnerable and fixed
services share one application and route contract; `RIFT_LAB_MODE` changes only
the security behavior under test.

## Start the lab

From the repository root, create `.env` as described in the root README, then run:

```sh
docker compose --env-file .env \
  -f infra/compose.yaml \
  -f infra/compose.lab.yaml \
  up --build lab-vulnerable lab-fixed
```

The services have no host ports and share only the internal `lab_private` Docker
network. Verify authentication and cross-user behavior from another terminal with
the short-lived verifier container:

```sh
docker compose --env-file .env \
  -f infra/compose.yaml \
  -f infra/compose.lab.yaml \
  run --rm --no-deps lab-fixed \
  python /lab/verify_lab.py \
  --allow-compose-network \
  --vulnerable-base http://lab-vulnerable:8080/ \
  --fixed-base http://lab-fixed:8080/
```

The verification script rejects targets other than loopback or the two exact lab
service names selected with `--allow-compose-network`. Stop the lab with:

```sh
docker compose --env-file .env \
  -f infra/compose.yaml \
  -f infra/compose.lab.yaml \
  down
```

## Deterministic seed

The application loads immutable `fixtures/seed.json` at process start and has no
state-changing routes. Restarting resets it. To create and verify a canonical
runtime copy:

```sh
python3 lab/scripts/reset_seed.py --output /tmp/rift-lab-seed.json
```

Running that command repeatedly produces the same SHA-256 digest. Tokens in the
fixture are synthetic lab-only values and grant access to no external system.

## Failure endpoints

The lab includes public, missing, expired-token, denied, redirect, slow,
oversized-response, server-error, and header/cookie configuration cases. These
exist only to support controlled engine and safety tests in later phases.
