#!/bin/sh
set -eu

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root_dir"

backend/.venv/bin/ruff check --select S backend/src scripts
backend/.venv/bin/python -m pip_audit \
  --cache-dir "${TMPDIR:-/tmp}/rift-pip-audit-cache" \
  --requirement backend/requirements.lock \
  --no-deps
(cd frontend && npm audit --omit=dev --audit-level=high)
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source . --redact --no-banner
  gitleaks dir . --redact --no-banner
else
  trivy fs --scanners secret --exit-code 1 .
fi
trivy config --ignorefile .trivyignore.yaml --severity HIGH,CRITICAL --exit-code 1 .
trivy fs --scanners vuln --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1 \
  --skip-dirs backend/.venv --skip-dirs frontend/node_modules .
docker build --provenance=false --tag rift-api:phase8 backend
docker build --provenance=false --target production --tag rift-frontend:phase8 frontend
docker build --provenance=false --tag rift-egress:phase8 infra/egress
trivy image --sbom-sources= --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1 rift-api:phase8
trivy image --sbom-sources= --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1 rift-frontend:phase8
trivy image --sbom-sources= --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1 rift-egress:phase8
