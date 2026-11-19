#!/usr/bin/env bash
# Runs every test and benchmark against a fresh docker-compose stack.
#   bash scripts/reproduce.sh          # results to out/ (committed results/ untouched)
#   RESULTS=results bash scripts/reproduce.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export AEGIS_RESULTS_DIR="${RESULTS:-out}"

python scripts/gen_test_keys.py
docker compose up --build -d
for _ in $(seq 1 90); do curl -sf "${AEGIS_URL:-http://localhost:8000}/ready" >/dev/null && break; sleep 2; done

(cd aegis-server && python -m pytest tests -q)
(cd aegis-sdk && python -m pytest tests -q)
python scripts/seed_tenant.py
python scripts/smoke_test.py
python examples/quickstart.py
python -m benchmarks.attacks
python -m benchmarks.fail_closed
python -m benchmarks.annotation_merge --url "http://localhost:${AEGIS_CEDAR_PORT:-8180}" --label after
python -m benchmarks.latency
python scripts/verify_audit_chain.py
echo "done: results in $AEGIS_RESULTS_DIR/"
