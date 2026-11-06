#!/usr/bin/env bash
# Fix SentinelGW Inventory so Docker can reach the host Parking API.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PARKING_PORT="${PARKING_PORT:-8001}"
# Prefer LAN IP so Docker can reach a uvicorn bound on 0.0.0.0.
# host.docker.internal also works if extra_hosts is set and Parking listens on 0.0.0.0.
LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
UPSTREAM_URL="${UPSTREAM_URL:-http://${LAN_IP:-host.docker.internal}:${PARKING_PORT}}"

echo "==> 1) Is Parking API listening on the host :${PARKING_PORT}?"
if curl -sf --max-time 3 "http://127.0.0.1:${PARKING_PORT}/openapi.json" >/dev/null 2>&1 \
  || curl -sf --max-time 3 "http://127.0.0.1:${PARKING_PORT}/docs" >/dev/null 2>&1; then
  echo "    OK — Parking responds on 127.0.0.1:${PARKING_PORT}"
else
  echo "    FAIL — start Parking bound to ALL interfaces (required for Docker):"
  echo "      cd ~/FastAPI_tutorial/parking-lot"
  echo "      source parking-env/bin/activate   # if you use a venv"
  echo "      uvicorn app.main:app --host 0.0.0.0 --port ${PARKING_PORT} --reload"
  exit 1
fi

echo "    Using Inventory base_url: ${UPSTREAM_URL}"

echo "==> 2) Recreate backend with host.docker.internal mapping..."
docker compose up -d --build backend

echo "==> 3) Set parking-v2 Inventory base_url → ${UPSTREAM_URL}"
docker compose exec -T postgres psql -U sentinel -d sentinel_gateway -v ON_ERROR_STOP=1 <<SQL
UPDATE upstreams
SET base_url = '${UPSTREAM_URL}'
WHERE slug = 'parking-v2';
SELECT id, slug, enabled, base_url FROM upstreams ORDER BY id;
SQL

echo "==> 4) Can backend container reach Parking?"
docker compose exec -T backend python - <<'PY'
import urllib.request
urls = [
    "http://host.docker.internal:8001/openapi.json",
    "http://127.0.0.1:8001/openapi.json",
]
for url in urls:
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            print(f"  OK  {url} -> HTTP {r.status}")
    except Exception as e:
        print(f"  FAIL {url} -> {type(e).__name__}: {e}")
PY

echo "==> 5) Restart backend to clear in-memory circuit breakers (up-2 OPEN state)..."
docker compose restart backend
# Wait until healthy
for i in $(seq 1 30); do
  if curl -sf --max-time 2 "http://127.0.0.1:8000/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo "==> 6) Probe through gateway"
RESP="$(curl -s --max-time 8 "http://127.0.0.1:8000/gw/parking-v2/openapi.json" || true)"
echo "$RESP" | head -c 220
echo
if echo "$RESP" | grep -q '"openapi"'; then
  echo
  echo "SUCCESS — gateway can reach Parking."
elif echo "$RESP" | grep -qi 'circuit breaker'; then
  echo
  echo "Circuit breaker still open on some worker — wait 30s or: docker compose restart backend"
elif echo "$RESP" | grep -qi 'connection\|Bad Gateway\|Could not connect'; then
  echo
  echo "Still cannot connect. Confirm Parking is on 0.0.0.0:${PARKING_PORT} and Inventory URL is ${UPSTREAM_URL}"
fi
echo
echo "Parking frontend API_PREFIX should stay:"
echo "  http://192.168.5.29:8000/gw/parking-v2"
echo "Inventory Backend URL must be:"
echo "  ${UPSTREAM_URL}"
echo
echo "Done. Retry the Parking UI."
