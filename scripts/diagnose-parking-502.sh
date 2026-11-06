#!/usr/bin/env bash
# One-shot diagnosis + fix for Parking → SentinelGW → Parking-API 502s.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
PARKING_PORT="${PARKING_PORT:-8001}"
TARGET_URL="${UPSTREAM_URL:-http://${LAN_IP}:${PARKING_PORT}}"

echo "LAN_IP=${LAN_IP}"
echo "TARGET_URL=${TARGET_URL}"
echo

echo "== A) Host listeners =="
ss -tlnp | grep -E ':(8000|8001|5173|3000)\b' || true
echo

echo "== B) Parking direct on host =="
for u in "http://127.0.0.1:${PARKING_PORT}/docs" "http://${LAN_IP}:${PARKING_PORT}/docs"; do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$u" || echo fail)"
  echo "  $u -> $code"
done
echo

echo "== C) Docker containers =="
docker compose ps
echo

echo "== D) Current Inventory base_urls =="
docker compose exec -T postgres psql -U sentinel -d sentinel_gateway -c \
  "SELECT id, slug, enabled, base_url FROM upstreams ORDER BY id;"
echo

echo "== E) Reachability FROM backend container =="
docker compose exec -T backend python - <<PY
import urllib.request
for url in [
    "http://127.0.0.1:${PARKING_PORT}/docs",
    "http://host.docker.internal:${PARKING_PORT}/docs",
    "http://${LAN_IP}:${PARKING_PORT}/docs",
]:
    try:
        r = urllib.request.urlopen(url, timeout=3)
        print("OK ", url, r.status)
    except Exception as e:
        print("FAIL", url, type(e).__name__, e)
PY
echo

echo "== F) Force Inventory base_url for parking-v2 =="
docker compose exec -T postgres psql -U sentinel -d sentinel_gateway -v ON_ERROR_STOP=1 -c \
  "UPDATE upstreams SET base_url='${TARGET_URL}' WHERE slug='parking-v2'; SELECT id, slug, base_url FROM upstreams WHERE slug='parking-v2';"
echo

echo "== G) Restart backend (clears circuit breakers) =="
docker compose up -d --build backend
docker compose restart backend
sleep 5
for i in $(seq 1 30); do
  if curl -sf --max-time 2 http://127.0.0.1:8000/health >/dev/null; then break; fi
  sleep 2
done
curl -s http://127.0.0.1:8000/health; echo
echo

echo "== H) Gateway login probe (form-urlencoded like Parking expects) =="
curl -sv --max-time 10 -X POST "http://127.0.0.1:8000/gw/parking-v2/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=demo&password=demo" 2>&1 | tail -50

echo
echo "If H still 502: Parking is not reachable from Docker."
echo "Start it with:  uvicorn app.main:app --host 0.0.0.0 --port ${PARKING_PORT} --reload"
echo "Parking frontend API_PREFIX stays: http://${LAN_IP}:8000/gw/parking-v2"
