#!/usr/bin/env bash
# Start SentinelGW with Docker Compose and print office-LAN demo URLs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is not installed. Install Docker Engine + Compose first."
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Cannot talk to the Docker daemon."
  echo "Try: sudo service docker start"
  echo "Or add your user to the docker group, then re-login."
  exit 1
fi

echo "==> Checking ports 5173 and 8000..."
for port in 5173 8000; do
  if command -v ss >/dev/null 2>&1; then
    if ss -tln | grep -qE ":${port}\\b"; then
      # Allow re-run if our own compose stack already owns the port
      if ! docker compose ps --status running --services 2>/dev/null | grep -qE '^(nginx|frontend)$'; then
        echo "Port ${port} is already in use by something else. Stop it first, e.g.:"
        echo "  fuser -k ${port}/tcp"
        echo "  # or Ctrl+C local uvicorn / vite"
        exit 1
      fi
    fi
  fi
done

echo "==> Building and starting stack (Postgres, Redis, backend, nginx, frontend)..."
docker compose up --build -d

echo "==> Waiting for containers..."
for i in $(seq 1 60); do
  backend_ok=0
  nginx_ok=0
  front_ok=0

  if docker compose exec -T backend python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" >/dev/null 2>&1; then
    backend_ok=1
  fi
  if curl -sf --max-time 3 "http://127.0.0.1:8000/health" >/dev/null 2>&1; then
    nginx_ok=1
  fi
  if curl -sf --max-time 3 "http://127.0.0.1:5173/" >/dev/null 2>&1; then
    front_ok=1
  fi

  if [[ "$backend_ok" -eq 1 && "$nginx_ok" -eq 1 && "$front_ok" -eq 1 ]]; then
    break
  fi

  sleep 2
  if [[ "$i" -eq 60 ]]; then
    echo
    echo "Timed out waiting for full readiness."
    echo "  backend inside container: $([[ $backend_ok -eq 1 ]] && echo OK || echo FAIL)"
    echo "  nginx on :8000:           $([[ $nginx_ok -eq 1 ]] && echo OK || echo FAIL)"
    echo "  frontend on :5173:        $([[ $front_ok -eq 1 ]] && echo OK || echo FAIL)"
    echo
    docker compose ps
    echo
    echo "---- nginx logs ----"
    docker compose logs nginx --tail 40
    echo
    echo "---- backend logs ----"
    docker compose logs backend --tail 40
    echo
    if [[ "$backend_ok" -eq 1 ]]; then
      echo "Backend is healthy inside Docker; continuing so you still get the demo URLs."
      break
    fi
    exit 1
  fi
done

PRIVATE_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [[ -z "${PRIVATE_IP}" ]]; then
  PRIVATE_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
fi
if [[ -z "${PRIVATE_IP}" ]]; then
  PRIVATE_IP="<your-private-ip>"
fi

# Quick status line for the URLs we care about
curl -sf --max-time 3 "http://127.0.0.1:8000/health" >/dev/null 2>&1 && API_STATE="up" || API_STATE="check logs"
curl -sf --max-time 3 "http://127.0.0.1:5173/" >/dev/null 2>&1 && UI_STATE="up" || UI_STATE="starting/check logs"

cat <<EOF

SentinelGW is up for office demo.

  Dashboard (share this):  http://${PRIVATE_IP}:5173   [${UI_STATE}]
  API / gateway:           http://${PRIVATE_IP}:8000   [${API_STATE}]
  Local dashboard:         http://127.0.0.1:5173
  Health:                  http://${PRIVATE_IP}:8000/health

Anyone on the same office Wi‑Fi/LAN can open the dashboard link.
This is a private IP — it will not work from the public internet.

Login: use any Demo Persona card on the login page
  (e.g. admin@sentinel.local)

Useful commands:
  docker compose logs -f
  docker compose ps
  docker compose down

EOF
