# SentinelGW — API Security Gateway & Threat Monitoring Platform

**SentinelGW** is a full-stack **API Security Gateway and Real-Time SOC Threat Monitoring Platform** built with **FastAPI** (Python) and **React + TypeScript + Tailwind CSS**. Every gateway enforcement stage, behavioral anomaly detector, and vulnerable demo endpoint is grounded in the **OWASP API Security Top 10 (2023 Edition)**.

---

## Architecture Highlights

1. **10-Stage Reverse Proxy Security Pipeline (`/gw/{path:path}`)**
   - **Stage 1 — Context & Correlation**: Assigns `X-Request-ID` UUID, client IP extraction, and high-precision latency timer.
   - **Stage 2 — Blocklist Quarantine**: Instant `403` rejection for blocked IPs, users, or API keys.
   - **Stage 3 — Route Matching & Shadow API Discovery (`API9:2023`)**: Matches against the registered route inventory and flags undocumented/legacy endpoints.
   - **Stage 4 — 8-Step Cryptographic JWT & API Key Validator (`API2:2023`)**: Enforces `alg` whitelist (blocks `alg:none`), HMAC signature verification, `exp`, `nbf`, `iat` (+30s skew limit), `iss`, `aud`, and `jti` revocation check.
   - **Stage 5 — Object & Function Level Authorization (`API1:2023` BOLA & `API5:2023` BFLA)**: Enforces role RBAC (`admin` vs `customer`) and verifies JWT `sub` ownership against path `{id}` parameters.
   - **Stage 6 — Hybrid Rate Limiter (`API4:2023` & `API6:2023`)**: Combines **Sliding Window Counter** + **Token Bucket** burst control with `X-RateLimit-*` and `Retry-After` headers.
   - **Stage 7 — Deep Payload & Query Inspector (`API3`, `API4`, `API7`, `API8`)**: Blocks SSRF internal IP/metadata targets, SQLi/NoSQLi/XSS/Command Injection/Path Traversal, Mass Assignment fields (`role`, `is_admin`, `balance`), and excessive pagination (`?limit=5000`).
   - **Stage 8 — Async Upstream Forwarding**: Proxies validated requests to the target upstream (`VulnShop`).
   - **Stage 9 — Response Hardening & PII Redaction (`API3:2023` & `API8:2023`)**: Strips sensitive fields (`password_hash`, `ssn`, `secret_mfa_seed`, `credit_card_last4`), removes leaky `Server`/`X-Powered-By` headers, injects `CSP`/`HSTS`/`X-Frame-Options`, and sanitizes `500` stack traces.
   - **Stage 10 — Real-Time Threat Detection & WebSocket Broadcast**: Evaluates 12 behavioral/signature rules + rolling Z-score client baseline ($Z = \frac{x - \mu}{\sigma}$), deduplicates alerts, auto-blocks critical offenders, and streams events over `/ws/live`.

2. **Intentionally Vulnerable Target API (`VulnShop` at `/demo/*`)**
   - Built-in e-commerce API containing 9 exploitable OWASP API Top 10 vulnerabilities. Use the **Gateway ON/OFF Switch** in the Attack Simulator to compare unprotected exploit output against gateway-protected responses side by side.

---

## Quick Start

### Option A: Local Development (Zero External Dependencies)

SentinelGW defaults to SQLite (`sentinel_gateway.db`) and an in-memory sliding-window/token-bucket store, so it runs out of the box with zero external containers required.

```bash
# 1. Start Backend (Port 8000)
cd backend
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# 2. Start Frontend (Port 5173)
cd ../frontend
npm install
npm run dev
```

Open **`http://localhost:5173`** and click any of the **4 Demo Persona Cards** on the login page.

### Option B: Docker Compose

```bash
docker compose up --build
```

---

## Documentation

- **[Role-Based User & Operational Guide](docs/ROLE_BASED_USER_GUIDE.md)**: Complete walkthroughs for `Admin`, `SOC Analyst`, `API Developer`, `Compliance Viewer`, and `API Consumer` roles, plus a 5-minute Judge Demo script.
