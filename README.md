# SentinelGW — API Security Gateway & Threat Monitoring Platform

**SentinelGW** is a full-stack **API Security Gateway and Real-Time SOC Threat Monitoring Platform** built with **FastAPI** (Python) and **React + TypeScript + Tailwind CSS**. Every gateway enforcement stage, behavioral anomaly detector, and vulnerable demo endpoint is grounded in the **OWASP API Security Top 10**.

---

## Architecture Highlights

1. **10-Stage Reverse Proxy Security Pipeline (**`/gw/{path:path}`**)**
   - **Stage 1 — Context & Correlation**: Assigns `X-Request-ID` UUID, client IP extraction, and high-precision latency timer.
   - **Stage 2 — Blocklist Quarantine**: Instant `403` rejection for blocked IPs, users, or API keys.
   - **Stage 3 — Route Matching & Shadow API Discovery (**`API9`**)**: Matches against the registered route inventory and flags undocumented/legacy endpoints.
   - **Stage 4 — 8-Step Cryptographic JWT & API Key Validator (**`API2`**)**: Enforces `alg` whitelist (blocks `alg:none`), HMAC signature verification, `exp`, `nbf`, `iat` (+30s skew limit), `iss`, `aud`, and `jti` revocation check.
   - **Stage 5 — Object & Function Level Authorization (**`API1` **BOLA &** `API5` **BFLA)**: Enforces role/scope RBAC and verifies JWT owner claims against path, query, and body object IDs (with learned-owner cache + enumeration caps).
   - **Stage 6 — Hybrid Rate Limiter (**`API4` **&** `API6`**)**: Redis **fixed-window counter** for sustained RPM plus a Redis **token bucket** for burst control, with per-principal sensitive-flow caps, `X-RateLimit-`*, and `Retry-After` headers.
   - **Stage 7 — Deep Payload & Query Inspector (**`API3`**,** `API4`**,** `API7`**,** `API8`**)**: JSON Schema validation, nested mass-assignment blocking, DNS-resolved SSRF (incl. decimal/IPv4-mapped IPs), normalized SQLi/XSS/traversal signatures, and policy-driven size/pagination caps.
   - **Stage 8 — Async Upstream Forwarding**: Proxies via a pooled HTTPX client with per-upstream circuit breaker and private-IP redirect pinning.
   - **Stage 9 — Response Hardening, PII Redaction & Unsafe Consumption (**`API3`**,** `API8`**,** `API10`**)**: Strips sensitive fields and pattern-matched SSN/PAN values, sanitizes all 5xx bodies, and strips/blocks third-party webhook URLs targeting private/metadata hosts.
   - **Stage 10 — Real-Time Threat Detection & WebSocket Broadcast**: Evaluates behavioral/signature rules + rolling Z-score baselines, deduplicates alerts, optional critical-alert webhooks, and streams events over `/ws/live`.
2. **Demo Project — VulnShop (`/demo/*`)**
   - **VulnShop** is the built-in demo project: an intentionally vulnerable e-commerce API covering **all 10** OWASP API Top 10 categories (including `/supplier/catalog` for API10). Use the **Gateway ON/OFF Switch** in the Attack Simulator to compare unprotected exploit output against gateway-protected responses side by side.

---

## Quick Start

### Option A: Local Development (Zero External Dependencies)

SentinelGW defaults to SQLite (`sentinel_gateway.db`). Set `REDIS_URL` (for example `redis://127.0.0.1:6379/0`) to store rate-limit counters and burst-detection history in Redis. With no Redis URL, those same fixed-window and token-bucket rules run in process memory.

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

Open `http://localhost:5173` and click any of the **4 Demo Persona Cards** on the login page.

### Option B: Docker Compose (Postgres, Redis, multiple workers)

```bash
docker compose up --build
```

This starts Postgres, Redis, 4 Uvicorn workers behind nginx on port `8000`, and the dashboard on port `5173`. To add more API processes:

```bash
docker compose up --build --scale backend=3
```

Local development without Docker still uses SQLite. Set `REDIS_URL` and a Postgres `DATABASE_URL` when you want the same shared-state path on a laptop.

---

## How SentinelGW Protects Your Application

1. **Any Caller Sends a Request**: Your web/mobile app, Postman, `curl`, or an external client calls `http://localhost:8000/gw/...` (or `/gw/docs` for the protected Swagger UI).
2. **SentinelGW Inspects & Enforces Live**: Blocks SQL Injection, SSRF, forged/expired JWT tokens, object ID tampering (BOLA), and rate-limit floods in `<5ms`, and automatically quarantines critical offending IPs.
3. **Clean Traffic Reaches Your Backend**: Only validated requests are forwarded to your upstream service (e.g. `:8001`, `:2340`, or any cloud URL), with sensitive response fields masked before returning to the caller.

---

## How to Use SentinelGW by Role

- **Platform Administrator**:
  - Manage users and RBAC roles in **Users & Access** (`/settings`) and reset or re-seed telemetry data.
  - Control the Gateway Master Protection Switch (`ON`/`OFF`) in the top bar or Attack Simulator.
  - Configure global and per-project JWT signing secrets, issuer/audience binding, and automated blocklist rules.
- **SOC Security Analyst**:
  - Monitor real-time traffic in **Overview** (`/`) and **Live Traffic** (`/traffic`).
  - Investigate correlated incidents in **Security Alerts** (`/alerts/:id`) and review automated triage findings.
  - Execute containment actions: block offending IPs, block user principals, or revoke JWT `jti` identifiers.
  - Tune policies between `Monitor` (dry-run) and `Enforce` (block) in **Security Policies** (`/policies`).
- **API Owner / Developer**:
  - Register upstream APIs and import OpenAPI 3.0 JSON/YAML specs in **API Inventory** (`/inventory`).
  - Review discovered Shadow APIs (`OWASP API9`) and register or block undocumented routes.
  - Configure per-route rate limits and token bucket bursts (`/rate-limits`) and test burst behavior.
  - Validate tokens with the 8-step JWT Token Tester (`/auth-settings`) and manage consumer API keys.
- **Compliance Auditor**:
  - Audit OWASP API Security Top 10 coverage in **OWASP Top 10** (`/owasp`).
  - Review `p50`/`p95`/`p99` gateway latency percentiles and client rate anomalies in **Analytics** (`/analytics`).
  - Export CSV traffic/alert logs and printable summary reports in **Reports** (`/reports`).

---

## Documentation

Hackathon delivery set:

- **[Research](docs/RESEARCH.md)**: Existing Indian and global API products, the business processes they follow, and the roles, rules, and exception cases that came out of that research.
- **[Application documentation](docs/APPLICATION.md)**: Requirements, permissions, business rules, exception handling, and how to operate the console. Includes the map to the twelve common expectations.
- **[Developer guide](docs/DEVELOPER_GUIDE.md)**: Tech stack, architecture, environment variables, tests, third-party integrations, and Docker deployment.
- **[Lessons learned](docs/LESSONS_LEARNED.md)**: Assumptions, limitations, deliberate exclusions, and how AI output was checked.
- **[AI review report](docs/AI_REVIEW_REPORT.md)**: Review of the delivery against the code and the test run.

Supporting documents already in the repo:

- **[Product Overview](docs/PRODUCT_OVERVIEW.md)**: Feature list, OWASP mapping, tool comparison, and a basic how-to.
- **[Project Proposal & Implementation Plan](docs/PROJECT_PROPOSAL_AND_IMPLEMENTATION_PLAN.md)**: Original planning document. The application documentation describes what was built.
- **[Role-Based User & Operational Guide](docs/ROLE_BASED_USER_GUIDE.md)**: Click-by-click playbooks. Prefer the simulator screen for the current attack list.
- **[Codebase Guide](docs/CODEBASE_GUIDE.md)**: File-by-file map of the repository.
