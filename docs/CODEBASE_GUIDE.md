# SentinelGW Codebase Guide

A plain-language map of the whole project: how a request flows end to end, what each folder is for, and what every important file and function does.

Use this when you need to explain the system in a demo, walk a teammate through the repo, or find where a feature lives.

---

## 1. What this app is (in one minute)

**SentinelGW** is two products in one process:

1. **A reverse-proxy security gateway** at `/gw/*`  
   Clients call SentinelGW instead of the real API. SentinelGW checks the request (auth, rate limits, injection, SSRF, etc.), then either blocks it or forwards it to the connected backend.

2. **A management dashboard** (React UI + `/api/v1/*` APIs)  
   Admins, analysts, developers, and viewers log in, pick an API project, watch live traffic, investigate alerts, tune policies, import OpenAPI routes, and run attack simulations.

There is also a built-in intentionally vulnerable demo API at `/demo/*` (**VulnShop**) so you can prove the gateway works without connecting an external service.

```text
Browser / Postman / Mobile app
        │
        ▼
┌───────────────────┐     management UI calls      ┌────────────────────┐
│  React dashboard  │ ───────────────────────────► │  /api/v1/* control │
│  (port 5173)      │ ◄──── WebSocket /ws/live ─── │  plane (FastAPI)   │
└───────────────────┘                              └─────────┬──────────┘
                                                             │
API clients ──► /gw/{slug}/... ──► 10-stage pipeline ────────┤
                                                             ▼
                                                    Upstream API project
                                                    (or /demo VulnShop)
```

---

## 2. End-to-end flows

### 2.1 Protected API traffic (the main product path)

1. Client sends `GET /gw/parking-api/parking/availability` (or `/gw/...` without a slug for the default project).
2. FastAPI routes that to `gateway/proxy.py` → `execute_gateway_pipeline()` in `gateway/pipeline.py`.
3. Pipeline stages (simplified):
   - Build request context (ID, IP, timing, which project).
   - Honor gateway ON/OFF switch (`runtime_state`).
   - Check blocklist (IP / user / API key).
   - Match route inventory or discover a **shadow** route.
   - Validate JWT / API key.
   - Check BOLA / BFLA (object and function authorization).
   - Apply rate limits (per project + IP + user + route).
   - Inspect payload (SQLi, XSS, SSRF, mass assignment, oversized body).
   - Forward to upstream with HTTPX (or local ASGI for `/demo`).
   - Harden the response (strip headers, redact PII).
   - Log the request and run detection (threat score, alerts, WebSocket broadcast).
4. Client gets either the upstream response or a gateway block (`403` / `401` / `429` / `502`).

### 2.2 Dashboard login and pages

1. User opens `http://localhost:5173` → `LoginPage`.
2. Frontend `POST /api/v1/auth/login` → backend issues a **dashboard JWT** (different from consumer API JWTs).
3. Token is stored in Zustand + `localStorage`.
4. `RequireAuth` in `App.tsx` wraps all pages; every `apiFetch` sends `Authorization: Bearer …`.
5. `MainLayout` loads projects, connects `/ws/live`, shows Observing Project selector, gateway ON/OFF, time range.
6. Each page calls its `/api/v1/...` endpoint filtered by `selectedProjectId`.

### 2.3 Attack Simulator

1. UI picks a scenario (BOLA, JWT tamper, SSRF, …) for the **currently selected project**.
2. `POST /api/v1/simulator/run` → `attack_sim/scenarios.py` builds requests against `/gw/{slug}/...`.
3. Targeting helpers in `attack_sim/targeting.py` pick the best matching routes from that project’s inventory (or mark N/A).
4. Results show whether SentinelGW blocked the attack or the request reached upstream.

---

## 3. Repository map

```text
API Gateway/
├── backend/                 # FastAPI app (gateway + control plane + demo API)
│   ├── app/
│   │   ├── main.py          # App entry: mounts routers, health, metrics
│   │   ├── config.py        # Env settings
│   │   ├── db.py            # SQLModel engine, tables, indexes
│   │   ├── models.py        # Database tables
│   │   ├── schemas.py       # Pydantic request/response bodies for APIs
│   │   ├── seed.py          # Demo users, VulnShop routes, sample data
│   │   ├── runtime_state.py # Shared ON/OFF + auto-block switches
│   │   ├── runtime_cache.py # Short TTL cache + Redis invalidation
│   │   ├── api/v1/          # Management REST + WebSocket
│   │   ├── gateway/         # Proxy pipeline and security helpers
│   │   ├── detection/       # Scoring, rules, anomaly, AI triage
│   │   ├── attack_sim/      # Adaptive attack scenarios
│   │   └── demo_api/        # VulnShop vulnerable upstream
│   ├── tests/               # Pytest suite
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/                # React + TypeScript + Tailwind dashboard
│   ├── src/
│   │   ├── main.tsx         # React mount
│   │   ├── App.tsx          # Routes + auth gate
│   │   ├── index.css        # Global styles
│   │   ├── pages/           # One screen per feature
│   │   ├── components/      # Layout + shared UI
│   │   ├── lib/api.ts       # HTTP helpers
│   │   ├── store/           # Zustand global state
│   │   └── types/api.ts     # Shared TS types
│   ├── vite.config.ts       # Dev server + API proxy
│   └── Dockerfile
├── nginx/nginx.conf         # Docker load balancer in front of workers
├── docker-compose.yml       # Postgres + Redis + backend + nginx + frontend
├── docs/                    # Guides (this file, proposal, role guide)
└── README.md
```

---

## 4. Backend core files

### 4.1 `backend/app/main.py` — application entry

Wires everything together.

| Symbol | What it does |
|--------|----------------|
| `lifespan()` | On startup: create DB tables, seed demo data, start WebSocket manager. On shutdown: stop WS, close HTTP client. |
| `app` | The FastAPI application instance. |
| Router mounts | `/demo` VulnShop, `/api/v1/*` control plane (most require login), `/ws/live`, `/gw/{path}`. |
| `health_check()` | Returns DB/Redis/rate-limit backend status for Docker/ops. |
| `prometheus_metrics()` | Simple text metrics (request counts, open alerts) without a separate Prometheus stack. |

CORS is intentionally open (`allow_origins=["*"]`) for demos; production hardening would tighten this.

### 4.2 `backend/app/config.py` — settings

| Symbol | What it does |
|--------|----------------|
| `Settings` | Reads env / `.env`: database URL, Redis URL, JWT secrets, default upstream, auto-block, webhook, response size cap. |
| `settings` | Singleton used everywhere. |

Important distinction:

- `DASHBOARD_JWT_*` — tokens for people logging into the UI.
- `GATEWAY_JWT_*` — default verification settings for **API consumer** tokens hitting `/gw/*` (per-project overrides live in `UpstreamJWTConfig`).

### 4.3 `backend/app/db.py` — database connection

| Symbol | What it does |
|--------|----------------|
| `_build_engine()` | SQLite for local demos; pooled Postgres when `DATABASE_URL` is Postgres. |
| `_configure_sqlite()` | WAL mode and busy timeout so concurrent reads/writes behave better. |
| `_ensure_indexes()` | Extra indexes on logs/alerts/blocklist. |
| `_add_column_if_missing()` / `_ensure_extra_columns()` | Lightweight schema upgrades without Alembic (adds new columns if missing). |
| `create_db_and_tables()` | `create_all` + SQLite tweaks + columns + indexes. |
| `get_session()` | FastAPI dependency that yields a SQLModel session. |
| `check_database()` | Used by `/health`. |

### 4.4 `backend/app/models.py` — tables

Time helpers:

| Function | What it does |
|----------|----------------|
| `utcnow()` | Current UTC timestamp. |
| `to_ist()` / `to_ist_iso()` | Convert timestamps to India Standard Time for display APIs. |

Tables (each is a SQLModel class mapped to one SQLite/Postgres table):

| Model | Purpose |
|-------|---------|
| `Organization` | Tenant/org for dashboard users. |
| `User` | Dashboard accounts (`admin` / `analyst` / `developer` / `viewer`). |
| `Upstream` | A connected API project (name, slug, base URL, OpenAPI JSON). |
| `UpstreamJWTConfig` | Per-project JWT secret/issuer/audience settings. |
| `Route` | One HTTP operation: path pattern, auth, rate limits, BOLA flags, redaction fields, shadow vs registered. |
| `Policy` | Security rule config (`enforce` vs `monitor`) tied to OWASP IDs. |
| `ApiKey` | Consumer API keys (hashed). |
| `RequestLog` | Every gateway request: decision, threat score, bodies preview, OWASP id. |
| `Alert` | Correlated security incidents with notes and AI triage JSON. |
| `BlocklistEntry` | Quarantined IP / user / API key. |
| `RevokedToken` | Revoked JWT `jti` values. |
| `ClientBaseline` | Per-client traffic mean/std for anomaly Z-scores. |

### 4.5 `backend/app/schemas.py` — API body shapes

Pydantic models for control-plane requests/responses (validation + OpenAPI docs):

| Schema | Used for |
|--------|----------|
| `LoginRequest` / `RegisterRequest` / `LoginResponse` / `UserOut` / `OrganizationOut` | Auth |
| `TokenTestRequest` / `TokenMintRequest` | JWT tester |
| `PolicyCreate` / `PolicyUpdate` | Policies page |
| `AlertActionRequest` / `AlertBulkActionRequest` | Incident response |
| `BlocklistCreateRequest` | Blocklist |
| `RouteCreateRequest` / `OpenAPIImportRequest` | Inventory |
| `RateLimitBurstTestRequest` | Rate-limit lab |
| `SimulatorRunRequest` / `SimulatorTokenValidateRequest` | Attack Simulator |

### 4.6 `backend/app/seed.py` — first-run demo data

| Function | What it does |
|----------|----------------|
| `ensure_demo_organization()` | Creates the default org if missing. |
| `ensure_seeded_users()` | Creates the four demo personas (`admin@…`, `analyst@…`, …) without wiping real registered users. |
| `seed_all_data()` | Seeds VulnShop upstream/routes, policies, sample logs/alerts when DB is empty (or when force reset). |
| `backfill_route_security_defaults()` | Fills BOLA/auth metadata on older imported routes. |

### 4.7 `backend/app/runtime_state.py` — live switches

| Symbol | What it does |
|--------|----------------|
| `_as_bool()` | Parses `"true"` / `"1"` / etc. |
| `GatewayRuntimeState` | Shared flags: gateway enabled, auto-block critical, duration, anomaly threshold. Uses Redis hash when available so all workers agree. |
| `gateway_state` | Global instance read by the pipeline and simulator toggle. |

### 4.8 `backend/app/runtime_cache.py` — short caches

| Symbol | What it does |
|--------|----------------|
| `VersionedTTLCache` | Process-local cache with TTL; generation counter in Redis so any worker’s write invalidates everyone’s cache. |
| `get` / `set` / `invalidate` / `current_gen` | Cache operations. |
| `_bump_cache()` | SQLAlchemy listener: after insert/update/delete on Policy, Blocklist, Upstream, Route → invalidate. |
| `runtime_cache` | Shared instance used when the pipeline loads upstreams/blocklists. |

---

## 5. Gateway package (`backend/app/gateway/`)

This is the heart of request protection.

### 5.1 `proxy.py` — HTTP entry for `/gw`

| Function | What it does |
|----------|----------------|
| `gateway_catch_all()` | Catch-all route for all methods under `/gw/{path:path}`. Forwards into the pipeline. |

### 5.2 `pipeline.py` — 10-stage security pipeline

Largest file. Main function:

| Function | What it does |
|----------|----------------|
| `execute_gateway_pipeline()` | Full request lifecycle: resolve project (slug or default), run stages, forward or reject, log + detect. |

Helpers:

| Function | What it does |
|----------|----------------|
| `_build_synthesized_openapi_spec()` | Builds OpenAPI JSON from registered routes when upstream has no real `/openapi.json`. |
| `_build_synthesized_swagger_html()` | Minimal Swagger HTML pointing at the gateway. |
| `_rewrite_swagger_if_needed()` | Rewrites proxied `/docs` / `/redoc` / `/openapi.json` so “Try it out” goes through `/gw/...`. |
| `_mask_sensitive_headers()` | Hides Authorization / cookies in stored logs. |
| `_cached_upstreams()` / `_cached_active_blocklist()` | Cached DB reads. |
| `_is_blocked()` | Matches client IP / user / API key against active blocklist. |
| `_detect_firebase_spa_config()` | Heuristic: if upstream looks like a Firebase-hosted SPA, find API config. |
| `_to_firestore_fields()` / `_from_firestore_doc()` | Firestore document field converters for the SPA bridge. |
| `_bridge_firebase_spa_request()` | Optional translation layer for certain Firebase SPA backends. |
| `_forward_to_upstream()` | Sends the allowed request to the real backend (HTTPX) or local VulnShop ASGI; uses circuit breaker. |
| `_reject_request()` | Builds a blocked response and records the event. |
| `_dispatch_record()` / `_record_and_detect_background()` / `_record_and_detect()` | Persist `RequestLog` and kick detection (often as a background task so the client isn’t delayed). |

**Stage map inside `execute_gateway_pipeline` (mental model):**

1. Context (request id, IP from `X-Simulated-Client-IP` / `X-Forwarded-For` / socket).
2. Gateway mode (bypass still logs).
3. Blocklist.
4. Route match / shadow discovery + counters.
5. Authentication (JWT checklist / API key).
6. Authorization (BFLA roles/scopes, BOLA ownership + enumeration caps).
7. Rate limits (login lockout, sensitive-flow caps, hybrid RPM+burst).
8. Payload inspection.
9. Upstream forward + response hardening.
10. Logging + detection + WebSocket.

### 5.3 `auth.py` — consumer JWT and API keys

| Function / class | What it does |
|------------------|----------------|
| `_fetch_google_firebase_certs()` | Caches Google x509 certs for Firebase RS256 tokens. |
| `_prepare_verification_key()` | Normalizes pasted PEM/certs/Firebase maps into something PyJWT can use. |
| `JWTConfigRuntime` | In-memory holder for default gateway JWT settings. |
| `get_upstream_jwt_config()` | Loads per-project JWT verification settings. |
| `_b64url_decode()` / `_b64url_encode()` | JWT segment helpers. |
| `_fail_step()` | Records which checklist step failed. |
| `validate_jwt_checklist()` | 8-step validation: alg whitelist (blocks `none`), signature, exp/nbf/iat, iss, aud, jti revocation, optional role/scope. |
| `mint_demo_jwt()` | Creates good or intentionally bad tokens for the Token Tester / Simulator. |
| `_simulator_signing_material()` / `infer_simulator_subject()` / `simulator_object_id()` / `resolve_simulator_user_jwt()` / `subject_from_jwt_payload()` / `_decode_unverified_jwt()` | Helpers so the Attack Simulator can mint/reuse tokens that match a project’s auth setup. |
| `hash_api_key()` / `verify_api_key()` | Store and check `X-API-Key` with SHA-256 hashes. |

### 5.4 `policy_engine.py` — routes, policies, BOLA

| Function | What it does |
|----------|----------------|
| `is_public_auth_path()` | Login/register paths that should stay public. |
| `_normalize_param_name()` / `_normalize_subject()` | Compare `user-101` vs `101` fairly. |
| `is_user_like_param()` / `is_resource_like_param()` | Guess whether `{id}` is a user id or a booking/order id. |
| `_parent_segment_for_param()` / `_infer_bola_param()` / `infer_bola_mode()` | Infer BOLA settings from path shapes. |
| `_is_public_content_route()` | Public profile-style routes that should not get BOLA. |
| `infer_route_security()` | When importing OpenAPI, set auth_required, admin role, sensitive flow, redaction, etc. |
| `match_route_pattern()` | `/users/{id}` matches `/users/102` and returns params. |
| `find_matching_route()` / `find_shadow_route()` | Lookup registered or previously discovered shadow routes. |
| `check_policy_mode()` | Is this control enabled? `enforce` or `monitor`? |
| `get_policy_config()` | Read JSON knobs from a policy (limits, lists, …). |
| `resolve_bola_owner_param()` / `_extract_object_ids()` | Find the object id in path/query/body. |
| `remember_object_owner()` / `_lookup_learned_owner()` / `list_learned_object_ids()` | Learn “order 55 belongs to user-101” from successful GETs. |
| `resolve_bola_mode()` / `check_bola_ownership()` | Enforce equals-sub or learned-owner BOLA. |
| `track_bola_enumeration()` / `reset_bola_enumeration()` | Cap how many distinct object IDs one client can probe per minute. |

### 5.5 `inspector.py` — payload / SSRF / schema checks

| Function | What it does |
|----------|----------------|
| `walk_json()` / `collect_string_values()` | Walk nested JSON. |
| `normalize_inspection_surface()` | Decode URL/HTML tricks so signatures still match. |
| `_try_parse_special_ip()` / `_is_restricted_ip()` | Catch decimal/octal/weird IPv4 forms. |
| `inspect_ssrf_url()` | DNS-resolve and reject private/metadata targets (API7). |
| `egress_trust_keys_for_base_url()` / `_egress_target_keys()` / `inspect_egress_destination()` | Allow gateway→upstream to the configured host, but not random loopback. |
| `_find_mass_assignment()` / `_find_ssrf_in_data()` / `_find_pagination_abuse()` | Find dangerous fields/URLs/huge limits in JSON. |
| `validate_request_schema()` / `_lightweight_schema_check()` / `_collect_readonly_paths()` | Enforce OpenAPI body schema (reject extra/readOnly props). |
| `inspect_response_for_unsafe_urls()` / `strip_unsafe_urls_from_json()` | API10: scrub unsafe URLs in upstream responses. |
| `inspect_request_payload()` | Main entry: SQLi/NoSQLi/XSS/traversal/cmd injection + size + pagination + mass assignment + SSRF + schema. |

### 5.6 `ratelimit.py` — RPM + burst

| Symbol | What it does |
|--------|----------------|
| Lua `_CONSUME_SCRIPT` | Atomic Redis fixed-window + token-bucket update. |
| `HybridRateLimiter.check_and_consume()` | Returns allow/deny, standard rate-limit headers, reason. Key is supplied by caller (pipeline uses project+IP+user+route). |
| `_consume_redis()` / `_consume_memory()` | Redis path or in-process fallback. |
| `_record_meter()` / `get_active_meters()` / `_meters_from_redis()` | UI meters for the Rate Limits page. |
| `reset_key()` | Clear one client’s counters (tests / simulator hygiene). |
| `rate_limiter` | Global instance. |

### 5.7 `responses.py` — response hardening

| Function | What it does |
|----------|----------------|
| `redact_json_fields()` | Mask named fields like `ssn`, `password_hash`. |
| `redact_pattern_values()` | Mask SSN/PAN-like strings anywhere. |
| `harden_response()` | Strip noisy server headers, add security headers, redact body, sanitize huge/5xx bodies. |

### 5.8 `http_client.py` — shared HTTPX client

| Function | What it does |
|----------|----------------|
| `get_http_client()` | One pooled async client for upstream calls. |
| `close_http_client()` | Shutdown cleanup. |

### 5.9 `circuit_breaker.py` — upstream failure protection

| Method | What it does |
|--------|----------------|
| `allow()` | Should we try this upstream? |
| `record_success()` / `record_failure()` | Update breaker state. |
| `snapshot()` | Debug/status view. |

Opens after repeated failures; half-open probes later to avoid hammering a dead backend.

### 5.10 `redis_client.py` — optional Redis

| Method | What it does |
|--------|----------------|
| `RedisHandle.get()` | Lazy connect when `REDIS_URL` is set; returns `None` otherwise. |
| `mark_down()` | After errors, stop retrying for a while so the app falls back to memory. |

---

## 6. Detection package (`backend/app/detection/`)

Runs after a request is logged.

### 6.1 `engine.py`

| Function | What it does |
|----------|----------------|
| `get_alert_upstream_id()` | Reads project id from alert evidence JSON. |
| `process_request_event()` | Score → evaluate rules → create/update alerts → optional auto-block → WebSocket broadcast → optional critical webhook. |
| `_maybe_post_critical_webhook()` | POSTs JSON to `WEBHOOK_URL` if configured. |

### 6.2 `scoring.py`

| Function | What it does |
|----------|----------------|
| `compute_threat_score()` | 0–100 score from decision, OWASP category, anomaly Z-score, etc. |

### 6.3 `anomaly.py`

| Symbol | What it does |
|--------|----------------|
| `RollingAnomalyDetector.record_and_score()` | Per-client (`upstream:user_or_ip`) request velocity vs baseline → Z-score; persists to `ClientBaseline`. |
| Redis/memory helpers | 15-second buckets. |

### 6.4 `rules.py`

| Symbol | What it does |
|--------|----------------|
| `BehavioralTracker.evaluate()` | Sliding-window correlation: JWT abuse, brute force, BOLA probes, injection bursts, shadow probing, high velocity, anomaly spikes, etc. Returns rule hit dicts for the engine. |

### 6.5 `ai_triage.py`

| Function | What it does |
|----------|----------------|
| `generate_ai_triage_summary()` | Builds a structured SecOps summary (root cause, impact, remediation). Uses Anthropic if `ANTHROPIC_API_KEY` is set; otherwise a deterministic expert template. |

---

## 7. Control-plane APIs (`backend/app/api/v1/`)

Shared auth helpers live in `deps.py`.

### 7.1 `deps.py`

| Function | What it does |
|----------|----------------|
| `hash_password()` / `verify_password()` | bcrypt for dashboard users. |
| `create_dashboard_token()` | Issues UI session JWT. |
| `get_current_user()` | Reads `Authorization: Bearer`, validates, loads User. |
| `require_roles([...])` | Dependency factory: 403 unless role is allowed. |

### 7.2 `auth.py` — login, JWT settings, API keys

| Endpoint function | What it does |
|-------------------|--------------|
| `list_organizations_for_registration()` | Orgs you can join when registering. |
| `login_dashboard()` / `register_dashboard()` | Sign in / sign up (create or join org). |
| `get_me()` | Current user profile. |
| `get_jwt_config()` | Global/default consumer JWT settings. |
| `get_project_jwt_config()` / `update_project_jwt_config()` | Per-upstream JWT settings. |
| `test_or_mint_jwt()` / `test_jwt_token()` / `mint_jwt_for_testing()` | Token Tester UI backends. |
| `list_api_keys()` / `create_api_key()` / `revoke_api_key()` | Consumer key management. |
| `list_revoked_tokens()` / `revoke_jti_token()` | JTI revocation list. |
| Helpers `_slugify`, `_unique_org_slug`, `_user_out`, `_issue_session`, `_normalize_email`, `_validate_credentials` | Plumbing for register/login. |

### 7.3 `overview.py`

| Function | What it does |
|----------|----------------|
| `_parse_window()` | Maps `15m` / `1h` / `24h` / `7d` to a timedelta. |
| `get_overview_dashboard()` | Project-filtered KPI cards: totals, block rate, alerts, latency, top paths/IPs. |

### 7.4 `traffic.py`

| Function | What it does |
|----------|----------------|
| `list_traffic_logs()` | Filterable request log list (decision, method, IP, OWASP, threat score, project). |
| `get_traffic_log_detail()` | Full single-request forensics for the drawer. |

### 7.5 `alerts.py`

| Function | What it does |
|----------|----------------|
| `list_alerts()` | Project-aware alert inbox. |
| `bulk_update_alerts()` | Bulk status changes. |
| `get_alert_detail()` | Alert + related requests + notes + AI summary. |
| `execute_alert_action()` | Status, notes, assign, block IP/user, revoke token, false positive. |
| `generate_alert_ai_triage_endpoint()` | On-demand triage refresh. |

### 7.6 `policies.py`

CRUD for security policies (`list_policies`, `create_policy`, `update_policy`, `delete_policy`) — enable/disable, enforce vs monitor, edit config JSON.

### 7.7 `ratelimits.py`

| Function | What it does |
|----------|----------------|
| `get_rate_limits_overview()` | Routes + limits + active client meters for one project. |
| `update_route_rate_limit()` | Patch RPM/burst on a route. |
| `run_rate_limit_burst_test()` | Fires N requests through `/gw` from a synthetic IP and reports allowed vs 429. |

### 7.8 `routes.py` (inventory)

| Function | What it does |
|----------|----------------|
| `get_inventory()` | All upstreams + routes + counters. |
| `create_upstream()` / `update_upstream()` / `delete_upstream()` / `activate_default_upstream()` | Manage API projects; activate sets default `/gw/*` target. |
| `create_route()` | Manual route add. |
| `promote_shadow_route()` / `block_shadow_route_permanently()` | Handle discovered undocumented APIs. |
| `import_openapi_spec()` | Paste JSON/YAML → register routes + infer security. |
| `sync_swagger_from_url()` | Connect backend URL, fetch OpenAPI, create/update project. |
| `_upsert_openapi_routes()` / `_extract_request_schema()` / `_resolve_local_ref()` | OpenAPI parsing internals. |
| `_derive_slug_and_name()` / `_discover_api_backend_from_frontend()` | Guess slug/name; try to find API behind a frontend URL. |

### 7.9 `blocklist.py`

| Function | What it does |
|----------|----------------|
| `list_blocklist()` / `add_to_blocklist()` / `remove_from_blocklist()` | Manual quarantine. |
| `update_auto_block_config()` | Toggle auto-block on critical alerts + duration. |

### 7.10 `analytics.py`

| Function | What it does |
|----------|----------------|
| `_percentile()` | p50/p95/p99 helper. |
| `get_deep_analytics()` | Latency percentiles, decision trends, anomaly clients for a project. |

### 7.11 `owasp.py`

| Function | What it does |
|----------|----------------|
| `get_owasp_coverage()` | Maps API1–API10 to which policies/controls cover them (for the OWASP/Simulator page). |

### 7.12 `simulator.py`

| Function | What it does |
|----------|----------------|
| `list_attack_scenarios()` | Catalogue + adaptive target plan for a project. |
| `toggle_gateway_protection()` | Sets `gateway_state.gateway_enabled`. |
| `validate_simulator_token()` | Checks the JWT the UI will send with attacks. |
| `run_attack_simulation()` | Runs one scenario or `all` via ASGI against `/gw`. |

### 7.13 `reports.py`

| Function | What it does |
|----------|----------------|
| `generate_executive_report()` | Summary metrics for printable report. |
| `export_traffic_csv()` / `export_alerts_csv()` | CSV downloads. |

### 7.14 `settings.py`

| Function | What it does |
|----------|----------------|
| `get_settings_and_users()` | Users list + system flags for Settings page. |
| `create_user()` / `update_user_role()` | Admin RBAC management (same-org rules). |
| `reseed_demo_database()` | Wipe/reseed demo telemetry (admin/analyst). |
| Helpers `_org_map`, `_active_org_admin_count`, `_require_same_org_admin` | Safety around org admin changes. |

### 7.15 `ws.py` — live updates

| Symbol | What it does |
|--------|----------------|
| `WebSocketConnectionManager` | Tracks connections; `broadcast` locally and optionally via Redis pub/sub across workers. |
| `start` / `stop` / `connect` / `disconnect` / `_local_broadcast` / `_listen_loop` | Lifecycle. |
| `websocket_live_endpoint()` | `/ws/live` handler; accepts `ping` keepalives. |

Empty `__init__.py` files under `api/` / `api/v1/` only mark packages.

---

## 8. Attack simulator (`backend/app/attack_sim/`)

### 8.1 `targeting.py`

Picks the best routes from **this project’s inventory** for each scenario role (login, admin, BOLA victim, SSRF, …).

| Symbol | What it does |
|--------|----------------|
| `SelectedRoute` / `ScenarioTargetPlan` | Data holders for chosen routes + reasons. |
| Scorers `_score_bola`, `_score_login`, `_score_jwt_victim`, … | Heuristic scores for route fitness. |
| Classifiers `_is_admin_route`, `_is_login_route`, … | Path/name heuristics. |
| `plan_scenario_targets()` | Main planner. |
| `list_scenario_route_options()` | Dropdown options for the UI. |
| `resolve_route_overrides()` | Honor manual route picks from the UI. |
| `describe_plan()` | Human-readable summary. |

### 8.2 `scenarios.py`

| Function | What it does |
|----------|----------------|
| `execute_attack_scenario()` | Runs bola_enum, brute_force, jwt_tamper, data_exposure, rate_flood, bfla_admin, ssrf_metadata, sqli, shadow_scan, supplier/API10, or `all`. Sends HTTP through the ASGI app to `/gw/{slug}/...`. |
| `_format_step()` | Formats one step result (blocked vs reached upstream). |
| `_resolve_login_request()` | Builds login body matching that project’s OpenAPI (JSON vs form). |

---

## 9. Demo API (`backend/app/demo_api/vulnshop.py`)

Intentionally insecure upstream mounted at `/demo/*`. Each endpoint demonstrates an OWASP issue so the gateway can block it when protection is ON.

| Function | Demo vulnerability |
|----------|--------------------|
| `vulnshop_login` / `vulnshop_register` | Weak auth surface for stuffing tests. |
| `vulnshop_users_me` | Excessive data exposure (PII fields). |
| `vulnshop_get_user` / `vulnshop_get_order` | BOLA — no ownership check. |
| `vulnshop_admin_users` | BFLA — no admin check. |
| `vulnshop_create_order` | Mass assignment. |
| `vulnshop_redeem_coupon` | Sensitive business flow / velocity abuse. |
| `vulnshop_ssrf_fetch` | SSRF to arbitrary URLs. |
| `vulnshop_search` | Injection sink. |
| `vulnshop_products` | Unbounded pagination. |
| `vulnshop_shadow_debug` | Undocumented shadow endpoint. |
| `vulnshop_supplier_catalog` | Unsafe consumption of third-party data (API10). |
| `_add_leaky_headers()` | Fingerprinting headers (API8). |

---

## 10. Frontend (`frontend/src/`)

### 10.1 Bootstrapping

| File | Role |
|------|------|
| `main.tsx` | Renders `<App />` into `#root`. |
| `index.css` | Tailwind layers + print helpers (`no-print`). |
| `index.html` | HTML shell. |
| `App.tsx` | Router table + `RequireAuth` (restores session via `/auth/me`). |
| `vite.config.ts` | Dev server proxies `/api`, `/gw`, `/demo`, `/ws` to the backend. |
| `tailwind.config.js` / `postcss.config.js` / `tsconfig.json` / `package.json` | Tooling only. |

`RequireAuth` in `App.tsx`: if no token → `/login`; if token → validate `/auth/me` then render child routes.

### 10.2 State — `store/useGatewayStore.ts`

Zustand store held in memory + `localStorage` for token, user, and selected project.

| Piece | What it does |
|-------|----------------|
| `readStoredUser()` | Parse user JSON from localStorage. |
| `setAuth` / `logout` | Login session lifecycle. |
| `setGatewayEnabled` / `setTimeRange` / `setGlobalSearch` | Top-bar controls. |
| `openRequestDrawer` / `closeRequestDrawer` | Traffic detail drawer id. |
| `setLiveStreamPaused` / `pushLiveTraffic` / `pushLiveAlert` | Live WS buffers (project-filtered toasts). |
| `addToast` / `dismissToast` | Transient notifications. |
| `setSelectedProject` | Persists Observing Project id/name/slug. |
| `canMutate(roles)` | UI enable/disable based on role. |

### 10.3 HTTP helpers — `lib/api.ts`

| Function | What it does |
|----------|----------------|
| `apiFetch()` | JSON fetch to `/api/v1…` with Bearer token; readable FastAPI errors; logout on 401. |
| `downloadAuthenticatedFile()` | CSV/blob download with auth. |
| `parseTimestamp()` / `formatTimeIST()` / `formatDateTimeIST()` | Display times in IST. |

### 10.4 Types — `types/api.ts`

Shared TypeScript shapes: `UserRole`, `UserProfile`, `OrganizationSummary`, `TrafficLogItem`, `AlertItem`.

### 10.5 Layout and shared components

| File / export | What it does |
|---------------|----------------|
| `MainLayout` | Sidebar nav (Monitor / Connect / Test groups), Observing Project select, gateway toggle, time range, role badge, WS connect/reconnect, toasts, outlet for pages. |
| `ErrorBoundary` | Catches React render crashes and shows a fallback. |
| `LoadError` | Standard “failed to load” panel with retry. |
| `RequestDetailDrawer` | Slide-over forensics for one traffic log. |
| `SeverityBadge` / `OwaspBadge` / `DecisionBadge` / `MethodBadge` | Colored chips used across pages. |

### 10.6 Pages (one UI screen each)

| Page file | Route | What the page does |
|-----------|-------|--------------------|
| `LoginPage.tsx` | `/login` | Persona cards + email/password; stores token; routes by role. |
| `OverviewPage.tsx` | `/` | Project KPIs, recent threats, quick gateway smoke test. |
| `LiveTrafficPage.tsx` | `/traffic` | Live + historical request table with filters; opens drawer. |
| `AlertsPage.tsx` | `/alerts` | Alert inbox, bulk actions. |
| `AlertDetailPage.tsx` | `/alerts/:id` | Investigation: status, notes, AI triage, block/revoke. |
| `AnalyticsPage.tsx` | `/analytics` | Charts for latency, decisions, anomalies (Recharts). |
| `InventoryPage.tsx` | `/inventory` | Connect APIs, import OpenAPI, shadow route actions, manual routes. |
| `PoliciesPage.tsx` | `/policies` | Toggle/enforce/monitor security policies. |
| `RateLimitsPage.tsx` | `/rate-limits` | Edit RPM/burst; run burst test (`RouteLimitRow` helper component). |
| `AuthSettingsPage.tsx` | `/auth-settings` | Per-project JWT config, token mint/test, API keys. |
| `BlocklistPage.tsx` | `/blocklist` | View/add/remove quarantine + auto-block settings. |
| `AttackSimulatorPage.tsx` | `/simulator` and `/owasp` | Run OWASP scenarios; shows coverage; stores sim JWT per project. Helpers: `simJwtStorageKey`, `readStoredSimJwt`, `writeStoredSimJwt`. |
| `ReportsPage.tsx` | `/reports` | Summary + CSV export + `window.print()`. |
| `SettingsUsersPage.tsx` | `/settings` | User/role management, reseed. |
| `NotFoundForbiddenPage.tsx` | `/forbidden` or unknown | 403/404 screens. |

Empty package markers: `backend/app/__init__.py`, `api/__init__.py`, `api/v1/__init__.py`, `attack_sim/__init__.py`, `detection/` and `gateway/` packages.

---

## 11. Infrastructure and docs

| File | What it does |
|------|----------------|
| `docker-compose.yml` | Postgres, Redis, backend workers, nginx on `:8000`, frontend on `:5173`. |
| `nginx/nginx.conf` | Proxies HTTP and WebSockets to `backend:8000`; forwards `X-Forwarded-For`. |
| `backend/Dockerfile` / `frontend/Dockerfile` | Container images. |
| `backend/requirements.txt` | Python deps (FastAPI, SQLModel, httpx, redis, jwt, bcrypt, …). |
| `README.md` | Quick start and role overview. |
| `docs/PROJECT_PROPOSAL_AND_IMPLEMENTATION_PLAN.md` | Original plan / acceptance criteria. |
| `docs/ROLE_BASED_USER_GUIDE.md` | How each persona uses the UI. |
| `docs/CODEBASE_GUIDE.md` | This file. |

---

## 12. Tests (`backend/tests/`)

| File | Focus |
|------|--------|
| `test_gateway_e2e.py` | End-to-end gateway + control plane smoke. |
| `test_auth_jwt.py` | JWT checklist (alg=none, aud, scopes, …). |
| `test_inspector.py` | Mass assignment, SSRF tricks, pagination, schema, egress trust. |
| `test_policy_engine.py` | Route matching, BOLA modes, enumeration tracker. |
| `test_openapi_import.py` | Request schema persistence on import. |
| `test_attack_targeting.py` | Adaptive route picking across fake inventories. |
| `test_redis_rate_limit.py` | Fixed window, token bucket, meters, anomaly (memory + Redis if present). |

There is no separate frontend unit-test suite today (`npm run lint` = TypeScript check).

---

## 13. How to explain it out loud (short script)

1. **“Clients never talk to the backend directly when protected.”** They hit `/gw/{project}/…`.
2. **“The pipeline is a checklist.”** Blocklist → route → auth → authz → rate limit → payload → forward → redact → log.
3. **“The dashboard is a SOC console.”** Same backend process exposes `/api/v1` and `/ws/live` for humans.
4. **“Projects don’t mix.”** Almost every query takes `upstream_id` / Observing Project.
5. **“Rate limits are per client.”** Key includes IP (and user), so two different IPs don’t share one bucket.
6. **“The simulator proves the gate works.”** It attacks the *selected* project’s real routes through `/gw`, not hard-coded demo paths only.
7. **“VulnShop is the practice target.”** `/demo` is vulnerable on purpose; gateway ON vs OFF is the demo punchline.

---

## 14. Quick “where do I change X?” index

| If you want to change… | Start here |
|------------------------|------------|
| New security check on every request | `gateway/pipeline.py` + maybe `inspector.py` / `policy_engine.py` |
| JWT validation rules | `gateway/auth.py` |
| Rate-limit algorithm | `gateway/ratelimit.py` |
| Alert creation logic | `detection/rules.py` + `detection/engine.py` |
| New dashboard API | New router under `api/v1/` + mount in `main.py` |
| New UI page | `pages/*.tsx` + route in `App.tsx` + nav in `MainLayout.tsx` |
| Demo vulnerability | `demo_api/vulnshop.py` + seed routes in `seed.py` |
| Simulator scenario | `attack_sim/scenarios.py` + targeting scorers |
| Env defaults | `config.py` |
| DB columns | `models.py` (+ `_ensure_extra_columns` in `db.py` if you need non-destructive add) |

---

*Generated for the SentinelGW repository. Prefer reading the cited files when explaining behavior in detail; this guide is the map, the source is the territory.*
