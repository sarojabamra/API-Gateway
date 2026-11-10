# SentinelGW — Product Overview

SentinelGW is an API security gateway and monitoring console. API clients call SentinelGW instead of calling your backend directly. SentinelGW checks each request, blocks or limits bad traffic, forwards clean requests to the backend, and shows what happened in a live dashboard.

It is built around the OWASP API Security Top 10.

This document covers why the product is needed, what key terms mean, what the product includes, how it compares with common tools, and how to use it.

---

## 1. Why this product is needed

If SentinelGW only checked tokens, roles, and rate limits one step before the backend, it would not be worth building. Every service is already expected to do that. SentinelGW includes a basic version of those checks, but that is not the main value.

A single backend cannot:

- see attacks that span several services
- catch its own broken access checks
- hide sensitive data after that data is already in the response
- track routes it never documented

Gartner’s 2024 Market Guide for API Protection reached the same conclusion: token checks and rate limits are not enough. Many real breaches came from access-control failures and from APIs that were not on any inventory.

### What SentinelGW does better

| Capability | Without SentinelGW | With SentinelGW |
|---|---|---|
| Stop “valid user, wrong object” access | Only if that handler checked ownership correctly | Checks object ids on the way in |
| Stop `role` / `is_admin` in the request body | Only if that handler rejected those fields | Blocks those fields before the service runs |
| Hide passwords, card numbers, and stack traces | Uncommon once the JSON is built | Masks fields and cleans 5xx errors before the caller sees them |
| Know which routes are actually live | An OpenAPI file that is often out of date | Live inventory plus unknown shadow routes from traffic |
| See one attacker across several APIs | Separate logs per service | One client timeline, grouped alerts, block from one screen |
| Enable a new rule without a release | Code change and deploy per service | Monitor first, then enforce, from the console |
| Prove protection on this API | Manual Postman or a pen-test | Attack simulator on the selected project’s real routes |
| Shared security baseline across services | Many teams, many implementations | One place for token, body, size, and field checks |

### Scope

SentinelGW is not a better login system than the service that issued the token. It does not own business rules such as “can this user cancel this booking.” It is not a replacement for a company API gateway used for routing, canaries, a developer portal, or billing. It is not a CDN, and it is not a defense against large network floods.

One operating rule: clients must not reach the backend directly. A call to the service port bypasses the gateway. In a real deployment the service listens on an internal network, and only the gateway is reachable from outside.

---

## 2. Key terms, in plain words

These terms appear throughout the product and this document. Each one is a real attack style or control idea.

### Access and identity

**JWT (JSON Web Token)**  
A signed string the client sends with a request (usually in the `Authorization` header). It says who the user is and when the token expires. If the signature is wrong, the token is expired, or the token was built with a weak setting (for example “no signature”), the gateway should reject it.

**API key (consumer key)**  
A long-lived secret that an *external API caller* (a partner app, script, or service) uses to call protected `/gw/...` routes. It is **not** the password for the SentinelGW dashboard, and it is **not** a JWT.

How it works in this product:

- An admin or developer creates the key in **Auth & JWT** (`/auth-settings`).
- The full key is shown once at creation. Only a prefix and a hash are stored afterward.
- The caller sends it on each request as the `X-API-Key` header.
- The gateway checks that the key exists, is not revoked, is not expired, and is not on the blocklist.
- A key can carry a simple role and scopes (for example read-only access to certain resources).

Use a JWT when the caller is a logged-in end user with short-lived sessions. Use an API key when a machine or partner needs steady access without a user login flow.

**BOLA (Broken Object Level Authorization)**  
Also related to IDOR. A logged-in user changes an id in the URL or body and opens someone else’s data. Example: Alice calls `/orders/1043` (her order), then `/orders/1044` (Bob’s order). The token is valid. The bug is that the service never checked ownership.

**BFLA (Broken Function Level Authorization)**  
A normal user calls an admin-only function. Example: a customer calls `/admin/users` or a delete-all endpoint because the route never checked the role.

**Mass assignment**  
The client adds extra fields to a JSON body that the service should never accept, such as `"role": "admin"` or `"is_admin": true`. If the service blindly saves the whole body, the caller can raise their own privileges.

**Shadow API**  
A live route that is not in your official docs or OpenAPI file. Examples: `/debug`, an old `/v1` after `/v2` shipped, or a test endpoint left online. Attackers look for these because they are often less protected.

### Request attacks

**SQLi (SQL Injection)**  
The attacker puts database commands into a field that the service later runs as SQL. Example: a search box value of `' OR 1=1 --` that changes the query so every row is returned, or worse, data is deleted. SentinelGW looks for common SQL attack patterns in query strings and bodies and can block them before they reach the service.

**NoSQLi (NoSQL Injection)**  
Same idea as SQLi, but for document databases such as MongoDB. The attacker sends operators like `$ne`, `$gt`, or `$where` inside JSON so the query matches more data than intended.

**XSS (Cross-Site Scripting)**  
The attacker sends script tags or event handlers (for example `<script>...` or `onerror=...`) in a field. If that value is later shown in a browser without cleaning, the script can run in another user’s session. For APIs this often shows up as stored malicious content in a name, comment, or profile field.

**Path traversal**  
The attacker uses `../` (or encoded forms) to read files outside the allowed folder, such as `/etc/passwd`. Example: a “download file” parameter set to `../../secret.env`.

**Command injection**  
The attacker tricks the server into running an operating-system command. Example: a field value that includes `; cat /etc/passwd` or `` `whoami` `` if the service builds a shell command from user input.

**SSRF (Server-Side Request Forgery)**  
The API accepts a URL from the client and then the *server* fetches that URL. The attacker points it at something the public internet cannot reach, such as:

- `http://127.0.0.1` (the server itself)
- an internal service on a private network
- `http://169.254.169.254/...` (cloud metadata, which can expose cloud credentials)

From the outside this looks like a normal API call. The damage happens because the server makes the second request with its own network rights. SentinelGW inspects URL-like fields, resolves the host, and rejects private, local, and metadata targets.

### Abuse and overload

**Rate limiting**  
A cap on how many requests a client can make in a time window. Stops password guessing, scrapers, and “try every order id” scripts from running at full speed.

**Burst control**  
A short-term limit on sudden spikes, even if the longer-term average is still under the rate limit. Stops a client from firing 100 requests in one second.

**Sensitive business flow abuse**  
A normal product action (buy, redeem coupon, reset password, book a slot) is automated far beyond what a real user would do. The calls look valid one by one; the problem is volume and intent.

**Credential stuffing**  
An attacker tries many stolen username/password pairs against your login. One IP, many different accounts, many failures.

**Brute force**  
An attacker tries many passwords against one account, or many guesses against a login endpoint, until something works.

### Response and config problems

**Excessive data exposure**  
The API returns more fields than the client needs: password hashes, full card numbers, internal ids, or debug fields. The request itself may be allowed; the leak is in the response.

**Security misconfiguration**  
Weak defaults: stack traces in errors, server banners that reveal the stack, open debug routes, missing security headers, or injection sinks left open.

**Unsafe consumption of APIs (API10)**  
Your service trusts data from a third-party API or webhook without checking it. That data may include a URL that points back at your internal network. The risk is the same shape as SSRF, but the bad URL arrives from a partner response rather than from your own client.

### Gateway modes

**Monitor mode**  
The rule records what would have happened and still allows the request. Used to learn about false positives before blocking.

**Enforce mode**  
The rule blocks the request (or rate-limits it) and returns an error to the client.

---

## 3. How traffic flows

```text
Client (app, Postman, curl, Swagger)
        |
        v
   SentinelGW  (/gw/{project}/...)
        |
   security checks (see feature list below)
        |
   allow / block / rate-limit
        |
        v
   Your backend API
```

Dashboard users log into the React UI. The UI talks to `/api/v1/*` and receives live updates on `/ws/live`. That path is separate from the protected API traffic on `/gw/*`.

Protected clients should call:

```text
http://host:8000/gw/{project-slug}/{backend-path}
```

not the backend port itself.

---

## 4. Full feature list

### 4.1 Gateway protection (request path)

Every call through `/gw/...` can pass through these stages:

**Request context**  
Assigns a request id, reads the client IP (including forwarded headers when present), and starts a latency timer so every decision can be traced later.

**Gateway master switch**  
ON means full protection. OFF means traffic is forwarded for demos or comparison, but requests can still be logged. Useful for “before vs after” in the Attack Simulator.

**Blocklist**  
Instant reject for a blocked IP, user, or API key. Entries can be added by hand or from an alert action. Critical alerts can also auto-block.

**Route inventory match**  
The request is matched to an imported or manually registered route. Counters update so you can see which paths are busy.

**Shadow API discovery**  
If the path is not in the inventory, it is recorded as a shadow route. Policy can monitor it or block it until someone promotes it or shuts it down.

**JWT and API key checks**  
For protected routes the gateway accepts either a user JWT (`Authorization: Bearer ...`) or a consumer API key (`X-API-Key: ...`). JWT checks include: allowed algorithms (rejects unsigned / `alg: none`), signature, expiry and time claims, issuer, audience, and whether the token id (`jti`) was revoked. API key checks confirm the key hash, expiry, and revoked status.

**Object and function access checks**  
- BOLA: path/body object ids must match the user, or match a previously seen owner; enumeration of many ids is capped.
- BFLA: admin-shaped routes require the right role or scope.

**Rate and burst limits**  
Per route, per client: a sustained requests-per-minute limit plus a short burst bucket. Login and sensitive flows can use stricter caps. Responses include standard rate-limit headers and `Retry-After` when limited.

**Payload inspection**  
Looks through query strings and JSON bodies for:

- SQL injection patterns
- NoSQL operators
- XSS payloads
- path traversal
- command injection
- SSRF URLs (including odd IP forms meant to bypass simple string filters)
- mass-assignment fields
- oversized bodies and huge page sizes
- OpenAPI body shape when a schema was imported

**Upstream forward**  
Allowed requests are sent to the configured backend. A circuit breaker stops hammering a backend that is failing or timing out, then probes again later.

**Response hardening**  
Before the reply goes back to the client, SentinelGW can:

- strip headers that reveal the server stack
- add security headers
- mask configured sensitive fields
- mask SSN-like and card-like values
- replace 5xx bodies so stack traces do not leave
- remove unsafe third-party / webhook URLs that point at private or metadata hosts

**Policy modes**  
Each control can run in **monitor** (log only) or **enforce** (block). That lets you turn protection on safely.

### 4.2 API inventory and onboarding

- Connect a backend by base URL (local port or deployed HTTP/HTTPS).
- Import OpenAPI 3.0 JSON or YAML (paste or file).
- Sync routes from a Swagger / OpenAPI URL.
- Create multiple projects so each API keeps its own routes, logs, alerts, and limits.
- Use the global **Observing Project** selector so every page shows one API at a time.
- Add routes by hand when OpenAPI is incomplete.
- Promote a shadow route into the inventory, or block it permanently.
- Set JWT secret / issuer / audience per project.
- Use gateway-proxied `/gw/docs`, `/gw/redoc`, and `/gw/openapi.json` so Swagger “Try it out” traffic is protected and logged.

### 4.3 Monitoring and detection

- **Overview** — totals, block rate, open alerts, latency, top paths and offending clients for the selected project.
- **Live Traffic** — every gateway call with decision (allow / block / rate-limit / monitor), method, path, status, OWASP id, threat score. Click a row for full detail.
- **Live stream** — WebSocket updates so new requests and alerts appear without refresh.
- **Threat score** — a 0–100 score based on decision, OWASP category, and anomaly signals.
- **Behavioral rules** — groups of related events, not just one bad request:
  - JWT tampering
  - expired / revoked token reuse
  - brute-force login
  - credential stuffing (many usernames from one IP)
  - BOLA object-id walking
  - admin-route probes
  - SSRF attempts
  - injection signatures
  - mass assignment
  - sensitive-flow velocity
  - shadow endpoint scanning
  - sudden traffic spikes above a client’s normal rate
- **Alerts** — inbox with severity and status; detail page with related requests, notes, assignment, and optional AI triage summary.
- **Containment** — from an alert: block IP, block user, revoke token `jti`. Optional auto-block and webhook for critical alerts.
- **Threat email alerts** — when a *new* threat/alert is opened, SentinelGW can email every active member of the organization that owns that API project. The message includes severity, title, OWASP category, source IP, target path, and a link to the incident. Repeat hits on the same open alert are grouped into that alert and do **not** send another email. Delivery uses SMTP (`SMTP_HOST`, and related settings). Status is visible under **Users & Access** (`/settings`): whether email is enabled and whether a mail server is configured.
- **Analytics** — latency percentiles (p50 / p95 / p99), decision trends, unusual clients.
- **OWASP page** — which Top 10 items are covered and how often they fire.
- **Reports** — executive summary, CSV export for traffic and alerts, printable view.

### 4.4 Controls and configuration

- **Policies** — enable/disable each rule; switch monitor vs enforce; edit rule settings.
- **Rate limits** — edit per-route limits; run a burst test and see allowed vs `429` results.
- **Auth settings** — project JWT config, interactive token tester (valid and bad presets), mint test tokens, create/revoke consumer API keys (`X-API-Key`), list revoked token ids.
- **Blocklist** — view/add/remove quarantined IPs, users, and keys; configure auto-block.
- **Users & Access** — admin / analyst / developer / viewer roles; org membership; threat-email status (enabled + SMTP configured); re-seed demo data for a clean presentation.

### 4.5 Testing and demo

- **Attack Simulator** — runs controlled attack scenarios against the *selected* project’s real routes (not only hard-coded demo paths).
- Each step reports whether SentinelGW blocked the call or the upstream answered.
- If the project has no suitable route for a scenario, it is marked **not applicable** instead of a fake failure.
- **VulnShop** (`/demo`) — built-in intentionally weak shop API covering all ten OWASP categories. Use gateway OFF then ON to show the difference.
- Simulator scenarios include BOLA, brute force / stuffing, JWT tampering, data exposure / mass assignment, rate flood, admin function abuse, SSRF, SQLi, shadow scan, and unsafe third-party URL cases.

### 4.6 Platform

- FastAPI backend + React / TypeScript dashboard
- SQLite for simple local use
- Docker Compose with Postgres, Redis, multiple workers, and nginx
- Shared rate-limit and behavior state in Redis when configured
- Health check and basic metrics endpoints
- Role checks on management APIs

---

## 5. OWASP API Security Top 10

| ID | Meaning in practice | Example | What SentinelGW does |
|---|---|---|---|
| **API1 — Broken Object Level Authorization** | A logged-in user changes an id and opens someone else’s record. | `GET /orders/1044` with Alice’s token returns Bob’s order. | Subject-vs-id checks, learned owner, enumeration cap |
| **API2 — Broken Authentication** | Weak or broken login and token handling. | Forged JWT, unsigned token, expired token reused, password guessing. | Eight-step JWT / API-key checks, login limits, related alerts |
| **API3 — Broken Object Property Level Authorization** | Caller reads or writes fields they should not. | Body includes `"role":"admin"`; response includes `password_hash`. | Block forbidden fields; redact response fields and card/SSN-like values |
| **API4 — Unrestricted Resource Consumption** | No useful limit on load. | 10,000 requests/min, 50 MB body, or `limit=1000000`. | Rate + burst limits, body and page-size caps |
| **API5 — Broken Function Level Authorization** | A normal user calls an admin-only function. | Customer calls `DELETE /admin/users`. | Role checks on admin routes; probe alerts |
| **API6 — Unrestricted Access to Sensitive Business Flows** | A normal flow is automated at an unsafe scale. | Bot redeems thousands of coupons. | Stricter limits and velocity alerts on sensitive routes |
| **API7 — Server Side Request Forgery** | The API is tricked into fetching an internal URL. | `url=http://169.254.169.254/...` in a fetch field. | Inspect URL fields; reject private, local, and metadata targets |
| **API8 — Security Misconfiguration** | Weak defaults and open attack surfaces. | Stack traces in 500s; SQLi in a search field. | Header hardening, 5xx cleanup, injection signatures |
| **API9 — Improper Inventory Management** | Unknown, old, or undocumented routes. | `/debug` still live; `/v1` never retired. | OpenAPI import + shadow route discovery |
| **API10 — Unsafe Consumption of APIs** | Trusting third-party / webhook data without checks. | Partner response contains an internal webhook URL. | Scrub unsafe URLs in responses before they reach the caller |

Pattern-based injection blocking has the same limit as any WAF: a new encoding may pass, and an unusual but valid string may trigger a rule. Use **monitor** first when you are unsure.

---

## 6. How this compares with other tools

**Kong, Apigee, NGINX, AWS API Gateway, Azure APIM**  
Good for TLS, tokens, rate limits, and routing. Weak at incident investigation, object-ownership abuse, and proving controls against your routes. If one of these is already the front door, SentinelGW sits behind or beside it for API-specific checks.

**A WAF (ModSecurity, Cloudflare, AWS WAF)**  
Good at SQLi, XSS, and obvious scanners. Blind to “valid user, wrong object,” and blind to routes it was never told about. We overlap on injection patterns. We are not a bot or flood product.

**API security platforms (Salt, Noname / Akamai, Traceable, Wallarm)**  
Closest category. Usually watch traffic and need another tool to block. SentinelGW sits in the request path, so a block is an HTTP response, and the console is part of the same product. It is smaller and self-hosted; it does not match their scale or enterprise contract depth.

**A shared library in every service**  
Right for business access rules. Wrong for live inventory, response cleaning after the JSON is built, one console across APIs, and services you do not own.

---

## 7. Basic guide: how to use SentinelGW

### 7.1 Start the app

**Local (simple):**

```bash
# Backend — port 8000
cd backend
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Frontend — port 5173
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

**Docker (Postgres + Redis + workers):**

```bash
docker compose up --build
```

Dashboard: `http://localhost:5173`  
Gateway / API: `http://localhost:8000`

### 7.2 Demo login accounts

| Role | Email | Password | Typical use |
|---|---|---|---|
| Admin | `admin@sentinel.local` | `sentinel123` | Policies, users, gateway switch, blocklist |
| Analyst | `analyst@sentinel.local` | `sentinel123` | Live traffic, alerts, containment |
| Developer | `dev@sentinel.local` | `sentinel123` | Inventory, OpenAPI, JWT tester |
| Viewer | `viewer@sentinel.local` | `sentinel123` | Read-only dashboards and reports |

On the login page you can also click a persona card to sign in quickly.

### 7.3 Screen map

| Page | Path | What it is for |
|---|---|---|
| Overview | `/` | Project totals, block rate, recent threats |
| Live Traffic | `/traffic` | Every gateway request; open a row for full detail |
| Security Alerts | `/alerts` | Grouped incidents across related requests |
| Alert detail | `/alerts/:id` | Notes, triage, block IP / user, revoke token |
| Analytics | `/analytics` | Latency, trends, unusual clients |
| API Inventory | `/inventory` | Connect backends, import OpenAPI, handle shadow routes |
| Security Policies | `/policies` | Turn rules on/off; monitor vs enforce |
| Rate Limits | `/rate-limits` | Edit limits; run a burst test |
| Auth & JWT | `/auth-settings` | JWT settings, token tester, consumer API keys (`X-API-Key`), revoked tokens |
| Blocklist | `/blocklist` | Blocked IPs / users / keys; auto-block settings |
| Attack Simulator | `/simulator` | Run OWASP attack scenarios against the selected project |
| OWASP coverage | `/owasp` | Map of Top 10 coverage and recent hits |
| Reports | `/reports` | Summary + CSV / print export |
| Users & Access | `/settings` | Users, roles, threat email status, re-seed demo data |

Top bar controls on every page:

- **Observing Project** — which API’s data you are looking at
- **Gateway ON / OFF** — protection switch
- **Time range** — window for charts and lists

### 7.4 First-time walkthrough (about 15 minutes)

1. **Log in** as admin.
2. **Open Overview** and confirm you can see the default project (VulnShop or another connected API).
3. **Connect your API** (optional): go to **API Inventory**, add the backend URL or import OpenAPI, then select that project in the top bar.
4. **Send a normal request** through the gateway:
   ```bash
   curl -i http://localhost:8000/gw/your-project-slug/your-path
   ```
   Or open `http://localhost:8000/gw/docs` for the proxied Swagger UI.
5. **Check Live Traffic** — the call should appear with decision, status, and latency. Open the row to see headers and body previews.
6. **Open Policies** — leave new rules in **monitor** first if you are unsure; switch to **enforce** when ready.
7. **Run the Attack Simulator** on the selected project. On VulnShop, try gateway OFF then ON for a clear before/after on BOLA or SSRF.
8. **Open an alert** from a blocked or flagged run. Read the related requests, add a note, then block the IP or revoke the token if needed. If SMTP is configured, active org members also get an email when that new threat was opened.
9. **Export** from Reports if you need a summary for review.

### 7.5 Consumer API keys (quick note)

1. Open **Auth & JWT** (`/auth-settings`).
2. Create a consumer API key (give it a name; optionally set role / scopes).
3. Copy the full key when it is shown — it is not shown again in full.
4. Call the gateway with:
   ```bash
   curl -i -H "X-API-Key: sgw_live_...." http://localhost:8000/gw/your-slug/your-path
   ```
5. Revoke the key from the same page when it is no longer needed, or block it from the blocklist / an alert.

Dashboard login still uses email + password (or the persona cards). That login JWT is only for the UI, not for `/gw` consumer traffic.

### 7.6 Day-to-day use by role

**Admin**  
Own policies, rate limits, blocklist, JWT settings, consumer API keys, users, the gateway switch, SMTP/email readiness, and demo re-seed before a presentation.

**Analyst**  
Watch Live Traffic, triage alerts (including emailed threats), use containment (block / revoke), review analytics, and keep investigation notes.

**Developer**  
Maintain inventory, import OpenAPI, review shadow routes, use the JWT tester, validate policies in monitor mode, and run rate-limit burst tests.

**Viewer**  
Read overview, OWASP coverage, analytics, and reports. Cannot change policies or the blocklist.

### 7.7 Calling a protected API as a client

Point your client at the gateway, not at the backend:

```text
http://localhost:8000/gw/{project-slug}/{backend-path}
```

Examples:

```bash
# Public or open route
curl -i http://localhost:8000/gw/vulnshop/products?limit=5

# With API key
curl -i -H "X-API-Key: your_key" http://localhost:8000/gw/vulnshop/users/101

# With JWT
curl -i -H "Authorization: Bearer your_jwt" http://localhost:8000/gw/your-slug/orders/5001

# Example SSRF-style probe (should be blocked when protection is ON)
curl -i "http://localhost:8000/gw/vulnshop/fetch?url=http://169.254.169.254/latest/meta-data/"
```

If the call goes to the backend port instead, SentinelGW will not see it and cannot protect it.

### 7.8 Safe order for turning protection on

1. Connect the API and import OpenAPI.
2. Review inferred auth / admin / object-id settings on routes; correct anything wrong.
3. Set policies to **monitor**.
4. Send real or test traffic; review Live Traffic and Alerts for false positives.
5. Switch policies to **enforce** one group at a time.
6. Keep the backend unreachable from outside the gateway.

---

## 8. What it does not claim

- No large-scale flood protection, bot scoring, mutual TLS to the backend, billing, or developer portal
- Object-owner memory is not a source of truth; the first sight of an id is allowed
- Injection detection is pattern-based; it can miss new variants and can flag valid strings
- The demo setup is for evaluation, not a finished production rollout
- Traffic that never passes through the gateway is invisible to it

---

## 9. Bottom line

SentinelGW inspects API traffic against the OWASP API Top 10, keeps a live inventory of what is being called, stops abuse a single service is weak at detecting — wrong-object access, unsafe fields, response leaks, injection, SSRF, unknown routes, and probing across services — and gives one place to investigate and cut off the caller, without waiting for every team to build the same protections the same way.

For role-by-role detail and a short demo script, see [Role-Based User Guide](ROLE_BASED_USER_GUIDE.md). For code layout, see [Codebase Guide](CODEBASE_GUIDE.md).
