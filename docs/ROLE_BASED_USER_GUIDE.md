# SentinelGW — Role-Based User & Operational Guide

Welcome to **SentinelGW**, an **OWASP API Security Top 10 (2023)** Enforcement Gateway & Real-Time Threat Monitoring Platform.

This operational guide walks you through **SentinelGW** from the perspective of all **5 user roles**, provides a **5-minute Judge/Demo Walkthrough**, and explains how every page, enforcement policy, and detection engine works together.

---

## 1. Quick-Start & Demo Accounts

When the platform boots, it automatically seeds **4 control-plane accounts**, **3 pre-minted API keys**, **240+ historical traffic logs**, **6 multi-stage OWASP security incidents**, and **11 active security policies**.

You can switch between any of the 4 dashboard personas at any time with **1 click** using either:
- The **Quick Demo Persona Switcher** on the `/login` page, or
- The **Role Switcher Pill** in the top navigation bar.

| Persona | Email | Password | Role Slug | Primary Focus |
| :--- | :--- | :--- | :--- | :--- |
| **Security Administrator** | `admin@sentinel.local` | `sentinel123` | `admin` | Full system control, policy authoring, JWT signing config, RBAC user management, manual & auto IP blocking |
| **SOC Analyst** | `analyst@sentinel.local` | `sentinel123` | `analyst` | Real-time traffic monitoring, alert triage, AI incident analysis, blocking malicious IPs, revoking compromised JWTs |
| **API Developer / Owner** | `dev@sentinel.local` | `sentinel123` | `developer` | API route inventory, OpenAPI 3.0 spec import, Shadow API discovery, JWT token testing, Monitor (dry-run) policy testing |
| **Compliance Viewer** | `viewer@sentinel.local` | `sentinel123` | `viewer` | Read-only access to dashboards, OWASP Top 10 coverage matrix, deep analytics, and CSV/PDF compliance reports |

---

## 2. The 5-Minute Live Demo Walkthrough (For Judges & Evaluators)

Follow this exact sequence to experience the full closed-loop lifecycle (**Unprotected Exploit → Gateway Enforcement → Real-Time Detection → AI Triage → Automated Response**):

1. **Log in as Security Admin (`admin@sentinel.local`)**
   - Open `/login` and click the **Security Admin** card.
   - Observe the **SOC Overview (`/`)**: KPI cards, Traffic Volume vs Blocked Attacks chart, OWASP API Top 10 breakdown donut, and Top Offending Clients.
2. **Prove `VulnShop` Is Vulnerable When Unprotected (`/simulator`)**
   - Navigate to **Attack Simulator (`/simulator`)**.
   - Click **GATEWAY OFF** in the top banner. The status indicator turns red (`VULNSHOP EXPOSED (PASS-THROUGH)`).
   - Click **Launch Attack Scenario** on **API1:2023 — BOLA ID Enumeration** or **API7:2023 — Cloud Metadata SSRF**.
   - Observe in the **Execution Output Console** that `VulnShop` returns `HTTP 200 OK` with raw user SSNs, password hashes, and simulated AWS IAM credentials (`ASIAIOSFODNN7EXAMPLE`).
3. **Arm SentinelGW & Block All 8 OWASP Attacks (`/simulator`)**
   - Click **GATEWAY ON** in the Attack Simulator banner (`SHIELD ARMED`).
   - Click **Run All 8 OWASP Attacks**.
   - Every attack is now intercepted by the 10-stage Gateway Pipeline (`403 BOLA`, `429 Rate Limit`, `403 BFLA`, `400 SSRF`, `400 SQLi`, `200 Redacted PII`).
4. **Watch Real-Time Streaming Telemetry (`/traffic`)**
   - Navigate to **Live Traffic (`/traffic`)**.
   - Click any red `BLOCKED` or amber `FLAGGED` row to open the **Request Detail Drawer**.
   - Inspect the **8-Point JWT Checklist**, **Risk Score**, **Matched Policy**, and **Response Hardening** headers.
5. **Triage Incidents with AI & Execute 1-Click Containment (`/alerts`)**
   - Navigate to **Security Alerts (`/alerts`)** and click any **CRITICAL** alert to open the **Incident Workbench (`/alerts/:id`)**.
   - Click **Re-Run AI Triage** to generate an executive root-cause explanation, blast-radius assessment, and concrete remediation steps.
   - Click **Block Offender IP (24h)** or **Revoke Token JTI** to immediately isolate the attacker.

---

## 3. Role-by-Role Operational Playbooks

### Role 1: Security Administrator (`admin`)

**Responsibilities:** Full governance over gateway enforcement rules, authentication settings, rate limits, blocklists, and platform users.

#### Step-by-Step Workflows:
1. **Manage Security Policies (`/policies`)**
   - Toggle any policy between **Enforce (Block)** and **Monitor (Log Only / Dry-Run)**.
   - Click **New Policy** to author a custom OWASP rule mapped to `API1:2023`–`API9:2023`.
2. **Tune Rate Limits & Verify with Burst Tester (`/rate-limits`)**
   - Inspect per-route **Sliding Window Counter** and **Token Bucket** configurations.
   - Select a route and fire a **25-Request Instant Burst** in the **Interactive Burst Tester** to verify exact `200 OK` vs `429 Too Many Requests` cutoffs and `Retry-After` headers.
3. **Configure Global Auto-Blocking (`/blocklist`)**
   - Toggle **Auto-Block Critical Alerts** ON so that any client triggering a Critical alert (`score >= 80`) is automatically quarantined.
4. **Manage Users & RBAC (`/settings`)**
   - Create new users, change role assignments (`admin`, `analyst`, `developer`, `viewer`), or click **Reset & Re-Seed Clean Demo Telemetry** before a presentation.

---

### Role 2: SOC Analyst (`analyst`)

**Responsibilities:** Continuous monitoring of API traffic, investigating behavioral anomalies, triaging alerts, and executing containment actions.

#### Step-by-Step Workflows:
1. **Monitor Live Traffic (`/traffic`)**
   - Filter real-time WebSocket traffic by **Decision (`blocked`, `rate_limited`, `flagged`)**, **Method**, or **OWASP Category**.
   - Use **Pause Stream** during active incident analysis so the table does not jump while inspecting payloads.
2. **Investigate & Triage Alerts (`/alerts` & `/alerts/:id`)**
   - Filter the alert queue by `CRITICAL` or `OPEN` status.
   - Open an alert to inspect the **Correlated Request Timeline**, **Offender Profile**, and **AI Security Triage**.
   - Transition alert status (`open` → `acknowledged` → `resolved` or `false_positive`) and record forensic notes in the **SOC Investigation Log**.
3. **Hunt Behavioral Z-Score Anomalies (`/analytics`)**
   - Open **Deep Analytics (`/analytics`)** and scroll to the **Per-Client Rolling Z-Score Behavioral Baseline (`API4` / `API6`)** table.
   - Identify clients whose current request velocity exceeds $Z > 3.0\sigma$ above their historical mean $\mu$.

---

### Role 3: API Developer / Service Owner (`developer`)

**Responsibilities:** Maintaining accurate API route inventories, eliminating Shadow/Zombie APIs (`OWASP API9`), testing JWT authentication tokens, and validating new security rules in Monitor mode before production enforcement.

#### Step-by-Step Workflows:
1. **Discover & Remediate Shadow APIs (`/inventory`)**
   - Open **API Inventory (`/inventory`)** and switch to the **Shadow & Legacy APIs (`API9:2023`)** tab.
   - Review undocumented endpoints discovered automatically by SentinelGW (such as `/gw/internal/debug` and `/gw/v1/users`).
   - Click **Promote to Inventory** to register a legitimate endpoint, or **Block Shadow Endpoint** to lock down an unmaintained debug route.
2. **Import OpenAPI 3.0 Specifications (`/inventory`)**
   - Click **Import OpenAPI 3.0 JSON** and load the sample spec to bulk-register routes, auth requirements, and schema constraints.
3. **Test & Debug JWTs Against the 8-Point Checklist (`/auth-settings`)**
   - Open **Auth & JWT (`/auth-settings`)**.
   - In the **Interactive JWT Token Tester**, click any of the **7 Presets** (*Valid Customer*, *Valid Admin*, *Alg:None Forgery*, *Expired Token*, *Wrong Audience*, *Bad Signature*, *Revoked JTI*).
   - Click **Run 8-Point Validation** to see the exact pass/fail status of every cryptographic check (`alg` whitelist, signature, `exp`, `nbf`, `iat`, `iss`, `aud`, `jti` revocation).
4. **Safely Test Policies in Monitor Mode (`/policies`)**
   - Switch a policy to **Monitor (Log)** mode to verify whether legitimate application traffic triggers false positives before switching to **Enforce (Block)**.

---

### Role 4: Executive / Compliance Viewer (`viewer`)

**Responsibilities:** Auditing OWASP API Security Top 10 coverage, reviewing SLA latency impact, and exporting compliance artifacts.

#### Step-by-Step Workflows:
1. **Audit OWASP API Top 10 Coverage (`/owasp`)**
   - Review all 10 categories (`API1:2023` through `API10:2023`), including active enforcing rule counts, 24-hour blocked event metrics, and the explicit architectural scope note for `API10:2023`.
2. **Generate & Export Compliance Reports (`/reports`)**
   - Open **Compliance Reports (`/reports`)** to view the **Overall Security Posture Score** and incident breakdown.
   - Click **Export Traffic (CSV)**, **Export Alerts (CSV)**, or **Print / Save PDF Report**.
3. **Verify RBAC Guardrails**
   - Notice that while logged in as `viewer`, mutation controls (such as deleting policies, toggling the gateway master switch, or unblocking IPs) are disabled to enforce least privilege.

---

### Role 5: External API Consumer / Attacker (`client`)

External API clients and scripts interact directly with the Gateway Data Plane (`/gw/*`):

```bash
# 1. Mint a test JWT or use an API key
curl -i http://localhost:8000/gw/products?limit=5

# 2. Attempt BOLA (User 101 accessing User 102's profile) -> Blocked 403 API1:2023
curl -i -H "X-API-Key: sgw_live_alice_101_secret" http://localhost:8000/gw/users/102

# 3. Attempt SSRF against AWS IMDSv1 -> Blocked 400 API7:2023
curl -i "http://localhost:8000/gw/fetch?url=http://169.254.169.254/latest/meta-data/iam"
```
