import uuid
from fastapi.testclient import TestClient
from app.main import app


def test_end_to_end_gateway_and_control_plane():
    with TestClient(app) as client:
        # 1. Health check
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "healthy"

        # 2. Unauthenticated control-plane calls are rejected
        assert client.get("/api/v1/overview").status_code == 401
        assert client.post("/api/v1/auth/quick-switch", json={"role": "admin"}).status_code == 404

        # 3. Seeded users sign in with email/password and belong to Sentinel Demo org
        seeded = {
            "admin": "admin@sentinel.local",
            "analyst": "analyst@sentinel.local",
            "developer": "dev@sentinel.local",
            "viewer": "viewer@sentinel.local",
        }
        for role, email in seeded.items():
            login_res = client.post(
                "/api/v1/auth/login",
                json={"email": email, "password": "sentinel123"},
            )
            assert login_res.status_code == 200
            body = login_res.json()["user"]
            assert body["role"] == role
            assert body["organization_slug"] == "sentinel-demo"

        orgs = client.get("/api/v1/auth/organizations")
        assert orgs.status_code == 200
        demo_org = next(o for o in orgs.json() if o["slug"] == "sentinel-demo")

        # Join existing org as viewer
        register_email = f"jordan-{uuid.uuid4().hex[:8]}@example.com"
        register_res = client.post(
            "/api/v1/auth/register",
            json={
                "email": register_email,
                "full_name": "Jordan Hayes",
                "password": "password123",
                "organization_mode": "join",
                "organization_id": demo_org["id"],
            },
        )
        assert register_res.status_code == 200
        assert register_res.json()["user"]["role"] == "viewer"
        assert register_res.json()["user"]["organization_id"] == demo_org["id"]

        duplicate = client.post(
            "/api/v1/auth/register",
            json={
                "email": register_email,
                "full_name": "Jordan Hayes",
                "password": "password123",
                "organization_mode": "join",
                "organization_id": demo_org["id"],
            },
        )
        assert duplicate.status_code == 409

        # Create a separate organization as its admin
        create_email = f"founder-{uuid.uuid4().hex[:8]}@example.com"
        create_res = client.post(
            "/api/v1/auth/register",
            json={
                "email": create_email,
                "full_name": "Org Founder",
                "password": "password123",
                "organization_mode": "create",
                "organization_name": f"Acme {uuid.uuid4().hex[:6]}",
            },
        )
        assert create_res.status_code == 200
        assert create_res.json()["user"]["role"] == "admin"
        assert create_res.json()["user"]["organization_id"] != demo_org["id"]

        admin_token = client.post(
            "/api/v1/auth/login",
            json={"email": "admin@sentinel.local", "password": "sentinel123"},
        ).json()["access_token"]
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Same-org admin can promote joiners
        promoted = client.patch(
            f"/api/v1/settings/users/{register_res.json()['user']['id']}",
            json={"role": "analyst", "is_active": True},
            headers=headers,
        )
        assert promoted.status_code == 200
        assert promoted.json()["role"] == "analyst"

        # Cross-org role changes are forbidden
        blocked = client.patch(
            f"/api/v1/settings/users/{create_res.json()['user']['id']}",
            json={"role": "viewer", "is_active": True},
            headers=headers,
        )
        assert blocked.status_code == 403

        # 3. Verify Overview KPIs and OWASP Top 10 coverage
        ov = client.get("/api/v1/overview?time_range=24h", headers=headers)
        assert ov.status_code == 200
        assert ov.json()["kpis"]["total_requests"] > 0

        owasp = client.get("/api/v1/owasp/coverage", headers=headers)
        assert owasp.status_code == 200
        assert len(owasp.json()["cards"]) == 10

        # 4. Verify 8-Step JWT Token Tester presets
        jwt_test = client.post("/api/v1/auth/jwt-test", json={"preset": "alg_none"}, headers=headers)
        assert jwt_test.status_code == 200
        assert jwt_test.json()["valid"] is False
        assert jwt_test.json()["failed_step"] == "jwt_alg_none"

        jwt_valid = client.post("/api/v1/auth/jwt-test", json={"preset": "valid_customer"}, headers=headers)
        assert jwt_valid.status_code == 200
        assert jwt_valid.json()["valid"] is True

        # 5. Test Gateway Enforcement ON vs OFF via Attack Simulator
        client.post("/api/v1/simulator/gateway-toggle", json={"gateway_enabled": True}, headers=headers)

        invalid_jwt = client.post(
            "/api/v1/simulator/validate-token",
            json={"token": "not-a-jwt", "upstream_id": 1},
            headers=headers,
        )
        assert invalid_jwt.status_code == 400
        assert "Invalid JWT" in invalid_jwt.json()["detail"]

        rejected_run = client.post(
            "/api/v1/simulator/run",
            json={"scenario_id": "bola_enum", "auth_token": "not-a-jwt"},
            headers=headers,
        )
        assert rejected_run.status_code == 400
        assert "Invalid JWT" in rejected_run.json()["detail"]

        # BOLA blocked when Gateway ON
        bola_on = client.post("/api/v1/simulator/run", json={"scenario_id": "bola_enum"}, headers=headers)
        assert bola_on.status_code == 200
        assert bola_on.json()["blocked_count"] >= 1

        # SSRF blocked when Gateway ON
        ssrf_on = client.post("/api/v1/simulator/run", json={"scenario_id": "ssrf_metadata"}, headers=headers)
        assert ssrf_on.status_code == 200
        assert ssrf_on.json()["blocked_count"] >= 1

        # Excessive Data Exposure redacted when Gateway ON
        redact_on = client.post("/api/v1/simulator/run", json={"scenario_id": "data_exposure"}, headers=headers)
        assert redact_on.status_code == 200
        preview_on = redact_on.json()["steps"][0]["response_preview"]
        assert "REDACTED BY GATEWAY" in preview_on

        # Toggle Gateway OFF and verify pass-through exposes VulnShop vulnerabilities
        client.post("/api/v1/simulator/gateway-toggle", json={"gateway_enabled": False}, headers=headers)
        redact_off = client.post("/api/v1/simulator/run", json={"scenario_id": "data_exposure"}, headers=headers)
        assert redact_off.status_code == 200
        preview_off = redact_off.json()["steps"][0]["response_preview"]
        assert "REDACTED BY GATEWAY" not in preview_off

        # Restore Gateway ON
        client.post("/api/v1/simulator/gateway-toggle", json={"gateway_enabled": True}, headers=headers)

        # 6. Test AI Alert Triage & CSV Exports
        alerts = client.get("/api/v1/alerts", headers=headers).json()["items"]
        assert len(alerts) > 0
        alert_id = alerts[0]["id"]
        triage = client.post(f"/api/v1/alerts/{alert_id}/ai-triage", headers=headers)
        assert triage.status_code == 200
        assert "summary" in triage.json()["triage"]

        csv_res = client.get("/api/v1/reports/export/traffic.csv", headers=headers)
        assert csv_res.status_code == 200
        assert "request_id" in csv_res.text
