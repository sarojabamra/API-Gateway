from fastapi.testclient import TestClient
from app.main import app


def test_end_to_end_gateway_and_control_plane():
    with TestClient(app) as client:
        # 1. Health check
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "healthy"

        # 2. Quick login for all 4 RBAC roles
        for role in ["admin", "analyst", "developer", "viewer"]:
            login_res = client.post("/api/v1/auth/quick-switch", json={"role": role})
            assert login_res.status_code == 200
            assert login_res.json()["user"]["role"] == role

        admin_token = client.post("/api/v1/auth/quick-switch", json={"role": "admin"}).json()["access_token"]
        headers = {"Authorization": f"Bearer {admin_token}"}

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
