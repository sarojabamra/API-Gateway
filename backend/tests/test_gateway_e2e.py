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

        # Customer projects stay inside one organization. VulnShop is shared.
        inventory = client.get("/api/v1/inventory", headers=headers)
        assert inventory.status_code == 200
        demo_projects = inventory.json()["upstreams"]
        assert any(project["slug"] == "vulnshop" for project in demo_projects)
        vulnshop_id = next(project["id"] for project in demo_projects if project["slug"] == "vulnshop")

        same_org = client.get(
            "/api/v1/inventory",
            headers={"Authorization": f"Bearer {register_res.json()['access_token']}"},
        )
        assert same_org.status_code == 200
        assert any(project["id"] == vulnshop_id for project in same_org.json()["upstreams"])

        other_headers = {"Authorization": f"Bearer {create_res.json()['access_token']}"}
        other_org = client.get("/api/v1/inventory", headers=other_headers)
        assert other_org.status_code == 200
        assert [project["id"] for project in other_org.json()["upstreams"]] == [vulnshop_id]
        assert other_org.json()["registered_routes"]
        assert all(route["upstream_id"] == vulnshop_id for route in other_org.json()["registered_routes"])
        assert client.get(f"/api/v1/overview?upstream_id={vulnshop_id}", headers=other_headers).status_code == 200
        assert client.get(f"/api/v1/alerts?upstream_id={vulnshop_id}", headers=other_headers).status_code == 200

        created_project = client.post(
            "/api/v1/inventory/upstreams",
            json={
                "name": "Acme Billing",
                "slug": f"acme-{uuid.uuid4().hex[:8]}",
                "base_url": "http://127.0.0.1:8099",
            },
            headers=other_headers,
        )
        assert created_project.status_code == 200
        created_id = created_project.json()["id"]
        assert created_project.json()["organization_id"] == create_res.json()["user"]["organization_id"]
        assert any(
            project["id"] == created_id
            for project in client.get("/api/v1/inventory", headers=other_headers).json()["upstreams"]
        )
        assert all(
            project["id"] != created_id
            for project in client.get("/api/v1/inventory", headers=headers).json()["upstreams"]
        )
        assert client.get(f"/api/v1/overview?upstream_id={created_id}", headers=headers).status_code == 404

        # Another organization can connect a project with the same name and backend URL
        shared = next(project for project in demo_projects if project["slug"] == "vulnshop")
        duplicate = client.post(
            "/api/v1/inventory/upstreams",
            json={
                "name": shared["name"],
                "slug": shared["slug"],
                "base_url": shared["base_url"],
            },
            headers=other_headers,
        )
        assert duplicate.status_code == 200
        duplicate_body = duplicate.json()
        assert duplicate_body["id"] != shared["id"]
        assert duplicate_body["name"] == shared["name"]
        assert duplicate_body["base_url"] == shared["base_url"]
        assert duplicate_body["organization_id"] == create_res.json()["user"]["organization_id"]
        assert duplicate_body["slug"] != shared["slug"]
        other_projects = client.get("/api/v1/inventory", headers=other_headers).json()["upstreams"]
        assert any(project["id"] == duplicate_body["id"] for project in other_projects)
        demo_again = client.get("/api/v1/inventory", headers=headers).json()["upstreams"]
        assert any(
            project["id"] == shared["id"] and project["base_url"] == shared["base_url"]
            for project in demo_again
        )
        assert all(project["id"] != duplicate_body["id"] for project in demo_again)

        # Bare /gw has no default project; the project slug is required
        missing_slug = client.get("/gw/products")
        assert missing_slug.status_code == 404
        assert "project-slug" in missing_slug.json()["message"]
        assert client.get("/gw/vulnshop/openapi.json").status_code == 200

        # 3. Verify Overview KPIs and OWASP Top 10 coverage
        ov = client.get("/api/v1/overview?time_range=24h", headers=headers)
        assert ov.status_code == 200
        assert ov.json()["kpis"]["total_requests"] > 0

        owasp = client.get("/api/v1/owasp/coverage", headers=headers)
        assert owasp.status_code == 200
        assert len(owasp.json()["cards"]) == 10
        assert owasp.json()["total_in_scope_count"] == 10
        api10 = next(c for c in owasp.json()["cards"] if c["owasp_id"] == "API10")
        assert api10["in_scope"] is True
        assert api10["protection_status"] in ("enforcing", "monitoring")

        metrics = client.get("/metrics")
        assert metrics.status_code == 200
        assert "sentinel_requests_total" in metrics.text

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

        # User 2 opening another user's route is blocked when Gateway ON
        cross_on = client.post("/api/v1/simulator/run", json={"scenario_id": "bola_cross_user"}, headers=headers)
        assert cross_on.status_code == 200
        cross_steps = cross_on.json()["steps"]
        assert len(cross_steps) == 7
        assert cross_steps[0]["status_code"] == 200
        assert sum(1 for step in cross_steps if step["status_code"] == 403) == 6

        # Distinct resource IDs 1–6 hit the enumeration cap when Gateway ON
        bola_on = client.post("/api/v1/simulator/run", json={"scenario_id": "bola_enum"}, headers=headers)
        assert bola_on.status_code == 200
        enum_steps = bola_on.json()["steps"]
        assert len(enum_steps) == 6
        assert enum_steps[0]["status_code"] == 200
        assert bola_on.json()["blocked_count"] >= 1
        assert any(
            step["status_code"] == 429 and "enumeration" in (step.get("response_preview") or "").lower()
            for step in bola_on.json()["steps"]
        )

        # SSRF blocked when Gateway ON
        ssrf_on = client.post("/api/v1/simulator/run", json={"scenario_id": "ssrf_metadata"}, headers=headers)
        assert ssrf_on.status_code == 200
        assert ssrf_on.json()["blocked_count"] >= 1

        # Excessive Data Exposure redacted when Gateway ON (+ nested mass assignment blocked)
        redact_on = client.post("/api/v1/simulator/run", json={"scenario_id": "data_exposure"}, headers=headers)
        assert redact_on.status_code == 200
        preview_on = redact_on.json()["steps"][0]["response_preview"]
        assert "REDACTED BY GATEWAY" in preview_on
        assert redact_on.json()["steps"][0]["outcome"] == "redacted"
        assert redact_on.json()["steps"][0]["blocked_by_gateway"] is False
        assert redact_on.json()["blocked_count"] >= 1  # mass assignment steps

        # API10 unsafe third-party URLs stripped when Gateway ON
        api10_on = client.post(
            "/api/v1/simulator/run",
            json={"scenario_id": "unsafe_api_consume"},
            headers=headers,
        )
        assert api10_on.status_code == 200
        api10_preview = api10_on.json()["steps"][0]["response_preview"]
        assert "STRIPPED BY GATEWAY API10" in api10_preview or api10_on.json()["blocked_count"] >= 1

        # Toggle Gateway OFF and verify pass-through exposes VulnShop vulnerabilities
        client.post("/api/v1/simulator/gateway-toggle", json={"gateway_enabled": False}, headers=headers)
        redact_off = client.post("/api/v1/simulator/run", json={"scenario_id": "data_exposure"}, headers=headers)
        assert redact_off.status_code == 200
        preview_off = redact_off.json()["steps"][0]["response_preview"]
        assert "REDACTED BY GATEWAY" not in preview_off

        api10_off = client.post(
            "/api/v1/simulator/run",
            json={"scenario_id": "unsafe_api_consume"},
            headers=headers,
        )
        assert api10_off.status_code == 200
        assert "169.254.169.254" in api10_off.json()["steps"][0]["response_preview"]

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
