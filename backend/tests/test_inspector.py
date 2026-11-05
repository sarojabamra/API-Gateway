import json
from app.gateway.inspector import (
    egress_trust_keys_for_base_url,
    inspect_egress_destination,
    inspect_request_payload,
    inspect_ssrf_url,
    inspect_response_for_unsafe_urls,
    normalize_inspection_surface,
    validate_request_schema,
)


def test_nested_mass_assignment_blocked():
    result = inspect_request_payload(
        path="/auth/register",
        query_string="",
        body_text=json.dumps({"email": "a@b.c", "profile": {"role": "admin"}}),
    )
    assert result["violation"] is True
    assert result["owasp_id"] == "API3"
    assert "Mass Assignment" in result["reason"]


def test_top_level_role_admin_blocked():
    result = inspect_request_payload(
        path="/auth/register",
        query_string="",
        body_text=json.dumps({"email": "a@b.c", "role": "admin"}),
    )
    assert result["violation"] is True
    assert result["owasp_id"] == "API3"


def test_ssrf_literal_metadata_blocked():
    err = inspect_ssrf_url("http://169.254.169.254/latest/meta-data/", resolve_dns=False)
    assert err is not None
    assert "SSRF" in err


def test_ssrf_decimal_loopback_blocked():
    # 2130706433 == 127.0.0.1
    err = inspect_ssrf_url("http://2130706433/", resolve_dns=False)
    assert err is not None


def test_ssrf_nested_json_body():
    result = inspect_request_payload(
        path="/orders",
        query_string="",
        body_text=json.dumps({"config": {"webhook": "http://127.0.0.1:6379"}}),
    )
    assert result["violation"] is True
    assert result["owasp_id"] == "API7"


def test_pagination_cap_query_and_body():
    q = inspect_request_payload("/products", "limit=50000", "", max_page_limit=100)
    assert q["violation"] is True
    assert q["owasp_id"] == "API4"

    b = inspect_request_payload(
        "/products",
        "",
        json.dumps({"limit": 50000}),
        max_page_limit=100,
    )
    assert b["violation"] is True
    assert b["owasp_id"] == "API4"


def test_normalized_sqli_detection():
    surface = normalize_inspection_surface("1' UNION/**/SELECT null--")
    assert "union" in surface and "select" in surface
    result = inspect_request_payload(
        "/search",
        "q=1'%20UNION/**/SELECT%20null--",
        "",
    )
    assert result["violation"] is True
    assert result["owasp_id"] == "API8"


def test_request_schema_rejects_extra_props():
    schema = {
        "type": "object",
        "properties": {"email": {"type": "string"}, "password": {"type": "string"}},
        "additionalProperties": False,
        "required": ["email", "password"],
    }
    err = validate_request_schema({"email": "a@b.c", "password": "x", "is_admin": True}, schema)
    assert err is not None

    result = inspect_request_payload(
        "/auth/register",
        "",
        json.dumps({"email": "a@b.c", "password": "x", "extra": 1}),
        request_schema_json=json.dumps(schema),
    )
    # May fail on mass assignment OR schema — either is a violation
    assert result["violation"] is True


def test_api10_response_unsafe_url():
    body = json.dumps({"webhook": "http://169.254.169.254/latest/meta-data/"})
    hit = inspect_response_for_unsafe_urls(body)
    assert hit is not None
    assert hit["owasp_id"] == "API10"


def test_egress_blocks_untrusted_localhost():
    err = inspect_egress_destination("http://localhost:8001/auth/login")
    assert err is not None
    assert "localhost" in err


def test_egress_allows_configured_upstream_localhost():
    trust = egress_trust_keys_for_base_url("http://localhost:8001")
    assert "localhost:8001" in trust
    err = inspect_egress_destination(
        "http://localhost:8001/auth/login",
        trusted_hosts=trust,
    )
    assert err is None


def test_egress_trusted_upstream_does_not_open_other_loopback_ports():
    trust = egress_trust_keys_for_base_url("http://localhost:8001")
    # Redis on another loopback port must still be blocked
    err = inspect_egress_destination("http://localhost:6379/info", trusted_hosts=trust)
    assert err is not None


def test_request_ssrf_still_blocks_localhost_webhook():
    """Trusted upstream allowlist must not weaken body/query SSRF (API7)."""
    result = inspect_request_payload(
        path="/orders",
        query_string="",
        body_text=json.dumps({"webhook": "http://localhost:8001/steal"}),
    )
    assert result["violation"] is True
    assert result["owasp_id"] == "API7"


def test_resolve_login_request_form_urlencoded_oauth2():
    from app.attack_sim.scenarios import _resolve_login_request
    from app.models import Route, Upstream

    schema = {
        "properties": {
            "grant_type": {"type": "string"},
            "username": {"type": "string"},
            "password": {"type": "string"},
        },
        "required": ["username", "password"],
        "title": "Body_login_auth_login_post",
    }
    upstream = Upstream(
        name="Parking",
        slug="parking-v2",
        base_url="http://localhost:8001",
        openapi_spec_json=json.dumps({
            "paths": {
                "/auth/login": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/x-www-form-urlencoded": {
                                    "schema": schema,
                                }
                            }
                        }
                    }
                }
            }
        }),
    )
    route = Route(
        upstream_id=2,
        method="POST",
        path_pattern="/auth/login",
        request_schema_json=json.dumps(schema),
        registered=True,
    )
    req = _resolve_login_request(upstream, route, "alice", "bad")
    assert req["content_type"] == "application/x-www-form-urlencoded"
    assert "data" in req
    assert req["data"]["username"] == "alice"
    assert req["data"]["password"] == "bad"
    assert req["data"]["grant_type"] == "password"


def test_resolve_login_request_json_vulnshop():
    from app.attack_sim.scenarios import _resolve_login_request
    from app.models import Route, Upstream

    schema = {
        "properties": {"username": {"type": "string"}, "password": {"type": "string"}},
        "required": ["username", "password"],
    }
    upstream = Upstream(
        name="VulnShop",
        slug="vulnshop",
        base_url="http://127.0.0.1:8000/demo",
        openapi_spec_json=json.dumps({
            "paths": {
                "/auth/login": {
                    "post": {
                        "requestBody": {
                            "content": {"application/json": {"schema": schema}}
                        }
                    }
                }
            }
        }),
    )
    route = Route(
        upstream_id=1,
        method="POST",
        path_pattern="/auth/login",
        request_schema_json=json.dumps(schema),
        registered=True,
    )
    req = _resolve_login_request(upstream, route, "alice", "bad")
    assert req["content_type"] == "application/json"
    assert req["json"] == {"username": "alice", "password": "bad"}
