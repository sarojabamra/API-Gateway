from app.attack_sim.targeting import plan_scenario_targets
from app.models import Route


def _route(**kwargs) -> Route:
    defaults = dict(
        upstream_id=1,
        method="GET",
        path_pattern="/",
        description="",
        auth_required=True,
        required_role=None,
        bola_check_enabled=False,
        bola_mode="equals_sub",
        bola_owner_param="id",
        is_sensitive_flow=False,
        registered=True,
    )
    defaults.update(kwargs)
    return Route(**defaults)


def test_parking_like_targets():
    routes = [
        _route(method="POST", path_pattern="/auth/login", auth_required=False, is_sensitive_flow=True),
        _route(method="POST", path_pattern="/auth/register", auth_required=False, is_sensitive_flow=True),
        _route(
            method="GET",
            path_pattern="/parking/users/{user_id}/history",
            bola_check_enabled=True,
            bola_mode="equals_sub",
            bola_owner_param="user_id",
        ),
        _route(
            method="DELETE",
            path_pattern="/bookings/{booking_id}",
            bola_check_enabled=True,
            bola_mode="learned_owner",
            bola_owner_param="booking_id",
            is_sensitive_flow=True,
        ),
        _route(method="POST", path_pattern="/bookings/", is_sensitive_flow=True),
        _route(method="GET", path_pattern="/bookings/", is_sensitive_flow=True),
        _route(method="GET", path_pattern="/admin/parking-history", required_role="admin"),
        _route(method="POST", path_pattern="/parking/lock"),
        _route(method="GET", path_pattern="/parking/availability"),
    ]

    login = plan_scenario_targets("brute_force", routes)
    assert login.applicable
    assert login.route("login").path_pattern == "/auth/login"

    bola = plan_scenario_targets("bola_enum", routes)
    assert bola.applicable
    # Prefer equals_sub user history over booking resource
    assert bola.route("bola").path_pattern == "/parking/users/{user_id}/history"

    admin = plan_scenario_targets("bfla_admin", routes)
    assert admin.applicable
    assert admin.route("admin").path_pattern == "/admin/parking-history"

    sens = plan_scenario_targets("coupon_scalp", routes)
    assert sens.applicable
    assert sens.route("sensitive").path_pattern in ("/bookings/", "/parking/lock", "/bookings/{booking_id}")

    # No supplier catalog → not applicable
    api10 = plan_scenario_targets("unsafe_api_consume", routes)
    assert api10.applicable is False


def test_trello_like_targets():
    routes = [
        _route(method="POST", path_pattern="/auth/login", auth_required=False, is_sensitive_flow=True),
        _route(method="POST", path_pattern="/auth/google"),
        _route(
            method="GET",
            path_pattern="/users/{userId}/boards",
            bola_check_enabled=True,
            bola_mode="equals_sub",
            bola_owner_param="userId",
        ),
        _route(
            method="POST",
            path_pattern="/users/{userId}/boards",
            bola_check_enabled=True,
            bola_mode="equals_sub",
            bola_owner_param="userId",
        ),
    ]
    bola = plan_scenario_targets("bola_enum", routes)
    assert bola.route("bola").path_pattern == "/users/{userId}/boards"
    assert bola.route("bola").method == "GET"

    jwt = plan_scenario_targets("jwt_tamper", routes)
    assert jwt.applicable
    assert jwt.route("jwt_victim").path_pattern == "/users/{userId}/boards"

    # No admin routes
    admin = plan_scenario_targets("bfla_admin", routes)
    assert admin.applicable is False

    # Google auth must not be chosen as login
    login = plan_scenario_targets("brute_force", routes)
    assert login.route("login").path_pattern == "/auth/login"


def test_vulnshop_prefers_demo_routes():
    routes = [
        _route(method="POST", path_pattern="/auth/login", auth_required=False, is_sensitive_flow=True),
        _route(method="POST", path_pattern="/auth/register", auth_required=False, is_sensitive_flow=True),
        _route(method="GET", path_pattern="/users/me"),
        _route(
            method="GET",
            path_pattern="/users/{id}",
            bola_check_enabled=True,
            bola_mode="equals_sub",
            bola_owner_param="id",
        ),
        _route(method="GET", path_pattern="/products", auth_required=False),
        _route(method="GET", path_pattern="/search", auth_required=False),
        _route(method="GET", path_pattern="/fetch"),
        _route(method="GET", path_pattern="/supplier/catalog"),
        _route(method="POST", path_pattern="/coupons/redeem", is_sensitive_flow=True),
        _route(method="GET", path_pattern="/admin/users", required_role="admin"),
    ]
    assert plan_scenario_targets("rate_flood", routes).route("list").path_pattern == "/products"
    assert plan_scenario_targets("sqli_inject", routes).route("search").path_pattern == "/search"
    assert plan_scenario_targets("ssrf_metadata", routes).route("fetch").path_pattern == "/fetch"
    assert plan_scenario_targets("unsafe_api_consume", routes).route("supplier").path_pattern == "/supplier/catalog"
    assert plan_scenario_targets("coupon_scalp", routes).route("sensitive").path_pattern == "/coupons/redeem"
    assert plan_scenario_targets("data_exposure", routes).route("read").path_pattern == "/users/me"
    assert plan_scenario_targets("data_exposure", routes).route("write").path_pattern == "/auth/register"


def test_login_not_confused_with_register_or_sensitive():
    routes = [
        _route(method="POST", path_pattern="/auth/register", auth_required=False, is_sensitive_flow=True),
        _route(method="POST", path_pattern="/auth/login", auth_required=False, is_sensitive_flow=True),
        _route(method="POST", path_pattern="/bookings/", is_sensitive_flow=True),
    ]
    assert plan_scenario_targets("brute_force", routes).route("login").path_pattern == "/auth/login"
    assert plan_scenario_targets("coupon_scalp", routes).route("sensitive").path_pattern == "/bookings/"


def test_manual_route_override_wins():
    login = _route(id=1, method="POST", path_pattern="/auth/login", auth_required=False, is_sensitive_flow=True)
    weird = _route(id=2, method="POST", path_pattern="/custom/sign-in", auth_required=False)
    plan = plan_scenario_targets("brute_force", [login, weird], overrides={"login": 2})
    assert plan.applicable
    assert plan.route("login").path_pattern == "/custom/sign-in"
    assert "manual selection" in plan.reason("login")


def test_list_scenario_route_options_marks_recommended():
    from app.attack_sim.targeting import list_scenario_route_options

    routes = [
        _route(id=10, method="POST", path_pattern="/auth/login", auth_required=False, is_sensitive_flow=True),
        _route(id=11, method="POST", path_pattern="/auth/register", auth_required=False, is_sensitive_flow=True),
        _route(id=12, method="GET", path_pattern="/products", auth_required=False),
    ]
    opts = list_scenario_route_options("brute_force", routes)
    assert len(opts) == 1
    assert opts[0]["role"] == "login"
    assert opts[0]["auto_route_id"] == 10
    rec = next(c for c in opts[0]["candidates"] if c["recommended"])
    assert rec["path_pattern"] == "/auth/login"
