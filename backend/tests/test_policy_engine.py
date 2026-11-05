from app.gateway.policy_engine import (
    check_bola_ownership,
    infer_route_security,
    is_resource_like_param,
    is_user_like_param,
    list_learned_object_ids,
    match_route_pattern,
    remember_object_owner,
    track_bola_enumeration,
)
from app.models import Route


def test_match_route_pattern_extracts_params():
    ok, params = match_route_pattern("/users/{id}", "/users/102")
    assert ok is True
    assert params == {"id": "102"}


def test_infer_admin_and_internal_paths():
    admin = infer_route_security("/admin/users")
    assert admin["required_role"] == "admin"
    assert admin["auth_required"] is True

    internal = infer_route_security("/internal/debug")
    assert internal["required_role"] == "admin"

    actuator = infer_route_security("/actuator/env")
    assert actuator["required_role"] == "admin"


def test_infer_bola_param_from_path():
    meta = infer_route_security("/orders/{order_id}")
    assert meta["bola_check_enabled"] is True
    assert meta["bola_owner_param"] == "order_id"
    assert meta["bola_mode"] == "learned_owner"


def test_infer_users_path_uses_equals_sub():
    meta = infer_route_security("/users/{id}")
    assert meta["bola_mode"] == "equals_sub"
    assert meta["bola_owner_param"] == "id"
    assert is_user_like_param("id", "/users/{id}") is True


def test_infer_booking_path_uses_learned_owner():
    meta = infer_route_security("/bookings/{bookingId}")
    assert meta["bola_check_enabled"] is True
    assert meta["bola_owner_param"] == "bookingId"
    assert meta["bola_mode"] == "learned_owner"
    assert is_user_like_param("bookingId", "/bookings/{bookingId}") is False
    assert is_resource_like_param("bookingId", "/bookings/{bookingId}") is True


def test_bola_allows_matching_sub():
    route = Route(
        upstream_id=1,
        method="GET",
        path_pattern="/users/{id}",
        bola_check_enabled=True,
        bola_owner_claim="sub",
        bola_owner_param="id",
        bola_mode="equals_sub",
        registered=True,
    )
    ok, err = check_bola_ownership(route, {"id": "101"}, "user-101", "user")
    assert ok is True
    assert err is None


def test_bola_blocks_cross_user():
    route = Route(
        upstream_id=1,
        method="GET",
        path_pattern="/users/{id}",
        bola_check_enabled=True,
        bola_owner_claim="sub",
        bola_owner_param="id",
        bola_mode="equals_sub",
        registered=True,
    )
    ok, err = check_bola_ownership(route, {"id": "102"}, "user-101", "user")
    assert ok is False
    assert "BOLA" in (err or "")


def test_bola_booking_id_not_treated_as_user_sub():
    """Parking-lot regression: booking 101 must NOT auto-belong to user-101."""
    route = Route(
        upstream_id=99,
        method="GET",
        path_pattern="/bookings/{bookingId}",
        bola_check_enabled=True,
        bola_owner_claim="sub",
        bola_owner_param="bookingId",
        bola_mode="learned_owner",
        registered=True,
    )
    # Unknown owner → fail-open (first access may learn ownership)
    ok_unknown, _ = check_bola_ownership(route, {"bookingId": "101"}, "user-101", "user")
    assert ok_unknown is True

    remember_object_owner(99, "/bookings/{bookingId}", "101", "user-202")
    ok_foreign, err = check_bola_ownership(route, {"bookingId": "101"}, "user-101", "user")
    assert ok_foreign is False
    assert "BOLA" in (err or "")

    remember_object_owner(99, "/bookings/{bookingId}", "555", "user-101")
    ok_own, _ = check_bola_ownership(route, {"bookingId": "555"}, "user-101", "user")
    assert ok_own is True
    assert list_learned_object_ids(99, "/bookings/{bookingId}", owner_sub="user-101") == ["555"]


def test_bola_checks_query_and_body_ids():
    route = Route(
        upstream_id=1,
        method="GET",
        path_pattern="/orders",
        bola_check_enabled=True,
        bola_owner_claim="sub",
        bola_owner_param="order_id",
        bola_mode="learned_owner",
        registered=True,
    )
    remember_object_owner(1, "/orders", "9999", "user-999")
    ok, _ = check_bola_ownership(
        route,
        {},
        "user-101",
        "user",
        query_params={"order_id": "9999"},
        body_json=None,
        decoded_jwt={"sub": "user-101"},
    )
    assert ok is False


def test_bola_enumeration_tracker():
    exceeded, count = track_bola_enumeration("test-client", "1", max_distinct=3)
    assert exceeded is False
    track_bola_enumeration("test-client", "2", max_distinct=3)
    track_bola_enumeration("test-client", "3", max_distinct=3)
    exceeded, count = track_bola_enumeration("test-client", "4", max_distinct=3)
    assert exceeded is True
    assert count >= 4


def test_bola_resolves_stale_userid_param_name():
    """Inventory saved bola_owner_param='id' but path uses {userId} — still enforce sub==userId."""
    route = Route(
        upstream_id=4,
        method="GET",
        path_pattern="/users/{userId}/boards",
        bola_check_enabled=True,
        bola_owner_claim="sub",
        bola_owner_param="id",  # stale
        bola_mode="equals_sub",
        auth_required=True,
        registered=True,
    )
    ok, err = check_bola_ownership(route, {"userId": "abc"}, "other-user", "user")
    assert ok is False
    assert "BOLA" in (err or "")
    ok_own, _ = check_bola_ownership(route, {"userId": "abc"}, "abc", "user")
    assert ok_own is True


def test_bola_skips_admin_routes():
    route = Route(
        upstream_id=2,
        method="PATCH",
        path_pattern="/admin/users/{user_id}/role",
        bola_check_enabled=True,
        bola_owner_claim="sub",
        bola_owner_param="user_id",
        bola_mode="equals_sub",
        required_role="admin",
        auth_required=True,
        registered=True,
    )
    # Non-admin caller is gated by BFLA; BOLA itself must not require sub==user_id here.
    ok, _ = check_bola_ownership(route, {"user_id": "999"}, "user-101", "user")
    assert ok is True


def test_bola_skips_public_user_pages():
    route = Route(
        upstream_id=5,
        method="GET",
        path_pattern="/users/{id}",
        bola_check_enabled=True,
        bola_owner_claim="sub",
        bola_owner_param="id",
        bola_mode="equals_sub",
        auth_required=False,  # public profile
        registered=True,
    )
    ok, _ = check_bola_ownership(route, {"id": "42"}, "user-101", "user")
    assert ok is True


def test_infer_admin_disables_bola():
    meta = infer_route_security("/admin/users/{user_id}/role")
    assert meta["required_role"] == "admin"
    assert meta["bola_check_enabled"] is False


def test_infer_public_profile_disables_bola():
    meta = infer_route_security("/public/users/{id}", {"security": [], "tags": ["public"]})
    assert meta["auth_required"] is False
    assert meta["bola_check_enabled"] is False
