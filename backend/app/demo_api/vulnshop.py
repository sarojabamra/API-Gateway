from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
import time
import uuid
import jwt
from app.config import settings

router = APIRouter(tags=["VulnShop Demo Upstream API"])

# Intentionally rich in-memory dataset with sensitive properties (to demonstrate API1, API3, API5)
VULNSHOP_USERS: Dict[str, Dict[str, Any]] = {
    "101": {
        "id": "101",
        "sub": "user-101",
        "username": "alice_mercer",
        "email": "alice@vulnshop.io",
        "role": "user",
        "full_name": "Alice Mercer",
        "password_hash": "$2b$12$9vK1xQ8mP2wL5nZ7rT4yU.secretHashAlice9912",
        "ssn": "999-42-8101",
        "credit_card": "4532-8812-0091-4411",
        "loyalty_balance": 420.50,
        "secret_note": "VIP customer - eligible for manual override",
    },
    "102": {
        "id": "102",
        "sub": "user-102",
        "username": "bob_chen",
        "email": "bob@vulnshop.io",
        "role": "user",
        "full_name": "Bob Chen",
        "password_hash": "$2b$12$7pM3kR9nL1xV6cZ2qW8eT.secretHashBob8821",
        "ssn": "999-18-3302",
        "credit_card": "5412-7530-9910-2284",
        "loyalty_balance": 115.00,
        "secret_note": "Standard tier account",
    },
    "103": {
        "id": "103",
        "sub": "user-103",
        "username": "charlie_davis",
        "email": "charlie@vulnshop.io",
        "role": "user",
        "full_name": "Charlie Davis",
        "password_hash": "$2b$12$2kL8mN4pQ6rS0tV1wX3yZ.secretHashCharlie773",
        "ssn": "999-77-9903",
        "credit_card": "4111-2222-3333-4444",
        "loyalty_balance": 890.00,
        "secret_note": "Flagged for chargeback review",
    },
    "999": {
        "id": "999",
        "sub": "admin-999",
        "username": "root_admin",
        "email": "admin@vulnshop.io",
        "role": "admin",
        "full_name": "Victor Vance (SysAdmin)",
        "password_hash": "$2b$12$0aA9bB8cC7dD6eE5fF4gG.rootAdminMasterHash",
        "ssn": "999-00-0001",
        "credit_card": "3782-822463-10005",
        "loyalty_balance": 99999.99,
        "secret_note": "AWS Prod IAM Role: arn:aws:iam::449102938112:role/VulnShopProdAdmin",
    },
}

# Generate additional synthetic users 104..135 for BOLA enumeration demos
for idx in range(104, 136):
    VULNSHOP_USERS[str(idx)] = {
        "id": str(idx),
        "sub": f"user-{idx}",
        "username": f"customer_{idx}",
        "email": f"customer{idx}@vulnshop.io",
        "role": "user",
        "full_name": f"Customer #{idx}",
        "password_hash": f"$2b$12$synthHashForCustomerRecord{idx}xyz99",
        "ssn": f"999-55-{idx:04d}",
        "credit_card": f"4000-1234-5678-{idx:04d}",
        "loyalty_balance": float((idx * 17) % 500),
        "secret_note": f"Internal CRM record ID #{idx}",
    }

VULNSHOP_PRODUCTS = [
    {"id": f"prod-{i}", "name": f"Hardware Security Key v{i}", "price": 49.99 + (i % 7) * 10, "stock": 120, "internal_cost": 8.50}
    for i in range(1, 201)
]

VULNSHOP_ORDERS: Dict[str, Dict[str, Any]] = {
    "5001": {"id": "5001", "owner_sub": "user-101", "item": "Hardware Security Key v1", "total": 59.99, "status": "shipped", "credit_card": "4532-8812-0091-4411", "shipping_address": "742 Evergreen Terrace"},
    "5002": {"id": "5002", "owner_sub": "user-102", "item": "Enterprise Firewall Appliance", "total": 1299.00, "status": "processing", "credit_card": "5412-7530-9910-2284", "shipping_address": "1600 Pennsylvania Ave"},
    "5003": {"id": "5003", "owner_sub": "admin-999", "item": "Zero-Trust HSM Cluster", "total": 14500.00, "status": "delivered", "credit_card": "3782-822463-10005", "shipping_address": "100 Cyber Command Way"},
}


def _add_leaky_headers(response: Response):
    """Intentionally adds verbose server fingerprinting headers (OWASP API8)."""
    response.headers["Server"] = "VulnShop-Legacy-Server/1.4.2 (Python/3.12 DebugMode=True)"
    response.headers["X-Powered-By"] = "FastAPI-Unpatched-Internal/0.1"
    response.headers["X-Backend-Host"] = "ip-10-0-14-88.ec2.internal"


class VulnLoginInput(BaseModel):
    username: str
    password: str


class VulnRegisterInput(BaseModel):
    username: str
    email: str
    password: str
    role: Optional[str] = "user"  # Intentionally vulnerable to mass assignment (API3)


@router.post("/auth/login")
async def vulnshop_login(payload: VulnLoginInput, response: Response):
    _add_leaky_headers(response)
    # Valid demo password for alice_mercer / bob_chen is "password123"
    matched_user = None
    for u in VULNSHOP_USERS.values():
        if u["username"] == payload.username or u["email"] == payload.username:
            matched_user = u
            break

    if not matched_user or payload.password not in ("password123", "admin123"):
        raise HTTPException(status_code=401, detail="Invalid username or password against VulnShop DB")

    now = int(time.time())
    token_payload = {
        "sub": matched_user["sub"],
        "email": matched_user["email"],
        "role": matched_user["role"],
        "scopes": ["read:products", "read:orders", "write:orders"],
        "iss": settings.GATEWAY_JWT_ISSUER,
        "aud": settings.GATEWAY_JWT_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        "jti": f"jti-{uuid.uuid4().hex[:12]}",
    }
    token = jwt.encode(token_payload, settings.GATEWAY_JWT_SECRET, algorithm="HS256")
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": matched_user,  # Intentionally leaks password_hash & ssn unless gateway redacts it!
    }


@router.post("/auth/register")
async def vulnshop_register(payload: VulnRegisterInput, response: Response):
    _add_leaky_headers(response)
    new_id = str(len(VULNSHOP_USERS) + 200)
    new_user = {
        "id": new_id,
        "sub": f"user-{new_id}",
        "username": payload.username,
        "email": payload.email,
        "role": payload.role or "user",
        "full_name": payload.username,
        "password_hash": f"$2b$12$rawUnk{payload.password}",
        "ssn": "000-00-0000",
        "credit_card": "0000-0000-0000-0000",
        "loyalty_balance": 100.0,
        "secret_note": "Newly registered account",
    }
    VULNSHOP_USERS[new_id] = new_user
    return {"status": "created", "user": new_user}


@router.get("/users/me")
async def vulnshop_users_me(request: Request, response: Response):
    """OWASP API3: Returns excessive object properties including password_hash, ssn, credit_card."""
    _add_leaky_headers(response)
    user_sub = request.headers.get("X-Gateway-User-Sub", "user-101")
    for u in VULNSHOP_USERS.values():
        if u["sub"] == user_sub:
            return u
    return VULNSHOP_USERS["101"]


@router.get("/users/{user_id}")
async def vulnshop_get_user(user_id: str, response: Response):
    """OWASP API1 (BOLA) & API3: No ownership check upstream, returns full PII and password hash."""
    _add_leaky_headers(response)
    # Normalize "user-101" or "101"
    clean_id = user_id.replace("user-", "")
    user = VULNSHOP_USERS.get(clean_id)
    if not user:
        raise HTTPException(status_code=404, detail=f"User ID {user_id} not found in table `users`")
    return user


@router.get("/admin/users")
async def vulnshop_admin_users(response: Response):
    """OWASP API5 (BFLA): Upstream forgot to verify admin role! Returns all users + secrets."""
    _add_leaky_headers(response)
    return {
        "admin_dump": True,
        "total_users": len(VULNSHOP_USERS),
        "users": list(VULNSHOP_USERS.values())[:15],
    }


@router.post("/orders")
async def vulnshop_create_order(payload: Dict[str, Any], response: Response):
    """OWASP API3 & API6: Accepts arbitrary mass-assigned fields (like status='paid', total=0.01)."""
    _add_leaky_headers(response)
    order_id = str(5000 + len(VULNSHOP_ORDERS) + 1)
    order = {
        "id": order_id,
        "owner_sub": payload.get("owner_sub", "user-101"),
        "item": payload.get("item", "Hardware Security Key v1"),
        "total": payload.get("total", 49.99),
        "status": payload.get("status", "created"),
        "is_admin_override": payload.get("is_admin_override", False),
        "credit_card": "4532-8812-0091-4411",
    }
    VULNSHOP_ORDERS[order_id] = order
    return {"status": "order_created", "order": order}


@router.get("/orders/{order_id}")
async def vulnshop_get_order(order_id: str, response: Response):
    """OWASP API1 (BOLA): Any user can fetch any order ID without ownership verification."""
    _add_leaky_headers(response)
    order = VULNSHOP_ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail=f"Order {order_id} not found")
    return order


@router.post("/coupons/redeem")
async def vulnshop_redeem_coupon(payload: Dict[str, Any], response: Response):
    """OWASP API6: Sensitive business flow vulnerable to automated bot velocity / coupon abuse."""
    _add_leaky_headers(response)
    code = payload.get("code", "WELCOME50")
    return {
        "status": "redeemed",
        "coupon_code": code,
        "discount_applied_usd": 50.0,
        "remaining_promo_pool_usd": 9450.0,
        "message": "Coupon applied without velocity limit upstream!",
    }


@router.get("/fetch")
async def vulnshop_ssrf_fetch(url: str = Query(..., description="Remote supplier URL to fetch"), response: Response = None):
    """OWASP API7 (SSRF): Fetches arbitrary attacker-supplied URLs including cloud metadata."""
    _add_leaky_headers(response)
    lower_url = url.lower()
    if "169.254.169.254" in lower_url or "metadata" in lower_url:
        return {
            "fetched_url": url,
            "ssrf_exploited": True,
            "cloud_metadata_leak": {
                "Code": "Success",
                "Type": "AWS-HMAC",
                "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "Token": "IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJHMEUCIQ...",
                "RoleArn": "arn:aws:iam::449102938112:role/VulnShopEC2InstanceProfile",
            },
        }
    if "localhost" in lower_url or "127.0.0.1" in lower_url or "10." in lower_url or "192.168." in lower_url:
        return {
            "fetched_url": url,
            "ssrf_exploited": True,
            "internal_service_response": {
                "redis_info": "redis_version:7.2.4, connected_clients:14, requirepass:disabled",
                "internal_admin_panel": "http://127.0.0.1:9000/cluster-keys",
            },
        }
    return {"fetched_url": url, "status": "ok", "supplier_catalog_items": 12}


@router.get("/search")
async def vulnshop_search(q: str = Query(""), response: Response = None):
    """OWASP API8 / Injection: Simulates SQL injection data dump if SQLi payload reaches upstream."""
    _add_leaky_headers(response)
    lower_q = q.lower()
    if "union select" in lower_q or "or 1=1" in lower_q or "' or '" in lower_q or "--" in lower_q:
        return {
            "query_executed": f"SELECT * FROM products WHERE name LIKE '%{q}%'",
            "sqli_exploited": True,
            "leaked_database_rows": list(VULNSHOP_USERS.values())[:5],
        }
    matches = [p for p in VULNSHOP_PRODUCTS[:20] if q.lower() in p["name"].lower()]
    return {"query": q, "count": len(matches), "results": matches}


@router.get("/products")
async def vulnshop_products(limit: int = Query(20), response: Response = None):
    """OWASP API4: No pagination cap upstream - allows ?limit=50000 resource exhaustion."""
    _add_leaky_headers(response)
    if limit > 200:
        # Simulate heavy response generation when unthrottled
        items = (VULNSHOP_PRODUCTS * ((limit // 200) + 1))[: min(limit, 2500)]
    else:
        items = VULNSHOP_PRODUCTS[:limit]
    return {"requested_limit": limit, "returned_count": len(items), "products": items}


@router.get("/internal/debug")
async def vulnshop_shadow_debug(response: Response):
    """OWASP API9 (Improper Inventory / Shadow API): Undocumented debug endpoint left in prod."""
    _add_leaky_headers(response)
    return {
        "shadow_endpoint": "/internal/debug",
        "debug_mode": True,
        "environment_secrets": {
            "DB_CONNECTION": "postgresql://vulnshop_root:SuperSecretDbPass!2026@10.0.4.12:5432/prod",
            "STRIPE_LIVE_SECRET": "[REDACTED]",
            "JWT_SIGNING_SECRET": settings.GATEWAY_JWT_SECRET,
        },
    }
