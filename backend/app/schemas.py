from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    email: str
    full_name: str
    password: str
    # create = start a new organization as its admin; join = join an existing one as viewer
    organization_mode: str = "create"
    organization_name: Optional[str] = None
    organization_id: Optional[int] = None


class OrganizationOut(BaseModel):
    id: int
    name: str
    slug: str


class UserOut(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    organization_id: Optional[int] = None
    organization_name: Optional[str] = None
    organization_slug: Optional[str] = None


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class TokenTestRequest(BaseModel):
    token: str
    upstream_id: Optional[int] = None
    expected_role: Optional[str] = None
    expected_scope: Optional[str] = None


class TokenMintRequest(BaseModel):
    sub: str = "user-101"
    email: str = "alice@sentinel.local"
    role: str = "user"
    scopes: List[str] = ["read:products", "read:orders", "write:orders"]
    preset: str = "valid_user"  # valid_user, valid_admin, expired, alg_none, tampered_sig, wrong_issuer, revoked_jti


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    mode: Optional[str] = None  # enforce, monitor
    enabled: Optional[bool] = None
    config: Optional[Dict[str, Any]] = None


class PolicyCreate(BaseModel):
    name: str
    description: str
    type: str
    scope: str = "global"
    target_id: Optional[int] = None
    owasp_id: str = "API8"
    mode: str = "enforce"
    config: Dict[str, Any] = {}
    enabled: bool = True


class AlertActionRequest(BaseModel):
    action: str  # update_status, block_ip, block_user, revoke_token, add_note, assign, create_exception
    status: Optional[str] = None
    note: Optional[str] = None
    assigned_to: Optional[str] = None
    block_duration_minutes: int = 1440


class AlertBulkActionRequest(BaseModel):
    alert_ids: List[int]
    status: str  # investigating, resolved, false_positive


class BlocklistCreateRequest(BaseModel):
    target_type: str  # ip, user_sub, api_key
    value: str
    reason: str
    owasp_id: Optional[str] = "API2"
    duration_minutes: Optional[int] = 1440


class RouteCreateRequest(BaseModel):
    upstream_id: int = 1
    method: str
    path_pattern: str
    description: str = ""
    auth_required: bool = True
    required_role: Optional[str] = None
    required_scopes: List[str] = []
    rate_limit_rpm: int = 60
    burst_capacity: int = 15
    is_sensitive_flow: bool = False
    bola_check_enabled: bool = False
    response_redact_fields: List[str] = ["password_hash", "ssn", "credit_card"]


class OpenAPIImportRequest(BaseModel):
    upstream_id: int = 1
    spec_content: Optional[str] = None


class RateLimitBurstTestRequest(BaseModel):
    upstream_id: int = 1
    path: str = "/products"
    method: str = "GET"
    request_count: int = 20
    client_ip: str = "198.51.100.77"
    auth_token: Optional[str] = None
    api_key: Optional[str] = None


class SimulatorRunRequest(BaseModel):
    scenario_id: str  # bola_cross_user, bola_enum, brute_force, jwt_tamper, data_exposure, rate_flood, bfla_admin, ssrf_metadata, sqli_shadow, all
    upstream_id: int = 1
    auth_token: Optional[str] = None
    api_key: Optional[str] = None
    # Manual route targeting (optional). route_id maps to the scenario's primary role;
    # route_overrides maps role name → route id (e.g. {"read": 12, "write": 15}).
    route_id: Optional[int] = None
    route_overrides: Optional[Dict[str, int]] = None


class SimulatorTokenValidateRequest(BaseModel):
    token: str
    upstream_id: int = 1
