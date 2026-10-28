from datetime import datetime, timedelta, timezone
from typing import Optional
from sqlmodel import Field, SQLModel

IST = timezone(timedelta(hours=5, minutes=30), name="IST")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_ist(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST)


def to_ist_iso(dt: Optional[datetime]) -> Optional[str]:
    ist_dt = to_ist(dt)
    return ist_dt.isoformat() if ist_dt is not None else None


class User(SQLModel, table=True):
    __tablename__ = "users"
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    full_name: str
    password_hash: str
    role: str = Field(default="viewer", index=True)  # admin, analyst, developer, viewer
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utcnow)
    last_login_at: Optional[datetime] = Field(default=None)


class Upstream(SQLModel, table=True):
    __tablename__ = "upstreams"
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    slug: str = Field(index=True, unique=True)
    base_url: str
    auth_mode: str = Field(default="jwt")  # jwt, api_key, both, none
    openapi_spec_json: Optional[str] = Field(default=None)
    enabled: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utcnow)


class UpstreamJWTConfig(SQLModel, table=True):
    """JWT verification settings owned by one connected upstream API project."""
    __tablename__ = "upstream_jwt_configs"
    id: Optional[int] = Field(default=None, primary_key=True)
    upstream_id: int = Field(index=True, unique=True)
    enabled: bool = Field(default=True)
    allowed_algorithms_json: str = Field(default='["HS256"]')
    verification_key: str = Field(default="")
    issuer: Optional[str] = Field(default=None)
    audience: Optional[str] = Field(default=None)
    require_jti: bool = Field(default=False)
    leeway_seconds: int = Field(default=10)
    updated_at: datetime = Field(default_factory=utcnow)


class Route(SQLModel, table=True):
    __tablename__ = "routes"
    id: Optional[int] = Field(default=None, primary_key=True)
    upstream_id: int = Field(index=True)
    method: str = Field(index=True)  # GET, POST, PUT, DELETE, *
    path_pattern: str = Field(index=True)  # e.g. /users/{id}
    description: str = Field(default="")
    auth_required: bool = Field(default=True)
    required_role: Optional[str] = Field(default=None)  # e.g. admin, user
    required_scopes_json: str = Field(default="[]")
    rate_limit_rpm: int = Field(default=60)
    burst_capacity: int = Field(default=15)
    is_sensitive_flow: bool = Field(default=False)  # OWASP API6
    bola_check_enabled: bool = Field(default=False)  # OWASP API1
    request_schema_json: Optional[str] = Field(default=None)
    response_redact_fields_json: str = Field(default='["password_hash", "ssn", "credit_card", "secret_note"]')  # OWASP API3
    registered: bool = Field(default=True, index=True)  # False = discovered Shadow API (OWASP API9)
    hit_count: int = Field(default=0)
    last_seen_at: Optional[datetime] = Field(default=None)


class Policy(SQLModel, table=True):
    __tablename__ = "policies"
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    description: str
    type: str = Field(index=True)  # rate_limit, auth, bola, bfla, ip_filter, size_limit, content_type, signature, ssrf, header_hardening, field_redaction, shadow_api
    scope: str = Field(default="global")  # global, upstream, route
    target_id: Optional[int] = Field(default=None)
    owasp_id: str = Field(index=True)  # API1 .. API9
    mode: str = Field(default="enforce")  # enforce, monitor (dry-run)
    config_json: str = Field(default="{}")
    enabled: bool = Field(default=True)
    updated_at: datetime = Field(default_factory=utcnow)


class ApiKey(SQLModel, table=True):
    __tablename__ = "api_keys"
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    key_prefix: str = Field(index=True)
    hashed_key: str = Field(index=True)
    owner_email: str
    role: str = Field(default="user")
    scopes_json: str = Field(default='["read:products", "read:orders"]')
    rate_limit_tier: str = Field(default="standard")  # standard, premium, internal
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: Optional[datetime] = Field(default=None)
    revoked: bool = Field(default=False)


class RequestLog(SQLModel, table=True):
    __tablename__ = "request_logs"
    id: Optional[int] = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=utcnow, index=True)
    request_id: str = Field(index=True)
    client_ip: str = Field(index=True)
    user_sub: Optional[str] = Field(default=None, index=True)
    user_role: Optional[str] = Field(default=None)
    api_key_id: Optional[int] = Field(default=None)
    upstream_id: Optional[int] = Field(default=1)
    route_id: Optional[int] = Field(default=None, index=True)
    method: str = Field(index=True)
    path: str = Field(index=True)
    query_params: str = Field(default="")
    request_headers_json: str = Field(default="{}")
    request_body_preview: str = Field(default="")
    response_body_preview: str = Field(default="")
    decoded_jwt_json: str = Field(default="{}")
    status_code: int = Field(index=True)
    latency_ms: float = Field(default=1.0)
    req_size_bytes: int = Field(default=0)
    resp_size_bytes: int = Field(default=0)
    user_agent: str = Field(default="")
    decision: str = Field(index=True)  # allowed, blocked, rate_limited, monitored
    block_reason: Optional[str] = Field(default=None)
    matched_policy_id: Optional[int] = Field(default=None)
    owasp_id: Optional[str] = Field(default=None, index=True)
    threat_score: int = Field(default=0)
    anomaly_zscore: float = Field(default=0.0)


class Alert(SQLModel, table=True):
    __tablename__ = "alerts"
    id: Optional[int] = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=utcnow, index=True)
    updated_at: datetime = Field(default_factory=utcnow)
    severity: str = Field(index=True)  # low, medium, high, critical
    type: str = Field(index=True)
    owasp_id: str = Field(index=True)
    title: str
    description: str
    client_ip: str = Field(index=True)
    user_sub: Optional[str] = Field(default=None)
    target_path: str = Field(default="")
    event_count: int = Field(default=1)
    status: str = Field(default="open", index=True)  # open, investigating, resolved, false_positive
    assigned_to: Optional[str] = Field(default=None)
    notes_json: str = Field(default="[]")
    related_request_ids_json: str = Field(default="[]")
    evidence_json: str = Field(default="{}")
    ai_summary_json: Optional[str] = Field(default=None)


class BlocklistEntry(SQLModel, table=True):
    __tablename__ = "blocklist"
    id: Optional[int] = Field(default=None, primary_key=True)
    target_type: str = Field(index=True)  # ip, user_sub, api_key
    value: str = Field(index=True)
    reason: str
    owasp_id: Optional[str] = Field(default=None)
    source: str = Field(default="manual")  # manual, auto_rule
    created_by: str = Field(default="system")
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: Optional[datetime] = Field(default=None)
    active: bool = Field(default=True, index=True)


class RevokedToken(SQLModel, table=True):
    __tablename__ = "revoked_tokens"
    id: Optional[int] = Field(default=None, primary_key=True)
    jti: str = Field(index=True, unique=True)
    user_sub: Optional[str] = Field(default=None)
    reason: str = Field(default="Admin revoked")
    revoked_by: str = Field(default="admin@sentinel.local")
    revoked_at: datetime = Field(default_factory=utcnow)
    expires_at: Optional[datetime] = Field(default=None)


class ClientBaseline(SQLModel, table=True):
    __tablename__ = "client_baselines"
    id: Optional[int] = Field(default=None, primary_key=True)
    client_key: str = Field(index=True, unique=True)
    window_counts_json: str = Field(default="[]")
    mean_rpm: float = Field(default=5.0)
    std_rpm: float = Field(default=2.0)
    current_rpm: int = Field(default=0)
    last_zscore: float = Field(default=0.0)
    last_updated_at: datetime = Field(default_factory=utcnow)
