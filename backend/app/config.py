from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional


class Settings(BaseSettings):
    APP_NAME: str = "SentinelGW - API Security Gateway & Threat Monitoring"
    ENVIRONMENT: str = "production-demo"
    DATABASE_URL: str = "sqlite:///./sentinel_gateway.db"
    REDIS_URL: Optional[str] = None
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 40
    CACHE_TTL_SECONDS: float = 2.0
    GATEWAY_ENABLED_BY_DEFAULT: bool = True

    # Dashboard Admin/User Auth JWT
    DASHBOARD_JWT_SECRET: str = "sentinel-dashboard-super-secret-key-2026-x99"
    DASHBOARD_JWT_ALGORITHM: str = "HS256"
    DASHBOARD_TOKEN_EXPIRE_MINUTES: int = 1440

    # Gateway Consumer JWT Validation Settings (configurable at runtime too)
    GATEWAY_JWT_SECRET: str = "sentinel-consumer-jwt-secret-key-2026-hs256"
    GATEWAY_JWT_PUBLIC_KEY: Optional[str] = None
    GATEWAY_ALLOWED_ALGORITHMS: List[str] = ["HS256"]
    GATEWAY_JWT_ISSUER: str = "https://auth.sentinel.local"
    GATEWAY_JWT_AUDIENCE: str = "sentinel-api"
    GATEWAY_JWT_LEEWAY_SECONDS: int = 10
    GATEWAY_REQUIRE_JTI: bool = True

    # Default Upstream (Demo API mounted locally on same server or custom URL)
    DEFAULT_UPSTREAM_URL: str = "http://127.0.0.1:8000/demo"

    # Optional Claude API key for live AI triage (falls back to deterministic expert triage if unset)
    ANTHROPIC_API_KEY: Optional[str] = None

    # Auto-block settings
    AUTO_BLOCK_CRITICAL: bool = False
    AUTO_BLOCK_DURATION_MINUTES: int = 60

    # Optional outbound webhook for critical alerts (JSON POST)
    WEBHOOK_URL: Optional[str] = None

    # Email every active organization member when a new threat alert is opened.
    ALERT_EMAIL_ENABLED: bool = True
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: str = "alerts@sentinel.local"
    SMTP_USE_TLS: bool = True
    SMTP_USE_SSL: bool = False
    DASHBOARD_BASE_URL: str = "http://localhost:5173"

    # Upstream response size cap (bytes) before Stage 10 truncates/sanitizes
    MAX_UPSTREAM_RESPONSE_BYTES: int = 1048576

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
