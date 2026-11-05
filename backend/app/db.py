from sqlalchemy import inspect, text
from sqlmodel import SQLModel, Session, create_engine

from app.config import settings

_INDEX_STATEMENTS = (
    "CREATE INDEX IF NOT EXISTS ix_request_logs_upstream_ts ON request_logs (upstream_id, ts)",
    "CREATE INDEX IF NOT EXISTS ix_request_logs_upstream_decision ON request_logs (upstream_id, decision)",
    "CREATE INDEX IF NOT EXISTS ix_alerts_status_ts ON alerts (status, ts)",
    "CREATE INDEX IF NOT EXISTS ix_blocklist_type_value_active ON blocklist (target_type, value, active)",
)

# Columns introduced after initial schema — added via ALTER when missing (SQLite + Postgres).
_ROUTE_EXTRA_COLUMNS = (
    ("bola_owner_claim", "VARCHAR", "'sub'"),
    ("bola_owner_param", "VARCHAR", "'id'"),
    ("bola_mode", "VARCHAR", "'equals_sub'"),
    ("request_schema_json", "TEXT", None),
)


def _build_engine():
    url = settings.DATABASE_URL
    if url.startswith("sqlite"):
        return create_engine(
            url,
            echo=False,
            connect_args={"check_same_thread": False, "timeout": 30},
            pool_pre_ping=True,
        )
    return create_engine(
        url,
        echo=False,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_pre_ping=True,
        pool_recycle=1800,
    )


engine = _build_engine()


def _configure_sqlite() -> None:
    if not settings.DATABASE_URL.startswith("sqlite"):
        return
    with engine.begin() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL"))
        conn.execute(text("PRAGMA synchronous=NORMAL"))
        conn.execute(text("PRAGMA busy_timeout=5000"))
        conn.execute(text("PRAGMA foreign_keys=ON"))
        conn.execute(text("PRAGMA temp_store=MEMORY"))


def _ensure_indexes() -> None:
    with engine.begin() as conn:
        for statement in _INDEX_STATEMENTS:
            conn.execute(text(statement))


def _add_column_if_missing(table: str, column: str, col_type: str, default_sql: str | None = None) -> None:
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    if table not in tables:
        return
    columns = {col["name"] for col in inspector.get_columns(table)}
    if column in columns:
        return
    default_clause = f" DEFAULT {default_sql}" if default_sql is not None else ""
    with engine.begin() as conn:
        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}{default_clause}"))


def _ensure_extra_columns() -> None:
    """Add newly introduced columns without wiping existing data (SQLite and Postgres)."""
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    if "users" in tables:
        columns = {col["name"] for col in inspector.get_columns("users")}
        if "organization_id" not in columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE users ADD COLUMN organization_id INTEGER"))

    for col_name, col_type, default_sql in _ROUTE_EXTRA_COLUMNS:
        _add_column_if_missing("routes", col_name, col_type, default_sql)

    if "upstreams" in tables:
        up_cols = {col["name"] for col in inspector.get_columns("upstreams")}
        if "openapi_spec_json" not in up_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE upstreams ADD COLUMN openapi_spec_json TEXT"))


def create_db_and_tables() -> None:
    SQLModel.metadata.create_all(engine)
    _configure_sqlite()
    _ensure_extra_columns()
    _ensure_indexes()


def get_session():
    with Session(engine) as session:
        yield session


def check_database() -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
