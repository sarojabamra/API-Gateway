import json
from sqlmodel import Session, select

from app.db import create_db_and_tables, engine
from app.models import Route, Upstream
from app.api.v1.routes import _upsert_openapi_routes


SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Demo", "version": "1.0.0"},
    "paths": {
        "/items": {
            "post": {
                "summary": "Create item",
                "security": [{"BearerAuth": []}],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "qty": {"type": "integer"},
                                },
                                "additionalProperties": False,
                                "required": ["name"],
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/users/{id}": {
            "get": {
                "summary": "Get user",
                "security": [{"BearerAuth": []}],
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
}


def test_openapi_import_persists_request_schema():
    create_db_and_tables()
    with Session(engine) as session:
        up = session.exec(select(Upstream).where(Upstream.slug == "vulnshop")).first()
        if not up:
            up = Upstream(name="Test", slug="test-openapi-import", base_url="http://127.0.0.1:8000/demo")
            session.add(up)
            session.commit()
            session.refresh(up)

        imported = _upsert_openapi_routes(session, up.id, SPEC)
        assert len(imported) >= 2

        route = session.exec(
            select(Route).where(
                Route.upstream_id == up.id,
                Route.path_pattern == "/items",
                Route.method == "POST",
            )
        ).first()
        assert route is not None
        assert route.request_schema_json
        schema = json.loads(route.request_schema_json)
        assert schema.get("type") == "object"
        assert "name" in (schema.get("properties") or {})

        session.refresh(up)
        assert up.openapi_spec_json

        bola_route = session.exec(
            select(Route).where(
                Route.upstream_id == up.id,
                Route.path_pattern == "/users/{id}",
            )
        ).first()
        assert bola_route is not None
        assert bola_route.bola_check_enabled is True
        assert getattr(bola_route, "bola_mode", "equals_sub") == "equals_sub"
