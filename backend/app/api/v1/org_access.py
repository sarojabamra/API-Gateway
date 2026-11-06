"""Organization scope for API projects (upstreams)."""
from typing import List, Optional

from fastapi import HTTPException
from sqlmodel import Session, select

from app.models import Route, Upstream, User


def require_visible_project(session: Session, user: User, upstream_id: int) -> Upstream:
    """Return the project only when the caller belongs to its organization."""
    upstream = session.get(Upstream, upstream_id)
    if (
        upstream is None
        or user.organization_id is None
        or upstream.organization_id != user.organization_id
    ):
        raise HTTPException(status_code=404, detail="API project not found")
    return upstream


def list_visible_projects(session: Session, user: User) -> List[Upstream]:
    if user.organization_id is None:
        return []
    return list(
        session.exec(
            select(Upstream)
            .where(Upstream.organization_id == user.organization_id)
            .order_by(Upstream.id)
        ).all()
    )


def visible_upstream_ids(session: Session, user: User) -> List[int]:
    return [project.id for project in list_visible_projects(session, user) if project.id is not None]


def require_visible_route(
    session: Session,
    user: User,
    route: Optional[Route],
    missing_detail: str = "Route not found",
) -> Route:
    if route is None:
        raise HTTPException(status_code=404, detail=missing_detail)
    upstream = session.get(Upstream, route.upstream_id)
    if (
        upstream is None
        or user.organization_id is None
        or upstream.organization_id != user.organization_id
    ):
        raise HTTPException(status_code=404, detail=missing_detail)
    return route
