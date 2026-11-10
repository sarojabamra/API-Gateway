"""Organization scope for API projects (upstreams)."""
from typing import List, Optional

from fastapi import HTTPException
from sqlmodel import Session, select

from app.models import Route, Upstream, User

# Built-in practice API. Every organization can open it. Other projects stay private.
SHARED_DEMO_SLUG = "vulnshop"


def is_shared_demo(upstream: Optional[Upstream]) -> bool:
    return bool(upstream and (upstream.slug or "").strip().lower() == SHARED_DEMO_SLUG)


def _project_visible(user: User, upstream: Optional[Upstream]) -> bool:
    if upstream is None or user.organization_id is None:
        return False
    if is_shared_demo(upstream):
        return True
    return upstream.organization_id == user.organization_id


def require_visible_project(session: Session, user: User, upstream_id: int) -> Upstream:
    """Return the project when it belongs to the caller's organization, or it is VulnShop."""
    upstream = session.get(Upstream, upstream_id)
    if not _project_visible(user, upstream):
        raise HTTPException(status_code=404, detail="API project not found")
    return upstream


def list_visible_projects(session: Session, user: User) -> List[Upstream]:
    if user.organization_id is None:
        return []
    own = list(
        session.exec(
            select(Upstream)
            .where(Upstream.organization_id == user.organization_id)
            .order_by(Upstream.id)
        ).all()
    )
    demo = session.exec(select(Upstream).where(Upstream.slug == SHARED_DEMO_SLUG)).first()
    if demo is not None and all(project.id != demo.id for project in own):
        return [demo, *own]
    return own


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
    if not _project_visible(user, upstream):
        raise HTTPException(status_code=404, detail=missing_detail)
    return route
