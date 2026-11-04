from fastapi import APIRouter, BackgroundTasks, Request, Response
from app.gateway.pipeline import execute_gateway_pipeline

router = APIRouter(tags=["API Security Gateway Proxy"])


@router.api_route(
    "/gw/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def gateway_catch_all(
    request: Request,
    path: str,
    background_tasks: BackgroundTasks,
) -> Response:
    return await execute_gateway_pipeline(
        request=request,
        forward_path=path,
        local_asgi_app=request.app,
        background_tasks=background_tasks,
    )
