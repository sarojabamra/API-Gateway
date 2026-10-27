from fastapi import APIRouter, Request, Response
from app.gateway.pipeline import execute_gateway_pipeline

router = APIRouter(tags=["API Security Gateway Proxy"])


@router.api_route(
    "/gw/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def gateway_catch_all(request: Request, path: str) -> Response:
    return await execute_gateway_pipeline(
        request=request,
        forward_path=path,
        local_asgi_app=request.app,
    )
