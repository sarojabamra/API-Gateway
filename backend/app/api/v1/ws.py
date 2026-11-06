import asyncio
import json
from typing import Any, Dict, List, Optional

import redis
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from redis.exceptions import RedisError
from sqlmodel import Session

from app.api.v1.deps import authenticate_access_token
from app.config import settings
from app.db import engine
from app.gateway.redis_client import redis_handle
from app.models import Upstream

router = APIRouter(tags=["Realtime WebSocket Hub"])

CHANNEL = "sgw:ws:events"


class WebSocketConnectionManager:
    def __init__(self) -> None:
        self.active_connections: Dict[WebSocket, Optional[int]] = {}
        self._listen_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self) -> None:
        if self._listen_task is None:
            self._running = True
            self._listen_task = asyncio.create_task(self._listen_loop())

    async def stop(self) -> None:
        self._running = False
        if self._listen_task is not None:
            self._listen_task.cancel()
            try:
                await self._listen_task
            except (asyncio.CancelledError, Exception):
                pass
            self._listen_task = None

    async def connect(self, websocket: WebSocket, organization_id: Optional[int]) -> None:
        await websocket.accept()
        self.active_connections[websocket] = organization_id

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.pop(websocket, None)

    def _can_view_event(self, organization_id: Optional[int], message: Dict[str, Any]) -> bool:
        data = message.get("data")
        upstream_id = data.get("upstream_id") if isinstance(data, dict) else None
        if organization_id is None or upstream_id is None:
            return False
        try:
            upstream_id = int(upstream_id)
        except (TypeError, ValueError):
            return False
        with Session(engine) as session:
            project = session.get(Upstream, upstream_id)
            return bool(project and project.organization_id == organization_id)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        client = redis_handle.get()
        if client is not None:
            try:
                client.publish(CHANNEL, json.dumps(message))
                return
            except RedisError:
                redis_handle.mark_down()
        await self._local_broadcast(message)

    async def _local_broadcast(self, message: Dict[str, Any]) -> None:
        if not self.active_connections:
            return
        payload = json.dumps(message)
        stale: List[WebSocket] = []
        for connection, organization_id in list(self.active_connections.items()):
            if not self._can_view_event(organization_id, message):
                continue
            try:
                await connection.send_text(payload)
            except Exception:
                stale.append(connection)
        for connection in stale:
            self.disconnect(connection)

    async def _listen_loop(self) -> None:
        while self._running:
            url = (settings.REDIS_URL or "").strip()
            if not url:
                await asyncio.sleep(1)
                continue
            pubsub_client = None
            pubsub = None
            try:
                pubsub_client = redis.Redis.from_url(
                    url,
                    decode_responses=True,
                    socket_connect_timeout=1,
                    socket_timeout=None,
                    health_check_interval=30,
                )
                pubsub = pubsub_client.pubsub(ignore_subscribe_messages=True)
                pubsub.subscribe(CHANNEL)
                loop = asyncio.get_running_loop()
                while self._running:
                    msg = await loop.run_in_executor(None, lambda: pubsub.get_message(timeout=1.0))
                    if not msg or msg.get("type") != "message":
                        continue
                    data = msg.get("data")
                    if not data:
                        continue
                    try:
                        payload = json.loads(data)
                    except Exception:
                        continue
                    await self._local_broadcast(payload)
            except asyncio.CancelledError:
                raise
            except Exception:
                await asyncio.sleep(1)
            finally:
                try:
                    if pubsub is not None:
                        pubsub.close()
                    if pubsub_client is not None:
                        pubsub_client.close()
                except Exception:
                    pass


ws_manager = WebSocketConnectionManager()


@router.websocket("/ws/live")
async def websocket_live_endpoint(websocket: WebSocket, token: Optional[str] = None):
    organization_id: Optional[int] = None
    if not token:
        await websocket.accept()
        await websocket.close(code=1008)
        return
    try:
        with Session(engine) as session:
            user = authenticate_access_token(token, session)
            organization_id = user.organization_id
    except HTTPException:
        await websocket.accept()
        await websocket.close(code=1008)
        return
    await ws_manager.connect(websocket, organization_id)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"event": "pong"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
