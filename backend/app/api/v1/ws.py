import asyncio
import json
from typing import Any, Dict, List, Optional

import redis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from redis.exceptions import RedisError

from app.config import settings
from app.gateway.redis_client import redis_handle

router = APIRouter(tags=["Realtime WebSocket Hub"])

CHANNEL = "sgw:ws:events"


class WebSocketConnectionManager:
    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []
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

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

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
        for connection in list(self.active_connections):
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
async def websocket_live_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"event": "pong"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
