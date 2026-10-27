import json
from typing import Any, Dict, List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["Realtime WebSocket Hub"])


class WebSocketConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        if not self.active_connections:
            return
        payload = json.dumps(message)
        stale: List[WebSocket] = []
        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload)
            except Exception:
                stale.append(connection)
        for s in stale:
            self.disconnect(s)


ws_manager = WebSocketConnectionManager()


@router.websocket("/ws/live")
async def websocket_live_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep alive and listen for client ping messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"event": "pong"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
