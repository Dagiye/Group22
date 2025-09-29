# backend/apps/api/ws/scan_stream.py
"""
WebSocket manager for real-time scan status updates.
"""

from fastapi import WebSocket, WebSocketDisconnect
import asyncio
from typing import Dict, Set


class ConnectionManager:
    """Tracks active WebSocket connections by scan_id."""

    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, scan_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.setdefault(scan_id, set()).add(websocket)

    def disconnect(self, scan_id: str, websocket: WebSocket):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].discard(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def broadcast(self, scan_id: str, message: dict):
        """Send a JSON message to all clients subscribed to a scan_id."""
        if scan_id not in self.active_connections:
            return
        dead_connections = []
        for ws in list(self.active_connections[scan_id]):
            try:
                await ws.send_json(message)
            except Exception:
                dead_connections.append(ws)
        for ws in dead_connections:
            self.disconnect(scan_id, ws)


manager = ConnectionManager()


async def scan_stream(websocket: WebSocket, scan_id: str):
    """FastAPI route handler for WebSocket connections.

    Clients connect to `/ws/scan/{scan_id}` and will receive periodic
    updates with scan progress, status, and findings.
    """
    await manager.connect(scan_id, websocket)
    try:
        while True:
            # Optionally receive messages (clients can send "ping")
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
                if data.strip().lower() == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                pass  # no message, continue sending updates

            # Periodic heartbeat (every loop iteration)
            await websocket.send_json({"event": "heartbeat", "scan_id": scan_id})
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)
    except Exception:
        manager.disconnect(scan_id, websocket)
