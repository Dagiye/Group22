# backend/apps/api/ws/scan_stream.py

from fastapi import WebSocket, WebSocketDisconnect
from typing import List, Dict
import asyncio

class ScanManager:
    """Manage active WebSocket connections and scan sessions."""
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)
        print(f"[WS] Connected client for scan_id={scan_id}")

    def disconnect(self, websocket: WebSocket, scan_id: str):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]
        print(f"[WS] Disconnected client for scan_id={scan_id}")

    async def send_update(self, scan_id: str, message: dict):
        """Send JSON updates to all clients connected to a scan session."""
        if scan_id in self.active_connections:
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    print(f"[WS] Failed to send message: {e}")

scan_manager = ScanManager()

async def fake_scan_process(scan_id: str):
    """Simulate scanning for demo purposes."""
    for i in range(1, 6):
        message = {
            "progress": i * 20,
            "finding": None if i < 5 else {
                "name": "SQL Injection",
                "severity": "High",
                "endpoint": "/login",
                "description": "Time-based SQLi detected"
            }
        }
        await scan_manager.send_update(scan_id, message)
        await asyncio.sleep(2)

# WebSocket endpoint
async def scan_stream(websocket: WebSocket, scan_id: str):
    await scan_manager.connect(websocket, scan_id)
    try:
        # Start scan process for this session
        asyncio.create_task(fake_scan_process(scan_id))
        
        while True:
            # Receive messages from client (optional, e.g., pause/cancel)
            data = await websocket.receive_text()
            print(f"[WS] Received from client: {data}")
    except WebSocketDisconnect:
        scan_manager.disconnect(websocket, scan_id)
