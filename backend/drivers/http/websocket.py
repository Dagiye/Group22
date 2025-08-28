# backend/drivers/http/websocket.py

import asyncio
import websockets
from typing import Callable, Dict, Any, Optional

class WebSocketClient:
    """
    Simple WebSocket client for scanning and interacting with WebSocket endpoints.
    Supports sending messages, receiving responses, and registering hooks.
    """

    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.url = url
        self.headers = headers or {}
        self.message_callbacks = []  # Functions to process incoming messages
        self._connection = None

    def add_message_callback(self, callback: Callable[[str], None]):
        """
        Register a callback to process incoming messages.
        """
        self.message_callbacks.append(callback)

    async def connect(self):
        """
        Establish a WebSocket connection.
        """
        self._connection = await websockets.connect(self.url, extra_headers=self.headers)

    async def send(self, message: str):
        """
        Send a message through the WebSocket connection.
        """
        if not self._connection:
            await self.connect()
        await self._connection.send(message)

    async def receive(self):
        """
        Receive messages and pass them to registered callbacks.
        """
        if not self._connection:
            await self.connect()
        async for message in self._connection:
            for callback in self.message_callbacks:
                callback(message)

    async def close(self):
        """
        Close the WebSocket connection.
        """
        if self._connection:
            await self._connection.close()
            self._connection = None

# Utility functions to run WebSocket interactions in a blocking way (optional)
def run_ws_client(url: str, headers: Optional[Dict[str, str]] = None, on_message: Optional[Callable[[str], None]] = None):
    client = WebSocketClient(url, headers)
    if on_message:
        client.add_message_callback(on_message)

    async def runner():
        await client.connect()
        await client.receive()

    asyncio.run(runner())
