import asyncio
import websockets
from typing import Callable, Any, Dict

class WebSocketFuzzer:
    """
    Performs WebSocket fuzzing on a target server.
    """

    def __init__(self, uri: str):
        self.uri = uri
        self.before_send: Callable[[Dict[str, Any]], Dict[str, Any]] = lambda x: x
        self.on_receive: Callable[[Dict[str, Any]], None] = lambda x: None

    async def _fuzz_message(self, ws, message: Dict[str, Any]):
        """Send and receive a single fuzzed message."""
        fuzzed_message = self.before_send(message)
        await ws.send(fuzzed_message if isinstance(fuzzed_message, str) else str(fuzzed_message))
        response = await ws.recv()
        self.on_receive(response)

    async def start(self, payloads: list):
        """
        Connect to WebSocket server and send all payloads asynchronously.
        """
        async with websockets.connect(self.uri) as ws:
            for payload in payloads:
                await self._fuzz_message(ws, payload)

    def run(self, payloads: list):
        """Run the fuzzer synchronously (wrapper)."""
        asyncio.run(self.start(payloads))
