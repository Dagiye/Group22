import websocket
import threading
import json
import time

class WebSocketScanner:
    """
    Connects to WebSocket endpoints and tests for
    unauthorized access, message injection, or data leakage.
    """
    def __init__(self, ws_url: str, timeout: int = 10):
        self.ws_url = ws_url
        self.timeout = timeout
        self.received_messages = []

    def _on_message(self, ws, message):
        self.received_messages.append(message)

    def _on_error(self, ws, error):
        print(f"WebSocket error: {error}")

    def _on_close(self, ws, close_status_code, close_msg):
        print("WebSocket closed")

    def scan(self, test_payload=None):
        ws = websocket.WebSocketApp(
            self.ws_url,
            on_message=self._on_message,
            on_error=self._on_error,
            on_close=self._on_close
        )
        thread = threading.Thread(target=ws.run_forever)
        thread.daemon = True
        thread.start()
        time.sleep(1)  # wait for connection
        if test_payload:
            try:
                ws.send(json.dumps(test_payload))
            except Exception as e:
                print(f"Send error: {e}")
        time.sleep(self.timeout)
        ws.close()
        return self.received_messages
