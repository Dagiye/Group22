# backend/drivers/http/interceptor.py

from typing import Callable, Dict, Any

class HTTPInterceptor:
    """
    Allows interception and modification of HTTP requests and responses.
    Useful for payload injection, testing evasion, or logging.
    """

    def __init__(self):
        # Callbacks for request and response interception
        self.request_callbacks = []
        self.response_callbacks = []

    def add_request_callback(self, callback: Callable[[Dict[str, Any]], Dict[str, Any]]):
        """
        Register a callback that receives a request dictionary and can modify it.
        Request dict example:
        {
            "method": "GET",
            "url": "https://example.com",
            "headers": {...},
            "body": "..."
        }
        """
        self.request_callbacks.append(callback)

    def add_response_callback(self, callback: Callable[[Dict[str, Any]], Dict[str, Any]]):
        """
        Register a callback that receives a response dictionary and can modify it.
        Response dict example:
        {
            "status_code": 200,
            "headers": {...},
            "body": "..."
        }
        """
        self.response_callbacks.append(callback)

    def process_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Pass the request through all registered request callbacks.
        """
        for callback in self.request_callbacks:
            request = callback(request) or request
        return request

    def process_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Pass the response through all registered response callbacks.
        """
        for callback in self.response_callbacks:
            response = callback(response) or response
        return response
