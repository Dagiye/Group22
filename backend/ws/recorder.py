import json
from typing import List, Dict, Any

class WSRecorder:
    """
    Records WebSocket traffic for scans, useful for fuzzing,
    XSS detection, or API interaction analysis.
    """

    def __init__(self):
        self.messages: List[Dict[str, Any]] = []

    def record_message(self, direction: str, data: Any):
        """
        Record a WebSocket message.
        :param direction: 'sent' or 'received'
        :param data: Message payload (str or dict)
        """
        if not isinstance(data, (str, dict)):
            raise TypeError("WebSocket data must be str or dict")
        self.messages.append({
            "direction": direction,
            "data": data
        })

    def export(self, file_path: str):
        """
        Export all recorded messages to a JSON file.
        """
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump({"messages": self.messages}, f, indent=4)

    def reset(self):
        """Clear all recorded messages."""
        self.messages = []
