# backend/drivers/http/recorder.py

import json
import os
from datetime import datetime
from typing import Dict, Any

class HTTPRecorder:
    """
    Records HTTP requests and responses for later analysis.
    Saves data to in-memory store and optionally to disk.
    """
    def __init__(self, save_dir: str = "recorded_requests"):
        self.save_dir = save_dir
        self.records = []
        os.makedirs(self.save_dir, exist_ok=True)

    def record(self, method: str, url: str, request_headers: Dict[str, Any], 
               request_body: str, status_code: int, response_headers: Dict[str, Any], 
               response_body: str):
        """
        Record a single HTTP transaction.
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "method": method.upper(),
            "url": url,
            "request_headers": request_headers,
            "request_body": request_body,
            "status_code": status_code,
            "response_headers": response_headers,
            "response_body": response_body
        }
        self.records.append(entry)

    def save_to_file(self, filename: str = None):
        """
        Save all recorded transactions to a JSON file.
        """
        if filename is None:
            filename = f"record_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        path = os.path.join(self.save_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.records, f, indent=4)
        print(f"[Recorder] Saved {len(self.records)} entries to {path}")
        return path

    def clear(self):
        """
        Clear all in-memory records.
        """
        self.records = []
