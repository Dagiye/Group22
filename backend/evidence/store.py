import os
import json
import threading
from datetime import datetime
from typing import Dict, Any, List
from backend.core.context import ScanContext  # integration with the scanning engine

class EvidenceStore:
    def __init__(self, base_path: str = "evidence_store"):
        self.base_path = base_path
        os.makedirs(self.base_path, exist_ok=True)
        self.lock = threading.Lock()

    def save(self, data: Dict[str, Any], filename: str = None) -> str:
        """Save JSON evidence safely, adding scan metadata."""
        if not filename:
            filename = f"evidence_{ScanContext.current_scan_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}.json"
        filepath = os.path.join(self.base_path, filename)

        # Thread-safe write
        with self.lock, open(filepath, "w") as f:
            json.dump(data, f, indent=4)
        return filepath

    def list_by_scan(self, scan_id: str) -> List[str]:
        """List all evidence files for a given scan."""
        return [f for f in os.listdir(self.base_path) if scan_id in f]

    def search(self, keyword: str) -> List[str]:
        """Search evidence files for a keyword."""
        results = []
        for fname in os.listdir(self.base_path):
            path = os.path.join(self.base_path, fname)
            with open(path) as f:
                content = f.read()
                if keyword.lower() in content.lower():
                    results.append(fname)
        return results
