import os
import json
from datetime import datetime
from typing import Dict, Any
from backend.core.context import ScanContext

class HARRecorder:
    def __init__(self, base_path: str = "har_files"):
        self.base_path = base_path
        os.makedirs(self.base_path, exist_ok=True)

    def save_har(self, har_data: Dict[str, Any], filename: str = None) -> str:
        """Save HAR JSON file with metadata."""
        if not filename:
            filename = f"har_{ScanContext.current_scan_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}.har"
        filepath = os.path.join(self.base_path, filename)

        with open(filepath, "w") as f:
            json.dump(har_data, f, indent=4)
        return filepath

    def read_har(self, filename: str) -> Dict[str, Any]:
        filepath = os.path.join(self.base_path, filename)
        with open(filepath) as f:
            return json.load(f)
