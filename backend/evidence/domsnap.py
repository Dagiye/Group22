import os
from datetime import datetime
from backend.core.context import ScanContext

class DOMSnapshot:
    def __init__(self, base_path: str = "dom_snapshots"):
        self.base_path = base_path
        os.makedirs(self.base_path, exist_ok=True)

    def save(self, html_content: str, url: str, filename: str = None) -> str:
        """Save DOM snapshot as HTML file."""
        if not filename:
            safe_url = url.replace("://", "_").replace("/", "_")
            filename = f"dom_{ScanContext.current_scan_id}_{safe_url}_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}.html"
        filepath = os.path.join(self.base_path, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        return filepath
