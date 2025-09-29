"""
Evidence Collection Module

This module provides structured storage and management for scan evidence.
It supports:
- HTTP request/response capture
- DOM snapshots
- File/attachment evidence
- Integration with reporting pipeline

Usage:
    from backend.core import evidence
    ev = evidence.EvidenceStore()
    ev.add_http("https://example.com", req, resp)
    ev.add_dom_snapshot("https://example.com", dom_html)
"""

import json
import os
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path

class EvidenceStore:
    """
    Central storage for scan evidence.
    """

    def __init__(self, base_dir: str = "evidence_store"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.data: List[Dict[str, Any]] = []

    def add_http(self, url: str, request: Dict[str, Any], response: Dict[str, Any]) -> None:
        """
        Add HTTP request/response evidence.
        """
        entry = {
            "type": "http",
            "url": url,
            "request": request,
            "response": response,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.data.append(entry)
        self._persist(entry)

    def add_dom_snapshot(self, url: str, dom_html: str) -> None:
        """
        Add DOM snapshot evidence.
        """
        entry = {
            "type": "dom",
            "url": url,
            "dom": dom_html,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.data.append(entry)
        self._persist(entry)

    def add_file(self, url: str, file_path: str, description: str = "") -> None:
        """
        Add file attachment or screenshot evidence.
        """
        entry = {
            "type": "file",
            "url": url,
            "file_path": file_path,
            "description": description,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.data.append(entry)
        self._persist(entry)

    def _persist(self, entry: Dict[str, Any]) -> None:
        """
        Persist evidence entry as JSON file.
        """
        filename = self.base_dir / f"{entry['type']}_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(entry, f, indent=2)
