# backend/drivers/browser/dom_snapshot.py

from typing import Dict, Any
import hashlib
import json
import os
from datetime import datetime


class DOMSnapshotManager:
    """
    Manages capturing, storing, and diffing DOM snapshots.
    Useful for detecting changes or analyzing dynamic content.
    """

    def __init__(self, storage_dir: str = "snapshots"):
        self.storage_dir = storage_dir
        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir)

    def save_snapshot(self, url: str, dom_content: str) -> str:
        """
        Save the DOM content to a file with a unique name.
        Returns the filepath.
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{self._sanitize_url(url)}_{timestamp}.html"
        filepath = os.path.join(self.storage_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(dom_content)
        return filepath

    def load_snapshot(self, filepath: str) -> str:
        """
        Load a saved DOM snapshot from a file.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Snapshot file not found: {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()

    def hash_snapshot(self, dom_content: str) -> str:
        """
        Generate a SHA256 hash of the DOM content.
        Useful for comparing snapshots.
        """
        return hashlib.sha256(dom_content.encode("utf-8")).hexdigest()

    def diff_snapshots(self, dom1: str, dom2: str) -> Dict[str, Any]:
        """
        Simple diff between two DOM snapshots.
        Returns a dictionary with hashes and a change flag.
        """
        hash1 = self.hash_snapshot(dom1)
        hash2 = self.hash_snapshot(dom2)
        changed = hash1 != hash2
        return {
            "hash_before": hash1,
            "hash_after": hash2,
            "changed": changed
        }

    @staticmethod
    def _sanitize_url(url: str) -> str:
        """
        Convert URL to a safe filename.
        """
        return url.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")
