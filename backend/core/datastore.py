# backend/core/datastore.py

import os
import json
from typing import Any, Dict, Optional, List
from pathlib import Path
import threading
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class DataStore:
    """
    Simple thread-safe persistent storage for scan results and evidence.
    Can store in JSON files under a specified base directory.
    """

    def __init__(self, base_dir: str = "data"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        logger.info(f"DataStore initialized at {self.base_dir.resolve()}")

    # -----------------------------
    # Scan result methods
    # -----------------------------
    def save_scan(self, scan_id: str, scan_data: Dict[str, Any]):
        """
        Save scan metadata/results to a JSON file.
        """
        scan_file = self.base_dir / f"{scan_id}.json"
        with self._lock:
            with open(scan_file, "w", encoding="utf-8") as f:
                json.dump(scan_data, f, indent=4)
            logger.info(f"Scan data saved: {scan_file}")

    def load_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Load scan data by scan_id.
        """
        scan_file = self.base_dir / f"{scan_id}.json"
        if not scan_file.exists():
            logger.warning(f"Scan file not found: {scan_file}")
            return None
        with self._lock:
            with open(scan_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            logger.info(f"Scan data loaded: {scan_file}")
            return data

    def list_scans(self) -> List[str]:
        """
        List all saved scan IDs.
        """
        return [f.stem for f in self.base_dir.glob("*.json")]

    def delete_scan(self, scan_id: str):
        """
        Delete a saved scan by scan_id.
        """
        scan_file = self.base_dir / f"{scan_id}.json"
        with self._lock:
            if scan_file.exists():
                scan_file.unlink()
                logger.info(f"Scan deleted: {scan_file}")
            else:
                logger.warning(f"Scan file not found for deletion: {scan_file}")

    # -----------------------------
    # Generic evidence methods
    # -----------------------------
    def save_evidence(self, scan_id: str, evidence_id: str, evidence_data: Dict[str, Any]):
        """
        Save evidence related to a scan.
        Stored under a subdirectory 'evidence/<scan_id>/<evidence_id>.json'.
        """
        evidence_dir = self.base_dir / "evidence" / scan_id
        evidence_dir.mkdir(parents=True, exist_ok=True)
        evidence_file = evidence_dir / f"{evidence_id}.json"
        with self._lock:
            with open(evidence_file, "w", encoding="utf-8") as f:
                json.dump(evidence_data, f, indent=4)
            logger.info(f"Evidence saved: {evidence_file}")

    def load_evidence(self, scan_id: str, evidence_id: str) -> Optional[Dict[str, Any]]:
        evidence_file = self.base_dir / "evidence" / scan_id / f"{evidence_id}.json"
        if not evidence_file.exists():
            logger.warning(f"Evidence file not found: {evidence_file}")
            return None
        with self._lock:
            with open(evidence_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            logger.info(f"Evidence loaded: {evidence_file}")
            return data

    def list_evidences(self, scan_id: str) -> List[str]:
        evidence_dir = self.base_dir / "evidence" / scan_id
        if not evidence_dir.exists():
            return []
        return [f.stem for f in evidence_dir.glob("*.json")]


# -----------------------------
# Singleton instance
# -----------------------------
datastore = DataStore()

# Example usage:
# datastore.save_scan("scan_001", {"target": "https://example.com", "status": "running"})
# datastore.save_evidence("scan_001", "evid_001", {"type": "sqli", "details": "..."} )
# scans = datastore.list_scans()
# evidence_files = datastore.list_evidences("scan_001")
