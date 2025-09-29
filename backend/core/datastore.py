# backend/core/datastore.py
import os
import json
from typing import Any, Dict, Optional, List
from pathlib import Path
import threading
import logging
import firebase_admin
from firebase_admin import auth as firebase_auth
from .firebase import verify_token

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class DataStore:
    """
    Thread-safe JSON storage for scans/evidence + Firebase user hooks.
    """

    def __init__(self, base_dir: str = "data"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        logger.info(f"DataStore initialized at {self.base_dir.resolve()}")

    # -----------------------------
    # Scan result methods (unchanged)
    # -----------------------------
    def save_scan(self, scan_id: str, scan_data: Dict[str, Any]):
        scan_file = self.base_dir / f"{scan_id}.json"
        with self._lock:
            with open(scan_file, "w", encoding="utf-8") as f:
                json.dump(scan_data, f, indent=4)
            logger.info(f"Scan data saved: {scan_file}")

    def load_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
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
        return [f.stem for f in self.base_dir.glob("*.json")]

    def delete_scan(self, scan_id: str):
        scan_file = self.base_dir / f"{scan_id}.json"
        with self._lock:
            if scan_file.exists():
                scan_file.unlink()
                logger.info(f"Scan deleted: {scan_file}")
            else:
                logger.warning(f"Scan file not found for deletion: {scan_file}")

    # -----------------------------
    # Evidence methods (unchanged)
    # -----------------------------
    def save_evidence(self, scan_id: str, evidence_id: str, evidence_data: Dict[str, Any]):
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
    # Firebase user helpers
    # -----------------------------
    def get_user(self, id_token: str) -> dict:
        """
        Verify Firebase token and return user info
        """
        try:
            decoded = verify_token(id_token)
            return decoded
        except Exception as e:
            logger.warning(f"Failed to verify Firebase token: {e}")
            return {}

    def create_user(self, email: str, password: str) -> dict:
        """
        Create Firebase user (used by AuthService)
        """
        try:
            user = firebase_auth.create_user(email=email, password=password)
            return {"uid": user.uid, "email": user.email}
        except Exception as e:
            logger.error(f"Firebase create_user error: {e}")
            raise


# -----------------------------
# Singleton instance
# -----------------------------
datastore = DataStore()
