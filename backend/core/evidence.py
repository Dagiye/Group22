# backend/core/evidence.py

from typing import Dict, List, Optional
from datetime import datetime
import uuid
import json
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class EvidenceItem:
    """
    Represents a single piece of evidence for a finding.
    """
    def __init__(
        self,
        scan_id: str,
        finding_id: str,
        type: str,
        content: Dict,
        sensitive: bool = False
    ):
        self.id = str(uuid.uuid4())
        self.scan_id = scan_id
        self.finding_id = finding_id
        self.type = type  # e.g., 'request', 'response', 'screenshot', 'dom_snapshot'
        self.content = content
        self.sensitive = sensitive
        self.timestamp = datetime.utcnow()

    def to_dict(self, redact_sensitive: bool = True) -> Dict:
        """
        Convert evidence to dict for storage or reporting.
        Redact content if sensitive.
        """
        content = self.content.copy()
        if self.sensitive and redact_sensitive:
            content = {"redacted": True}
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "finding_id": self.finding_id,
            "type": self.type,
            "content": content,
            "sensitive": self.sensitive,
            "timestamp": self.timestamp.isoformat() + "Z"
        }


class EvidenceManager:
    """
    Stores and manages evidence items for all scans/findings.
    """
    def __init__(self):
        # Mapping: scan_id -> finding_id -> list of EvidenceItem
        self._evidence_store: Dict[str, Dict[str, List[EvidenceItem]]] = {}
        logger.info("EvidenceManager initialized")

    def add_evidence(
        self,
        scan_id: str,
        finding_id: str,
        type: str,
        content: Dict,
        sensitive: bool = False
    ) -> str:
        """
        Add a new piece of evidence.
        Returns the evidence ID.
        """
        evidence = EvidenceItem(scan_id, finding_id, type, content, sensitive)
        self._evidence_store.setdefault(scan_id, {}).setdefault(finding_id, []).append(evidence)
        logger.info(f"Evidence added: {evidence.id} for finding {finding_id}")
        return evidence.id

    def get_evidence(self, scan_id: str, finding_id: str, redact_sensitive: bool = True) -> List[Dict]:
        """
        Retrieve all evidence for a finding.
        """
        items = self._evidence_store.get(scan_id, {}).get(finding_id, [])
        return [item.to_dict(redact_sensitive=redact_sensitive) for item in items]

    def remove_evidence(self, scan_id: str, finding_id: str, evidence_id: str) -> bool:
        """
        Remove a specific evidence item.
        Returns True if removed.
        """
        items = self._evidence_store.get(scan_id, {}).get(finding_id, [])
        for i, item in enumerate(items):
            if item.id == evidence_id:
                del items[i]
                logger.info(f"Evidence removed: {evidence_id}")
                return True
        logger.warning(f"Evidence not found: {evidence_id}")
        return False

    def clear_finding_evidence(self, scan_id: str, finding_id: str):
        """
        Remove all evidence for a specific finding.
        """
        if scan_id in self._evidence_store and finding_id in self._evidence_store[scan_id]:
            del self._evidence_store[scan_id][finding_id]
            logger.info(f"All evidence cleared for finding {finding_id}")

    def clear_scan_evidence(self, scan_id: str):
        """
        Remove all evidence for a scan.
        """
        if scan_id in self._evidence_store:
            del self._evidence_store[scan_id]
            logger.info(f"All evidence cleared for scan {scan_id}")

    def export_scan_evidence(self, scan_id: str, redact_sensitive: bool = True) -> str:
        """
        Export all evidence for a scan as JSON string.
        """
        scan_data = {}
        for finding_id, items in self._evidence_store.get(scan_id, {}).items():
            scan_data[finding_id] = [item.to_dict(redact_sensitive=redact_sensitive) for item in items]
        return json.dumps(scan_data, indent=2, ensure_ascii=False)


# Singleton instance to be used across backend
evidence_manager = EvidenceManager()

# -----------------------------
# Example usage
# -----------------------------
# evidence_id = evidence_manager.add_evidence(
#     scan_id="scan_001",
#     finding_id="finding_001",
#     type="request",
#     content={"method": "POST", "url": "/login", "body": "username=admin&password=1234"},
#     sensitive=True
# )
# all_evidence = evidence_manager.get_evidence("scan_001", "finding_001")
# print(all_evidence)
