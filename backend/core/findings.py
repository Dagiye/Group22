# backend/core/findings.py

from typing import List, Dict, Optional
from dataclasses import dataclass, field
import uuid
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@dataclass
class Finding:
    """
    Represents a single vulnerability finding.
    """
    id: str
    scan_id: str
    target: str
    vulnerability: str
    severity: str
    description: str
    impact: str
    evidence: List[Dict] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


class FindingsManager:
    """
    Manages findings for scans.
    Stores them in-memory initially and can integrate with DataStore for persistence.
    """

    def __init__(self):
        # Mapping: scan_id -> list of Finding objects
        self._findings: Dict[str, List[Finding]] = {}
        logger.info("FindingsManager initialized")

    def add_finding(
        self,
        scan_id: str,
        target: str,
        vulnerability: str,
        severity: str,
        description: str,
        impact: str,
        evidence: Optional[List[Dict]] = None,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Add a new finding to a scan. Returns the finding ID.
        Avoids duplicates based on target + vulnerability.
        """
        if evidence is None:
            evidence = []
        if metadata is None:
            metadata = {}

        # Check for duplicates
        existing = self._findings.get(scan_id, [])
        for f in existing:
            if f.target == target and f.vulnerability == vulnerability:
                logger.warning(f"Duplicate finding ignored for target {target}, vulnerability {vulnerability}")
                return f.id

        finding_id = str(uuid.uuid4())
        finding = Finding(
            id=finding_id,
            scan_id=scan_id,
            target=target,
            vulnerability=vulnerability,
            severity=severity,
            description=description,
            impact=impact,
            evidence=evidence,
            metadata=metadata
        )

        self._findings.setdefault(scan_id, []).append(finding)
        logger.info(f"Finding added: {finding_id} for scan {scan_id}")
        return finding_id

    def get_findings(self, scan_id: str) -> List[Finding]:
        """
        Get all findings for a specific scan.
        """
        return self._findings.get(scan_id, [])

    def get_finding(self, scan_id: str, finding_id: str) -> Optional[Finding]:
        """
        Get a single finding by its ID.
        """
        for f in self._findings.get(scan_id, []):
            if f.id == finding_id:
                return f
        return None

    def remove_finding(self, scan_id: str, finding_id: str) -> bool:
        """
        Remove a finding from a scan. Returns True if removed.
        """
        scan_findings = self._findings.get(scan_id, [])
        for i, f in enumerate(scan_findings):
            if f.id == finding_id:
                del scan_findings[i]
                logger.info(f"Finding removed: {finding_id}")
                return True
        logger.warning(f"Finding not found: {finding_id}")
        return False

    def count_findings(self, scan_id: str) -> int:
        return len(self._findings.get(scan_id, []))

    def clear_scan_findings(self, scan_id: str):
        """
        Remove all findings for a scan.
        """
        if scan_id in self._findings:
            del self._findings[scan_id]
            logger.info(f"All findings cleared for scan {scan_id}")


# Singleton instance to be used across backend
findings_manager = FindingsManager()

# -----------------------------
# Example usage
# -----------------------------
# finding_id = findings_manager.add_finding(
#     scan_id="scan_001",
#     target="https://example.com/login",
#     vulnerability="SQL Injection",
#     severity="High",
#     description="User input in login form is vulnerable to SQL injection",
#     impact="Attacker can bypass authentication",
#     evidence=[{"request": "POST /login", "response_snippet": "..."}]
# )
# all_findings = findings_manager.get_findings("scan_001")
