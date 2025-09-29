# backend/core/context.py

import datetime
from typing import Dict, Any, List, Optional

class ScanContext:
    """
    Holds runtime context for a scan session.
    This includes metadata, discovered URLs, findings, and scan configuration.
    """

    def __init__(self, scan_id: str, target_url: str, mode: str = "full"):
        self.scan_id = scan_id
        self.target_url = target_url
        self.mode = mode  # full, quick, custom
        self.start_time: datetime.datetime = datetime.datetime.utcnow()
        self.end_time: Optional[datetime.datetime] = None
        self.status: str = "initialized"  # initialized, running, completed, failed
        self.metadata: Dict[str, Any] = {}  # additional info (headers, tech stack, etc.)
        self.discovered_urls: List[str] = []
        self.findings: List[Dict[str, Any]] = []
        self.config: Dict[str, Any] = {}  # loaded rules, settings

    def add_metadata(self, key: str, value: Any):
        """Add or update scan metadata"""
        self.metadata[key] = value

    def add_discovered_url(self, url: str):
        """Track URLs discovered during crawling"""
        if url not in self.discovered_urls:
            self.discovered_urls.append(url)

    def add_finding(self, finding: Dict[str, Any]):
        """Add a security finding"""
        self.findings.append(finding)

    def set_config(self, config: Dict[str, Any]):
        """Set scan configuration (rules, thresholds, etc.)"""
        self.config = config

    def start(self):
        """Mark scan as running"""
        self.status = "running"
        self.start_time = datetime.datetime.utcnow()

    def complete(self):
        """Mark scan as completed"""
        self.status = "completed"
        self.end_time = datetime.datetime.utcnow()

    def fail(self):
        """Mark scan as failed"""
        self.status = "failed"
        self.end_time = datetime.datetime.utcnow()

    def duration(self) -> Optional[float]:
        """Return scan duration in seconds"""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    def summary(self) -> Dict[str, Any]:
        """Return a summary of the scan"""
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "mode": self.mode,
            "status": self.status,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_sec": self.duration(),
            "metadata": self.metadata,
            "discovered_urls": self.discovered_urls,
            "findings_count": len(self.findings),
        }

# Example usage:
# context = ScanContext("scan_001", "https://example.com")
# context.start()
# context.add_discovered_url("https://example.com/login")
# context.add_finding({"vuln": "sqli", "url": "/login"})
# context.complete()
# print(context.summary())
