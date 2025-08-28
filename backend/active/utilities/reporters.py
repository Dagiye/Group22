import json
from typing import List, Dict, Any

class Reporter:
    """
    Generates structured scan reports for findings,
    can be extended to support multiple formats.
    """

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    def add_finding(self, finding: Dict[str, Any]):
        """
        Add a new finding to the report.
        Expected keys: 'name', 'target', 'severity', 'description', 'impact', 'evidence'
        """
        required_keys = {"name", "target", "severity", "description", "impact", "evidence"}
        missing_keys = required_keys - finding.keys()
        if missing_keys:
            raise ValueError(f"Missing keys in finding: {missing_keys}")
        self.findings.append(finding)

    def generate_json(self) -> str:
        """Return JSON string of all findings."""
        return json.dumps({"findings": self.findings}, indent=4)

    def reset(self):
        """Clear all findings."""
        self.findings = []
