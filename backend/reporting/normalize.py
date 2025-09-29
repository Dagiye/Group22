from typing import Dict, List

class Normalizer:
    @staticmethod
    def normalize_finding(finding: Dict) -> Dict:
        """
        Standardize a finding dictionary.
        Ensures keys: id, type, target, severity, description, evidence
        """
        normalized = {
            "id": finding.get("id") or finding.get("uuid"),
            "type": finding.get("type"),
            "target": finding.get("target"),
            "severity": finding.get("severity", "medium").lower(),
            "description": finding.get("description", ""),
            "evidence": finding.get("evidence", []),
            "remediation": finding.get("remediation", "")
        }
        return normalized

    @staticmethod
    def normalize_findings(findings: List[Dict]) -> List[Dict]:
        """Normalize a list of findings."""
        return [Normalizer.normalize_finding(f) for f in findings]
