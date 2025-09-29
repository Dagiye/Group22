from typing import Dict

REMEDY_MAP = {
    "sqli": "Use parameterized queries / ORM, validate user input.",
    "xss": "Escape output, use CSP, sanitize input.",
    "csrf": "Implement CSRF tokens in forms.",
    "ssrf": "Validate and whitelist external URLs.",
    "lfi": "Sanitize file input, use whitelists.",
    "rfi": "Avoid remote file inclusion, sanitize paths.",
    "auth_bypass": "Enforce strong authentication and session management.",
    "ssrf": "Whitelist allowed domains and validate inputs.",
    "xxe": "Disable external entity parsing in XML parsers.",
}

class RemediationAdvisor:
    @staticmethod
    def get_remediation(vuln_type: str) -> str:
        """Return remediation guidance for a vulnerability type."""
        return REMEDY_MAP.get(vuln_type.lower(), "Refer to security best practices.")

    @staticmethod
    def apply_remediations(findings: Dict) -> Dict:
        """Attach remediation guidance to each finding."""
        for f in findings:
            f["remediation"] = RemediationAdvisor.get_remediation(f.get("type", ""))
        return findings
