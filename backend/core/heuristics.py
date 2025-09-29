# backend/core/heuristics.py

from typing import Dict, Any, Tuple
import re
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Example patterns for detection heuristics
HEURISTIC_PATTERNS = {
    "sqli": [
        r"SQL syntax.*MySQL", 
        r"unclosed quotation mark", 
        r"SQLSTATE\[\d+\]"
    ],
    "xss": [
        r"<script>alert\(",
        r"onerror=",
        r"javascript:"
    ],
    "ssrf": [
        r"connection refused", 
        r"connection timed out",
        r"curl error"
    ],
    "lfi": [
        r"failed to open stream",
        r"include\(\):"
    ],
    "xxe": [
        r"DOCTYPE xml",
        r"entity not defined",
        r"XML parsing error"
    ]
}

# Severity levels
DEFAULT_SEVERITY = {
    "sqli": "CRITICAL",
    "xss": "HIGH",
    "ssrf": "HIGH",
    "lfi": "MEDIUM",
    "xxe": "HIGH",
    "csrf": "MEDIUM",
    "id_or": "MEDIUM"
}

def evaluate_heuristics(vuln_type: str, payload: str, response: Dict[str, Any]) -> Tuple[bool, str, str]:
    """
    Evaluate response against heuristics for a given vulnerability type.

    Args:
        vuln_type (str): Vulnerability type e.g., sqli, xss, ssrf.
        payload (str): Payload used to test the input.
        response (Dict[str, Any]): Response dictionary with keys like 'status_code', 'body', 'headers'.

    Returns:
        Tuple[bool, str, str]: (vulnerability_found, severity, description)
    """
    body = response.get("body", "")
    headers = response.get("headers", {})
    status_code = response.get("status_code", 200)

    patterns = HEURISTIC_PATTERNS.get(vuln_type, [])

    for pattern in patterns:
        if re.search(pattern, body, re.IGNORECASE):
            severity = DEFAULT_SEVERITY.get(vuln_type, "MEDIUM")
            description = f"Detected {vuln_type.upper()} with payload '{payload}' using heuristic pattern '{pattern}'"
            logger.info(f"[HEURISTIC MATCH] {description}")
            return True, severity, description

    # Additional heuristic: for XSS, see if payload appears unescaped in body
    if vuln_type == "xss" and payload in body:
        severity = DEFAULT_SEVERITY.get(vuln_type, "HIGH")
        description = f"Reflected payload detected in response body, possible XSS: '{payload}'"
        logger.info(f"[XSS HEURISTIC] {description}")
        return True, severity, description

    # Fallback: no vulnerability detected
    return False, "NONE", "No heuristic match found"
