"""
LDAP injection detection module.
"""

from typing import List, Dict, Any
import re
import logging

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

LDAP_INJECTION_PAYLOADS = [
    "*",
    "*)(",
    "admin)(|(password=*))",
    "*)(&))",
    "test)(|(objectclass=*))"
]


def test_payloads(param: str, payloads: List[str] = None) -> List[str]:
    """
    Test a single input parameter for LDAP injection using payloads.
    Returns list of payloads that triggered suspicious patterns.
    """
    payloads = payloads or LDAP_INJECTION_PAYLOADS
    detected = []
    for payload in payloads:
        injected = f"{param}{payload}"
        if _is_suspicious(injected):
            detected.append(payload)
            log.debug("LDAP injection payload detected: %s", payload)
    return detected


def _is_suspicious(value: str) -> bool:
    """
    Simple heuristic check for suspicious LDAP characters.
    Can be extended with more advanced detection.
    """
    suspicious_patterns = [r"\*\)", r"\(\|", r"\)\("]
    for pat in suspicious_patterns:
        if re.search(pat, value):
            return True
    return False


def scan_request_params(params: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Scan multiple parameters from a request.
    Returns dict {param_name: [list of detected payloads]}
    """
    results = {}
    for k, v in params.items():
        if isinstance(v, str):
            detected = test_payloads(v)
            if detected:
                results[k] = detected
    return results
