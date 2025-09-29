# backend/core/detection.py

from typing import Dict, Any, List
import logging
from backend.core.heuristics import evaluate_heuristics
from backend.core.evidence import evidence_manager

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class DetectionResult:
    """
    Represents the result of a detection attempt for a single payload/input.
    """
    def __init__(self, finding_id: str, vuln_type: str, severity: str, description: str, evidence: List[Dict] = None):
        self.finding_id = finding_id
        self.vuln_type = vuln_type  # e.g., SQLi, XSS, CSRF, LFI, SSRF
        self.severity = severity  # e.g., LOW, MEDIUM, HIGH, CRITICAL
        self.description = description
        self.evidence = evidence or []

    def add_evidence(self, scan_id: str, type: str, content: Dict, sensitive: bool = False):
        """
        Add evidence using the central evidence manager.
        """
        evidence_id = evidence_manager.add_evidence(
            scan_id=scan_id,
            finding_id=self.finding_id,
            type=type,
            content=content,
            sensitive=sensitive
        )
        self.evidence.append({"id": evidence_id, "type": type})
        logger.debug(f"Evidence {evidence_id} added to detection result {self.finding_id}")


class Detector:
    """
    The main detection engine that runs scans against targets.
    """
    def __init__(self, scan_id: str, target: str):
        self.scan_id = scan_id
        self.target = target
        self.results: List[DetectionResult] = []
        logger.info(f"Detector initialized for scan {scan_id} on target {target}")

    def run_detection(self, inputs: List[Dict[str, Any]], payloads: Dict[str, List[str]]):
        """
        Run detection for given inputs and payloads.
        inputs: List of parameter dicts found during crawling.
        payloads: Dict mapping vuln_type to list of payload strings
        """
        logger.info(f"Running detection for {len(inputs)} inputs and {len(payloads)} payload categories")
        for inp in inputs:
            param_name = inp.get("name")
            param_location = inp.get("location", "query")
            for vuln_type, payload_list in payloads.items():
                for payload in payload_list:
                    result = self._test_input(param_name, param_location, payload, vuln_type)
                    if result:
                        self.results.append(result)

    def _test_input(self, param_name: str, location: str, payload: str, vuln_type: str) -> DetectionResult:
        """
        Core logic for testing a single input with a payload.
        This is generic and relies on heuristics for any tech stack.
        """
        # Here we could send the payload to the target using HTTP driver
        # Simulate sending request and receiving response
        response = {"status_code": 200, "body": "<html>response</html>"}  # Placeholder

        # Evaluate heuristics for this response
        vuln_found, severity, description = evaluate_heuristics(vuln_type, payload, response)

        if vuln_found:
            finding_id = f"{vuln_type}_{param_name}_{hash(payload)}"
            detection_result = DetectionResult(
                finding_id=finding_id,
                vuln_type=vuln_type,
                severity=severity,
                description=description
            )
            # Capture evidence
            detection_result.add_evidence(
                scan_id=self.scan_id,
                type="request_response",
                content={"param": param_name, "payload": payload, "response": response},
                sensitive=False
            )
            logger.info(f"Vulnerability detected: {vuln_type} on {param_name} with payload {payload}")
            return detection_result

        logger.debug(f"No vulnerability detected for {param_name} with payload {payload}")
        return None

    def get_results(self) -> List[DetectionResult]:
        """
        Return all detection results.
        """
        return self.results

