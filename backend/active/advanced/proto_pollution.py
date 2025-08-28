import requests

class PrototypePollutionScanner:
    """
    Detects JavaScript Prototype Pollution vulnerabilities
    by injecting payloads into query parameters, JSON, or form data.
    """
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout

    def scan_json_payload(self, payload: dict):
        try:
            response = requests.post(
                self.target_url,
                json=payload,
                timeout=self.timeout
            )
            return {
                "status_code": response.status_code,
                "response_body": response.text,
                "payload_sent": payload
            }
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}

    def scan_query_params(self, param_payload: dict):
        try:
            response = requests.get(
                self.target_url,
                params=param_payload,
                timeout=self.timeout
            )
            return {
                "status_code": response.status_code,
                "response_body": response.text,
                "params_sent": param_payload
            }
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
