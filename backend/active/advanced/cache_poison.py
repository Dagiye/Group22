import requests

class CachePoisonScanner:
    """
    Detects HTTP cache poisoning vulnerabilities by sending
    malicious headers and observing cached responses.
    """
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.payloads = [
            {"header": "X-Forwarded-Host", "value": "evil.com"},
            {"header": "X-Host", "value": "evil.com"},
            {"header": "X-Forwarded-For", "value": "127.0.0.1"},
        ]

    def test_payloads(self):
        results = []
        for payload in self.payloads:
            try:
                headers = {payload["header"]: payload["value"]}
                response = requests.get(self.target_url, headers=headers, timeout=self.timeout)
                results.append({
                    "header": payload["header"],
                    "value": payload["value"],
                    "status": response.status_code,
                    "content_snippet": response.text[:200]
                })
            except requests.exceptions.RequestException as e:
                results.append({"header": payload["header"], "error": str(e)})
        return results

    def is_vulnerable(self, response_snippet: str) -> bool:
        # Heuristic: presence of malicious host or cacheable responses reflecting payload
        suspicious_keywords = ["evil.com", "127.0.0.1"]
        return any(k in response_snippet for k in suspicious_keywords)
