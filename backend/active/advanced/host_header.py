import requests

class HostHeaderScanner:
    """
    Detects Host Header injection vulnerabilities.
    Useful for web apps that use the Host header in routing, redirects, or email generation.
    """
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.payloads = [
            "evil.com",
            "127.0.0.1",
            "localhost",
        ]

    def test_payloads(self):
        results = []
        for payload in self.payloads:
            try:
                headers = {"Host": payload}
                response = requests.get(self.target_url, headers=headers, timeout=self.timeout)
                results.append({
                    "payload": payload,
                    "status": response.status_code,
                    "content_snippet": response.text[:200]
                })
            except requests.exceptions.RequestException as e:
                results.append({"payload": payload, "error": str(e)})
        return results

    def is_vulnerable(self, response_snippet: str) -> bool:
        # Heuristic: server reflects injected host or redirects unexpectedly
        suspicious_keywords = ["evil.com", "localhost", "127.0.0.1"]
        return any(k in response_snippet for k in suspicious_keywords)
