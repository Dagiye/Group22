import requests

class ClickjackingScanner:
    """
    Detects Clickjacking vulnerabilities by checking if pages
    can be embedded in iframes without proper X-Frame-Options or CSP headers.
    """
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout

    def scan(self):
        try:
            response = requests.get(self.target_url, timeout=self.timeout)
            x_frame_options = response.headers.get("X-Frame-Options", "")
            csp = response.headers.get("Content-Security-Policy", "")
            vulnerable = not x_frame_options and "frame-ancestors" not in csp
            return {
                "status_code": response.status_code,
                "x_frame_options": x_frame_options,
                "csp": csp,
                "vulnerable": vulnerable
            }
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
