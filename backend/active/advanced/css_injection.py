import requests

class CSSInjectionScanner:
    """
    Detects CSS Injection vulnerabilities where user-controlled input
    can inject styles or manipulate page rendering.
    """
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout

    def scan_form_field(self, field_name: str, payload: str):
        data = {field_name: payload}
        try:
            response = requests.post(self.target_url, data=data, timeout=self.timeout)
            reflected = payload in response.text
            return {
                "field": field_name,
                "payload_sent": payload,
                "reflected": reflected,
                "status_code": response.status_code
            }
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
