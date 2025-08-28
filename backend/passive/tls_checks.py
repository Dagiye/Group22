"""
tls_checks.py
-------------
Passive scanner for TLS/SSL misconfigurations.
"""

import ssl
import socket
from typing import Dict
from datetime import datetime

class TLSChecker:
    def __init__(self, host: str, port: int = 443, timeout: int = 5):
        self.host = host
        self.port = port
        self.timeout = timeout

    def get_certificate_info(self) -> Dict:
        """Retrieve certificate details."""
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=self.host)
        conn.settimeout(self.timeout)
        try:
            conn.connect((self.host, self.port))
            cert = conn.getpeercert()
            return {
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "valid_from": cert.get("notBefore"),
                "valid_to": cert.get("notAfter"),
                "serial_number": cert.get("serialNumber")
            }
        except Exception as e:
            return {"error": str(e)}
        finally:
            conn.close()

    def check_tls_version(self) -> Dict:
        """Check supported TLS versions."""
        versions = {
            "TLSv1": ssl.TLSVersion.TLSv1,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3
        }
        supported = []
        for name, version in versions.items():
            try:
                context = ssl.SSLContext(version)
                with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=self.host) as s:
                    s.settimeout(self.timeout)
                    s.connect((self.host, self.port))
                    supported.append(name)
            except Exception:
                continue
        return {"supported_versions": supported}

    def run_all_checks(self) -> Dict:
        """Run all passive TLS checks."""
        result = {}
        result["certificate"] = self.get_certificate_info()
        result["tls_versions"] = self.check_tls_version()
        return result

# Example usage:
# checker = TLSChecker("example.com")
# print(checker.run_all_checks())
