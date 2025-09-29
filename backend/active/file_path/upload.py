"""
File Upload vulnerability scanner module.
"""

import aiohttp
from backend.core.evidence import EvidenceLogger


class UploadProbe:
    def __init__(self, base_url: str, session: aiohttp.ClientSession, logger: EvidenceLogger):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.logger = logger

        # Test files for upload vulnerabilities
        self.test_files = {
            "shell.php": "<?php echo 'UPLOAD_VULN'; ?>",
            "malicious.jsp": "<% out.println('UPLOAD_VULN'); %>",
        }

    async def scan(self, upload_endpoint: str, upload_field: str = "file"):
        """
        Scan file upload functionality for dangerous extensions.
        """
        for filename, content in self.test_files.items():
            try:
                data = aiohttp.FormData()
                data.add_field(upload_field, content, filename=filename, content_type="application/octet-stream")

                async with self.session.post(f"{self.base_url}/{upload_endpoint}", data=data, timeout=15) as resp:
                    text = await resp.text()
                    if "UPLOAD_VULN" in text:
                        self.logger.log_finding(
                            category="File Upload",
                            url=f"{self.base_url}/{upload_endpoint}",
                            evidence=f"Arbitrary file ({filename}) executed on server",
                            severity="Critical"
                        )
                        return True
            except Exception as e:
                self.logger.log_error("UploadProbe", str(e))
        return False
