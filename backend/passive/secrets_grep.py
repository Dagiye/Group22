"""
secrets_grep.py
----------------
Passive scanner to detect exposed secrets, keys, and tokens in content.
"""

import re
from typing import List, Dict

class SecretsGrep:
    """
    Class to scan content for potential secrets like API keys, tokens, and credentials.
    """

    # Common regex patterns for secrets
    SECRET_PATTERNS = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key": r"(?i)aws_secret_access_key.*?['\"]([A-Za-z0-9/+=]{40})['\"]",
        "JWT Token": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
       # "Slack Token": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "Private Key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"
    }

    def __init__(self, content: str):
        """
        Initialize with the raw content (HTML, JS, config, etc.)
        """
        self.content = content

    def scan(self) -> List[Dict]:
        """
        Scan the content for all defined secret patterns.
        Returns a list of dictionaries containing type and matched secret.
        """
        findings = []
        for name, pattern in self.SECRET_PATTERNS.items():
            matches = re.findall(pattern, self.content)
            for match in matches:
                findings.append({
                    "type": name,
                    "secret": match
                })
        return findings

# Example usage:
# scanner = SecretsGrep(content)
# print(scanner.scan())
