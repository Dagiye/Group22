import re
from typing import Dict, Any

class Redactor:
    SENSITIVE_PATTERNS = [
        r"(?i)password\s*=\s*['\"]?[^'\"\s]+['\"]?",
        r"(?i)api[_-]?key\s*=\s*['\"]?[^'\"\s]+['\"]?",
        r"(?i)token\s*=\s*['\"]?[^'\"\s]+['\"]?",
        r"(?i)authorization\s*:\s*bearer\s+[^'\"\s]+"
    ]

    @staticmethod
    def redact_text(text: str) -> str:
        for pattern in Redactor.SENSITIVE_PATTERNS:
            text = re.sub(pattern, "<REDACTED>", text)
        return text

    @staticmethod
    def redact_dict(data: Dict[str, Any]) -> Dict[str, Any]:
        redacted = {}
        for key, value in data.items():
            if isinstance(value, str):
                redacted[key] = Redactor.redact_text(value)
            elif isinstance(value, dict):
                redacted[key] = Redactor.redact_dict(value)
            else:
                redacted[key] = value
        return redacted
