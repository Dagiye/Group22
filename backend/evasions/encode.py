import urllib.parse
import base64
import html
from typing import List

class Encoder:
    @staticmethod
    def url_encode(payload: str) -> str:
        """URL encode a payload."""
        return urllib.parse.quote(payload)

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode a payload."""
        return urllib.parse.quote(urllib.parse.quote(payload))

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """Encode special HTML characters."""
        return html.escape(payload)

    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 encode a payload."""
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def all_encodings(payload: str) -> List[str]:
        """Generate all common encodings for a payload."""
        return [
            payload,
            Encoder.url_encode(payload),
            Encoder.double_url_encode(payload),
            Encoder.html_entity_encode(payload),
            Encoder.base64_encode(payload)
        ]
