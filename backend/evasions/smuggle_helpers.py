from typing import Dict

class SmuggleHelper:
    @staticmethod
    def chunked_transfer(payload: str) -> str:
        """Wrap payload using chunked transfer encoding format."""
        length = hex(len(payload))[2:]
        return f"{length}\r\n{payload}\r\n0\r\n\r\n"

    @staticmethod
    def split_headers(headers: Dict[str, str]) -> str:
        """Convert headers dict into raw HTTP header string for smuggling."""
        return "\r\n".join(f"{k}: {v}" for k, v in headers.items()) + "\r\n\r\n"

    @staticmethod
    def add_obfuscation(payload: str) -> str:
        """Add simple obfuscation to bypass naive WAF filters."""
        return "".join([f"%{ord(c):02x}" for c in payload])

    @staticmethod
    def combine_chunked_with_obfuscation(payload: str) -> str:
        """Chunked + obfuscation for advanced bypass."""
        obf = SmuggleHelper.add_obfuscation(payload)
        return SmuggleHelper.chunked_transfer(obf)
