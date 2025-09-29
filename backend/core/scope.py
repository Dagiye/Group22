# backend/core/scope.py

from urllib.parse import urlparse, urljoin
from typing import List, Set
import re


class ScopeError(Exception):
    pass


class Scope:
    """
    Represents the scanning scope.
    Determines which URLs/domains are included/excluded from the scan.
    """

    def __init__(self, base_urls: List[str] = None, exclude_patterns: List[str] = None):
        """
        Initialize a Scope.
        :param base_urls: List of base URLs to scan
        :param exclude_patterns: List of regex patterns to exclude
        """
        self.base_urls: Set[str] = set(base_urls) if base_urls else set()
        self.exclude_patterns: List[str] = exclude_patterns or []
        self._compiled_excludes = [re.compile(p) for p in self.exclude_patterns]

    def add_url(self, url: str):
        """Add a base URL to the scope"""
        self.base_urls.add(url)

    def add_exclude_pattern(self, pattern: str):
        """Add a regex pattern to exclude URLs"""
        self.exclude_patterns.append(pattern)
        self._compiled_excludes.append(re.compile(pattern))

    def in_scope(self, url: str) -> bool:
        """
        Check if a URL is within the scope.
        """
        parsed_url = urlparse(url)
        base = f"{parsed_url.scheme}://{parsed_url.netloc}"

        if not any(base.startswith(b) for b in self.base_urls):
            return False

        for pattern in self._compiled_excludes:
            if pattern.search(url):
                return False

        return True

    def normalize_url(self, url: str) -> str:
        """
        Normalize URL to absolute form based on base URLs.
        """
        for base in self.base_urls:
            try:
                joined = urljoin(base, url)
                return joined
            except Exception:
                continue
        raise ScopeError(f"Cannot normalize URL: {url}")

    def all_urls(self) -> List[str]:
        """Return all base URLs in scope"""
        return list(self.base_urls)

    def __repr__(self):
        return f"<Scope base_urls={self.base_urls}, exclude_patterns={self.exclude_patterns}>"


# Example usage:
# scope = Scope(base_urls=["https://example.com"], exclude_patterns=[r"/admin"])
# scope.in_scope("https://example.com/login")  # True
# scope.in_scope("https://example.com/admin")  # False
# scope.normalize_url("/login")  # "https://example.com/login"
