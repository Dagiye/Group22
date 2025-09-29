"""
Basic and Digest HTTP Authentication Strategy

This module supports:
- Basic Auth: sends username/password in Authorization header.
- Digest Auth: supports HTTP Digest authentication flow.

Usage:
    from auth.strategies import basic_digest
    session = basic_digest.HttpAuthSession("user", "pass")
    response = session.get("https://example.com/protected")
"""

from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import requests
from typing import Optional


class HttpAuthSession:
    def __init__(self, username: str, password: str, auth_type: str = "basic"):
        """
        :param username: User login
        :param password: User password
        :param auth_type: "basic" or "digest"
        """
        self.username = username
        self.password = password
        if auth_type not in ("basic", "digest"):
            raise ValueError("auth_type must be 'basic' or 'digest'")
        self.auth_type = auth_type
        self.session = requests.Session()
        self._set_auth()

    def _set_auth(self):
        if self.auth_type == "basic":
            self.session.auth = HTTPBasicAuth(self.username, self.password)
        else:
            self.session.auth = HTTPDigestAuth(self.username, self.password)

    def get(self, url: str, **kwargs):
        return self.session.get(url, **kwargs)

    def post(self, url: str, data=None, json=None, **kwargs):
        return self.session.post(url, data=data, json=json, **kwargs)

    def request(self, method: str, url: str, **kwargs):
        return self.session.request(method, url, **kwargs)
