"""
Form-based Authentication Strategy

This module logs into web apps that use HTML forms for authentication.
It supports CSRF tokens, custom login field names, and session persistence.

Usage:
    from auth.strategies import form_login
    auth = form_login.FormLogin("https://example.com/login", "user", "pass")
    auth.login()
    response = auth.session.get("https://example.com/protected")
"""

import requests
from bs4 import BeautifulSoup
from typing import Optional


class FormLogin:
    def __init__(self, login_url: str, username: str, password: str,
                 username_field: str = "username", password_field: str = "password",
                 csrf_field: Optional[str] = None):
        """
        :param login_url: Full URL to login form
        :param username: Login username
        :param password: Login password
        :param username_field: Form field for username
        :param password_field: Form field for password
        :param csrf_field: Optional CSRF hidden field name
        """
        self.login_url = login_url
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.csrf_field = csrf_field
        self.session = requests.Session()

    def login(self):
        """Perform login and store session cookies."""
        resp = self.session.get(self.login_url)
        resp.raise_for_status()
        data = {}
        soup = BeautifulSoup(resp.text, "html.parser")
        # CSRF token if required
        if self.csrf_field:
            csrf_tag = soup.find("input", {"name": self.csrf_field})
            if csrf_tag and csrf_tag.get("value"):
                data[self.csrf_field] = csrf_tag["value"]
        # Add credentials
        data[self.username_field] = self.username
        data[self.password_field] = self.password
        # Submit form
        post_resp = self.session.post(self.login_url, data=data)
        post_resp.raise_for_status()
        return post_resp
