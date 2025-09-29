# backend/drivers/http/client.py

import requests
from requests.adapters import HTTPAdapter, Retry
from typing import Dict, Any, Optional, Tuple
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class HTTPClient:
    """
    HTTP client for web scanning.
    Handles requests with retries, timeouts, and optional headers/cookies.
    """
    def __init__(self,
                 timeout: int = 15,
                 max_retries: int = 3,
                 verify_ssl: bool = True,
                 default_headers: Optional[Dict[str, str]] = None):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update(default_headers or {"User-Agent": "WebScanner/1.0"})

        retries = Retry(total=max_retries,
                        backoff_factor=0.5,
                        status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def request(self,
                method: str,
                url: str,
                headers: Optional[Dict[str, str]] = None,
                params: Optional[Dict[str, Any]] = None,
                data: Optional[Any] = None,
                json: Optional[Any] = None,
                cookies: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, Any], str]:
        """
        Make an HTTP request and return status code, headers, and body.
        """
        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                params=params,
                data=data,
                json=json,
                cookies=cookies,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            logger.info(f"{method.upper()} {url} -> {response.status_code}")
            return response.status_code, dict(response.headers), response.text
        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP request failed: {e}")
            return 0, {}, str(e)

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs):
        return self.request("OPTIONS", url, **kwargs)
