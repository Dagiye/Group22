"""
Session management for authenticated scan modules.
"""

from __future__ import annotations
import secrets
import time
import threading
from typing import Dict, Optional, Any
import logging

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

DEFAULT_TTL = 3600  # 1 hour


class SessionExpired(Exception):
    pass


class AuthSession:
    """Represents a single user/session."""

    def __init__(self, user_id: str, data: Optional[Dict[str, Any]] = None, ttl: int = DEFAULT_TTL):
        self.user_id = user_id
        self.data = data or {}
        self.ttl = ttl
        self.created_at = int(time.time())
        self.token = secrets.token_urlsafe(32)

    def is_expired(self) -> bool:
        return int(time.time()) > self.created_at + self.ttl


class SessionStore:
    """Thread-safe in-memory session store."""

    def __init__(self):
        self._sessions: Dict[str, AuthSession] = {}
        self._lock = threading.Lock()

    def create_session(self, user_id: str, data: Optional[Dict[str, Any]] = None, ttl: int = DEFAULT_TTL) -> str:
        session = AuthSession(user_id, data, ttl)
        with self._lock:
            self._sessions[session.token] = session
        log.info("Created session for user %s token=%s", user_id, session.token)
        return session.token

    def get_session(self, token: str) -> AuthSession:
        with self._lock:
            session = self._sessions.get(token)
            if not session:
                raise SessionExpired("Session not found or expired")
            if session.is_expired():
                del self._sessions[token]
                raise SessionExpired("Session expired")
            return session

    def destroy_session(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)
            log.info("Destroyed session token %s", token)

    def refresh_session(self, token: str) -> None:
        with self._lock:
            session = self.get_session(token)
            session.created_at = int(time.time())
            log.debug("Refreshed session token %s", token)
