"""
Dependency injection utilities for FastAPI.

Provides:
  - get_scan_engine(): returns a singleton ScanEngine instance
  - get_current_user(): placeholder auth dependency

Extend `get_current_user` later with real authentication (JWT, OAuth2, etc.).
"""

from fastapi import Depends, HTTPException, status
from typing import Optional

# ✅ Correct import path
from backend.core.engine import ScanEngine

# Global singleton scan engine (kept alive across requests)
_scan_engine: Optional[ScanEngine] = None


def get_scan_engine() -> ScanEngine:
    """
    Returns a singleton ScanEngine instance.
    Initializes on first call.
    """
    global _scan_engine
    if _scan_engine is None:
        _scan_engine = ScanEngine()
    return _scan_engine


# --- Auth stub ---
# Replace this with real JWT / OAuth2 logic later.
def get_current_user(token: str = "") -> dict:
    """
    Very simple placeholder. Always returns a dummy user if token is provided,
    otherwise raises 401.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return {"username": "demo_user", "scopes": ["read", "write"]}
