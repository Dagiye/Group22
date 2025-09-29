"""
Core Firebase wrapper.
This file reuses the Firebase clients initialized in services/firebase_admin.py
to avoid multiple initialize_app() calls.
"""

from backend.services.firebase_admin import (
    firebase_auth,
    firestore_client,
    verify_token,
)

# Expose firebase_auth and firestore_client for other modules
auth = firebase_auth
db = firestore_client


def get_user(uid: str):
    """Fetch a user from Firebase Authentication by UID."""
    return auth.get_user(uid)


def get_user_by_email(email: str):
    """Fetch a user from Firebase Authentication by email."""
    return auth.get_user_by_email(email)


def verify_id_token(id_token: str):
    """Verify a Firebase ID token and return decoded claims."""
    return verify_token(id_token)