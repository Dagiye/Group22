# backend/services/firebase_admin.py
import os
import firebase_admin
from firebase_admin import credentials, auth, firestore

# Default path (file should exist here) or override with env var
DEFAULT_CRED_PATH = os.path.join(os.path.dirname(__file__), "firebase-service-account.json")
cred_path = os.getenv("FIREBASE_CREDENTIALS", DEFAULT_CRED_PATH)

if not os.path.exists(cred_path):
    raise FileNotFoundError(
        f"Firebase credentials not found. Expected at: {cred_path}. "
        "Download it from Firebase Console > Project Settings > Service Accounts, "
        "place it there, or set FIREBASE_CREDENTIALS env var to its path."
    )

# Initialize Firebase app only once
if not firebase_admin._apps:  # safe check on module-level attribute
    cred = credentials.Certificate(cred_path)
    firebase_app = firebase_admin.initialize_app(cred)
else:
    # if already initialized get default app
    firebase_app = firebase_admin.get_app()

# Expose firebase helpers
firebase_auth = auth
firestore_client = firestore.client()

def verify_token(id_token: str):
    """
    Verify Firebase ID token and return decoded payload.
    Raises an exception if invalid/expired.
    """
    return firebase_auth.verify_id_token(id_token)