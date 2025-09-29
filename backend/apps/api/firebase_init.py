
"""
Initialize Firebase Admin SDK exactly once. Exports firebase auth & firestore client.
Expects service account JSON at backend/firebase-service-account.json
"""
import os
import firebase_admin
from firebase_admin import credentials, auth as _auth, firestore as _firestore

DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "firebase-service-account.json")
cred_path = os.getenv("FIREBASE_SERVICE_ACCOUNT", DEFAULT_PATH)

if not os.path.exists(cred_path):
    raise FileNotFoundError(f"Firebase service account not found at {cred_path}. Place the service account JSON there.")

# initialize only once (idempotent)
if not firebase_admin._apps:
    cred = credentials.Certificate(cred_path)
    _app = firebase_admin.initialize_app(cred)
else:
    _app = list(firebase_admin._apps.values())[0]

auth = _auth
firestore_client = _firestore.client()
