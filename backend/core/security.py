# backend/core/security.py
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from backend.core import firebase as core_firebase
from backend.core.firebase import firestore_client

security_scheme = HTTPBearer(auto_error=False)

USERS_COLLECTION = "users"

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)):
    """
    Expects Authorization: Bearer <firebase-id-token>.
    Verifies token via Firebase Admin SDK and returns a dict with at least 'uid' and 'role'.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    id_token = credentials.credentials
    try:
        decoded = core_firebase.verify_token(id_token)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    uid = decoded.get("uid") or decoded.get("sub")
    # First check custom claims
    claims = decoded.get("claims") or decoded.get("firebase", {}).get("claims", {})
    role = claims.get("role")
    # Fallback: read Firestore profile
    if not role:
        doc = firestore_client.collection(USERS_COLLECTION).document(uid).get()
        if doc.exists:
            role = doc.to_dict().get("role", "user")
        else:
            role = "user"
    return {"uid": uid, "email": decoded.get("email"), "role": role}


def require_role(required_role: str):
    def dependency(user = Depends(get_current_user)):
        if user.get("role") != required_role:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")
        return user
    return dependency
