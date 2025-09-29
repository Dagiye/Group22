# backend/apps/api/routers/admin.py
from fastapi import APIRouter, Depends, HTTPException
from typing import List
from pydantic import BaseModel
from backend.core.firebase import auth as firebase_auth, firestore_client
from backend.core.security import require_role

router = APIRouter(prefix="/admin", tags=["admin"])

class UserResponse(BaseModel):
    uid: str
    email: str
    role: str

# -----------------------------
# Routes
# -----------------------------
@router.get("/users", response_model=List[UserResponse])
def list_users(current_user=Depends(require_role("admin"))):
    """
    List all users (admin only).
    Pulls from Firebase Auth + Firestore role metadata.
    """
    users = []
    page = firebase_auth.list_users()
    for u in page.users:
        role = "user"
        doc = firestore_client.collection("users").document(u.uid).get()
        if doc.exists:
            role = doc.to_dict().get("role", "user")
        users.append(UserResponse(uid=u.uid, email=u.email, role=role))
    return users

@router.delete("/users/{uid}")
def delete_user(uid: str, current_user=Depends(require_role("admin"))):
    """
    Delete Firebase Auth account + Firestore doc (admin only).
    """
    try:
        firebase_auth.delete_user(uid)
        firestore_client.collection("users").document(uid).delete()
        return {"status": "deleted", "uid": uid}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
