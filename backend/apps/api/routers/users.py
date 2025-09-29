# backend/apps/api/routers/users.py
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List
from backend.core.security import get_current_user
from backend.core.firebase import firestore_client

router = APIRouter(prefix="/users", tags=["users"])

class UserResponse(BaseModel):
    uid: str
    email: str
    role: str

class UpdateUserRequest(BaseModel):
    role: str | None = None

@router.get("/me", response_model=UserResponse)
def get_me(current_user=Depends(get_current_user)):
    """
    Get the current Firebase-authenticated user.
    """
    return UserResponse(**current_user)

@router.put("/me")
def update_me(req: UpdateUserRequest, current_user=Depends(get_current_user)):
    """
    Update Firestore user metadata (e.g., role, profile info).
    """
    updates = req.dict(exclude_none=True)
    firestore_client.collection("users").document(current_user["uid"]).update(updates)
    return {"status": "updated", "updates": updates}
