# webscanner/backend/apps/api/routes/admin.py

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from uuid import UUID

from webscanner.backend.apps.api.dependencies import get_db, get_current_user
from webscanner.backend.models.user import User, UserRole
from webscanner.backend.schemas.user import UserResponse
from webscanner.backend.services.user_service import UserService
from webscanner.backend.services.scan_service import ScanService

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
)


def require_admin(user: User = Depends(get_current_user)):
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admins only")
    return user


@router.get("/users", response_model=List[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    List all users (admin only).
    """
    return UserService(db=db).list_users()


@router.delete("/users/{user_id}")
def delete_user(
    user_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Delete a user account (admin only).
    """
    service = UserService(db=db)
    service.delete_user(user_id)
    return {"status": "deleted", "user_id": str(user_id)}


@router.get("/scans")
def list_all_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    List all scans in the system (admin only).
    """
    return ScanService(db=db, user=current_user).list_all_scans()
