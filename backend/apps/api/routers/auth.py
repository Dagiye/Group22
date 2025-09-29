from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from backend.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])

class RegisterModel(BaseModel):
    email: str
    password: str

class LoginModel(BaseModel):
    email: str
    password: str

@router.post("/register")
async def register_user(data: RegisterModel):
    try:
        user = AuthService.register_user(data.email, data.password)
        return {"success": True, "user": user}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/login")
async def login_user(data: LoginModel):
    try:
        user, token = AuthService.login_user(data.email, data.password)
        return {"success": True, "user": user, "access_token": token}
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))