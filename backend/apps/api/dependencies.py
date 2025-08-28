# webscanner/backend/apps/api/dependencies.py

from typing import Generator, Optional
from fastapi import Depends, HTTPException, status
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from webscanner.backend.core.security import oauth2_scheme
from webscanner.backend.core.database import SessionLocal
from webscanner.backend.models.user import User
from webscanner.backend.core.config import settings


# --- Database Dependency ---
def get_db() -> Generator:
    """Provide a database session to routes/services."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- Auth Helpers ---
def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    """Extract the current user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception

    return user


def get_current_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """Require that the current user is an admin."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user


# --- Example: Rate Limiting (optional placeholder) ---
# Could plug in Redis or an in-memory limiter
def rate_limiter():
    # TODO: Implement rate limiting logic here
    return True
