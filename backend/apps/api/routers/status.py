# webscanner/backend/apps/api/routes/status.py

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from webscanner.backend.apps.api.dependencies import get_db
import psutil
import platform
import datetime

router = APIRouter(
    prefix="/status",
    tags=["status"],
)

@router.get("/health")
def health_check():
    """
    Basic health check endpoint.
    """
    return {"status": "ok", "timestamp": datetime.datetime.utcnow()}

@router.get("/system")
def system_status():
    """
    Returns server system info (CPU, memory, platform).
    """
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "memory": psutil.virtual_memory()._asdict(),
        "disk": psutil.disk_usage("/")._asdict(),
        "platform": platform.platform(),
    }

@router.get("/db")
def db_status(db: Session = Depends(get_db)):
    """
    Simple database connection check.
    """
    try:
        db.execute("SELECT 1")
        return {"database": "connected"}
    except Exception as e:
        return {"database": "error", "detail": str(e)}
