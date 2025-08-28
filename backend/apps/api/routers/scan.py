# backend/apps/api/routers/scan.py
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl, Field
from typing import List, Optional
from uuid import uuid4
from datetime import datetime
from ..dependencies import get_scan_engine, ScanEngine

router = APIRouter(
    prefix="/scan",
    tags=["scan"]
)

# --- Request and Response Schemas ---

class ScanRequest(BaseModel):
    target_url: HttpUrl = Field(..., description="URL of the target web application")
    ruleset: Optional[str] = Field("baseline", description="Scan ruleset to use")
    depth: Optional[int] = Field(2, description="Crawl depth for spidering")
    auth_token: Optional[str] = Field(None, description="Optional auth token if login required")

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    created_at: datetime

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: int = Field(..., ge=0, le=100)
    findings: List[dict] = []

# --- Scan Storage (in-memory for demo, can be DB) ---
active_scans = {}

# --- Endpoints ---

@router.post("/", response_model=ScanResponse)
async def start_scan(scan_req: ScanRequest, background_tasks: BackgroundTasks, engine: ScanEngine = Depends(get_scan_engine)):
    """
    Start a new web application scan.
    """
    scan_id = str(uuid4())
    active_scans[scan_id] = {
        "status": "queued",
        "progress": 0,
        "findings": []
    }

    # Run scan in background
    background_tasks.add_task(engine.run_scan, scan_id, scan_req.dict())

    return ScanResponse(scan_id=scan_id, status="queued", created_at=datetime.utcnow())


@router.get("/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """
    Get current status and findings of a scan.
    """
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan ID not found")

    scan_info = active_scans[scan_id]
    return ScanStatus(
        scan_id=scan_id,
        status=scan_info["status"],
        progress=scan_info["progress"],
        findings=scan_info["findings"]
    )


@router.get("/", response_model=List[ScanStatus])
async def list_active_scans():
    """
    List all active or completed scans.
    """
    return [
        ScanStatus(
            scan_id=sid,
            status=info["status"],
            progress=info["progress"],
            findings=info["findings"]
        ) for sid, info in active_scans.items()
    ]
