"""
Report router: simple in-memory report management.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict
from backend.apps.api.dependencies import get_scan_engine  # ✅ fixed import
from backend.core.engine import ScanEngine

router = APIRouter()

# In-memory report storage
_reports: Dict[str, dict] = {}


# ---- Schemas ----
class ReportCreate(BaseModel):
    scan_id: str
    content: str


class ReportResponse(BaseModel):
    report_id: str
    scan_id: str
    content: str


# ---- Routes ----
@router.post("/", response_model=ReportResponse)
async def create_report(
    report: ReportCreate, engine: ScanEngine = Depends(get_scan_engine)
):
    """Attach a report to an existing scan."""
    scan_status = engine.status(report.scan_id)
    if scan_status["status"] == "unknown":
        raise HTTPException(status_code=404, detail="Scan not found")

    report_id = f"report-{report.scan_id}"
    _reports[report_id] = report.dict()
    return {"report_id": report_id, **report.dict()}


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(report_id: str):
    """Retrieve a previously stored report."""
    if report_id not in _reports:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"report_id": report_id, **_reports[report_id]}
