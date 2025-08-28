# backend/apps/api/routers/report.py
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import uuid

router = APIRouter(prefix="/report", tags=["report"])

# --- Schemas ---

class Finding(BaseModel):
    title: str
    description: str
    severity: str  # e.g., "low", "medium", "high", "critical"
    url: str
    evidence: Optional[str] = None

class ScanReport(BaseModel):
    id: str
    target: str
    status: str  # e.g., "pending", "completed", "failed"
    started_at: datetime
    completed_at: Optional[datetime] = None
    findings: List[Finding] = []

# --- In-memory storage ---
reports_db = {}

# --- Routes ---

@router.post("/", response_model=ScanReport)
async def create_report(target: str, findings: List[Finding] = []):
    report_id = str(uuid.uuid4())
    report = ScanReport(
        id=report_id,
        target=target,
        status="completed" if findings else "pending",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow() if findings else None,
        findings=findings
    )
    reports_db[report_id] = report
    return report

@router.get("/", response_model=List[ScanReport])
async def get_reports(status: Optional[str] = Query(None), severity: Optional[str] = Query(None)):
    results = list(reports_db.values())
    if status:
        results = [r for r in results if r.status == status]
    if severity:
        results = [
            r for r in results if any(f.severity.lower() == severity.lower() for f in r.findings)
        ]
    return results

@router.get("/{report_id}", response_model=ScanReport)
async def get_report(report_id: str):
    report = reports_db.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report
