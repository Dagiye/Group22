"""
backend/apps/api/routers/status.py
Simple status router for health checks and listing scans (fallback in-memory).
(This file is loaded by main.py with prefix '/status'.)
"""
from fastapi import APIRouter, Body
from typing import List, Dict, Any

router = APIRouter()

# In-memory scans for test/demo
_in_memory_scans: List[Dict[str, Any]] = []

@router.get("/health")
async def health_check():
    """Simple health check endpoint."""
    return {"status": "ok"}

@router.get("/scans")
async def list_scans():
    """
    Return scans from an in-memory list.
    Registered under /status/scans because main.py includes this router with prefix '/status'.
    """
    return _in_memory_scans

@router.post("/scans/start")
async def start_scan(payload: dict = Body(...)):
    """
    Start a simple in-memory scan entry (for testing).
    POST JSON: {"target": "https://example.com"}
    """
    target = payload.get("target")
    if not target:
        return {"error": "missing target"}
    scan_id = len(_in_memory_scans) + 1
    entry = {"scan_id": str(scan_id), "target": target, "status": "started"}
    _in_memory_scans.append(entry)
    return entry
