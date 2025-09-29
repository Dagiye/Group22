#backend/apps/api/routers/scan.py
from fastapi import APIRouter, Request, HTTPException, Body
from pydantic import BaseModel
from typing import Optional, List
import uuid
import datetime
import backend.apps.api.firebase_init as fb

router = APIRouter(prefix="/scan", tags=["scan"])
db = fb.firestore_client
auth = fb.auth

# Simple in-memory store for quick dev convenience (keeps parity with Firestore)
_inmemory_scans = []

class StartScanBody(BaseModel):
    target: str
    id_token: Optional[str] = None

class StartScanResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    created_at: str
    finished_at: Optional[str] = None

def verify_token_from_request(request: Request, body_token: Optional[str]) -> dict:
    # 1) Authorization header "Bearer <token>"
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    # 2) fallback to id_token in body
    if not token and body_token:
        token = body_token
    if not token:
        raise HTTPException(status_code=401, detail="Missing ID token (put in Authorization header or body.id_token)")
    try:
        decoded = auth.verify_id_token(token)
        return decoded
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid ID token: {str(e)}")

@router.post("/start", response_model=StartScanResponse)
async def start_scan(request: Request, body: StartScanBody = Body(...)):
    # require authentication
    decoded = verify_token_from_request(request, body.id_token)
    uid = decoded.get("uid") or decoded.get("sub")
    # Create scan metadata
    scan_id = str(uuid.uuid4())
    now_iso = datetime.datetime.utcnow().isoformat() + "Z"
    entry = {
        "scan_id": scan_id,
        "target": body.target,
        "status": "started",
        "created_at": now_iso,
        "finished_at": None,
        "user_uid": uid,
    }
    # store in-memory for dev
    _inmemory_scans.insert(0, entry)
    # also persist to Firestore
    try:
        doc_ref = db.collection("scans").document(scan_id)
        doc_ref.set({
            "target": body.target,
            "status": "started",
            "created_at": fb.firestore_client.SERVER_TIMESTAMP,
            "finished_at": None,
            "user_uid": uid,
        })
    except Exception:
        # non-fatal on backend; keep in-memory store
        pass
    return entry

@router.get("/", response_model=List[StartScanResponse])
async def list_scans(request: Request):
    # For demonstration: list in-memory scans
    return _inmemory_scans

@router.get("/{scan_id}", response_model=StartScanResponse)
async def get_scan(scan_id: str, request: Request):
    for s in _inmemory_scans:
        if s["scan_id"] == scan_id:
            return s
    # try Firestore
    try:
        doc = db.collection("scans").document(scan_id).get()
        if doc.exists:
            d = doc.to_dict()
            return {
                "scan_id": scan_id,
                "target": d.get("target"),
                "status": d.get("status"),
                "created_at": d.get("created_at").isoformat() if d.get("created_at") else None,
                "finished_at": d.get("finished_at"),
            }
    except Exception:
        pass
    raise HTTPException(status_code=404, detail="Scan not found")
