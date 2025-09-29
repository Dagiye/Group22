# backend/services/scan_service.py
from backend.services.firebase_admin import firestore_client
from typing import Dict, List
import uuid
from datetime import datetime

SCANS_COLLECTION = "scans"

class ScanService:
    def __init__(self):
        self.db = firestore_client

    def start_scan(self, target: str, user_id: str) -> Dict:
        scan_id = str(uuid.uuid4())
        scan_data = {
            "scan_id": scan_id,
            "user_id": user_id,
            "target": target,
            "status": "started",
            "progress": 0,
            "created_at": datetime.utcnow(),
            "finished_at": None,
            "findings": [],
        }
        self.db.collection(SCANS_COLLECTION).document(scan_id).set(scan_data)
        return scan_data

    def get_scan(self, scan_id: str) -> Dict:
        doc = self.db.collection(SCANS_COLLECTION).document(scan_id).get()
        if doc.exists:
            return doc.to_dict()
        raise Exception("Scan not found")

    def list_scans(self, user_id: str = None) -> List[Dict]:
        query = self.db.collection(SCANS_COLLECTION)
        if user_id:
            query = query.where("user_id", "==", user_id)
        return [doc.to_dict() for doc in query.stream()]

    def update_scan_status(self, scan_id: str, status: str, progress: int = None):
        update_data = {"status": status}
        if progress is not None:
            update_data["progress"] = progress
        if status == "finished":
            update_data["finished_at"] = datetime.utcnow()
        self.db.collection(SCANS_COLLECTION).document(scan_id).update(update_data)
        return self.get_scan(scan_id)
