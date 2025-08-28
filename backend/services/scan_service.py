# services/scan_service.py
from core import engine, datastore, state

class ScanService:
    def __init__(self):
        self.engine = engine.ScanEngine()
        self.datastore = datastore.DataStore()

    def start_scan(self, config: dict) -> dict:
        """
        Start a new scan with provided configuration.
        Returns metadata about the scan.
        """
        scan_id = self.engine.start(config)
        self.datastore.save_scan(scan_id, config)
        return {"scan_id": scan_id, "status": "started"}

    def get_scan_status(self, scan_id: str) -> dict:
        """
        Check the current status of a scan.
        """
        status = state.get_status(scan_id)
        return {"scan_id": scan_id, "status": status}

    def stop_scan(self, scan_id: str) -> dict:
        """
        Gracefully stop a running scan.
        """
        self.engine.stop(scan_id)
        return {"scan_id": scan_id, "status": "stopped"}
