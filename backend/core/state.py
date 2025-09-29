# backend/core/state.py

import threading
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class ScannerState:
    """
    Global runtime state for the scanner.
    Thread-safe access to active scans, targets, and configuration.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        # Singleton pattern: only one global state
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(ScannerState, cls).__new__(cls)
                    cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        # Dictionary mapping scan_id -> scan metadata
        self.active_scans: Dict[str, Dict[str, Any]] = {}

        # Global config (from backend.core/config.py)
        self.config: Dict[str, Any] = {}

        # Any additional runtime flags
        self.flags: Dict[str, Any] = {}

        logger.info("ScannerState initialized.")

    # Active scans management
    def add_scan(self, scan_id: str, data: Dict[str, Any]):
        self.active_scans[scan_id] = data
        logger.info(f"Scan added: {scan_id}")

    def update_scan(self, scan_id: str, data: Dict[str, Any]):
        if scan_id in self.active_scans:
            self.active_scans[scan_id].update(data)
            logger.info(f"Scan updated: {scan_id}")
        else:
            logger.warning(f"Scan ID not found: {scan_id}")

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return self.active_scans.get(scan_id)

    def remove_scan(self, scan_id: str):
        if scan_id in self.active_scans:
            del self.active_scans[scan_id]
            logger.info(f"Scan removed: {scan_id}")
        else:
            logger.warning(f"Scan ID not found: {scan_id}")

    def list_active_scans(self):
        return list(self.active_scans.keys())

    # Flags management
    def set_flag(self, key: str, value: Any):
        self.flags[key] = value
        logger.debug(f"Flag set: {key}={value}")

    def get_flag(self, key: str) -> Any:
        return self.flags.get(key)

    def remove_flag(self, key: str):
        if key in self.flags:
            del self.flags[key]
            logger.debug(f"Flag removed: {key}")


# Singleton instance to be imported anywhere in the backend
scanner_state = ScannerState()

# Example usage:
# scanner_state.add_scan("scan_123", {"target": "https://example.com", "status": "running"})
# scanner_state.update_scan("scan_123", {"status": "completed"})
# print(scanner_state.get_scan("scan_123"))
