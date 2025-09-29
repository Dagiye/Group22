# backend/core/engine.py
"""
Minimal, self-contained engine shim for the scanner backend.
This file provides small, well-documented classes used throughout the
codebase: `HTTPRequest`, `HTTPResponse`, and a lightweight `ScanEngine`.

The goal is to restore a consistent interface for other modules (pipeline,
active checks, services, API) while keeping external dependencies optional
(we try to use `httpx` if present; otherwise a harmless stub is returned).

This implementation is intentionally conservative: it simulates scans and
keeps scan state in-memory. Replace or extend with your real engine later.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from uuid import uuid4
import time

try:
    import httpx  # optional — used to perform real HTTP requests if installed
except Exception:
    httpx = None


@dataclass
class HTTPRequest:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    params: Dict[str, str] = field(default_factory=dict)


@dataclass
class HTTPResponse:
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    content: str = ""
    url: str = ""
    reason: Optional[str] = None


class ScanEngine:
    """A small, synchronous/async hybrid engine used by services and API.

    Public methods used by the rest of the project:
      - start(config: dict) -> str  # return scan_id
      - stop(scan_id: str)
      - status(scan_id: str) -> dict
      - list_scans() -> dict
      - send(request: HTTPRequest) -> HTTPResponse (async)

    The engine keeps scan metadata in an in-memory dict (`_scans`). This
    is sufficient for API development and frontend work. Replace with a
    production implementation backed by a persistent datastore later.
    """

    # in-memory store of scans (scan_id -> metadata)
    _scans: Dict[str, Dict[str, Any]] = {}
    _tasks: Dict[str, asyncio.Task] = {}

    def __init__(self, target_url: Optional[str] = None, scan_id: Optional[str] = None):
        self.target_url = target_url
        self.scan_id = scan_id

    def start(self, config: Dict[str, Any]) -> str:
        """Start a new scan and schedule the background worker.

        `config` can contain `target` (string) and optionally `scan_id`.
        Returns the chosen `scan_id`.
        """
        scan_id = str(config.get("scan_id") or config.get("id") or uuid4())
        target = config.get("target") or self.target_url or config.get("target_url")

        self._scans[scan_id] = {
            "status": "queued",
            "progress": 0,
            "findings": [],
            "target": target,
            "started_at": time.time(),
        }

        # Try to schedule the background worker on the running event loop.
        try:
            loop = asyncio.get_event_loop()
            task = loop.create_task(self._run_scan(scan_id, target))
            self._tasks[scan_id] = task
        except RuntimeError:
            # Event loop not running (e.g., called from sync tests). We leave the
            # scan record and allow the caller to schedule execution.
            pass

        return scan_id

    async def _run_scan(self, scan_id: str, target: Optional[str]):
        """Simulated scan worker — updates progress and appends a sample finding.

        Replace with the real orchestration (invoking active checks, fetches,
        parsing, reporting, etc.) when available.
        """
        self._scans[scan_id]["status"] = "running"
        for i in range(1, 11):
            # simulate work
            await asyncio.sleep(0.5)
            self._scans[scan_id]["progress"] = i * 10
            if i == 5:
                # add a synthetic finding as an example
                self._scans[scan_id]["findings"].append(
                    {
                        "title": "Simulated issue",
                        "url": target or "",
                        "severity": "low",
                        "description": "Auto-generated finding for demo purposes",
                    }
                )

        self._scans[scan_id]["status"] = "completed"
        self._scans[scan_id]["completed_at"] = time.time()

    def stop(self, scan_id: str):
        """Attempt to stop a running scan (best-effort).

        If the engine scheduled a task, it will be cancelled; the scan status
        will be set to `stopped` for callers to observe.
        """
        task = self._tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
        meta = self._scans.get(scan_id)
        if meta:
            meta["status"] = "stopped"

    def status(self, scan_id: str) -> Dict[str, Any]:
        return self._scans.get(scan_id, {"status": "unknown"})

    def list_scans(self) -> Dict[str, Dict[str, Any]]:
        return self._scans

    async def send(self, request: HTTPRequest) -> HTTPResponse:
        """Perform an HTTP request for active checks.

        This helper attempts to use `httpx` (async). If `httpx` isn't
        available we return a minimal stub response so checks can execute
        without raising import errors.
        """
        if httpx is not None:
            async with httpx.AsyncClient() as client:
                r = await client.request(
                    method=request.method,
                    url=request.url,
                    headers=request.headers,
                    params=request.params,
                    content=request.body,
                )
                return HTTPResponse(status_code=r.status_code, headers=dict(r.headers), content=r.text, url=str(r.url))

        # fallback - nonblocking stub response
        await asyncio.sleep(0)
        return HTTPResponse(status_code=200, headers={}, content="", url=request.url or "")
