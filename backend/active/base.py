# backend/active/base.py
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, List
import logging
from backend.core.findings import Finding
from backend.core.evidence import Evidence
from backend.core.context import ScanContext
from backend.core.engine import HTTPRequest, HTTPResponse

logger = logging.getLogger(__name__)


class ActiveCheck(ABC):
    """
    Base class for all active vulnerability checks.
    Provides a common interface for payload injection, execution,
    and reporting.
    """

    name: str = "base-check"
    description: str = "Abstract active check"
    severity: str = "info"
    categories: List[str] = []

    def __init__(self, context: ScanContext):
        self.context = context
        self.findings: List[Finding] = []

    @abstractmethod
    async def run(self, request: HTTPRequest, response: HTTPResponse) -> None:
        """
        Run the check against a request/response pair.
        Must be implemented by subclasses.
        """
        raise NotImplementedError

    def build_payload(self, template: str, **kwargs) -> str:
        """
        Render a payload template with context variables.
        Example: template="id={{injection}}" -> id=1' OR '1'='1
        """
        try:
            return template.format(**kwargs)
        except KeyError as e:
            logger.error(f"Payload template missing key: {e}")
            return template

    def record_finding(
        self,
        title: str,
        description: str,
        severity: str,
        request: HTTPRequest,
        response: Optional[HTTPResponse] = None,
        evidence: Optional[Evidence] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        """
        Create and register a finding from a vulnerability check.
        """
        finding = Finding(
            title=title,
            description=description,
            severity=severity,
            categories=self.categories,
            request=request,
            response=response,
            evidence=evidence,
            metadata=metadata or {},
            source=self.name,
        )
        self.findings.append(finding)
        self.context.datastore.save_finding(finding)
        logger.info(f"[{self.name}] Finding recorded: {title}")
        return finding

    def add_evidence(self, content: Any, content_type: str = "text") -> Evidence:
        """
        Wrap raw content into an Evidence object.
        """
        return Evidence(content=content, content_type=content_type)
