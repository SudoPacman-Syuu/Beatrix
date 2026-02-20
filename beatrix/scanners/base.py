"""
BEATRIX Base Scanner

Abstract base class for all scanner modules.
Inspired by Burp's IScannerCheck interface.
"""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from beatrix.core.types import (
    Confidence,
    Finding,
    HttpRequest,
    HttpResponse,
    InsertionPoint,
    Severity,
)


@dataclass
class ScanContext:
    """
    Context passed to scanners containing request/response and metadata.

    Similar to Burp's IHttpRequestResponse but async-friendly.
    """
    # Target info
    url: str
    base_url: str

    # Original request/response
    request: HttpRequest
    response: Optional[HttpResponse] = None

    # Parsed data
    parameters: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)

    # Insertion points detected
    insertion_points: List[InsertionPoint] = field(default_factory=list)

    # Extra data from crawling (JS files, forms, technologies, etc.)
    extra: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)

    @classmethod
    def from_url(cls, url: str) -> "ScanContext":
        """Create context from just a URL"""
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Parse query parameters
        params = {}
        if parsed.query:
            for k, v in parse_qs(parsed.query).items():
                params[k] = v[0] if v else ""

        request = HttpRequest(
            method="GET",
            url=url,
            headers={},
            body="",
        )

        return cls(
            url=url,
            base_url=base_url,
            request=request,
            parameters=params,
        )


class BaseScanner(ABC):
    """
    Abstract base class for all BEATRIX scanners.

    Each scanner implements:
    - scan(): Main entry point, yields findings
    - passive_scan(): Analyze response without sending requests
    - active_scan(): Send attack payloads

    Modeled after Burp's scanner architecture but fully async.
    """

    # Scanner metadata
    name: str = "base"
    description: str = "Base scanner"
    author: str = "BEATRIX"
    version: str = "1.0.0"

    # What this scanner checks for
    checks: List[str] = []

    # OWASP/MITRE alignment
    owasp_category: Optional[str] = None
    mitre_technique: Optional[str] = None

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.client: Optional[httpx.AsyncClient] = None
        self.findings: List[Finding] = []

        # Rate limiting
        self.rate_limit = self.config.get("rate_limit", 10)
        self.semaphore = asyncio.Semaphore(self.rate_limit)

        # Timeout
        self.timeout = self.config.get("timeout", 10)

    async def __aenter__(self):
        """Async context manager entry"""
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,  # Security scanner: don't follow redirects by default
            verify=False,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                ),
            },
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.client:
            await self.client.aclose()

    # =========================================================================
    # MAIN ENTRY POINTS
    # =========================================================================

    @abstractmethod
    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Main scan entry point. Yields findings as discovered.

        Implement this in subclasses.
        """
        # Subclasses must implement this
        raise NotImplementedError
        yield  # type: ignore  # Make it a generator

    async def passive_scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Analyze existing response without sending new requests.

        Override in subclasses that support passive scanning.
        """
        # Empty generator - subclasses override
        if False:
            yield  # type: ignore

    async def active_scan(
        self,
        context: ScanContext,
        insertion_point: InsertionPoint,
    ) -> AsyncIterator[Finding]:
        """
        Actively test an insertion point with payloads.

        Override in subclasses that support active scanning.
        """
        # Empty generator - subclasses override
        if False:
            yield  # type: ignore

    # =========================================================================
    # HTTP HELPERS
    # =========================================================================

    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        """Make an HTTP request with rate limiting and retry on 429"""
        if not self.client:
            raise RuntimeError("Scanner not initialized. Use 'async with' context.")

        retry_count = 0
        while True:
            async with self.semaphore:
                response = await self.client.request(method, url, **kwargs)

            # Retry on rate limit with exponential backoff (max 3 retries)
            if response.status_code == 429 and retry_count < 3:
                try:
                    retry_after = float(response.headers.get("retry-after", 2 ** retry_count))
                except (ValueError, TypeError):
                    retry_after = float(2 ** retry_count)

                await asyncio.sleep(min(retry_after, 30))
                retry_count += 1
                continue

            return response

    async def get(self, url: str, **kwargs) -> httpx.Response:
        """GET request"""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        """POST request"""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> httpx.Response:
        """PUT request"""
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> httpx.Response:
        """PATCH request"""
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> httpx.Response:
        """DELETE request"""
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> httpx.Response:
        """HEAD request"""
        return await self.request("HEAD", url, **kwargs)

    # =========================================================================
    # FINDING HELPERS
    # =========================================================================

    def create_finding(
        self,
        title: str,
        severity: Severity,
        confidence: Confidence,
        url: str,
        description: str,
        evidence: Optional[str] = None,
        request: Optional[str] = None,
        response: Optional[str] = None,
        remediation: Optional[str] = None,
        references: Optional[List[str]] = None,
    ) -> Finding:
        """Helper to create a Finding with scanner metadata"""
        return Finding(
            title=title,
            severity=severity,
            confidence=confidence,
            url=url,
            description=description,
            evidence=evidence,
            request=request,
            response=response,
            remediation=remediation or "",
            references=references or [],
            scanner_module=self.name,
            owasp_category=self.owasp_category,
            mitre_technique=self.mitre_technique,
            found_at=datetime.now(),
        )

    # =========================================================================
    # UTILITIES
    # =========================================================================

    def log(self, message: str, level: str = "info") -> None:
        """Log a message (will be hooked into proper logging later)"""
        print(f"[{self.name}] {message}")
