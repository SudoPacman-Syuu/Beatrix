"""
BEATRIX Base Scanner

Abstract base class for all scanner modules.
Inspired by Sweet Scanner's IScannerCheck interface.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

logger = logging.getLogger("beatrix.scanners.base")

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

    Similar to Sweet Scanner's IHttpRequestResponse but async-friendly.
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

    Modeled after Sweet Scanner's architecture but fully async.
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

        # Auth state tracking — for session expiry detection
        self._auth_creds = None
        self._auth_failure_count = 0
        self._auth_failure_threshold = 3  # consecutive 401/403s before warning
        self._session_dead_warned = False

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
            self.client = None

    def apply_auth(self, auth_creds) -> None:
        """Inject authentication headers/cookies into the scanner's HTTP client.

        Called by the kill chain AFTER __aenter__ (so self.client exists)
        and BEFORE the first scan() call.  Headers are injected once and
        persist for every subsequent request this scanner makes.

        Also stores the auth_creds reference so the scanner can detect
        session expiry (repeated 401/403) and report it.

        Args:
            auth_creds: An AuthCredentials instance (or any object with
                merged_headers() and cookie_header() methods).
        """
        if not auth_creds or not self.client:
            return

        # Store reference for session monitoring
        self._auth_creds = auth_creds
        self._auth_failure_count = 0
        self._session_dead_warned = False

        # Inject headers (Authorization, X-API-Key, etc.)
        if hasattr(auth_creds, 'merged_headers'):
            for key, value in auth_creds.merged_headers().items():
                self.client.headers[key] = value

        # Inject cookies via the Cookie header
        if hasattr(auth_creds, 'cookie_header'):
            cookie_str = auth_creds.cookie_header()
            if cookie_str:
                self.client.headers["Cookie"] = cookie_str

    def reapply_auth(self, auth_creds) -> None:
        """Re-inject fresh auth credentials after re-authentication.

        Called when the kill chain detects session expiry and performs
        a fresh login mid-scan. Updates the scanner's HTTP client headers
        with the new session tokens.
        """
        self._auth_creds = auth_creds
        self._auth_failure_count = 0
        self._session_dead_warned = False
        self.apply_auth(auth_creds)

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
        """Make an HTTP request with rate limiting, 429 retry, and session
        expiry detection.

        When auth is configured and the server returns 401/403, tracks
        consecutive failures. After hitting the threshold, logs a warning
        that the session may have expired. This allows the kill chain to
        detect and handle re-authentication between phases.
        """
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

            # ── Session expiry detection ──────────────────────────────
            # When we're running authenticated and get 401, track it.
            # A single 401 could be expected (e.g., testing auth bypass).
            # Consecutive 401s across multiple requests = session died.
            # NOTE: Only 401 (Unauthorized) is tracked, NOT 403 (Forbidden).
            # 403 often means access denied regardless of auth state
            # (e.g., .git/, .env, admin panels, security-blocked paths).
            # Security-probe scanners hammering blocked endpoints would
            # otherwise generate constant false session-death warnings.
            if self._auth_creds and response.status_code == 401:
                self._auth_failure_count += 1
                if (self._auth_failure_count >= self._auth_failure_threshold
                        and not self._session_dead_warned):
                    self._session_dead_warned = True
                    logger.warning(
                        f"[{self.name}] Session may have expired — "
                        f"{self._auth_failure_count} consecutive 401 "
                        f"responses on {url}"
                    )
            elif self._auth_creds and response.status_code < 400:
                # Successful response resets the failure counter
                self._auth_failure_count = 0

            return response

    @property
    def session_appears_dead(self) -> bool:
        """Whether this scanner has detected likely session expiry."""
        return (self._auth_creds is not None
                and self._auth_failure_count >= self._auth_failure_threshold)

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
        impact: Optional[str] = None,
        poc_curl: Optional[str] = None,
        poc_python: Optional[str] = None,
        reproduction_steps: Optional[List[str]] = None,
        parameter: Optional[str] = None,
        payload: Optional[str] = None,
        cwe_id: Optional[str] = None,
    ) -> Finding:
        """Helper to create a Finding with scanner metadata and all fields"""
        return Finding(
            title=title,
            severity=severity,
            confidence=confidence,
            url=url,
            description=description,
            evidence=evidence,
            request=request,
            response=response,
            impact=impact or "",
            remediation=remediation or "",
            references=references or [],
            poc_curl=poc_curl,
            poc_python=poc_python,
            reproduction_steps=reproduction_steps or [],
            parameter=parameter,
            payload=payload,
            cwe_id=cwe_id,
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
