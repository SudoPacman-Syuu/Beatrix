"""
BEATRIX Base Scanner

Abstract base class for all scanner modules.
Inspired by Sweet Scanner's IScannerCheck interface.
"""

import asyncio
import logging
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

logger = logging.getLogger("beatrix.scanners.base")

# ── User-Agent rotation pool ────────────────────────────────────────
# Realistic, modern browser UAs.  Rotated per-request to avoid
# trivial fingerprinting by WAFs that track a single static UA.
_UA_POOL: list[str] = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
]


def _random_ua() -> str:
    """Return a random realistic User-Agent string."""
    return random.choice(_UA_POOL)


# ── Supplementary header sets for fingerprint diversity ─────────────
# WAFs correlate header *sets* (presence/absence of Accept-Language,
# DNT, Sec-Fetch-*, etc.) to fingerprint automated traffic.  We define
# a few header "profiles" modelled after real browser behaviour and
# pick one at random per BaseScanner instance.
_HEADER_PROFILES: list[dict[str, str]] = [
    {  # Chrome-like
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
    {  # Firefox-like
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
    },
    {  # Edge-like
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Upgrade-Insecure-Requests": "1",
    },
    {  # Minimal (Safari-ish)
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    },
]

# G-02: Global rate limit shared across all scanner instances.
# When multiple scanners run in parallel, each has its own per-scanner
# semaphore (default 10), so 5 parallel scanners = up to 50 requests.
# This global semaphore caps the total concurrent requests to prevent
# overwhelming the target.  Default 20 = comfortable for most targets.
_GLOBAL_SEMAPHORE_LIMIT = 20
_global_semaphore: Optional[asyncio.Semaphore] = None


def _get_global_semaphore() -> asyncio.Semaphore:
    """Lazily create the global semaphore (must be in a running event loop)."""
    global _global_semaphore
    if _global_semaphore is None:
        _global_semaphore = asyncio.Semaphore(_GLOBAL_SEMAPHORE_LIMIT)
    return _global_semaphore


class CircuitBreakerOpen(Exception):
    """Raised when a host has exceeded consecutive transport-error threshold.

    Scanners that catch generic ``Exception`` will naturally skip this URL
    and move to the next one.  The kill chain's host-failure tracker (A-05)
    can also intercept this to skip remaining URLs on the dead host.
    """


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

    # Default per-request timeout — subclasses can override (e.g.,
    # injection scanner needs more for time-based detection).
    DEFAULT_TIMEOUT: int = 10

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.client: Optional[httpx.AsyncClient] = None
        self.findings: List[Finding] = []

        # Rate limiting
        self.rate_limit = self.config.get("rate_limit", 10)
        self.semaphore = asyncio.Semaphore(self.rate_limit)

        # G-03: Per-scanner timeout — config overrides class default
        self.timeout = self.config.get("timeout", self.DEFAULT_TIMEOUT)

        # Auth state tracking — for session expiry detection
        self._auth_creds = None
        self._auth_failure_count = 0
        self._auth_failure_threshold = 3  # consecutive 401/403s before warning
        self._session_dead_warned = False

        # Circuit breaker — tracks consecutive transport errors per host.
        # After _CB_THRESHOLD consecutive ConnectError/TimeoutException on
        # the same host, further requests to that host raise immediately
        # instead of waiting for another timeout.  Prevents wasting minutes
        # retrying dead hosts across payload loops.
        self._cb_host_failures: Dict[str, int] = {}  # host -> consecutive failure count
        self._cb_tripped_hosts: set = set()  # hosts that have been circuit-broken

        # WAF evasion state
        self._waf_profile: Optional[str] = None
        self._waf_block_count: int = 0   # consecutive WAF blocks
        self._waf_throttle_delay: float = 0.0  # adaptive delay (seconds)
        self._header_profile: dict[str, str] = random.choice(_HEADER_PROFILES)

    # Circuit breaker threshold — class-level constant
    _CB_THRESHOLD: int = 5

    async def __aenter__(self):
        """Async context manager entry"""
        # Build initial headers: random UA + random header profile
        _init_headers = {"User-Agent": _random_ua()}
        _init_headers.update(self._header_profile)
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,  # Security scanner: don't follow redirects by default
            verify=False,
            headers=_init_headers,
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


    # =========================================================================
    # HTTP HELPERS
    # =========================================================================

    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        """Make an HTTP request with rate limiting, circuit breaker, 429
        retry, WAF evasion, and session expiry detection.

        WAF evasion features (all automatic, zero scanner-level changes):
        - Rotates User-Agent on every request
        - Adds random timing jitter when WAF profile is set
        - Detects WAF block pages and retries with HTTP-level bypasses
        - Adaptive throttling: slows down when consecutive blocks detected
        - Exponential backoff on 429 (up to 3 retries)

        Circuit breaker: tracks consecutive transport errors (DNS failure,
        connection refused, timeout) per host.  After _CB_THRESHOLD
        consecutive failures on the same host, raises
        ``CircuitBreakerOpen`` immediately — prevents scanners from
        spending minutes retrying a dead host across their payload loop.
        A successful response resets the counter for that host.

        When auth is configured and the server returns 401/403, tracks
        consecutive failures. After hitting the threshold, logs a warning
        that the session may have expired. This allows the kill chain to
        detect and handle re-authentication between phases.
        """
        if not self.client:
            raise RuntimeError("Scanner not initialized. Use 'async with' context.")

        # ── Circuit breaker check ─────────────────────────────────────
        from urllib.parse import urlparse as _urlparse
        host = _urlparse(url).netloc.lower()
        if host in self._cb_tripped_hosts:
            raise CircuitBreakerOpen(
                f"Circuit breaker open for {host} — "
                f"{self._CB_THRESHOLD} consecutive transport errors"
            )

        # ── UA rotation — new UA on every request ─────────────────────
        self.client.headers["User-Agent"] = _random_ua()

        # ── Request timing jitter — simulate human-like intervals ─────
        # When a WAF profile is set, add 50-300ms random delay per
        # request.  Added to adaptive throttle delay from WAF blocks.
        if self._waf_profile or self._waf_throttle_delay > 0:
            jitter = random.uniform(0.05, 0.3) + self._waf_throttle_delay
            await asyncio.sleep(jitter)

        rate_retries = 0
        waf_retries = 0
        while True:
            try:
                async with _get_global_semaphore():
                    async with self.semaphore:
                        response = await self.client.request(method, url, **kwargs)
            except (httpx.ConnectError, httpx.ConnectTimeout,
                    httpx.ReadTimeout, httpx.WriteTimeout,
                    httpx.PoolTimeout, httpx.RemoteProtocolError) as exc:
                # Transport-level failure — increment circuit breaker
                count = self._cb_host_failures.get(host, 0) + 1
                self._cb_host_failures[host] = count
                if count >= self._CB_THRESHOLD:
                    self._cb_tripped_hosts.add(host)
                    logger.warning(
                        f"[{self.name}] Circuit breaker OPEN for {host} — "
                        f"{count} consecutive transport errors"
                    )
                    raise CircuitBreakerOpen(
                        f"Circuit breaker open for {host} after {count} failures"
                    ) from exc
                raise  # Re-raise the original transport error

            # Transport succeeded — reset circuit breaker for this host
            if host in self._cb_host_failures:
                del self._cb_host_failures[host]

            # ── 429 backoff — exponential retry with Retry-After ──────
            if response.status_code == 429 and rate_retries < 3:
                try:
                    retry_after = float(response.headers.get("retry-after", 2 ** rate_retries))
                except (ValueError, TypeError):
                    retry_after = float(2 ** rate_retries)

                await asyncio.sleep(min(retry_after, 30))
                rate_retries += 1
                # Engage adaptive throttle — WAF is rate-limiting us
                self._waf_throttle_delay = min(
                    self._waf_throttle_delay + 0.5, 3.0
                )
                continue

            # ── CDN/WAF challenge page detection ──────────────────────
            # If the response body is a WAF challenge page (not a real
            # application response), try HTTP-level bypasses.
            if (response.status_code in (403, 406, 503)
                    and waf_retries < 1):
                try:
                    body = response.text[:5000]
                except Exception:
                    body = ""
                if self.is_cdn_challenge(body):
                    waf_retries += 1
                    self._waf_block_count += 1
                    # Adaptive throttle: ramp up delay on consecutive blocks
                    self._waf_throttle_delay = min(
                        0.5 * self._waf_block_count, 5.0
                    )
                    # Retry once with WAF bypass headers
                    bypass_headers = dict(kwargs.get("headers", {}))
                    bypass_headers.update({
                        "X-Originating-IP": "127.0.0.1",
                        "X-Forwarded-For": "127.0.0.1",
                        "X-Remote-IP": "127.0.0.1",
                        "X-Remote-Addr": "127.0.0.1",
                        "X-Original-URL": _urlparse(url).path,
                        "X-Rewrite-URL": _urlparse(url).path,
                    })
                    bypass_kwargs = dict(kwargs)
                    bypass_kwargs["headers"] = bypass_headers
                    await asyncio.sleep(random.uniform(0.5, 1.5))
                    try:
                        async with _get_global_semaphore():
                            async with self.semaphore:
                                resp2 = await self.client.request(
                                    method, url, **bypass_kwargs
                                )
                        if resp2.status_code not in (403, 406, 503):
                            self._waf_block_count = max(
                                self._waf_block_count - 1, 0
                            )
                            return resp2
                    except Exception:
                        pass
                    # Method override attempt for GET requests
                    if method == "GET":
                        mo_headers = dict(bypass_headers)
                        mo_headers["X-HTTP-Method-Override"] = "GET"
                        mo_kwargs = dict(kwargs)
                        mo_kwargs["headers"] = mo_headers
                        try:
                            async with _get_global_semaphore():
                                async with self.semaphore:
                                    resp3 = await self.client.request(
                                        "POST", url, **mo_kwargs
                                    )
                            if resp3.status_code not in (403, 406, 503):
                                self._waf_block_count = max(
                                    self._waf_block_count - 1, 0
                                )
                                return resp3
                        except Exception:
                            pass
                    # All bypass attempts failed — return original
                    return response
            else:
                # Successful non-WAF response — decay throttle delay
                if response.status_code < 400:
                    self._waf_block_count = max(
                        self._waf_block_count - 1, 0
                    )
                    self._waf_throttle_delay = max(
                        self._waf_throttle_delay - 0.1, 0.0
                    )

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
    # WAF BYPASS — HTTP-LEVEL TECHNIQUES
    # =========================================================================

    def set_waf_profile(self, waf_name: str) -> None:
        """Set WAF profile for HTTP-level bypass techniques.

        Activates per-request timing jitter, adaptive throttling on
        blocks, and CDN challenge auto-bypass in ``request()``.
        Override in subclasses for scanner-specific payload behavior.
        """
        self._waf_profile = waf_name



    # =========================================================================
    # CDN / WAF CHALLENGE DETECTION
    # =========================================================================

    # Markers that indicate response is from a CDN/WAF challenge, not the real app
    _CDN_CHALLENGE_MARKERS = (
        # Cloudflare
        "<title>Just a moment...</title>",       # Cloudflare JS challenge
        "<title>Attention Required!</title>",     # Cloudflare block page
        "<title>Access denied</title>",           # Cloudflare/Akamai block
        "cf-browser-verification",               # Cloudflare verification div
        "cf_chl_opt",                            # Cloudflare challenge options JS
        "challenges.cloudflare.com",             # Cloudflare challenge iframe
        "cdn-cgi/challenge-platform",            # Cloudflare challenge platform
        # Akamai
        "Pardon Our Interruption",               # Akamai bot manager
        "akam/13/",                              # Akamai sensor data
        "_abck",                                 # Akamai bot manager cookie JS
        # PerimeterX
        "perimeterx",                            # PerimeterX challenge
        "/_px/",                                 # PerimeterX challenge path
        "px-captcha",                            # PerimeterX captcha div
        "PXmvTNFT",                              # PerimeterX sensor ID
        "human-challenge",                       # PerimeterX human challenge
        # Imperva / Incapsula
        "incapsula",                             # Incapsula block
        "_Incapsula_Resource",                   # Incapsula resource check
        "robots.incapsula.com",                  # Incapsula robot check
        # DataDome
        "datadome",                              # DataDome challenge
        "dd.datadome.com",                       # DataDome JS SDK
        # Kasada
        "ips.js",                                # Kasada challenge
        # Generic
        "bot detection",                         # Generic bot detection
        "automated request",                     # Generic block message
    )

    @staticmethod
    def is_cdn_challenge(body: str) -> bool:
        """Return True if the response body is a CDN/WAF challenge page."""
        body_lower = body[:5000].lower()  # Only check the head — saves time
        for marker in BaseScanner._CDN_CHALLENGE_MARKERS:
            if marker.lower() in body_lower:
                return True
        return False

    # =========================================================================
    # HTTP FORMATTING — convert httpx objects to readable HTTP text
    # =========================================================================

    @staticmethod
    def format_http_request(resp: httpx.Response, *, max_body: int = 2000) -> str:
        """Format the request side of an httpx.Response as readable HTTP text.

        Args:
            resp: httpx.Response whose `.request` attribute is used.
            max_body: Maximum body bytes to include (default 2000).

        Returns:
            Human-readable HTTP request string like::

                GET /path?q=1 HTTP/1.1
                Host: example.com
                User-Agent: ...

                <body if present>
        """
        req = resp.request
        try:
            from urllib.parse import urlparse
            parsed = urlparse(str(req.url))
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
        except Exception:
            path = str(req.url)

        lines = [f"{req.method} {path} HTTP/1.1"]
        for name, value in req.headers.items():
            lines.append(f"{name}: {value}")
        header_block = "\n".join(lines)

        body = ""
        if req.content:
            try:
                body_text = req.content.decode("utf-8", errors="replace")
            except Exception:
                body_text = repr(req.content[:max_body])
            if len(body_text) > max_body:
                body_text = body_text[:max_body] + f"\n... ({len(body_text)} bytes total)"
            body = f"\n\n{body_text}"

        return header_block + body

    @staticmethod
    def format_http_response(resp: httpx.Response, *, max_body: int = 2000) -> str:
        """Format an httpx.Response as readable HTTP text.

        Args:
            resp: httpx.Response to format.
            max_body: Maximum body bytes to include (default 2000).

        Returns:
            Human-readable HTTP response string like::

                HTTP/1.1 200 OK
                Content-Type: application/json
                ...

                {"key": "value", ...}
        """
        reason = resp.reason_phrase or ""
        lines = [f"HTTP/1.1 {resp.status_code} {reason}".rstrip()]
        for name, value in resp.headers.items():
            lines.append(f"{name}: {value}")
        header_block = "\n".join(lines)

        body = ""
        try:
            body_text = resp.text
        except Exception:
            body_text = repr(resp.content[:max_body])
        if body_text:
            if len(body_text) > max_body:
                body_text = body_text[:max_body] + f"\n... ({len(body_text)} bytes total)"
            body = f"\n\n{body_text}"

        return header_block + body

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
        """Log a message through the standard logging framework."""
        log_func = getattr(logger, level, logger.info)
        log_func(f"[{self.name}] {message}")
