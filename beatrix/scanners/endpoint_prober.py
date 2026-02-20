"""
BEATRIX Endpoint Prober

Born from: Bykea engagement (2026-02-05)
The manual process of curling /v1/invoice, /v1/booking, /v1/autocomplete
one by one is exactly what this module automates.

Technique:
1. Take a base URL (e.g., track-backend.bykea.net)
2. Probe common API path patterns (/v1, /v2, /api, /graphql, etc.)
3. Categorize responses: 200=alive, 401/403=auth-protected (interesting!),
   404=not found, 500=error (run error_disclosure scanner), 301/302=redirect
4. Build a map of the attack surface
5. Flag auth-protected endpoints for deeper testing

This replaces the tedious manual curl loop that eats processing time.

OWASP: A01:2021 Broken Access Control (finds unprotected endpoints)
"""

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from typing import AsyncIterator, Dict, List, Set
from urllib.parse import urljoin, urlparse

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext


@dataclass
class EndpointResult:
    """Result of probing a single endpoint"""
    url: str
    status: int
    content_type: str = ""
    body_length: int = 0
    body_preview: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    response_time_ms: float = 0
    category: str = "unknown"  # alive, auth, error, not_found, redirect
    is_soft_404: bool = False  # Soft-404 detection flag
    structure_hash: str = ""   # HTML structural fingerprint


class EndpointProber(BaseScanner):
    """
    Automated endpoint discovery and categorization.

    Instead of manually curling 50 paths, this scanner probes them all
    in parallel, categorizes the responses, and flags the interesting ones.
    """

    name = "endpoint_prober"
    description = "API endpoint discovery and attack surface mapper"
    version = "1.0.0"

    owasp_category = "A01:2021"

    async def __aenter__(self):
        """Override to follow redirects and use a browser User-Agent."""
        import httpx
        self.client = httpx.AsyncClient(
            timeout=self.config.get("timeout", 10),
            follow_redirects=True,
            verify=False,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                ),
            },
        )
        return self

    # =========================================================================
    # PATH DICTIONARIES — organized by likelihood of finding something good
    # =========================================================================

    # API version prefixes to try
    API_PREFIXES = ["/v1", "/v2", "/v3", "/api", "/api/v1", "/api/v2"]

    # High-value endpoints (auth, user data, payments)
    HIGH_VALUE_PATHS = [
        "/user", "/users", "/user/me", "/me", "/profile",
        "/account", "/accounts",
        "/admin", "/admin/users", "/admin/dashboard",
        "/auth", "/auth/login", "/auth/register", "/auth/token", "/auth/refresh",
        "/login", "/register", "/signup", "/oauth",
        "/payment", "/payments", "/billing", "/invoice", "/invoices",
        "/order", "/orders", "/transaction", "/transactions",
        "/booking", "/bookings", "/trip", "/trips", "/ride", "/rides",
        "/wallet", "/balance",
        "/upload", "/file", "/files", "/download",
        "/settings", "/config", "/configuration",
        "/notification", "/notifications",
        "/message", "/messages", "/chat",
    ]

    # Infrastructure endpoints (usually shouldn't be public)
    INFRA_PATHS = [
        "/health", "/healthcheck", "/health-check",
        "/status", "/ping", "/ready", "/readiness",
        "/info", "/version", "/build-info",
        "/metrics", "/prometheus",
        "/debug", "/debug/vars", "/debug/pprof",
        "/env", "/environment",
        "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
        "/.env", "/config.json", "/config.yaml",
        "/swagger", "/swagger.json", "/swagger-ui", "/swagger-ui.html",
        "/api-docs", "/openapi.json", "/openapi.yaml",
        "/graphql", "/graphiql", "/playground",
        "/console", "/shell", "/terminal",
        "/phpinfo.php", "/server-status", "/server-info",
        "/wp-admin", "/wp-login.php",
        "/.git/HEAD", "/.git/config",
        "/.svn/entries",
        "/robots.txt", "/sitemap.xml",
        "/.well-known/security.txt",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
    ]

    # Geocoding / Maps (found these on Bykea)
    GEO_PATHS = [
        "/geocode", "/reverse-geocode", "/autocomplete",
        "/search", "/suggest", "/places",
        "/directions", "/route", "/routing",
        "/map", "/maps", "/tile", "/tiles",
    ]

    # Socket.IO / WebSocket
    REALTIME_PATHS = [
        "/socket.io/",
        "/socket.io/?EIO=4&transport=polling",
        "/ws", "/websocket",
        "/hub", "/signalr",
        "/cable", "/streaming",
    ]

    # E-commerce / Customer Data (Zooplus lessons)
    ECOMMERCE_PATHS = [
        "/customer-data/api/v2/customers",
        "/customer-data/api/v2/address-validation-rules",
        "/cart-api/v2/cart",
        "/cart-api/v2/checkout",
        "/wishlist-api/v2/wishlist",
        "/product-api/v2/products",
        "/review-api/v2/reviews",
        "/subscription-api/v2/subscriptions",
        "/autoshipment-api/v2/autoshipments",
        "/order-api/v2/orders",
        "/payment-api/v2/payment-methods",
        "/coupon-api/v2/coupons",
        "/search-api/v2/search",
        "/guest-checkout",
        "/guest-checkout/api/v2/checkout",
        "/newsletter/subscribe",
        "/newsletter/unsubscribe",
        # Generic e-commerce
        "/cart", "/basket", "/checkout",
        "/wishlist", "/favorites",
        "/orders", "/order-history",
        "/addresses", "/address-book",
        "/returns", "/refunds",
        "/gift-cards", "/vouchers",
        "/rewards", "/loyalty",
    ]

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Probe all endpoint patterns against the target.
        """
        base = context.base_url
        self.log(f"Endpoint probing on {base}")

        # Build the full path list
        all_paths = self._build_path_list()
        self.log(f"Testing {len(all_paths)} paths")

        # Step 1: Detect soft-404 patterns BEFORE probing
        soft_404_sigs = await self._detect_soft_404(base)
        if soft_404_sigs:
            self.log(f"Detected {len(soft_404_sigs)} soft-404 signatures")

        # Probe in parallel batches
        results: List[EndpointResult] = []
        batch_size = self.config.get("batch_size", 20)

        for i in range(0, len(all_paths), batch_size):
            batch = all_paths[i:i + batch_size]
            tasks = [self._probe_endpoint(base, path) for path in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in batch_results:
                if isinstance(result, EndpointResult):
                    # Check against soft-404 signatures
                    if result.status == 200 and self._is_soft_404(result, soft_404_sigs):
                        result.is_soft_404 = True
                        result.category = "not_found"
                    else:
                        results.append(result)

        # Categorize and generate findings
        categorized = self._categorize_results(results)

        # --- Alive endpoints (200) ---
        alive = categorized.get("alive", [])
        if alive:
            yield self.create_finding(
                title=f"Live API Endpoints Discovered ({len(alive)} endpoints)",
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                url=base,
                description=(
                    "The following endpoints returned 200 OK:\n\n"
                    + "\n".join(
                        f"- `{r.url}` ({r.content_type}, {r.body_length} bytes)"
                        for r in alive[:30]
                    )
                ),
                evidence=json.dumps(
                    [{"url": r.url, "status": r.status, "type": r.content_type, "size": r.body_length}
                     for r in alive[:30]],
                    indent=2
                ),
            )

        # --- Auth-protected endpoints (401/403) — MOST INTERESTING ---
        auth = categorized.get("auth", [])
        if auth:
            yield self.create_finding(
                title=f"Auth-Protected Endpoints Found ({len(auth)} endpoints)",
                severity=Severity.LOW,
                confidence=Confidence.CERTAIN,
                url=base,
                description=(
                    "These endpoints require authentication — they exist and "
                    "are functional, just gated. High-value targets for auth "
                    "bypass, IDOR, and token manipulation:\n\n"
                    + "\n".join(
                        f"- `{r.url}` → HTTP {r.status}"
                        for r in auth[:30]
                    )
                ),
                evidence=json.dumps(
                    [{"url": r.url, "status": r.status, "preview": r.body_preview[:100]}
                     for r in auth[:30]],
                    indent=2
                ),
                remediation="Verify that all auth-protected endpoints properly validate authorization, not just authentication.",
            )

        # --- Error endpoints (500) — run error_disclosure next ---
        errors = categorized.get("error", [])
        if errors:
            yield self.create_finding(
                title=f"Server Errors on API Endpoints ({len(errors)} endpoints)",
                severity=Severity.LOW,
                confidence=Confidence.CERTAIN,
                url=base,
                description=(
                    "These endpoints return 500 Internal Server Error. "
                    "Error responses often leak database details, stack traces, "
                    "and framework internals:\n\n"
                    + "\n".join(
                        f"- `{r.url}` → {r.body_preview[:100]}"
                        for r in errors[:20]
                    )
                ),
                evidence=json.dumps(
                    [{"url": r.url, "status": r.status, "error": r.body_preview[:200]}
                     for r in errors[:20]],
                    indent=2
                ),
                remediation="Investigate why these endpoints throw unhandled exceptions.",
            )

        # --- Infrastructure endpoints that shouldn't be public ---
        for result in alive:
            path = urlparse(result.url).path
            if any(p in path for p in [
                '/actuator', '/debug', '/.git', '/.env', '/swagger',
                '/graphiql', '/playground', '/phpinfo', '/server-status',
                '/console', '/metrics', '/env', '/.svn'
            ]):
                severity = Severity.HIGH if any(
                    p in path for p in ['/.git', '/.env', '/actuator/env', '/debug', '/console']
                ) else Severity.MEDIUM

                yield self.create_finding(
                    title=f"Sensitive Infrastructure Endpoint Exposed: {path}",
                    severity=severity,
                    confidence=Confidence.CERTAIN,
                    url=result.url,
                    description=(
                        f"Infrastructure/debug endpoint `{path}` is publicly "
                        f"accessible without authentication. Content-Type: {result.content_type}, "
                        f"Body size: {result.body_length} bytes."
                    ),
                    evidence=result.body_preview[:500],
                    request=f"GET {result.url}",
                    response=f"HTTP {result.status}\n{result.body_preview[:300]}",
                    remediation="Restrict access to infrastructure endpoints via firewall rules or authentication.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"],
                )

        # --- Swagger/OpenAPI docs ---
        for result in alive:
            path = urlparse(result.url).path
            if any(p in path for p in ['/swagger', '/openapi', '/api-docs']):
                yield self.create_finding(
                    title=f"API Documentation Publicly Accessible: {path}",
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    url=result.url,
                    description=(
                        f"API documentation at `{path}` is publicly accessible. "
                        f"This provides a complete map of the API attack surface."
                    ),
                    evidence=result.body_preview[:500],
                    remediation="Restrict API docs to authenticated users or internal networks.",
                )

    async def _detect_soft_404(self, base_url: str) -> List[Dict]:
        """
        Detect soft-404 patterns by requesting definitely-nonexistent paths.

        Many apps return HTTP 200 for all paths (SPAs, custom error pages).
        We fingerprint the "not found" response so we can filter it out.

        Returns list of signature dicts with body_hash, body_length, and
        a structural fingerprint of the HTML shell.
        """
        signatures = []

        # Use several random-looking paths to build a fingerprint
        canary_paths = [
            '/bxprobe-404-test-a1b2c3d4e5',
            '/api/bxprobe-nonexistent-f6g7h8',
            '/v1/bxprobe-fake-endpoint-i9j0',
            '/definitely-not-a-real-page-k1l2m3',
        ]

        for path in canary_paths:
            try:
                url = urljoin(base_url, path)
                response = await self.get(url)

                if response.status_code == 200:
                    body = response.text.strip()
                    normalized = body.replace(path, '').replace(path.lstrip('/'), '')
                    body_hash = hashlib.md5(normalized.encode()).hexdigest()

                    # Extract structural fingerprint: script src URLs, main div ids
                    # SPAs serve the same shell with same scripts for every path
                    struct_sig = self._extract_structure(body)

                    sig = {
                        'body_hash': body_hash,
                        'body_length': len(body),
                        'content_type': response.headers.get('content-type', ''),
                        'status': response.status_code,
                        'structure': struct_sig,
                    }

                    if not any(s['body_hash'] == body_hash for s in signatures):
                        signatures.append(sig)

            except Exception:
                continue

        return signatures

    @staticmethod
    def _extract_structure(html: str) -> str:
        """Extract a structural fingerprint from HTML — script tags, framework markers."""
        import re
        parts = []
        # Extract <script src="..."> URLs — these are the INVARIANT part of an SPA
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)
        parts.extend(sorted(scripts[:20]))
        # Framework mount points
        for marker in ['id="__next"', 'id="root"', 'id="app"', 'id="__nuxt"',
                       'ng-app=', 'data-reactroot']:
            if marker in html:
                parts.append(marker)
        return hashlib.md5("|".join(parts).encode()).hexdigest() if parts else ""

    def _is_soft_404(self, result: EndpointResult, signatures: List[Dict]) -> bool:
        """Check if a result matches a known soft-404 signature"""
        if not signatures:
            return False

        for sig in signatures:
            # Check 1: Same structural fingerprint (most reliable for SPAs)
            # Uses pre-computed hash from full response body
            if sig.get('structure') and result.structure_hash:
                if result.structure_hash == sig['structure']:
                    return True

            # Check 2: Similar body length + same content type (within 25% tolerance)
            if sig['body_length'] > 0:
                length_ratio = abs(result.body_length - sig['body_length']) / sig['body_length']
                same_type = result.content_type.split(';')[0] == sig['content_type'].split(';')[0]
                if length_ratio < 0.25 and same_type:
                    return True

        return False

    async def _probe_endpoint(self, base_url: str, path: str) -> EndpointResult:
        """Probe a single endpoint and categorize the response"""
        url = urljoin(base_url, path)

        try:
            start = asyncio.get_event_loop().time()
            response = await self.get(url)
            elapsed = (asyncio.get_event_loop().time() - start) * 1000

            # Compute structure hash on FULL body before truncating
            full_text = response.text
            struct_hash = self._extract_structure(full_text)

            return EndpointResult(
                url=url,
                status=response.status_code,
                content_type=response.headers.get("content-type", ""),
                body_length=len(response.content),
                body_preview=full_text[:2000],
                headers=dict(response.headers),
                response_time_ms=elapsed,
                structure_hash=struct_hash,
            )
        except Exception as e:
            return EndpointResult(
                url=url,
                status=0,
                category="error",
                body_preview=str(e),
            )

    def _build_path_list(self) -> List[str]:
        """Build the complete list of paths to probe"""
        paths: Set[str] = set()

        # Add infra paths (no prefix needed)
        paths.update(self.INFRA_PATHS)
        paths.update(self.REALTIME_PATHS)

        # Add high-value and geo paths with API prefixes
        for prefix in self.API_PREFIXES:
            for path in self.HIGH_VALUE_PATHS + self.GEO_PATHS:
                paths.add(f"{prefix}{path}")

        # Also try high-value paths without prefix
        paths.update(self.HIGH_VALUE_PATHS)
        paths.update(self.GEO_PATHS)

        # E-commerce paths (already include version prefixes, add as-is)
        paths.update(self.ECOMMERCE_PATHS)

        return sorted(paths)

    def _categorize_results(self, results: List[EndpointResult]) -> Dict[str, List[EndpointResult]]:
        """Categorize probe results by response type"""
        categories: Dict[str, List[EndpointResult]] = {
            "alive": [],
            "auth": [],
            "error": [],
            "redirect": [],
            "not_found": [],
        }

        for r in results:
            if r.status == 0:
                continue  # Connection failed
            elif r.status == 200:
                r.category = "alive"
                categories["alive"].append(r)
            elif r.status in (401, 403):
                r.category = "auth"
                categories["auth"].append(r)
            elif r.status >= 500:
                r.category = "error"
                categories["error"].append(r)
            elif r.status in (301, 302, 307, 308):
                r.category = "redirect"
                categories["redirect"].append(r)
            # 404s are ignored — they're noise

        return categories
