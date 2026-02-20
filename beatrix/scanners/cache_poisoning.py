"""
BEATRIX Web Cache Poisoning Scanner

Born from: PortSwigger research (James Kettle) — "Practical Web Cache Poisoning"
https://portswigger.net/research/practical-web-cache-poisoning

TECHNIQUE:
1. Identify cache behavior: probe cache headers (Age, X-Cache, CF-Cache-Status, Via)
2. Find unkeyed inputs: headers/cookies that affect response but aren't in cache key
3. Inject payloads via unkeyed inputs → response reflects XSS/redirect → cache stores it
4. Cache deception: trick CDN into caching authenticated responses at static URLs
5. Cache key normalization: exploit URL normalization differences between CDN and origin
6. Parameter cloaking: hide poisoned params using parsing discrepancies (;, &, ?)
7. Fat GET: POST-style bodies on GET requests that some servers process
8. Host header injection: X-Forwarded-Host / X-Host not in cache key but reflected

SEVERITY: HIGH-CRITICAL — cache poisoning achieves:
- Stored XSS at scale (every user gets poisoned response)
- Open redirect → phishing all users
- DoS (cache permanent error page)
- Data theft via cache deception
- JS resource poisoning → supply chain attack

OWASP: WSTG-ATHN-00 (not directly mapped — novel attack class)
       A05:2021 - Security Misconfiguration

MITRE: T1190 (Exploit Public-Facing Application)
       T1189 (Drive-by Compromise — via cached XSS)

CWE: CWE-349 (Acceptance of Extraneous Untrusted Data with Trusted Data)
     CWE-525 (Use of Web Browser Cache Containing Sensitive Information)

REFERENCES:
- https://portswigger.net/research/practical-web-cache-poisoning
- https://portswigger.net/research/web-cache-entanglement
- https://portswigger.net/web-security/web-cache-poisoning
- https://youst.in/posts/cache-poisoning-at-scale/
"""

import asyncio
import random
import re
import string
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional

try:
    import httpx
except ImportError:
    httpx = None

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext

# =============================================================================
# DATA MODELS
# =============================================================================

class CachePoisonType(Enum):
    """Cache poisoning technique variants"""
    UNKEYED_HEADER = "unkeyed_header"
    UNKEYED_COOKIE = "unkeyed_cookie"
    UNKEYED_PORT = "unkeyed_port"
    FAT_GET = "fat_get"
    PARAMETER_CLOAKING = "parameter_cloaking"
    CACHE_DECEPTION = "cache_deception"
    NORMALIZE_EXPLOIT = "normalization_exploit"
    HOST_OVERRIDE = "host_override"


@dataclass
class CacheFingerprint:
    """Cache behavior information"""
    has_cache: bool = False
    cache_type: Optional[str] = None       # CDN/proxy name
    cache_headers: Dict[str, str] = field(default_factory=dict)
    cache_hit_indicator: Optional[str] = None  # Header value for HIT
    ttl: Optional[int] = None
    varies_on: List[str] = field(default_factory=list)


@dataclass
class UnkeyedInput:
    """An input (header/cookie/param) that's not in cache key"""
    input_type: str   # header, cookie, parameter
    name: str
    reflected_in: str  # body, header, redirect
    reflection_context: str  # Where in response it appears
    sample_value: str


# =============================================================================
# PROBE HEADERS — headers to test if they're unkeyed
# =============================================================================

PROBE_HEADERS = [
    # Host overrides (very common in CDN setups)
    ("X-Forwarded-Host", "BTRXCANARY.example.com"),
    ("X-Host", "BTRXCANARY.example.com"),
    ("X-Forwarded-Server", "BTRXCANARY.example.com"),
    ("X-Original-URL", "/BTRXCANARY"),
    ("X-Rewrite-URL", "/BTRXCANARY"),

    # Protocol/scheme overrides
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Forwarded-Proto", "nothttps"),
    ("X-Forwarded-SSL", "off"),

    # Port manipulation
    ("X-Forwarded-Port", "1337"),

    # Path/routing overrides
    ("X-Original-URL", "/BTRXCANARY"),
    ("X-Rewrite-URL", "/BTRXCANARY"),

    # Misc headers that apps sometimes reflect
    ("X-Forwarded-For", "BTRXCANARY"),
    ("X-Real-IP", "BTRXCANARY"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("True-Client-IP", "BTRXCANARY"),
    ("Fastly-Client-IP", "BTRXCANARY"),
    ("CF-Connecting-IP", "BTRXCANARY"),

    # Misc reflected
    ("X-Custom-Header", "BTRXCANARY"),
    ("Origin", "https://BTRXCANARY.example.com"),
]

# Cache status header patterns
CACHE_INDICATORS = {
    "x-cache": {"HIT": True, "MISS": False},
    "cf-cache-status": {"HIT": True, "MISS": False, "DYNAMIC": None},
    "x-cache-status": {"HIT": True, "MISS": False},
    "x-varnish": {},  # Just presence = Varnish
    "x-proxy-cache": {"HIT": True, "MISS": False},
    "x-rack-cache": {"hit": True, "miss": False},
    "x-drupal-cache": {"HIT": True},
    "x-cache-hits": {},  # Numeric
    "age": {},  # Seconds since cached
    "via": {},  # Proxy chain
    "x-served-by": {},  # CDN node name
    "x-fastly-request-id": {},  # Fastly
    "x-amz-cf-id": {},  # CloudFront
    "x-cdn": {},  # Generic CDN header
    "x-edge-location": {},  # Edge location
    "akamai-cache-status": {"Hit": True, "Miss": False},
}


# =============================================================================
# SCANNER
# =============================================================================

class CachePoisoningScanner(BaseScanner):
    """
    Web Cache Poisoning Scanner.

    Systematic approach:
    1. Fingerprint cache behavior (CDN type, cache key composition)
    2. Enumerate unkeyed inputs (headers, cookies, params)
    3. Test payload reflection via unkeyed inputs
    4. Verify cacheability of poisoned responses
    5. Test cache deception scenarios
    """

    name = "cache_poisoning"
    description = "Web Cache Poisoning Scanner"
    version = "1.0.0"

    checks = [
        "cache_fingerprint",
        "unkeyed_header",
        "unkeyed_cookie",
        "fat_get",
        "parameter_cloaking",
        "cache_deception",
        "host_header_poison",
    ]

    owasp_category = "A05:2021"
    mitre_technique = "T1190"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.safe_mode = self.config.get("safe_mode", True)
        # IMPORTANT: use SEPARATE canaries for probe values vs cache busters
        # to avoid false positives from SSR URL echo (e.g., current_url in JSON state)
        self.canary = "BTRX" + "".join(random.choices(string.ascii_lowercase, k=8))
        self._cb_prefix = "cb" + "".join(random.choices(string.ascii_lowercase, k=6))
        self.cache_buster_counter = 0

    def _cache_buster(self) -> str:
        """Generate a unique cache-busting param to get clean MISS"""
        self.cache_buster_counter += 1
        return f"btrxcb={self._cb_prefix}{self.cache_buster_counter}"

    def _add_cache_buster(self, url: str) -> str:
        """Add cache buster to URL"""
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{self._cache_buster()}"

    # =========================================================================
    # CACHE FINGERPRINTING
    # =========================================================================

    async def _fingerprint_cache(self, context: ScanContext) -> CacheFingerprint:
        """Identify cache technology and behavior"""
        fp = CacheFingerprint()

        # Send two identical requests — second should be cached
        try:
            url = self._add_cache_buster(context.url)
            resp1 = await self.get(url)
            await asyncio.sleep(0.5)
            resp2 = await self.get(url)
        except Exception:
            return fp

        for resp in [resp1, resp2]:
            for header, values in CACHE_INDICATORS.items():
                val = resp.headers.get(header, "").strip()
                if val:
                    fp.has_cache = True
                    fp.cache_headers[header] = val

                    # Identify CDN
                    if header == "x-fastly-request-id" or "fastly" in val.lower():
                        fp.cache_type = "Fastly"
                    elif header == "x-amz-cf-id" or "cloudfront" in val.lower():
                        fp.cache_type = "CloudFront"
                    elif header == "cf-cache-status":
                        fp.cache_type = "Cloudflare"
                    elif "varnish" in val.lower() or header == "x-varnish":
                        fp.cache_type = "Varnish"
                    elif "akamai" in header.lower():
                        fp.cache_type = "Akamai"

                    # Parse age
                    if header == "age":
                        try:
                            fp.ttl = int(val)
                        except ValueError:
                            pass

        # Check Vary header (tells us what's in cache key)
        vary = resp2.headers.get("vary", "")
        if vary:
            fp.varies_on = [v.strip() for v in vary.split(",")]

        # Determine cache hit indicator
        r2_xcache = resp2.headers.get("x-cache", "").upper()
        r2_cf = resp2.headers.get("cf-cache-status", "").upper()
        if "HIT" in r2_xcache:
            fp.cache_hit_indicator = "x-cache: HIT"
        elif "HIT" in r2_cf:
            fp.cache_hit_indicator = "cf-cache-status: HIT"
        elif resp2.headers.get("age", "0") != "0":
            fp.cache_hit_indicator = f"age: {resp2.headers.get('age')}"

        return fp

    # =========================================================================
    # UNKEYED INPUT DETECTION
    # =========================================================================

    async def _find_unkeyed_headers(
        self, context: ScanContext, cache_fp: CacheFingerprint
    ) -> List[UnkeyedInput]:
        """Find headers that affect response content but aren't in cache key"""
        unkeyed = []

        # Get a baseline response (no extra headers) to compare against.
        # This prevents false positives from SSR JSON echoing the URL
        # (e.g., current_url field containing query params).
        try:
            baseline_url = self._add_cache_buster(context.url)
            baseline_resp = await self.get(baseline_url)
            baseline_body = baseline_resp.text
        except Exception:
            baseline_body = ""

        for header_name, header_value in PROBE_HEADERS:
            # Skip if header is in Vary (means it IS keyed)
            if header_name.lower() in [v.lower() for v in cache_fp.varies_on]:
                continue

            probe_value = header_value.replace("BTRXCANARY", self.canary)

            try:
                # Use cache buster so we get a fresh response
                url = self._add_cache_buster(context.url)
                resp = await self.get(
                    url,
                    headers={header_name: probe_value},
                )

                body = resp.text

                # Check if canary is reflected IN A WAY THAT ISN'T URL ECHO.
                # The canary must appear in the response body but NOT in the
                # baseline (which has no injected headers). If the canary also
                # appears in the baseline, it's just URL echo of the cachebuster
                # or coincidental match.
                if self.canary in body and self.canary not in baseline_body:
                    # Find reflection context (exclude URL-echo contexts)
                    idx = body.find(self.canary)
                    context_str = body[max(0, idx - 80):idx + len(self.canary) + 80]

                    # Extra guard: skip if canary only appears inside a URL/href context
                    if not self._is_url_echo(context_str, self.canary):
                        unkeyed.append(UnkeyedInput(
                            input_type="header",
                            name=header_name,
                            reflected_in="body",
                            reflection_context=context_str,
                            sample_value=probe_value,
                        ))
                        continue

                # Check if reflected in response headers
                for rh_name, rh_val in resp.headers.items():
                    if self.canary in rh_val:
                        unkeyed.append(UnkeyedInput(
                            input_type="header",
                            name=header_name,
                            reflected_in="header",
                            reflection_context=f"{rh_name}: {rh_val}",
                            sample_value=probe_value,
                        ))
                        break

                # Check for redirect containing canary
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if self.canary in location:
                        unkeyed.append(UnkeyedInput(
                            input_type="header",
                            name=header_name,
                            reflected_in="redirect",
                            reflection_context=f"Location: {location}",
                            sample_value=probe_value,
                        ))

            except Exception:
                continue

        return unkeyed

    def _is_url_echo(self, context_str: str, canary: str) -> bool:
        """Check if the canary only appears inside a URL/href echo context.

        Many SPAs echo the current URL in SSR JSON state (e.g. current_url field).
        If the canary only appears as part of a URL string, it's not a real reflection.
        """
        # Common URL-echo JSON patterns
        url_echo_patterns = [
            r'"current_url"\s*:\s*"[^"]*' + re.escape(canary),
            r'"url"\s*:\s*"[^"]*' + re.escape(canary),
            r'"canonical_url"\s*:\s*"[^"]*' + re.escape(canary),
            r'"request_url"\s*:\s*"[^"]*' + re.escape(canary),
            r'"page_url"\s*:\s*"[^"]*' + re.escape(canary),
            r'href="[^"]*' + re.escape(canary),
            r'action="[^"]*' + re.escape(canary),
            r'btrxcb=' + re.escape(canary),  # Cache buster param echo
        ]
        for pat in url_echo_patterns:
            if re.search(pat, context_str, re.IGNORECASE):
                return True
        return False

    async def _find_unkeyed_cookies(self, context: ScanContext) -> List[UnkeyedInput]:
        """Test if cookie values are reflected but not keyed"""
        unkeyed = []

        probe_cookies = [
            "lang", "locale", "country", "currency", "theme",
            "tracking", "utm_source", "ab_test", "variant",
            "session_pref", "display", "view",
        ]

        # Get baseline response WITHOUT cookie injection for comparison
        try:
            baseline_url = self._add_cache_buster(context.url)
            baseline_resp = await self.get(baseline_url)
            baseline_body = baseline_resp.text
        except Exception:
            baseline_body = ""

        for cookie_name in probe_cookies:
            try:
                url = self._add_cache_buster(context.url)
                resp = await self.get(
                    url,
                    headers={"Cookie": f"{cookie_name}={self.canary}"},
                )

                # Canary must appear in response AND NOT in baseline
                # (baseline check prevents false positives from URL echo)
                if self.canary in resp.text and self.canary not in baseline_body:
                    idx = resp.text.find(self.canary)
                    ctx = resp.text[max(0, idx - 80):idx + len(self.canary) + 80]

                    # Extra guard: skip URL-echo contexts
                    if not self._is_url_echo(ctx, self.canary):
                        unkeyed.append(UnkeyedInput(
                            input_type="cookie",
                            name=cookie_name,
                            reflected_in="body",
                            reflection_context=ctx,
                            sample_value=f"{cookie_name}={self.canary}",
                        ))
            except Exception:
                continue

        return unkeyed

    # =========================================================================
    # ATTACK TECHNIQUES
    # =========================================================================

    async def _test_fat_get(self, context: ScanContext) -> Optional[UnkeyedInput]:
        """Test if server processes GET request body (Fat GET)"""
        # Use a unique canary NOT shared with the cache buster
        fat_canary = "FATGET" + "".join(random.choices(string.ascii_lowercase, k=8))
        try:
            url = self._add_cache_buster(context.url)

            # Get baseline (normal GET without body)
            baseline = await self.get(url)
            baseline_body = baseline.text

            # Now send GET with body
            url2 = self._add_cache_buster(context.url)
            resp = await self.request(
                "GET", url2,
                content=f'{{"test": "{fat_canary}"}}',
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            # Fat canary must be in response but NOT in baseline
            if fat_canary in resp.text and fat_canary not in baseline_body:
                return UnkeyedInput(
                    input_type="fat_get_body",
                    name="GET request body",
                    reflected_in="body",
                    reflection_context=resp.text[:300],
                    sample_value=f'test={fat_canary}',
                )

            # Also check: if response body is meaningfully different from baseline
            # (server processed the body and changed its output)
            if len(resp.text) != len(baseline_body) and abs(len(resp.text) - len(baseline_body)) > 100:
                # Content length changed significantly — might be processing body
                return UnkeyedInput(
                    input_type="fat_get_body",
                    name="GET request body",
                    reflected_in="body",
                    reflection_context=resp.text[:300],
                    sample_value=f'test={fat_canary}',
                )
        except Exception:
            pass
        return None

    async def _test_parameter_cloaking(self, context: ScanContext) -> List[UnkeyedInput]:
        """Test URL parsing discrepancies between cache and origin"""
        unkeyed = []

        # Use a unique canary for cloaking tests (not shared with cache buster)
        cloak_canary = "CLOAK" + "".join(random.choices(string.ascii_lowercase, k=8))

        # Get baseline first (normal URL, no cloaked params)
        try:
            baseline_resp = await self.get(context.url)
            baseline_body = baseline_resp.text
        except Exception:
            baseline_body = ""

        # Semicolon delimiter (some frameworks treat ; as & but CDN doesn't)
        cloaking_tests = [
            (f"{context.url}?legit=1;{cloak_canary}=injected", "semicolon_delimiter"),
            (f"{context.url}?legit=1%26{cloak_canary}=injected", "encoded_ampersand"),
        ]
        # Note: fragment_injection removed — fragments are client-side only,
        # never sent to the server, so can't cause server-side cache poisoning

        for test_url, technique in cloaking_tests:
            try:
                resp = await self.get(test_url)
                # Canary must be in response but NOT as simple URL echo
                if cloak_canary in resp.text and cloak_canary not in baseline_body:
                    # Verify it's not just the URL being echoed in SSR JSON
                    idx = resp.text.find(cloak_canary)
                    ctx = resp.text[max(0, idx - 100):idx + len(cloak_canary) + 100]
                    if not self._is_url_echo(ctx, cloak_canary):
                        unkeyed.append(UnkeyedInput(
                            input_type="parameter_cloaking",
                            name=technique,
                            reflected_in="body",
                            reflection_context=ctx,
                            sample_value=test_url,
                        ))
            except Exception:
                continue

        return unkeyed

    async def _test_cache_deception(self, context: ScanContext) -> List[str]:
        """Test cache deception — trick CDN into caching authenticated pages"""
        deceptive_extensions = []

        # Append static file extensions to dynamic URLs
        extensions = [".css", ".js", ".png", ".jpg", ".gif", ".ico", ".svg", ".woff", "/style.css", "/main.js"]

        for ext in extensions:
            try:
                test_url = context.url.rstrip("/") + ext
                resp1 = await self.get(test_url)

                # If server returns same content as original (not 404)
                if resp1.status_code == 200:
                    # Check if it gets cached
                    await asyncio.sleep(0.3)
                    resp2 = await self.get(test_url)

                    # Look for cache HIT
                    for header in ["x-cache", "cf-cache-status", "x-cache-status"]:
                        val = resp2.headers.get(header, "").upper()
                        if "HIT" in val:
                            deceptive_extensions.append(ext)
                            break

                    # Age > 0 = cached
                    age = resp2.headers.get("age", "0")
                    if age != "0":
                        deceptive_extensions.append(ext)

            except Exception:
                continue

        return deceptive_extensions

    # =========================================================================
    # MAIN SCAN
    # =========================================================================

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Full cache poisoning assessment"""

        # Step 1: Fingerprint cache
        cache_fp = await self._fingerprint_cache(context)

        if not cache_fp.has_cache:
            yield self.create_finding(
                title="No Caching Detected",
                severity=Severity.INFO,
                confidence=Confidence.TENTATIVE,
                url=context.url,
                description="No caching headers detected. Cache poisoning unlikely on this endpoint.",
                evidence="No X-Cache, CF-Cache-Status, Age, or Via headers found.",
            )
            # Still test cache deception — CDN might cache without headers

        if cache_fp.has_cache:
            yield self.create_finding(
                title=f"Cache Detected: {cache_fp.cache_type or 'Unknown CDN'}",
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                url=context.url,
                description=(
                    f"Cache type: {cache_fp.cache_type or 'Unknown'}\n"
                    f"Varies on: {', '.join(cache_fp.varies_on) or 'nothing detected'}\n"
                    f"Cache headers: {cache_fp.cache_headers}"
                ),
                evidence=str(cache_fp.cache_headers),
            )

        # Step 2: Find unkeyed headers
        unkeyed_headers = await self._find_unkeyed_headers(context, cache_fp)

        for uki in unkeyed_headers:
            severity = Severity.HIGH
            if uki.reflected_in == "redirect":
                severity = Severity.HIGH
            elif "<" in uki.reflection_context and ">" in uki.reflection_context:
                severity = Severity.CRITICAL  # Likely XSS context

            yield self.create_finding(
                title=f"Unkeyed Header Reflected: {uki.name}",
                severity=severity,
                confidence=Confidence.FIRM,
                url=context.url,
                description=(
                    f"Header '{uki.name}' is not included in the cache key but is reflected "
                    f"in the response {uki.reflected_in}.\n\n"
                    f"This allows cache poisoning: inject a malicious value via this header, "
                    f"and the poisoned response will be cached and served to all subsequent users.\n\n"
                    f"Reflection context:\n{uki.reflection_context}"
                ),
                evidence=uki.reflection_context,
                request=f"{uki.name}: {uki.sample_value}",
                remediation=(
                    f"1. Add '{uki.name}' to the Vary header (makes it part of cache key)\n"
                    f"2. Stop reflecting the '{uki.name}' header in responses\n"
                    f"3. Sanitize/validate the header value before use\n"
                    f"4. Consider excluding pages that use this header from caching"
                ),
                references=[
                    "https://portswigger.net/research/practical-web-cache-poisoning",
                ],
            )

        # Step 3: Find unkeyed cookies
        unkeyed_cookies = await self._find_unkeyed_cookies(context)

        for ukc in unkeyed_cookies:
            yield self.create_finding(
                title=f"Unkeyed Cookie Reflected: {ukc.name}",
                severity=Severity.HIGH,
                confidence=Confidence.FIRM,
                url=context.url,
                description=(
                    f"Cookie '{ukc.name}' is not keyed by the cache but is reflected in response.\n"
                    f"An attacker can set this cookie via a subdomain or XSS, then the poisoned "
                    f"response is cached for all users.\n\n"
                    f"Context: {ukc.reflection_context}"
                ),
                evidence=ukc.reflection_context,
                remediation=(
                    "1. Add 'Cookie' to the Vary header\n"
                    "2. Stop reflecting cookie values in HTML\n"
                    "3. Use CDN cookie-stripping rules for non-essential cookies"
                ),
            )

        # Step 4: Fat GET test
        fat_get = await self._test_fat_get(context)
        if fat_get:
            yield self.create_finding(
                title="Fat GET Request Body Processed",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                url=context.url,
                description=(
                    "Server processes the body of GET requests. Since CDNs typically ignore "
                    "GET bodies for cache key computation, this creates a cache poisoning vector.\n"
                    "Attacker sends GET with malicious body → response cached → all users get poisoned response."
                ),
                evidence=fat_get.reflection_context[:500],
                remediation="Do not process request body for GET requests.",
            )

        # Step 5: Parameter cloaking
        cloaked = await self._test_parameter_cloaking(context)
        for cl in cloaked:
            yield self.create_finding(
                title=f"Parameter Cloaking: {cl.name}",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                url=context.url,
                description=(
                    f"URL parsing discrepancy detected ({cl.name}). "
                    f"The cache and origin interpret the URL differently, allowing an attacker "
                    f"to inject parameters that aren't part of the cache key."
                ),
                evidence=cl.reflection_context[:500],
                remediation="Ensure cache and origin use identical URL parsing rules.",
            )

        # Step 6: Cache deception
        deceptive = await self._test_cache_deception(context)
        if deceptive:
            yield self.create_finding(
                title=f"Cache Deception Possible ({len(deceptive)} extensions)",
                severity=Severity.HIGH,
                confidence=Confidence.FIRM,
                url=context.url,
                description=(
                    "The server returns identical content when static file extensions are appended "
                    "to the URL, and the CDN caches these responses.\n\n"
                    f"Vulnerable extensions: {', '.join(deceptive)}\n\n"
                    "Attack: Trick a victim into visiting /my-account/sensitive-data.css → "
                    "CDN caches their authenticated response → attacker retrieves cached data."
                ),
                evidence=f"Cached extensions: {', '.join(deceptive)}",
                remediation=(
                    "1. Only cache responses with explicit Cache-Control headers\n"
                    "2. Don't ignore URL path suffixes — return 404 for fake extensions\n"
                    "3. Use cache rules based on Content-Type, not URL extension\n"
                    "4. Set Cache-Control: no-store on all authenticated pages"
                ),
                references=[
                    "https://portswigger.net/web-security/web-cache-deception",
                ],
            )

        async for finding in self.passive_scan(context):
            yield finding

    async def passive_scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Detect cache configuration issues from response headers"""
        if not context.response:
            return

        headers = context.response.headers if hasattr(context.response, 'headers') else {}

        # Check for missing Cache-Control on sensitive pages
        cache_control = headers.get("cache-control", "")
        if not cache_control or ("no-store" not in cache_control and "private" not in cache_control):
            # Look for signs this is a sensitive page
            body = context.response.body if hasattr(context.response, 'body') else ""
            sensitive_indicators = [
                r"(password|passwd|credit.?card|ssn|account.?number)",
                r"(logout|sign.?out|my.?account|dashboard|profile|settings)",
                r'type="password"',
                r"csrf.?token",
            ]

            for pattern in sensitive_indicators:
                if re.search(pattern, body, re.IGNORECASE):
                    yield self.create_finding(
                        title="Sensitive Page Missing Cache-Control: no-store",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.TENTATIVE,
                        url=context.url,
                        description=(
                            "This page contains sensitive content but doesn't set "
                            "Cache-Control: no-store. It may be cacheable by CDN/proxy."
                        ),
                        evidence=f"Cache-Control: {cache_control or '(not set)'}",
                        remediation="Add Cache-Control: no-store, no-cache, private to all authenticated pages.",
                    )
                    break
