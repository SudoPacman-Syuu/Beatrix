"""
BEATRIX JS Bundle Analyzer

Born from: Bykea track.bykea.net engagement (2026-02-05)
Discovered track-backend.bykea.net, betadispatch.bykea.net:3000,
geocode-beta.bykea.net, internal API routes, auth mechanism, and
localStorage keys — all from downloading and grepping JS chunks.

Technique:
1. Fetch target, find asset-manifest.json or webpack chunk references
2. Download all JS bundles
3. Extract: API endpoints, internal hostnames, auth tokens/keys,
   hardcoded secrets, localStorage/sessionStorage keys, WebSocket URLs,
   environment variables, debug flags

This is PASSIVE RECON — no interaction with APIs, just reading publicly
served JavaScript that the browser would download anyway.

OWASP: A05:2021 Security Misconfiguration (secrets in client JS)
CWE: CWE-540 (Inclusion of Sensitive Information in Source Code)
"""

import json
import re
from dataclasses import dataclass, field
from typing import AsyncIterator, List, Set, Tuple
from urllib.parse import urljoin

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext


@dataclass
class BundleIntel:
    """Intelligence extracted from a single JS bundle"""
    source_url: str
    api_endpoints: List[str] = field(default_factory=list)
    internal_hosts: List[str] = field(default_factory=list)
    auth_patterns: List[str] = field(default_factory=list)
    storage_keys: List[str] = field(default_factory=list)
    websocket_urls: List[str] = field(default_factory=list)
    potential_secrets: List[Tuple[str, str]] = field(default_factory=list)  # (key, value)
    env_vars: List[str] = field(default_factory=list)
    debug_flags: List[str] = field(default_factory=list)
    interesting_strings: List[str] = field(default_factory=list)


class JSBundleAnalyzer(BaseScanner):
    """
    Downloads and analyzes JavaScript bundles for information disclosure.

    Battle-tested: This exact technique discovered 4 new backend hosts
    and the full API structure on Bykea from a geo-locked React app.
    """

    name = "js_bundle"
    description = "JavaScript bundle analyzer — extracts API routes, secrets, and internal hosts"
    version = "1.0.0"

    owasp_category = "A05:2021"

    # =========================================================================
    # MANIFEST DISCOVERY
    # =========================================================================

    MANIFEST_PATHS = [
        "/asset-manifest.json",
        "/manifest.json",
        "/build/asset-manifest.json",
        "/static/asset-manifest.json",
        "/_next/static/chunks/",
        "/webpack-manifest.json",
        # Next.js specific
        "/_next/buildManifest.js",
        "/_next/static/buildManifest.js",
    ]

    # Patterns to find JS bundle references in HTML
    JS_SRC_PATTERN = re.compile(
        r'<script[^>]+src=["\']([^"\']+\.(?:js|mjs)(?:\?[^"\']*)?)["\']',
        re.IGNORECASE
    )

    # Pattern to find chunk references in webpack runtime
    CHUNK_PATTERN = re.compile(
        r'["\'](?:static/js/|chunks/|js/)([^"\']+\.(?:chunk\.)?js)["\']'
    )

    # =========================================================================
    # EXTRACTION PATTERNS
    # =========================================================================

    # API endpoint patterns (what we're really after)
    API_PATTERNS = [
        re.compile(r'["\'](/(?:api|v[0-9]+)/[a-zA-Z0-9/_\-{}:]+)["\']'),
        re.compile(r'["\'](?:https?://[^"\']+)(/[a-zA-Z0-9/_\-{}:]+)["\']'),
        re.compile(r'fetch\(["\']([^"\']+)["\']'),
        re.compile(r'axios\.\w+\(["\']([^"\']+)["\']'),
        re.compile(r'\.(?:get|post|put|patch|delete)\(["\']([^"\']+)["\']'),
    ]

    # Internal hostname patterns (generic — no hardcoded target domains)
    HOST_PATTERNS = [
        # Internal/dev/staging subdomains — require at least one more TLD segment after
        # the indicator word, so "staging.example.com" matches but "react.dev" does not.
        # The negative lookahead excludes known public TLDs used as primary domains.
        re.compile(r'https?://([a-zA-Z0-9][\w\-]*\.(?:internal|local|corp|staging|beta|test|preprod|sandbox|uat|qa|int)\.[a-zA-Z]{2,}[^\s"\'\\]*)'),
        # .dev subdomains: only match when .dev is a subdomain indicator (has further TLD),
        # NOT when .dev IS the TLD (e.g., react.dev, web.dev are public sites).
        re.compile(r'https?://([a-zA-Z0-9][\w\-]*\.dev\.[a-zA-Z]{2,}[^\s"\'\\]*)'),
        # Private IPs
        re.compile(r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?)'),
        # WebSocket URLs
        re.compile(r'wss?://([^\s"\'\\]+)'),
        # Non-standard ports on any domain (port != 80, 443)
        re.compile(r'https?://([a-zA-Z0-9][\w\-.]+:\d{3,5})[/"\'\s]'),
    ]

    # Public TLDs that look like internal indicators — never flag these as "internal"
    PUBLIC_TLDS = {'.dev', '.app', '.io', '.ai', '.co', '.me', '.sh', '.run', '.build', '.cloud'}

    # Auth/token patterns
    AUTH_PATTERNS = [
        re.compile(r'["\'](?:Authorization|Bearer|Token|API[_-]?KEY|api[_-]?key|apiKey|secret|SECRET)["\']'),
        re.compile(r'localStorage\.(?:getItem|setItem)\(["\']([^"\']+)["\']'),
        re.compile(r'sessionStorage\.(?:getItem|setItem)\(["\']([^"\']+)["\']'),
        re.compile(r'["\']x-api-key["\']\s*:\s*["\']([^"\']+)["\']'),
    ]

    # Potential secrets (high-entropy strings, API keys)
    SECRET_PATTERNS = [
        # AWS
        (re.compile(r'AKIA[0-9A-Z]{16}'), "aws_access_key"),
        # Google
        (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "google_api_key"),
        # Mapbox
        (re.compile(r'pk\.[a-zA-Z0-9]{60,}'), "mapbox_public_key"),
        (re.compile(r'sk\.[a-zA-Z0-9]{60,}'), "mapbox_secret_key"),
        # Stripe
        (re.compile(r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}'), "stripe_key"),
        # Firebase
        (re.compile(r'["\']AIza[0-9A-Za-z\-_]{35}["\']'), "firebase_key"),
        # GitHub
        (re.compile(r'gh[ps]_[A-Za-z0-9_]{36,}'), "github_token"),
        # Slack
        (re.compile(r'xox[bpors]-[0-9]{10,}-[0-9a-zA-Z]{10,}'), "slack_token"),
        # JWT tokens
        (re.compile(r'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'), "jwt_token"),
        # Generic: key=value assignments where key contains 'secret', 'key', 'token', 'password'
        (re.compile(r'["\'](?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|password|private[_-]?key)["\']\s*[:=]\s*["\']([A-Za-z0-9+/=_\-]{20,})["\']', re.IGNORECASE), "hardcoded_credential"),
        # Generic hex secrets (40+ chars) — note: pure lowercase hex is filtered
        # by _is_likely_false_positive as build hashes; this catches mixed-case hex
        (re.compile(r'["\']([0-9a-f]{40,64})["\']'), "hex_secret"),
    ]

    # Environment variable references
    ENV_PATTERNS = [
        re.compile(r'process\.env\.([A-Z_][A-Z0-9_]+)'),
        re.compile(r'REACT_APP_([A-Z0-9_]+)'),
        re.compile(r'NEXT_PUBLIC_([A-Z0-9_]+)'),
        re.compile(r'VUE_APP_([A-Z0-9_]+)'),
    ]

    # Debug/dev flags
    DEBUG_PATTERNS = [
        re.compile(r'["\'](?:debug|DEBUG|verbose|VERBOSE)["\']:\s*(?:true|1|["\']true["\'])'),
        re.compile(r'(?:isDebug|debugMode|isDev|devMode)\s*[=:]\s*true'),
        re.compile(r'console\.\w+\(["\'](?:DEBUG|TRACE|INTERNAL)'),
    ]

    async def __aenter__(self):
        """Override to follow redirects — we need the actual HTML page, not 301s"""
        import httpx
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,   # JS discovery NEEDS to follow redirects
            verify=False,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        return self

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Discover and analyze JS bundles from the target.

        Can receive pre-crawled JS URLs via context.extra['js_files']
        from the crawler, or discover them independently.
        """
        base = context.base_url
        self.log(f"JS bundle analysis on {base}")

        # Use pre-crawled JS URLs if available (from crawler)
        pre_crawled_js = []
        if hasattr(context, 'extra') and context.extra:
            pre_crawled_js = list(context.extra.get('js_files', []))

        # Also discover bundles independently
        bundle_urls = await self._discover_bundles(base)

        # Merge pre-crawled and discovered
        all_urls = set(bundle_urls)
        all_urls.update(pre_crawled_js)
        bundle_urls = list(all_urls)

        if not bundle_urls:
            self.log("No JS bundles discovered")
            return

        self.log(f"Found {len(bundle_urls)} JS bundles")

        # Step 2: Download and analyze each bundle
        all_intel = BundleIntel(source_url=base)

        for url in bundle_urls:
            try:
                response = await self.get(url)
                if response.status_code == 200:
                    intel = self._analyze_bundle(url, response.text)
                    self._merge_intel(all_intel, intel)
            except Exception as e:
                self.log(f"Failed to fetch {url}: {e}")
                continue

        # Step 3: Generate findings from extracted intelligence
        async for finding in self._generate_findings(base, all_intel, len(bundle_urls)):
            yield finding

    async def _discover_bundles(self, base_url: str) -> List[str]:
        """Find all JS bundle URLs via manifests and HTML parsing"""
        urls: Set[str] = set()

        # Try asset-manifest.json first (React/CRA apps — how we cracked Bykea)
        for manifest_path in self.MANIFEST_PATHS:
            try:
                resp = await self.get(urljoin(base_url, manifest_path))
                if resp.status_code == 200 and "application/json" in resp.headers.get("content-type", ""):
                    manifest = resp.json()
                    # CRA format: {"files": {"main.js": "/static/js/main.xyz.js"}}
                    if "files" in manifest:
                        for key, path in manifest["files"].items():
                            if path.endswith(".js"):
                                urls.add(urljoin(base_url, path))
                    # Alternative format: {"entrypoints": ["static/js/..."]}
                    if "entrypoints" in manifest:
                        for path in manifest["entrypoints"]:
                            if path.endswith(".js"):
                                urls.add(urljoin(base_url, path))
            except Exception:
                continue

        # Parse HTML for script tags
        try:
            resp = await self.get(base_url)
            if resp.status_code == 200:
                for match in self.JS_SRC_PATTERN.finditer(resp.text):
                    src = match.group(1)
                    if not src.startswith("http"):
                        src = urljoin(base_url, src)
                    urls.add(src)

                # Find chunk references in inline scripts
                for match in self.CHUNK_PATTERN.finditer(resp.text):
                    chunk = match.group(1)
                    urls.add(urljoin(base_url, f"/static/js/{chunk}"))

                # Extract __NEXT_DATA__ (Next.js apps — props, build ID, etc.)
                next_data_match = re.search(
                    r'<script\s+id="__NEXT_DATA__"[^>]*>(.*?)</script>',
                    resp.text, re.DOTALL
                )
                if next_data_match:
                    try:
                        next_data = json.loads(next_data_match.group(1))
                        build_id = next_data.get('buildId', '')
                        if build_id:
                            # Discover Next.js _buildManifest and _ssgManifest
                            urls.add(urljoin(base_url, f"/_next/static/{build_id}/_buildManifest.js"))
                            urls.add(urljoin(base_url, f"/_next/static/{build_id}/_ssgManifest.js"))
                        # Store __NEXT_DATA__ content for analysis
                        self._next_data = next_data
                    except (json.JSONDecodeError, AttributeError):
                        pass
        except Exception:
            pass

        # Try to discover source maps for each JS file
        source_map_urls = set()
        for js_url in list(urls):
            map_url = js_url + '.map'
            source_map_urls.add(map_url)

        # Check source maps in a quick batch (HEAD requests)
        for map_url in source_map_urls:
            try:
                resp = await self.request("HEAD", map_url)
                if resp.status_code == 200:
                    urls.add(map_url)
                    self.log(f"Source map found: {map_url}")
            except Exception:
                continue

        return list(urls)

    def _analyze_bundle(self, url: str, code: str) -> BundleIntel:
        """Extract intelligence from a single JS bundle or source map"""
        intel = BundleIntel(source_url=url)

        # If this is a source map, extract original source filenames
        if url.endswith('.map'):
            try:
                map_data = json.loads(code)
                sources = map_data.get('sources', [])
                intel.interesting_strings.extend([
                    f"[SOURCE MAP] {s}" for s in sources
                    if not s.startswith('webpack://') or 'node_modules' not in s
                ])
                # Analyze the sourcesContent if present (full original source!)
                for content in map_data.get('sourcesContent', []):
                    if content:
                        sub_intel = self._analyze_bundle(url + '#content', content)
                        self._merge_intel(intel, sub_intel)
                return intel
            except (json.JSONDecodeError, AttributeError):
                pass  # Not valid JSON, analyze as regular code

        # API endpoints
        for pattern in self.API_PATTERNS:
            for match in pattern.finditer(code):
                endpoint = match.group(1)
                if len(endpoint) > 3 and not endpoint.endswith(('.js', '.css', '.png', '.svg', '.ico')):
                    intel.api_endpoints.append(endpoint)

        # Internal hosts
        for pattern in self.HOST_PATTERNS:
            for match in pattern.finditer(code):
                host = match.group(1)
                if any(skip in host for skip in ['googleapis.com', 'gstatic.com', 'fonts.', 'cdn.']):
                    continue
                # Skip hosts that are just public TLD domains (e.g. react.dev, web.dev)
                parsed_host = host.split('/')[0].split(':')[0]  # strip path and port
                parts = parsed_host.rsplit('.', 1)
                if len(parts) == 2 and f'.{parts[1]}' in self.PUBLIC_TLDS:
                    # This is something like "react.dev" — a public domain, not internal
                    # Only skip if there's no further subdomain (i.e., only 2 parts)
                    domain_parts = parsed_host.split('.')
                    if len(domain_parts) <= 2:
                        continue
                intel.internal_hosts.append(host)

        # Auth patterns + storage keys
        for pattern in self.AUTH_PATTERNS:
            for match in pattern.finditer(code):
                value = match.group(1) if match.lastindex else match.group(0)
                if 'localStorage' in match.group(0) or 'sessionStorage' in match.group(0):
                    intel.storage_keys.append(value)
                else:
                    intel.auth_patterns.append(value)

        # Potential secrets
        for pattern, secret_type in self.SECRET_PATTERNS:
            for match in pattern.finditer(code):
                value = match.group(1) if match.lastindex else match.group(0)
                # Filter out common false positives (hashes in filenames, etc.)
                if not self._is_likely_false_positive(value):
                    intel.potential_secrets.append((secret_type, value))

        # Env vars
        for pattern in self.ENV_PATTERNS:
            for match in pattern.finditer(code):
                intel.env_vars.append(match.group(1))

        # Debug flags
        for pattern in self.DEBUG_PATTERNS:
            for match in pattern.finditer(code):
                intel.debug_flags.append(match.group(0)[:100])

        # WebSocket URLs
        ws_pattern = re.compile(r'wss?://[^\s"\'\\]+')
        for match in ws_pattern.finditer(code):
            intel.websocket_urls.append(match.group(0))

        return intel

    def _merge_intel(self, target: BundleIntel, source: BundleIntel) -> None:
        """Merge intelligence from one bundle into the aggregate"""
        target.api_endpoints.extend(source.api_endpoints)
        target.internal_hosts.extend(source.internal_hosts)
        target.auth_patterns.extend(source.auth_patterns)
        target.storage_keys.extend(source.storage_keys)
        target.websocket_urls.extend(source.websocket_urls)
        target.potential_secrets.extend(source.potential_secrets)
        target.env_vars.extend(source.env_vars)
        target.debug_flags.extend(source.debug_flags)

    async def _generate_findings(
        self, base_url: str, intel: BundleIntel, bundle_count: int
    ) -> AsyncIterator[Finding]:
        """Convert extracted intel into actionable findings"""

        # Dedup everything
        unique_endpoints = sorted(set(intel.api_endpoints))
        unique_hosts = sorted(set(intel.internal_hosts))
        unique_secrets = list({v: k for k, v in intel.potential_secrets}.items())
        unique_storage = sorted(set(intel.storage_keys))
        unique_ws = sorted(set(intel.websocket_urls))
        unique_env = sorted(set(intel.env_vars))

        # --- Internal hosts discovered ---
        if unique_hosts:
            yield self.create_finding(
                title=f"Internal Hostnames Disclosed in JS Bundles ({len(unique_hosts)} hosts)",
                severity=Severity.LOW,
                confidence=Confidence.CERTAIN,
                url=base_url,
                description=(
                    f"Analysis of {bundle_count} JavaScript bundles revealed "
                    f"{len(unique_hosts)} internal/backend hostnames:\n\n"
                    + "\n".join(f"- `{h}`" for h in unique_hosts[:20])
                ),
                evidence=json.dumps(unique_hosts[:20], indent=2),
                remediation=(
                    "Remove internal hostnames from client-side JavaScript. "
                    "Use a reverse proxy or API gateway to abstract backend services."
                ),
                references=["https://cwe.mitre.org/data/definitions/540.html"],
            )

        # --- API endpoints discovered ---
        if unique_endpoints:
            yield self.create_finding(
                title=f"API Routes Disclosed in JS Bundles ({len(unique_endpoints)} endpoints)",
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                url=base_url,
                description=(
                    f"JavaScript bundle analysis extracted {len(unique_endpoints)} "
                    f"API endpoints. These can be probed for IDOR, auth bypass, "
                    f"and injection vulnerabilities:\n\n"
                    + "\n".join(f"- `{e}`" for e in unique_endpoints[:30])
                    + (f"\n\n... and {len(unique_endpoints) - 30} more" if len(unique_endpoints) > 30 else "")
                ),
                # Store ALL endpoints — kill chain extracts these for downstream scanners
                evidence=json.dumps(unique_endpoints),
                remediation="This is expected behavior for SPAs but review endpoints for sensitive operations.",
            )

        # --- Hardcoded secrets ---
        # Limit to 10 max per type to avoid noise
        seen_types = {}
        for value, secret_type in unique_secrets:
            seen_types[secret_type] = seen_types.get(secret_type, 0) + 1
            if seen_types[secret_type] > 5:
                continue  # Skip excessive findings of same type

            # High-confidence: known provider patterns (AWS, Google, Stripe, etc.)
            # Low-confidence: generic hex strings (could be content hashes)
            if secret_type in ("aws_access_key", "mapbox_secret_key", "stripe_key",
                               "github_token", "slack_token", "jwt_token"):
                severity = Severity.HIGH
            elif secret_type == "hardcoded_credential":
                severity = Severity.HIGH
            elif secret_type == "hex_secret":
                severity = Severity.LOW
            else:
                severity = Severity.MEDIUM

            yield self.create_finding(
                title=f"Potential Hardcoded Secret in JS: {secret_type}",
                severity=severity,
                confidence=Confidence.TENTATIVE,
                url=base_url,
                description=(
                    f"A potential {secret_type.replace('_', ' ')} was found in "
                    f"client-side JavaScript: `{value[:20]}...`"
                ),
                evidence=f"Type: {secret_type}\nValue: {value[:40]}{'...' if len(value) > 40 else ''}",
                remediation=(
                    "Never hardcode secrets in client-side JavaScript. "
                    "Rotate this credential immediately if valid."
                ),
                references=["https://cwe.mitre.org/data/definitions/798.html"],
            )

        # --- localStorage/sessionStorage keys ---
        if unique_storage:
            # Auth-related storage keys are more interesting
            auth_keys = [k for k in unique_storage if any(
                w in k.lower() for w in ('token', 'auth', 'session', 'user', 'jwt', 'bearer', 'key')
            )]
            if auth_keys:
                yield self.create_finding(
                    title=f"Auth-Related Storage Keys in JS ({len(auth_keys)} keys)",
                    severity=Severity.LOW,
                    confidence=Confidence.FIRM,
                    url=base_url,
                    description=(
                        "JavaScript bundles reference authentication-related "
                        "localStorage/sessionStorage keys:\n\n"
                        + "\n".join(f"- `{k}`" for k in auth_keys)
                        + "\n\nThese reveal the authentication mechanism and "
                        "can aid in session hijacking attacks."
                    ),
                    evidence=json.dumps(auth_keys, indent=2),
                    remediation="Use httpOnly cookies instead of localStorage for auth tokens.",
                )

        # --- WebSocket URLs ---
        if unique_ws:
            yield self.create_finding(
                title=f"WebSocket Endpoints Disclosed ({len(unique_ws)} URLs)",
                severity=Severity.LOW,
                confidence=Confidence.CERTAIN,
                url=base_url,
                description=(
                    "WebSocket endpoints found in JS bundles:\n\n"
                    + "\n".join(f"- `{ws}`" for ws in unique_ws[:10])
                ),
                evidence=json.dumps(unique_ws[:10], indent=2),
                remediation="Ensure WebSocket endpoints require authentication and validate origin.",
            )

        # --- Debug flags ---
        if intel.debug_flags:
            yield self.create_finding(
                title="Debug/Dev Flags Enabled in Production JS",
                severity=Severity.LOW,
                confidence=Confidence.FIRM,
                url=base_url,
                description=(
                    "Debug or development flags found active in production JavaScript:\n\n"
                    + "\n".join(f"- `{f}`" for f in set(intel.debug_flags)[:10])
                ),
                evidence="\n".join(set(intel.debug_flags)[:10]),
                remediation="Ensure all debug flags are disabled in production builds.",
            )

        # --- Source map files found ---
        source_map_files = [s for s in intel.interesting_strings if s.startswith('[SOURCE MAP]')]
        if source_map_files:
            yield self.create_finding(
                title="JavaScript Source Maps Publicly Accessible",
                severity=Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                url=base_url,
                description=(
                    "Source map files (.js.map) are publicly accessible, exposing "
                    "the full original source code including comments, internal "
                    "variable names, and file structure:\n\n"
                    + "\n".join(f"- {s.replace('[SOURCE MAP] ', '')}" for s in source_map_files[:20])
                ),
                evidence=json.dumps(source_map_files[:20], indent=2),
                remediation=(
                    "Remove source map files from production deployment. "
                    "Configure your build tool to not generate source maps for production, "
                    "or restrict access to .map files via server configuration."
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/540.html",
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
                ],
            )

        # --- __NEXT_DATA__ exposure ---
        if hasattr(self, '_next_data') and self._next_data:
            next_data = self._next_data
            # Check for sensitive data in __NEXT_DATA__ props
            props_str = json.dumps(next_data.get('props', {})).lower()
            sensitive_found = []
            for keyword in ['token', 'secret', 'password', 'api_key', 'apikey',
                           'private', 'internal', 'admin', 'credential']:
                if keyword in props_str:
                    sensitive_found.append(keyword)

            if sensitive_found:
                yield self.create_finding(
                    title="Sensitive Data in Next.js __NEXT_DATA__",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    url=base_url,
                    description=(
                        f"The Next.js `__NEXT_DATA__` script tag contains potentially "
                        f"sensitive server-side props exposed to the client:\n\n"
                        f"Sensitive keywords found: {', '.join(sensitive_found)}\n\n"
                        f"Build ID: {next_data.get('buildId', 'unknown')}\n"
                        f"Data size: {len(json.dumps(next_data))} bytes"
                    ),
                    evidence=json.dumps(next_data.get('props', {}))[:1000],
                    remediation=(
                        "Review getServerSideProps/getStaticProps to ensure no "
                        "internal data is passed to the client. Use server-only "
                        "data fetching for sensitive information."
                    ),
                )

    @staticmethod
    def _is_likely_false_positive(value: str) -> bool:
        """Filter out common false positives for secret detection"""
        import math

        # Too short or too long
        if len(value) < 20 or len(value) > 200:
            return True
        # All same character
        if len(set(value)) < 5:
            return True
        # Looks like a hash in a filename
        if any(ext in value for ext in ['.chunk', '.js', '.css', '.map', '.png', '.svg', '.jpg']):
            return True
        # Common webpack/build hashes (pure hex of any length)
        # SHA-1 (40), SHA-256 (64), and shorter chunk hashes are all build artifacts
        # Real secrets are almost never pure lowercase hex — they use mixed case,
        # special chars, or known provider prefixes (which are caught earlier)
        if re.match(r'^[0-9a-f]+$', value):
            return True

        # ── NEW: Strong camelCase / JS identifier detection ──────────
        # camelCase or PascalCase strings are identifiers, not secrets.
        # Count uppercase transitions: "FormattedDescriptionAnnotationLinks"
        # has many capital letters mid-string = definitely an identifier
        upper_count = sum(1 for c in value if c.isupper())
        if upper_count >= 3 and value[0].isupper():
            return True  # PascalCase identifier
        if upper_count >= 2 and value[0].islower():
            return True  # camelCase identifier

        # Pure alphabetic with mixed case = identifier, not a secret
        if value.isalpha() and any(c.isupper() for c in value) and any(c.islower() for c in value):
            return True

        # Contains common JS keywords = identifier
        js_keywords = [
            'function', 'return', 'module', 'export', 'import', 'class',
            'Component', 'Handler', 'Provider', 'Wrapper', 'Context',
            'Container', 'Controller', 'Manager', 'Factory', 'Builder',
            'Request', 'Response', 'Listener', 'Observer', 'Adapter',
            'Experience', 'Analytics', 'Tracking', 'Feature', 'Config',
            'Settings', 'Options', 'Params', 'Props', 'State',
            'Modal', 'Button', 'Form', 'Input', 'Header', 'Footer',
            'Navigation', 'Menu', 'List', 'Grid', 'Card', 'Board',
            'Search', 'Filter', 'Sort', 'Page', 'View', 'Layout',
        ]
        for kw in js_keywords:
            if kw in value:
                return True

        # ── Entropy check ────────────────────────────────────────────
        # Real secrets have high Shannon entropy. Identifiers don't.
        charset = set(value)
        if len(value) > 0 and charset:
            entropy = -sum(
                (value.count(c) / len(value)) * math.log2(value.count(c) / len(value))
                for c in charset
            )
            # Real API keys/secrets typically have entropy > 3.5
            # camelCase identifiers typically have entropy 2.5-3.5
            if entropy < 3.5:
                return True

        return False
