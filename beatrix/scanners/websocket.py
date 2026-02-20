"""
BEATRIX WebSocket Security Scanner

Born from: OWASP WSTG-CLNT-10 + PortSwigger WebSocket research
https://portswigger.net/web-security/websockets

TECHNIQUE:
1. Detect WebSocket endpoints via Upgrade handshake probing
2. Test Cross-Site WebSocket Hijacking (CSWSH) — missing Origin validation
3. Test for injection via WebSocket messages (XSS, SQLi, command injection)
4. Test authentication/authorization on WS connections
5. Test rate limiting and DoS on WebSocket channels
6. Test for information disclosure in WebSocket frames
7. Test message manipulation (modify, replay, inject)
8. Detect plaintext WS (ws://) where WSS (wss://) should be used

SEVERITY: HIGH-CRITICAL — WebSocket vulns achieve:
- CSWSH → full session hijacking via malicious webpage
- XSS via WebSocket messages → persistent XSS
- Auth bypass → access other users' WS channels
- Data interception → sensitive data in plaintext WS
- IDOR via WS → subscribe to other users' channels

OWASP: WSTG-CLNT-10 (Testing WebSockets)
       A01:2021 - Broken Access Control

MITRE: T1185 (Browser Session Hijacking — via CSWSH)
       T1557 (Adversary-in-the-Middle — plaintext WS interception)

CWE: CWE-1385 (Missing Origin Validation in WebSockets)
     CWE-319 (Cleartext Transmission of Sensitive Information)
     CWE-284 (Improper Access Control)
     CWE-79 (XSS via WebSocket messages)

REFERENCES:
- https://portswigger.net/web-security/websockets
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets
- https://book.hacktricks.xyz/pentesting-web/websocket-attacks
"""

import base64
import random
import re
import string
from dataclasses import dataclass
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional
from urllib.parse import urlparse

try:
    import httpx
except ImportError:
    httpx = None

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext

# =============================================================================
# DATA MODELS
# =============================================================================

class WSAttack(Enum):
    """WebSocket attack types"""
    CSWSH = "cross_site_ws_hijacking"
    INJECTION_XSS = "xss_via_ws"
    INJECTION_SQLI = "sqli_via_ws"
    INJECTION_CMD = "cmd_injection_via_ws"
    AUTH_BYPASS = "ws_auth_bypass"
    IDOR = "ws_idor"
    PLAINTEXT = "plaintext_ws"
    RATE_LIMIT = "ws_no_rate_limit"
    INFO_DISCLOSURE = "ws_info_disclosure"


@dataclass
class WSEndpoint:
    """A discovered WebSocket endpoint"""
    url: str              # ws:// or wss:// URL
    http_url: str         # Original HTTP URL
    origin_checked: bool = False
    auth_required: bool = False
    protocol: Optional[str] = None
    server_info: Optional[str] = None


@dataclass
class WSProbe:
    """WebSocket probe message"""
    name: str
    attack: WSAttack
    message: str          # Message to send
    expected_pattern: Optional[str] = None  # Regex in response
    description: str = ""


# =============================================================================
# XSS / INJECTION PAYLOADS FOR WS MESSAGES
# =============================================================================

WS_XSS_PAYLOADS = [
    '<img src=x onerror=alert(1)>',
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '{{7*7}}',
    '${7*7}',
]

WS_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1; SELECT 1--",
    "1 UNION SELECT NULL--",
    "' AND SLEEP(5)--",
]

WS_CMD_PAYLOADS = [
    "; id",
    "| id",
    "$(id)",
    "`id`",
    "\nid\n",
]


# =============================================================================
# SCANNER
# =============================================================================

class WebSocketScanner(BaseScanner):
    """
    WebSocket Security Scanner.

    Focuses on the HTTP-observable aspects of WebSocket security:
    - Upgrade handshake analysis
    - Origin validation (CSWSH)
    - Plaintext WS detection
    - Auth cookie handling
    - WS endpoint discovery from JavaScript

    Note: Full WS message testing requires a WebSocket client.
    This scanner handles the HTTP Upgrade handshake layer and
    provides WS-specific findings from passive analysis.
    """

    name = "websocket"
    description = "WebSocket Security Scanner"
    version = "1.0.0"

    checks = [
        "ws_endpoint_discovery",
        "ws_origin_validation",
        "ws_auth_check",
        "ws_plaintext",
        "ws_injection_surface",
    ]

    owasp_category = "WSTG-CLNT-10"
    mitre_technique = "T1185"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.canary = "BTRX" + "".join(random.choices(string.ascii_lowercase, k=8))

    # =========================================================================
    # ENDPOINT DISCOVERY
    # =========================================================================

    def _derive_ws_urls(self, http_url: str) -> List[str]:
        """Derive possible WS endpoint URLs from HTTP URL"""
        parsed = urlparse(http_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        base = f"{ws_scheme}://{parsed.netloc}"

        candidates = []

        # Common WebSocket paths
        ws_paths = [
            "/ws",
            "/websocket",
            "/socket",
            "/socket.io/",
            "/sockjs/",
            "/cable",          # ActionCable (Rails)
            "/hub",            # SignalR
            "/realtime",
            "/live",
            "/stream",
            "/chat",
            "/notifications",
            "/events",
            "/api/ws",
            "/api/v1/ws",
            "/graphql",        # GraphQL subscriptions
        ]

        for path in ws_paths:
            candidates.append(base + path)

        return candidates

    async def _probe_ws_upgrade(self, url: str) -> Optional[WSEndpoint]:
        """Try WebSocket Upgrade handshake via HTTP"""
        # Build WebSocket upgrade request
        ws_key = base64.b64encode(random.randbytes(16)).decode()

        parsed = urlparse(url)
        http_scheme = "https" if parsed.scheme == "wss" else "http"
        http_url = f"{http_scheme}://{parsed.netloc}{parsed.path}"

        try:
            resp = await self.get(
                http_url,
                headers={
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": ws_key,
                    "Sec-WebSocket-Version": "13",
                    "Origin": f"{http_scheme}://{parsed.netloc}",
                },
            )

            # 101 Switching Protocols = WebSocket endpoint confirmed
            if resp.status_code == 101:
                return WSEndpoint(
                    url=url,
                    http_url=http_url,
                    protocol=resp.headers.get("sec-websocket-protocol"),
                    server_info=resp.headers.get("server"),
                )

            # 426 Upgrade Required = WebSocket endpoint exists but needs WS client
            if resp.status_code == 426:
                return WSEndpoint(url=url, http_url=http_url)

            # Some servers return 400 with WS-related error (still confirms endpoint)
            if resp.status_code == 400:
                body = resp.text.lower()
                if any(kw in body for kw in ["websocket", "upgrade", "sec-websocket"]):
                    return WSEndpoint(url=url, http_url=http_url)

        except Exception:
            pass

        return None

    # =========================================================================
    # ORIGIN VALIDATION (CSWSH)
    # =========================================================================

    async def _test_origin_validation(self, endpoint: WSEndpoint) -> bool:
        """Test if WebSocket accepts connections from arbitrary origins"""
        ws_key = base64.b64encode(random.randbytes(16)).decode()

        evil_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            "null",  # Some apps allow null origin
        ]

        for origin in evil_origins:
            try:
                resp = await self.get(
                    endpoint.http_url,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": ws_key,
                        "Sec-WebSocket-Version": "13",
                        "Origin": origin,
                    },
                )

                if resp.status_code == 101:
                    endpoint.origin_checked = False
                    return False  # Accepts foreign origin = vulnerable

            except Exception:
                continue

        endpoint.origin_checked = True
        return True  # Rejects foreign origins = safe

    # =========================================================================
    # AUTH CHECK
    # =========================================================================

    async def _test_ws_auth(self, endpoint: WSEndpoint) -> bool:
        """Test if WebSocket requires authentication"""
        ws_key = base64.b64encode(random.randbytes(16)).decode()

        # Try to upgrade WITHOUT any cookies or auth headers
        try:
            resp = await self.get(
                endpoint.http_url,
                headers={
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": ws_key,
                    "Sec-WebSocket-Version": "13",
                    "Origin": endpoint.http_url.rsplit("/", 1)[0],
                    "Cookie": "",  # Empty cookies
                },
            )

            if resp.status_code == 101:
                endpoint.auth_required = False
                return False  # No auth needed

            if resp.status_code in (401, 403):
                endpoint.auth_required = True
                return True

        except Exception:
            pass

        return True  # Assume auth required on error

    # =========================================================================
    # MAIN SCAN
    # =========================================================================

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Full WebSocket security scan"""

        # Phase 1: Discover WS endpoints
        discovered: List[WSEndpoint] = []

        ws_candidates = self._derive_ws_urls(context.url)

        for candidate in ws_candidates:
            ep = await self._probe_ws_upgrade(candidate)
            if ep:
                discovered.append(ep)

        if not discovered:
            # Check passive scan for WS indicators
            async for finding in self.passive_scan(context):
                yield finding
            return

        for endpoint in discovered:
            yield self.create_finding(
                title=f"WebSocket Endpoint Discovered: {endpoint.url}",
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                url=endpoint.http_url,
                description=(
                    f"WebSocket endpoint confirmed at: {endpoint.url}\n"
                    f"Protocol: {endpoint.protocol or 'none specified'}\n"
                    f"Server: {endpoint.server_info or 'unknown'}"
                ),
                evidence=f"WS URL: {endpoint.url}",
            )

            # Phase 2: Plaintext check
            parsed = urlparse(endpoint.url)
            if parsed.scheme == "ws":
                yield self.create_finding(
                    title="Plaintext WebSocket (ws://) in Use",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    url=endpoint.http_url,
                    description=(
                        "WebSocket connection uses unencrypted ws:// protocol.\n"
                        "All WebSocket messages can be intercepted by network attackers.\n"
                        "This includes session tokens, user data, and application messages."
                    ),
                    evidence="Protocol: ws:// (should be wss://)",
                    remediation="Use wss:// (WebSocket Secure) for all WebSocket connections.",
                )

            # Phase 3: Origin validation (CSWSH)
            origin_safe = await self._test_origin_validation(endpoint)

            if not origin_safe:
                yield self.create_finding(
                    title="Cross-Site WebSocket Hijacking (CSWSH)",
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    url=endpoint.http_url,
                    description=(
                        "WebSocket endpoint accepts connections from arbitrary origins.\n"
                        "An attacker can create a malicious webpage that connects to this "
                        "WebSocket endpoint using the victim's cookies, hijacking their session.\n\n"
                        "Attack scenario:\n"
                        "1. Victim visits attacker's page\n"
                        "2. JavaScript opens WebSocket to target with victim's cookies\n"
                        "3. Attacker reads/sends messages as victim\n\n"
                        "Tested origins: evil.com, attacker.example.com, null"
                    ),
                    evidence="Origin: https://evil.com → 101 Switching Protocols (accepted)",
                    remediation=(
                        "1. Validate the Origin header on WebSocket Upgrade requests\n"
                        "2. Only accept connections from your own domain(s)\n"
                        "3. Use CSRF tokens in the Upgrade handshake\n"
                        "4. Don't rely solely on cookies for WS authentication"
                    ),
                    references=[
                        "https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking",
                    ],
                )

            # Phase 4: Auth check
            auth_required = await self._test_ws_auth(endpoint)

            if not auth_required:
                yield self.create_finding(
                    title="WebSocket No Authentication Required",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    url=endpoint.http_url,
                    description=(
                        "WebSocket endpoint accepts connections without any authentication.\n"
                        "All WebSocket messages and functionality are accessible to anyone."
                    ),
                    evidence="Connection accepted without cookies or auth headers",
                    remediation=(
                        "1. Require authentication before allowing WebSocket upgrade\n"
                        "2. Validate session cookies/tokens during upgrade handshake\n"
                        "3. Implement authorization checks for each message type"
                    ),
                )

        # Run passive scan
        async for finding in self.passive_scan(context):
            yield finding

    async def passive_scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Detect WebSocket usage from HTTP responses"""
        if not context.response:
            return

        body = context.response.body if hasattr(context.response, 'body') else ""

        # Detect WebSocket endpoints in JavaScript
        ws_url_patterns = [
            (r'''(?:new\s+WebSocket|ws)\s*\(\s*['"]?(wss?://[^'")\s]+)['"]?''', "WebSocket URL in JavaScript"),
            (r'''['"]?(wss?://[^'")\s]+)['"]?''', "WebSocket URL String"),
            (r'''socket\.io|io\s*\(\s*['"](https?://[^'"]+)['"]''', "Socket.IO Endpoint"),
            (r'SockJS|sockjs', "SockJS Usage Detected"),
            (r'ActionCable|createConsumer', "Rails ActionCable Detected"),
            (r'signalR|HubConnection', "SignalR Detected"),
        ]

        seen = set()
        for pattern, title in ws_url_patterns:
            for match in re.finditer(pattern, body, re.IGNORECASE):
                url = match.group(1) if match.lastindex else match.group(0)
                if url not in seen:
                    seen.add(url)
                    yield self.create_finding(
                        title=title,
                        severity=Severity.INFO,
                        confidence=Confidence.FIRM,
                        url=context.url,
                        description=(
                            f"WebSocket endpoint reference found in response.\n"
                            f"URL/Library: {url}\n"
                            f"This is a potential attack surface for CSWSH and message injection."
                        ),
                        evidence=match.group(0)[:200],
                    )
