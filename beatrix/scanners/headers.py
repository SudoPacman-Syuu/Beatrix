"""
BEATRIX Header Security Scanner

Detects missing or misconfigured security headers.

While often considered "informational", missing headers on authentication
endpoints can sometimes be escalated to higher severity findings.

Checks:
- Missing Strict-Transport-Security
- Missing X-Content-Type-Options
- Missing X-Frame-Options / CSP frame-ancestors
- Missing Content-Security-Policy
- Insecure cookie flags
- Exposed server version info
"""

from typing import AsyncIterator

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext


class HeaderSecurityScanner(BaseScanner):
    """
    Security Headers Scanner

    Analyzes HTTP response headers for security misconfigurations.
    """

    name = "headers"
    description = "Security header misconfiguration scanner"
    version = "1.0.0"

    # Required headers and their severity if missing
    REQUIRED_HEADERS = {
        "strict-transport-security": {
            "severity": Severity.LOW,
            "description": "HTTP Strict Transport Security (HSTS) not enforced",
            "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "cwe": "CWE-319",
        },
        "x-content-type-options": {
            "severity": Severity.INFO,
            "description": "X-Content-Type-Options not set, MIME sniffing possible",
            "remediation": "Add header: X-Content-Type-Options: nosniff",
            "cwe": "CWE-693",
        },
        "x-frame-options": {
            "severity": Severity.LOW,
            "description": "X-Frame-Options not set, clickjacking possible",
            "remediation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN)",
            "cwe": "CWE-1021",
        },
        "content-security-policy": {
            "severity": Severity.INFO,
            "description": "Content-Security-Policy not set",
            "remediation": "Implement a Content-Security-Policy header appropriate for your application",
            "cwe": "CWE-693",
        },
        "referrer-policy": {
            "severity": Severity.INFO,
            "description": "Referrer-Policy not set — full URL may leak to third parties via Referer header",
            "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer)",
            "cwe": "CWE-200",
        },
        "permissions-policy": {
            "severity": Severity.INFO,
            "description": "Permissions-Policy not set — browser features (camera, mic, geolocation) not restricted",
            "remediation": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            "cwe": "CWE-693",
        },
    }

    # Headers that expose sensitive info
    SENSITIVE_HEADERS = [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
    ]

    async def __aenter__(self):
        """Override to follow redirects — we need the final page's headers"""
        import httpx
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
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

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Check security headers on target"""

        self.log(f"Scanning headers on {context.url}")

        try:
            response = await self.get(context.url)
            headers = {k.lower(): v for k, v in response.headers.items()}

            # Check for missing security headers
            for header, info in self.REQUIRED_HEADERS.items():
                if header not in headers:
                    # Check CSP for frame-ancestors (alternative to X-Frame-Options)
                    if header == "x-frame-options":
                        csp = headers.get("content-security-policy", "")
                        if "frame-ancestors" in csp.lower():
                            continue

                    yield self.create_finding(
                        title=f"Missing Security Header: {header.title()}",
                        severity=info["severity"],
                        confidence=Confidence.CERTAIN,
                        url=context.url,
                        description=info["description"],
                        evidence=f"Header '{header}' not found in response",
                        request=f"GET {context.url}",
                        response=f"HTTP {response.status_code}",
                        remediation=info["remediation"],
                        references=[f"https://cwe.mitre.org/data/definitions/{info['cwe'].split('-')[1]}.html"],
                        cwe_id=info["cwe"],
                        parameter=header,
                        poc_curl=f"curl -sSk -I {context.url} | grep -i '{header}'",
                    )

            # Check for info leakage headers
            for header in self.SENSITIVE_HEADERS:
                if header in headers:
                    value = headers[header]
                    yield self.create_finding(
                        title=f"Information Disclosure: {header.title()} Header",
                        severity=Severity.INFO,
                        confidence=Confidence.CERTAIN,
                        url=context.url,
                        description=f"Server exposes '{header}' header which reveals technology stack information",
                        evidence=f"{header}: {value}",
                        request=f"GET {context.url}",
                        response=f"HTTP {response.status_code}\n{header}: {value}",
                        remediation=f"Remove or obfuscate the {header} header",
                        cwe_id="CWE-200",
                        parameter=header,
                        poc_curl=f"curl -sSk -I {context.url} | grep -i '{header}'",
                    )

            # Check cookie security
            async for finding in self._check_cookies(context.url, response):
                yield finding

            # Check CSP weaknesses
            if "content-security-policy" in headers:
                async for finding in self._analyze_csp(context.url, headers["content-security-policy"]):
                    yield finding

            # Check HSTS weaknesses
            if "strict-transport-security" in headers:
                async for finding in self._analyze_hsts(context.url, headers["strict-transport-security"]):
                    yield finding

        except Exception as e:
            self.log(f"Error scanning headers: {e}")

    async def _check_cookies(self, url: str, response) -> AsyncIterator[Finding]:
        """Check for insecure cookie configurations"""

        # httpx uses .multi_items() to get all headers including duplicates
        cookies = [v for k, v in response.headers.multi_items() if k.lower() == "set-cookie"]
        if not cookies:
            raw = response.headers.get("set-cookie", "")
            cookies = [raw] if raw else []

        for cookie in cookies:
            if not cookie:
                continue

            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=")[0] if "=" in cookie else "unknown"

            issues = []

            # Check for missing Secure flag on HTTPS
            if url.startswith("https://") and "secure" not in cookie_lower:
                issues.append("Missing Secure flag")

            # Check for missing HttpOnly on session-like cookies
            # CSRF tokens intentionally lack HttpOnly so JS can read them for
            # anti-CSRF header submission — this is correct security practice
            session_indicators = ["session", "auth", "jwt", "sid"]
            csrf_indicators = ["csrf", "xsrf", "_token"]
            name_lower = cookie_name.lower().strip()
            is_csrf_cookie = any(ind in name_lower for ind in csrf_indicators)
            is_session_cookie = any(ind in name_lower for ind in session_indicators) and not is_csrf_cookie

            # Don't flag CSRF cookies for missing HttpOnly — that's by design
            if is_session_cookie and "httponly" not in cookie_lower:
                issues.append("Missing HttpOnly flag on session cookie")

            # Check for missing SameSite
            if "samesite" not in cookie_lower:
                issues.append("Missing SameSite attribute")
            elif "samesite=none" in cookie_lower:
                issues.append("SameSite=None allows cross-site sending")

            if issues:
                # Severity: MEDIUM only for real session cookies with auth impact
                # LOW for CSRF tokens, routing cookies, and non-sensitive cookies
                if is_session_cookie:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW

                yield self.create_finding(
                    title=f"Insecure Cookie: {cookie_name}",
                    severity=severity,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    description=f"Cookie '{cookie_name}' has security issues: {', '.join(issues)}",
                    evidence=f"Set-Cookie: {cookie[:200]}...",
                    request=f"GET {url}",
                    remediation="Add Secure, HttpOnly, and SameSite=Strict flags to sensitive cookies",
                    cwe_id="CWE-614",
                    parameter=cookie_name,
                    poc_curl=f"curl -sSk -v {url} 2>&1 | grep -i 'set-cookie.*{cookie_name}'",
                )

    async def _analyze_csp(self, url: str, csp: str) -> AsyncIterator[Finding]:
        """Analyze Content-Security-Policy for weaknesses"""

        csp_lower = csp.lower()

        # Check for unsafe-inline
        if "unsafe-inline" in csp_lower:
            yield self.create_finding(
                title="CSP Allows unsafe-inline",
                severity=Severity.LOW,
                confidence=Confidence.CERTAIN,
                url=url,
                description="Content-Security-Policy contains 'unsafe-inline' which reduces XSS protection",
                evidence=f"CSP: {csp[:500]}",
                remediation="Remove 'unsafe-inline' and use nonces or hashes instead",
            )

        # Check for unsafe-eval (but NOT wasm-unsafe-eval, which is safe)
        import re as _re
        if _re.search(r"(?<!wasm-)'unsafe-eval'", csp_lower):
            yield self.create_finding(
                title="CSP Allows unsafe-eval",
                severity=Severity.LOW,
                confidence=Confidence.CERTAIN,
                url=url,
                description="Content-Security-Policy contains 'unsafe-eval' which allows eval() and related functions",
                evidence=f"CSP: {csp[:500]}",
                remediation="Remove 'unsafe-eval' and refactor code to avoid eval()",
            )

        # Check for wildcard sources — match * as a directive value
        import re
        if re.search(r'(?:^|\s)\*(?:\s|;|$)', csp):
            yield self.create_finding(
                title="CSP Contains Wildcard Source",
                severity=Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                url=url,
                description="Content-Security-Policy contains wildcard (*) sources which significantly weakens protection",
                evidence=f"CSP: {csp[:500]}",
                remediation="Replace wildcard sources with specific allowed domains",
            )

    async def _analyze_hsts(self, url: str, hsts: str) -> AsyncIterator[Finding]:
        """Analyze HSTS header for weaknesses"""

        hsts_lower = hsts.lower()

        # Parse max-age
        import re
        max_age_match = re.search(r'max-age=(\d+)', hsts_lower)
        if max_age_match:
            max_age = int(max_age_match.group(1))

            # Less than 1 year is considered weak
            if max_age < 31536000:
                yield self.create_finding(
                    title="HSTS max-age Too Short",
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    description=f"HSTS max-age is {max_age} seconds ({max_age // 86400} days). Recommended is at least 1 year (31536000 seconds)",
                    evidence=f"HSTS: {hsts}",
                    remediation="Increase max-age to at least 31536000 (1 year)",
                )

        # Check for missing includeSubDomains
        if "includesubdomains" not in hsts_lower:
            yield self.create_finding(
                title="HSTS Missing includeSubDomains",
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                url=url,
                description="HSTS header does not include 'includeSubDomains' directive",
                evidence=f"HSTS: {hsts}",
                remediation="Add 'includeSubDomains' to HSTS header",
            )
