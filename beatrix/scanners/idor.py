"""
BEATRIX IDOR Scanner (A01:2025 - Broken Access Control)

This is the #1 bug bounty earner. Period.

IDORs (Insecure Direct Object References) allow attackers to access
resources belonging to other users by manipulating identifiers.

EXPLOITATION STRATEGY:
1. Identify numeric/UUID IDs in URLs and bodies
2. Increment/decrement numeric IDs
3. Swap UUIDs between accounts
4. Check if authorization is enforced

Unlike CORS, these are ALWAYS exploitable if found.
"""

import asyncio
import re
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from beatrix.core.types import Confidence, Finding, HttpResponse, Severity
from beatrix.scanners.base import BaseScanner, ScanContext


@dataclass
class IDORCandidate:
    """Potential IDOR target"""
    param_name: str
    param_value: str
    location: str  # url_path, query, body, header
    id_type: str   # numeric, uuid, hash, sequential
    original_url: str


@dataclass
class IDORFinding:
    """Confirmed IDOR vulnerability"""
    candidate: IDORCandidate
    test_value: str
    original_response: HttpResponse
    test_response: HttpResponse
    evidence: str


class IDORScanner(BaseScanner):
    """
    IDOR/Broken Access Control Scanner

    OWASP A01:2025 - #1 most critical web vulnerability

    This scanner:
    1. Identifies ID parameters (numeric, UUID, hashes)
    2. Tests incrementing/decrementing IDs
    3. Compares responses to detect unauthorized access
    4. Generates PoC requests

    REQUIRES: Two accounts or two sessions for proper testing
    """

    name = "idor"
    description = "Insecure Direct Object Reference Scanner"
    author = "BEATRIX"
    version = "2.0.0"

    checks = [
        "horizontal_privilege_escalation",
        "vertical_privilege_escalation",
        "direct_object_reference",
        "missing_authorization",
        "predictable_resource_id",
    ]

    owasp_category = "A01:2025 - Broken Access Control"

    # ID detection patterns
    NUMERIC_ID_PATTERN = re.compile(r'^[1-9]\d{0,9}$')  # 1-10 digit numbers, no leading zeros
    UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
    UUID_NOHYPHEN = re.compile(r'^[0-9a-f]{32}$', re.I)
    MD5_PATTERN = re.compile(r'^[0-9a-f]{32}$', re.I)
    SHA1_PATTERN = re.compile(r'^[0-9a-f]{40}$', re.I)
    BASE64_ID_PATTERN = re.compile(r'^[A-Za-z0-9+/]{10,}={0,2}$')
    MONGO_OID_PATTERN = re.compile(r'^[0-9a-f]{24}$', re.I)

    # Parameter names commonly containing IDs
    ID_PARAM_NAMES = {
        'id', 'uid', 'user_id', 'userid', 'user',
        'account', 'account_id', 'accountid',
        'profile', 'profile_id', 'profileid',
        'doc', 'doc_id', 'docid', 'document_id',
        'file', 'file_id', 'fileid',
        'order', 'order_id', 'orderid',
        'invoice', 'invoice_id', 'invoiceid',
        'customer', 'customer_id', 'customerid',
        'message', 'message_id', 'messageid', 'msg_id',
        'post', 'post_id', 'postid',
        'comment', 'comment_id', 'commentid',
        'project', 'project_id', 'projectid',
        'org', 'org_id', 'orgid', 'organization_id',
        'team', 'team_id', 'teamid',
        'workspace', 'workspace_id', 'workspaceid',
        'report', 'report_id', 'reportid',
        'ticket', 'ticket_id', 'ticketid',
        'item', 'item_id', 'itemid',
        'record', 'record_id', 'recordid',
        'ref', 'reference', 'reference_id',
        'key', 'api_key', 'apikey',
        'token', 'session', 'sess',
    }

    # URL path patterns that indicate REST resources
    REST_PATTERNS = [
        r'/users?/([^/]+)',
        r'/accounts?/([^/]+)',
        r'/profiles?/([^/]+)',
        r'/documents?/([^/]+)',
        r'/files?/([^/]+)',
        r'/orders?/([^/]+)',
        r'/invoices?/([^/]+)',
        r'/messages?/([^/]+)',
        r'/posts?/([^/]+)',
        r'/comments?/([^/]+)',
        r'/projects?/([^/]+)',
        r'/teams?/([^/]+)',
        r'/workspaces?/([^/]+)',
        r'/organizations?/([^/]+)',
        r'/reports?/([^/]+)',
        r'/tickets?/([^/]+)',
        r'/api/v\d+/([^/]+)/([^/]+)',
        # E-commerce / Zooplus-style patterns
        r'/customers?/([^/]+)',
        r'/customer-data/([^/]+)',
        r'/addresses?/([^/]+)',
        r'/carts?/([^/]+)',
        r'/cart/([^/]+)',
        r'/wishlists?/([^/]+)',
        r'/favorites?/([^/]+)',
        r'/subscriptions?/([^/]+)',
        r'/autoshipments?/([^/]+)',
        r'/payments?/([^/]+)',
        r'/payment-methods?/([^/]+)',
        r'/reviews?/([^/]+)',
        r'/returns?/([^/]+)',
        r'/shipments?/([^/]+)',
        r'/transactions?/([^/]+)',
        r'/receipts?/([^/]+)',
        # Nested resource patterns (e.g. /customers/{id}/addresses/{id})
        r'/customers?/([^/]+)/addresses',
        r'/customers?/([^/]+)/orders',
        r'/customers?/([^/]+)/cart',
        r'/customers?/([^/]+)/wishlist',
        r'/customers?/([^/]+)/payment-methods',
        r'/customers?/([^/]+)/subscriptions',
        r'/customers?/([^/]+)/preferences',
        r'/customers?/([^/]+)/notifications',
    ]

    # Cookie names that may contain customer/session IDs exploitable for IDOR
    ID_COOKIE_NAMES = {
        'cid', 'customer_id', 'customerid', 'custid', 'cust_id',
        'uid', 'user_id', 'userid', 'account_id', 'accountid',
        'sid', 'session_id', 'sessionid', 'sess_id',
        'cart_id', 'cartid', 'basket_id',
        'member_id', 'memberid',
    }

    # Header names that may contain IDs
    ID_HEADER_NAMES = {
        'x-customer-id', 'x-user-id', 'x-account-id', 'x-session-id',
        'x-cart-id', 'x-basket-id', 'x-member-id', 'x-client-id',
        'x-request-id',  # sometimes correlates to user context
    }

    # PII patterns for assessing IDOR impact in responses
    PII_PATTERNS = {
        'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        'phone': re.compile(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'),
        'address': re.compile(r'\b\d{1,5}\s+[\w\s]+(?:street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln|way|court|ct)\b', re.I),
        'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
        'iban': re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b'),
        'postal_code': re.compile(r'\b\d{5}(?:-\d{4})?\b'),
        'date_of_birth': re.compile(r'\b(?:dob|dateOfBirth|birth_date|birthdate|date_of_birth)\b', re.I),
    }

    # HTTP methods to test for write-based IDOR
    WRITE_METHODS = ['PUT', 'PATCH', 'DELETE', 'POST']

    def __init__(self,
                 config=None,
                 user1_auth: Optional[Dict[str, str]] = None,
                 user2_auth: Optional[Dict[str, str]] = None,
                 timeout: float = 10.0):
        """
        Initialize IDOR scanner.

        Supports being called with:
        - A config dict (from engine): IDORScanner({"rate_limit": 100, "timeout": 10})
        - Keyword args: IDORScanner(user1_auth={...}, timeout=10)

        For best results, provide two different user sessions:
        - user1_auth: Headers/cookies for user A
        - user2_auth: Headers/cookies for user B

        The scanner will use user2's session to access user1's resources.
        """
        # Handle being called with config dict from engine
        if isinstance(config, dict) and 'rate_limit' in config:
            timeout = config.get("timeout", timeout)

        super().__init__(config if isinstance(config, dict) else None)
        self.user1_auth = user1_auth or {}
        self.user2_auth = user2_auth or {}
        self.timeout = timeout

    async def __aenter__(self):
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,  # Important for auth checks
            verify=False,
        )
        return self

    def identify_id_type(self, value: str) -> Optional[str]:
        """Determine what type of ID a value appears to be"""
        if self.NUMERIC_ID_PATTERN.match(value):
            return "numeric"
        if self.UUID_PATTERN.match(value):
            return "uuid"
        if self.MONGO_OID_PATTERN.match(value):
            return "mongo_oid"
        if self.SHA1_PATTERN.match(value):
            return "sha1_hash"
        # MD5 and UUID-no-hyphen are both 32 hex chars — treat as "hex_id"
        # (ambiguous, but still worth testing for IDOR)
        if self.UUID_NOHYPHEN.match(value):
            return "hex_id"
        if self.BASE64_ID_PATTERN.match(value) and len(value) <= 50:
            return "base64"
        return None

    def extract_ids_from_url(self, url: str) -> List[IDORCandidate]:
        """Extract potential ID parameters from URL"""
        candidates = []
        parsed = urlparse(url)

        # Check query parameters
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in params.items():
                value = values[0] if values else ""

                # Check if param name suggests an ID
                name_lower = name.lower()
                is_id_param = any(
                    name_lower == idname or
                    name_lower.endswith(f"_{idname}") or
                    name_lower.endswith(f"-{idname}")
                    for idname in self.ID_PARAM_NAMES
                )

                # Check if value looks like an ID
                id_type = self.identify_id_type(value)

                if is_id_param or id_type:
                    candidates.append(IDORCandidate(
                        param_name=name,
                        param_value=value,
                        location="query",
                        id_type=id_type or "unknown",
                        original_url=url,
                    ))

        # Check URL path for REST-style IDs
        path = parsed.path
        for pattern in self.REST_PATTERNS:
            matches = re.findall(pattern, path)
            for match in matches:
                if isinstance(match, tuple):
                    # Multiple groups
                    for m in match:
                        id_type = self.identify_id_type(m)
                        if id_type:
                            candidates.append(IDORCandidate(
                                param_name=f"path_segment:{m}",
                                param_value=m,
                                location="url_path",
                                id_type=id_type,
                                original_url=url,
                            ))
                else:
                    id_type = self.identify_id_type(match)
                    if id_type:
                        candidates.append(IDORCandidate(
                            param_name=f"path_segment:{match}",
                            param_value=match,
                            location="url_path",
                            id_type=id_type,
                            original_url=url,
                        ))

        return candidates

    def extract_ids_from_body(self, body: str, content_type: str = "") -> List[Dict]:
        """Extract IDs from request/response body"""
        candidates = []

        # JSON body
        if "json" in content_type.lower() or body.strip().startswith('{'):
            # Find all key-value pairs that might be IDs
            json_patterns = [
                r'"(\w*id\w*)"\s*:\s*"?(\d+)"?',
                r'"(\w*id\w*)"\s*:\s*"([0-9a-f-]{36})"',
                r'"(\w+)"\s*:\s*(\d{1,10})',
            ]
            for pattern in json_patterns:
                for match in re.finditer(pattern, body, re.I):
                    name, value = match.groups()
                    id_type = self.identify_id_type(value)
                    if id_type:
                        candidates.append({
                            'name': name,
                            'value': value,
                            'type': id_type,
                            'location': 'json_body'
                        })

        # Form data
        elif "form" in content_type.lower():
            for match in re.finditer(r'([^&=]+)=([^&]*)', body):
                name, value = match.groups()
                id_type = self.identify_id_type(value)
                name_lower = name.lower()
                is_id_param = any(idname in name_lower for idname in self.ID_PARAM_NAMES)
                if id_type or is_id_param:
                    candidates.append({
                        'name': name,
                        'value': value,
                        'type': id_type or 'unknown',
                        'location': 'form_body'
                    })

        return candidates

    def extract_ids_from_cookies(self, cookies: Dict[str, str]) -> List[IDORCandidate]:
        """
        Extract potential IDs from cookies.

        Lesson from Zooplus: the 'cid' cookie contained the customer ID used
        in API paths like /customers/{cid}/addresses. Cookie-based IDOR is
        often overlooked but critical for e-commerce targets.
        """
        candidates = []
        for name, value in cookies.items():
            if name.lower() in self.ID_COOKIE_NAMES:
                id_type = self.identify_id_type(value)
                if id_type or len(value) >= 3:  # Even short cookies can be IDs
                    candidates.append(IDORCandidate(
                        param_name=f"cookie:{name}",
                        param_value=value,
                        location="cookie",
                        id_type=id_type or "unknown",
                        original_url="",  # Cookies are cross-endpoint
                    ))
        return candidates

    def extract_ids_from_headers(self, headers: Dict[str, str]) -> List[IDORCandidate]:
        """
        Extract potential IDs from request/response headers.

        Some APIs use custom headers like X-Customer-Id for authorization context.
        """
        candidates = []
        for name, value in headers.items():
            if name.lower() in self.ID_HEADER_NAMES:
                id_type = self.identify_id_type(value)
                if id_type:
                    candidates.append(IDORCandidate(
                        param_name=f"header:{name}",
                        param_value=value,
                        location="header",
                        id_type=id_type or "unknown",
                        original_url="",
                    ))
        return candidates

    def detect_pii_in_response(self, response_text: str) -> Dict[str, List[str]]:
        """
        Detect PII patterns in response body to assess IDOR impact.

        A response containing PII (email, phone, address) from another user
        elevates an IDOR from low to high/critical severity.
        """
        pii_found = {}
        for pii_type, pattern in self.PII_PATTERNS.items():
            matches = pattern.findall(response_text)
            if matches:
                # Deduplicate and limit
                unique_matches = list(set(matches))[:5]
                pii_found[pii_type] = unique_matches
        return pii_found

    def assess_idor_severity(self, pii_found: Dict[str, List[str]],
                              method: str = "GET",
                              endpoint_type: str = "") -> Severity:
        """
        Dynamically assess IDOR severity based on PII exposure and method.

        - Write-method IDOR (PUT/PATCH/DELETE) on user data = Critical
        - Read IDOR exposing email + address = High
        - Read IDOR exposing only non-sensitive data = Medium
        """
        has_sensitive_pii = any(
            k in pii_found for k in ['email', 'credit_card', 'iban', 'address']
        )
        has_any_pii = bool(pii_found)
        is_write = method.upper() in ['PUT', 'PATCH', 'DELETE', 'POST']

        # Financial/payment endpoints always critical
        financial_keywords = ['payment', 'card', 'bank', 'billing', 'invoice', 'transaction']
        is_financial = any(kw in endpoint_type.lower() for kw in financial_keywords)

        if is_financial:
            return Severity.CRITICAL
        if is_write and has_sensitive_pii:
            return Severity.CRITICAL
        if is_write:
            return Severity.HIGH
        if has_sensitive_pii:
            return Severity.HIGH
        if has_any_pii:
            return Severity.MEDIUM
        return Severity.MEDIUM

    def generate_test_ids(self, original: str, id_type: str) -> List[str]:
        """Generate alternative IDs to test"""
        test_ids = []

        if id_type == "numeric":
            num = int(original)
            # Try adjacent IDs (most common IDOR)
            test_ids.extend([
                str(num - 1),
                str(num + 1),
                str(num - 2),
                str(num + 2),
            ])
            # Try 1 (admin is often ID 1)
            if num > 1:
                test_ids.append("1")
            # Try some common IDs
            test_ids.extend(["0", "2", "100", "1000"])

        elif id_type == "uuid":
            # Can't guess UUIDs, but try null UUID and some variants
            test_ids.extend([
                "00000000-0000-0000-0000-000000000000",
                "00000000-0000-0000-0000-000000000001",
                # Modify last character
                original[:-1] + ('0' if original[-1] != '0' else '1'),
            ])

        elif id_type == "mongo_oid":
            # MongoDB ObjectIDs are timestamped - try incrementing
            if len(original) == 24:
                test_ids.extend([
                    original[:22] + "00",
                    original[:22] + "01",
                ])

        elif id_type == "base64":
            # Try decoding, modifying, re-encoding
            try:
                import base64
                decoded = base64.b64decode(original).decode()
                # If it's a number, increment it
                if decoded.isdigit():
                    test_ids.append(base64.b64encode(str(int(decoded) + 1).encode()).decode())
            except Exception:
                pass

        # Remove original value and duplicates
        test_ids = list(set(test_ids) - {original})

        return test_ids[:5]  # Limit to 5 tests

    def build_test_url(self, original_url: str, candidate: IDORCandidate, new_value: str) -> str:
        """Build URL with modified ID for testing"""
        parsed = urlparse(original_url)

        if candidate.location == "query":
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[candidate.param_name] = [new_value]
            new_query = urlencode(params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))

        elif candidate.location in ("url_path", "cookie_in_path"):
            # Replace only the FIRST occurrence to avoid clobbering duplicate segments
            new_path = parsed.path.replace(candidate.param_value, new_value, 1)
            return urlunparse(parsed._replace(path=new_path))

        return original_url

    def compare_responses(self,
                         original: httpx.Response,
                         test: httpx.Response,
                         candidate: IDORCandidate) -> Optional[Dict[str, Any]]:
        """
        Compare responses to detect IDOR.

        IDOR is confirmed when:
        - Different ID returns 200 (not 403/404)
        - Response contains different user's data
        - No redirect to login
        """
        findings = {}

        # If test returns success status, potential IDOR
        if test.status_code in [200, 201]:
            if original.status_code in [200, 201]:
                # Both successful - compare content
                if test.text != original.text and len(test.text) > 50:
                    # Different data is EXPECTED for different resource IDs on public endpoints.
                    # Only flag as IDOR if we detect PII/sensitive data that suggests
                    # cross-user data access, or if the endpoint appears to require auth.
                    pii_detected = self.detect_pii_in_response(test.text) if hasattr(self, 'detect_pii_in_response') else False
                    auth_required = any(h.lower() in ['authorization', 'cookie', 'x-auth-token']
                                       for h in (candidate.headers or {}))

                    if pii_detected or auth_required:
                        findings['status'] = 'different_data_returned'
                        findings['evidence'] = f"Original ID returned {len(original.text)} bytes, test ID returned {len(test.text)} bytes"
                        findings['severity'] = 'high' if pii_detected else 'medium'
                    else:
                        # Different data on what appears to be a public endpoint — not IDOR
                        findings['status'] = 'different_data_public'
                        findings['severity'] = 'info'
                else:
                    findings['status'] = 'same_data'
                    findings['severity'] = 'low'
            else:
                # Original failed but test succeeded - interesting
                findings['status'] = 'test_succeeded_original_failed'
                findings['evidence'] = f"Original: {original.status_code}, Test: {test.status_code}"
                findings['severity'] = 'high'

        elif test.status_code in [403, 401]:
            # Properly denied - good!
            findings['status'] = 'properly_denied'
            findings['severity'] = 'info'

        elif test.status_code == 404:
            # Resource not found - need more testing
            findings['status'] = 'not_found'
            findings['severity'] = 'info'

        elif test.status_code in [301, 302, 303, 307, 308]:
            # Redirect - check if to login
            location = test.headers.get('location', '')
            if 'login' in location.lower() or 'auth' in location.lower():
                findings['status'] = 'redirected_to_login'
                findings['severity'] = 'info'
            else:
                findings['status'] = 'redirected'
                findings['evidence'] = f"Redirected to: {location}"
                findings['severity'] = 'medium'

        return findings if findings else None

    async def test_candidate(self,
                            candidate: IDORCandidate,
                            auth_headers: Dict[str, str]) -> List[Finding]:
        """Test a single IDOR candidate with GET and write methods"""
        findings = []

        if not self.client:
            return findings

        # Test with GET first (read IDOR)
        get_findings = await self._test_candidate_with_method(
            candidate, auth_headers, "GET"
        )
        findings.extend(get_findings)

        # Test with write methods (write IDOR — often more impactful)
        # Lesson from Zooplus: read IDOR was blocked on /customers/{id}/addresses
        # but write IDOR (PUT) should also be tested since access control may
        # differ between read and write operations
        for method in self.WRITE_METHODS:
            write_findings = await self._test_candidate_with_method(
                candidate, auth_headers, method
            )
            findings.extend(write_findings)

        return findings

    async def _test_candidate_with_method(self,
                                           candidate: IDORCandidate,
                                           auth_headers: Dict[str, str],
                                           method: str) -> List[Finding]:
        """Test a single IDOR candidate with a specific HTTP method"""
        findings = []

        if not self.client:
            return findings

        # Make original request
        headers = {**auth_headers, "User-Agent": "BEATRIX-IDOR-Scanner/2.0"}

        # For write methods, include a minimal JSON body
        request_kwargs = {"headers": headers}
        if method in self.WRITE_METHODS:
            headers["Content-Type"] = "application/json"
            request_kwargs["headers"] = headers
            # Use empty JSON as a probe — we're testing auth, not functionality
            request_kwargs["content"] = b'{}'

        try:
            original_response = await self.client.request(
                method,
                candidate.original_url,
                **request_kwargs,
            )
        except Exception:
            return findings

        # Generate and test alternative IDs
        test_ids = self.generate_test_ids(candidate.param_value, candidate.id_type)

        for test_id in test_ids:
            test_url = self.build_test_url(candidate.original_url, candidate, test_id)

            try:
                test_response = await self.client.request(
                    method,
                    test_url,
                    **request_kwargs,
                )

                result = self.compare_responses(original_response, test_response, candidate)

                if result and result.get('severity') in ['high', 'medium']:
                    # Detect PII in the response to assess real impact
                    pii_found = self.detect_pii_in_response(test_response.text)

                    # Determine severity based on PII and method
                    severity = self.assess_idor_severity(
                        pii_found, method, candidate.param_name
                    )

                    pii_summary = ""
                    if pii_found:
                        pii_types = ", ".join(pii_found.keys())
                        pii_summary = f"\n**PII Detected in Response:** {pii_types}"

                    method_note = ""
                    if method != "GET":
                        method_note = f"\n**HTTP Method:** {method} (write-based IDOR — may allow data modification)"

                    finding = Finding(
                        title=f"{'Write ' if method != 'GET' else ''}IDOR in {candidate.param_name} [{method}]",
                        description=f"""
**Insecure Direct Object Reference (IDOR)**

A potential IDOR vulnerability was detected using {method} method.
The application may not properly validate authorization when accessing resources by ID.

**Location:** {candidate.location}
**Parameter:** {candidate.param_name}
**ID Type:** {candidate.id_type}
**Original ID:** {candidate.param_value}
**Test ID:** {test_id}{method_note}{pii_summary}

**Status:** {result.get('status')}
**Evidence:** {result.get('evidence', 'N/A')}

**Impact:**
- {"Unauthorized modification/deletion of other users' data" if method != 'GET' else "Unauthorized access to other users' data"}
- Data breach / information disclosure
- Potential account takeover

**To Verify:**
1. Log in as User A
2. Note the URL/ID for User A's resource
3. Log in as User B
4. Try accessing User A's resource with User B's session using {method}
5. If successful without authorization error, IDOR confirmed
""".strip(),
                        severity=severity,
                        confidence=Confidence.TENTATIVE,
                        url=test_url,
                        evidence={
                            "original_url": candidate.original_url,
                            "test_url": test_url,
                            "method": method,
                            "original_id": candidate.param_value,
                            "test_id": test_id,
                            "original_status": original_response.status_code,
                            "test_status": test_response.status_code,
                            "pii_found": pii_found if pii_found else None,
                            "comparison": result,
                        },
                        remediation="""
1. Implement proper authorization checks on EVERY resource access (read AND write)
2. Verify the authenticated user has permission to access the requested resource
3. Use indirect references or access control lists
4. Ensure write operations (PUT/PATCH/DELETE) have equally strict auth as read (GET)
5. Log and alert on authorization failures
""".strip(),
                        references=[
                            "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                            "https://portswigger.net/web-security/access-control/idor",
                        ],
                        cwe_id=639,
                        owasp_category=self.owasp_category,
                    )
                    findings.append(finding)

            except Exception:
                continue

            # Small delay between requests
            await asyncio.sleep(0.2)

        return findings

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        """
        Main IDOR scanning entry point.

        Scans for IDOR vulnerabilities by:
        1. Extracting ID parameters from URLs, cookies, and headers
        2. Testing with modified IDs across GET and write methods (PUT/PATCH/DELETE)
        3. Comparing responses and detecting PII in leaked data
        """

        # Extract ID candidates from URL
        candidates = self.extract_ids_from_url(ctx.url)

        # Extract from cookies (Zooplus lesson: cid cookie = customer ID)
        if ctx.cookies:
            cookie_candidates = self.extract_ids_from_cookies(ctx.cookies)
            # For each cookie-based ID, try it in the URL path
            for cc in cookie_candidates:
                # Check if the cookie value appears in the URL path
                if cc.param_value in ctx.url:
                    cc.original_url = ctx.url
                    cc.location = "cookie_in_path"
                    candidates.append(cc)

        # Extract from headers
        if ctx.headers:
            header_candidates = self.extract_ids_from_headers(ctx.headers)
            for hc in header_candidates:
                hc.original_url = ctx.url
                candidates.append(hc)

        if not candidates:
            return

        # Ensure client is initialized (engine manages context manager)
        if not self.client:
            await self.__aenter__()

        for candidate in candidates:
            findings = await self.test_candidate(candidate, self.user1_auth)
            for finding in findings:
                yield finding

    async def scan_url(self, url: str, auth_headers: Optional[Dict[str, str]] = None) -> List[Finding]:
        """Convenience method to scan a single URL"""
        ctx = ScanContext.from_url(url)
        self.user1_auth = auth_headers or {}

        findings = []
        async for finding in self.scan(ctx):
            findings.append(finding)
        return findings


class BACScanner(IDORScanner):
    """
    Broader Broken Access Control scanner.

    Extends IDOR scanning to also check:
    - Horizontal privilege escalation (same role, different user)
    - Vertical privilege escalation (lower role accessing higher role functions)
    - Function-level access control (admin endpoints accessible to regular users)
    """

    name = "bac"
    description = "Broken Access Control Scanner (comprehensive)"

    # Admin/privileged endpoints to probe
    ADMIN_ENDPOINTS = [
        "/admin",
        "/admin/",
        "/administrator",
        "/admin/users",
        "/admin/settings",
        "/api/admin",
        "/api/v1/admin",
        "/api/v2/admin",
        "/management",
        "/manage",
        "/dashboard/admin",
        "/internal",
        "/internal/api",
        "/console",
        "/config",
        "/settings/admin",
        "/_admin",
        "/wp-admin",
        "/phpmyadmin",
        "/adminer",
    ]

    # Role-related parameters to tamper with
    ROLE_PARAMS = [
        'role', 'user_role', 'userRole', 'is_admin', 'isAdmin',
        'admin', 'privilege', 'level', 'access_level', 'accessLevel',
        'permission', 'permissions', 'group', 'user_type', 'userType',
    ]

    async def probe_admin_endpoints(self, base_url: str, auth_headers: Dict[str, str]) -> List[Finding]:
        """Check if admin endpoints are accessible without admin role"""
        findings = []

        # Ensure client is initialized
        if not self.client:
            await self.__aenter__()

        for endpoint in self.ADMIN_ENDPOINTS:
            url = f"{base_url.rstrip('/')}{endpoint}"

            try:
                response = await self.client.get(url, headers=auth_headers)

                # If we get 200 on admin endpoint as non-admin, potential issue
                if response.status_code == 200:
                    # Check for admin-specific content — require STRUCTURAL indicators,
                    # not just common words that appear on login pages and marketing sites
                    content_lower = response.text.lower()

                    # Generic words like 'admin', 'users', 'settings' appear on login forms,
                    # docs, marketing pages. Require multiple structural admin panel indicators.
                    strong_indicators = [
                        'create user', 'delete user', 'user management',
                        'system configuration', 'admin panel', 'admin dashboard',
                        'role management', 'permission management',
                        'server status', 'system health', 'audit log',
                    ]
                    weak_indicators = [
                        'admin', 'dashboard', 'manage', 'users', 'settings', 'configuration'
                    ]

                    strong_matches = sum(1 for ind in strong_indicators if ind in content_lower)
                    weak_matches = sum(1 for ind in weak_indicators if ind in content_lower)

                    # Require at least 1 strong or 3+ weak to flag
                    # Also exclude login/auth pages
                    is_login_page = any(w in content_lower for w in ['login', 'sign in', 'log in', 'password', 'forgot password'])

                    if (strong_matches >= 1 or weak_matches >= 3) and not is_login_page:
                        findings.append(Finding(
                            title=f"Admin Endpoint Accessible: {endpoint}",
                            description=f"""
**Vertical Privilege Escalation**

An administrative endpoint appears to be accessible without proper authorization.

**Endpoint:** {url}
**Response Status:** {response.status_code}
**Response Size:** {len(response.text)} bytes

This could indicate missing role-based access control.

**To Verify:**
1. Access this endpoint without authentication or as a regular user
2. Check if administrative functions are visible/usable
3. Compare with actual admin user's view
""".strip(),
                            severity=Severity.HIGH,
                            confidence=Confidence.TENTATIVE,
                            url=url,
                            evidence={
                                "endpoint": endpoint,
                                "status_code": response.status_code,
                                "response_size": len(response.text),
                            },
                            cwe_id=284,
                            owasp_category=self.owasp_category,
                        ))

            except Exception:
                continue

                await asyncio.sleep(0.1)

        return findings


# Quick CLI test
if __name__ == "__main__":
    import sys

    async def main():
        if len(sys.argv) < 2:
            print("Usage: python idor.py <url> [auth_header_value]")
            print("Example: python idor.py 'https://api.example.com/users/123' 'Bearer token123'")
            return

        url = sys.argv[1]
        auth = {}
        if len(sys.argv) > 2:
            auth["Authorization"] = sys.argv[2]

        scanner = IDORScanner(user1_auth=auth)

        print(f"[*] Scanning for IDOR: {url}")
        print(f"[*] Auth headers: {list(auth.keys())}")

        findings = await scanner.scan_url(url, auth)

        if findings:
            print(f"\n[!] Found {len(findings)} potential IDOR issues:\n")
            for f in findings:
                print(f"  [{f.severity.value.upper()}] {f.title}")
                print(f"    URL: {f.url}")
                print(f"    {f.description[:200]}...")
                print()
        else:
            print("\n[✓] No IDOR vulnerabilities detected")

    asyncio.run(main())
