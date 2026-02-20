"""
BEATRIX Business Logic Vulnerability Scanner

Born from: OWASP WSTG-BUSL (4.10 - Business Logic Testing)
Cross-referenced with: PCI DSS v4.0.1 Req 6.2.4, MITRE ATT&CK T1190

Business logic bugs are the #1 missed vulnerability class because:
- Automated scanners can't detect them (no signature/pattern)
- They require understanding of the application's PURPOSE
- Each one is unique to the application's workflow
- They often bypass all technical controls

TECHNIQUE:
1. Workflow circumvention — skip steps in multi-step processes
2. Rate limit testing — abuse lack of throttling on sensitive operations
3. Numeric boundary testing — INT overflow, negative values, MAX_INT
4. Race condition detection — TOCTOU on state-changing operations
5. Privilege boundary confusion — mix roles in multi-tenant systems
6. Feature abuse — use intended features for unintended purposes
7. Data validation bypass — inconsistent validation between client/server

OWASP Business Logic Tests (WSTG-BUSL-01 through BUSL-09):
- BUSL-01: Test business logic data validation
- BUSL-02: Test ability to forge requests
- BUSL-03: Test integrity checks
- BUSL-04: Test for process timing
- BUSL-05: Test number of times a function can be used / limits
- BUSL-06: Test circumvention of work flow
- BUSL-07: Test defenses against application misuse
- BUSL-08: Test upload of unexpected file types
- BUSL-09: Test upload of malicious files
- BUSL-10: Test payment functionality (see payment_scanner.py)

SEVERITY: HIGH-CRITICAL — logic bugs frequently = money
- Direct financial loss (price manipulation, free orders)
- Data breach via access control bypass
- Regulatory violations (PCI DSS, SOX, HIPAA)
- Reputation damage

CWE: CWE-840 (Business Logic Errors)
     CWE-841 (Improper Enforcement of Behavioral Workflow)
     CWE-799 (Improper Control of Interaction Frequency)
     CWE-770 (Allocation of Resources Without Limits)
     CWE-362 (Race Condition - TOCTOU)
"""

import asyncio
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import AsyncIterator, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

try:
    import httpx
except ImportError:
    httpx = None

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext

# =============================================================================
# DATA MODELS
# =============================================================================

class LogicTestType(Enum):
    """Types of business logic tests"""
    WORKFLOW_BYPASS = auto()         # BUSL-06: Skip steps
    RATE_LIMIT_ABUSE = auto()        # BUSL-05: No throttling
    NUMERIC_BOUNDARY = auto()        # BUSL-01: INT overflow / negative
    RACE_CONDITION = auto()          # BUSL-04: TOCTOU
    PRIVILEGE_CONFUSION = auto()     # Mixed role actions
    DATA_CONSISTENCY = auto()        # BUSL-03: Integrity checks
    REQUEST_FORGERY = auto()         # BUSL-02: Forged requests
    FEATURE_ABUSE = auto()           # BUSL-07: Application misuse
    FILE_UPLOAD_LOGIC = auto()       # BUSL-08/09: Upload bypass


class RaceConditionStrategy(Enum):
    """Race condition exploitation strategies"""
    PARALLEL_REQUESTS = auto()       # Send N identical requests simultaneously
    LAST_BYTE_SYNC = auto()          # Send all-but-last-byte, release together
    PIPELINE = auto()                # HTTP pipelining for synchronized arrival
    CHUNK_TRANSFER = auto()          # Chunked encoding for timing control


@dataclass
class WorkflowStep:
    """A step in a multi-step workflow"""
    name: str
    url: str
    method: str = "GET"
    required_state: Optional[str] = None  # State from previous step
    produces_state: Optional[str] = None  # State for next step
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    expected_status: int = 200


@dataclass
class LogicTest:
    """A business logic test case"""
    name: str
    test_type: LogicTestType
    description: str
    severity: Severity
    owasp_ref: str = ""            # e.g., "BUSL-06"
    cwe_id: str = ""               # e.g., "CWE-841"


# =============================================================================
# SCANNER
# =============================================================================

class BusinessLogicScanner(BaseScanner):
    """
    Business Logic Vulnerability Scanner.

    Unlike technical vulnerability scanners, this module tests for
    LOGICAL FLAWS in how the application handles workflows, state
    transitions, and business rules.

    Key testing areas:
    1. Numeric boundary testing (negative quantities, INT overflow, zero prices)
    2. Rate limiting (can I call this 1000 times?)
    3. Workflow circumvention (can I skip step 2?)
    4. Race conditions (can I redeem this coupon twice simultaneously?)
    5. Data consistency (does the server actually re-validate prices?)
    6. Privilege confusion (can user A access user B's resources?)
    """

    name = "business_logic"
    description = "Business Logic Vulnerability Scanner (OWASP WSTG-BUSL)"
    version = "1.0.0"
    author = "BEATRIX"

    owasp_category = "WSTG-BUSL"
    mitre_technique = "T1190"

    checks = [
        "Numeric boundary testing (negative, zero, overflow)",
        "Rate limiting / function abuse",
        "Workflow circumvention",
        "Race condition detection",
        "Data consistency validation",
        "Parameter tampering (hidden fields, state params)",
        "HTTP method confusion",
    ]

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.race_concurrency = self.config.get("race_concurrency", 20)
        self.rate_test_count = self.config.get("rate_test_count", 50)
        self.numeric_test_values = self._build_numeric_test_values()

    def _build_numeric_test_values(self) -> List[Tuple[str, str, Severity]]:
        """
        Build numeric boundary test values.

        These values are designed to trigger:
        - Integer overflow on 32-bit and 64-bit signed integers
        - Negative value handling (negative quantities, prices)
        - Zero values (free items, zero-length allocations)
        - Floating point precision issues
        - String-to-number coercion bugs
        """
        return [
            # Negative values
            ("-1", "Negative value", Severity.HIGH),
            ("-100", "Large negative value", Severity.HIGH),
            ("-0.01", "Negative fractional", Severity.HIGH),
            ("-999999", "Very large negative", Severity.HIGH),

            # Zero
            ("0", "Zero value", Severity.MEDIUM),
            ("0.00", "Zero decimal", Severity.MEDIUM),
            ("0e0", "Scientific zero", Severity.MEDIUM),

            # Near-zero fractional
            ("0.001", "Near-zero fractional", Severity.MEDIUM),
            ("0.0000001", "Micro-fractional", Severity.MEDIUM),

            # Integer overflow (32-bit signed max = 2147483647)
            ("2147483647", "INT32_MAX", Severity.MEDIUM),
            ("2147483648", "INT32_MAX + 1 (overflow)", Severity.HIGH),
            ("-2147483648", "INT32_MIN", Severity.MEDIUM),
            ("-2147483649", "INT32_MIN - 1 (underflow)", Severity.HIGH),

            # 64-bit overflow
            ("9999999999999999", "Near INT64_MAX", Severity.HIGH),
            ("9223372036854775807", "INT64_MAX", Severity.MEDIUM),
            ("9223372036854775808", "INT64_MAX + 1", Severity.HIGH),

            # Floating point confusion
            ("1e308", "Float near MAX (may → Infinity)", Severity.HIGH),
            ("1e-308", "Float near MIN (may → 0)", Severity.MEDIUM),
            ("99999999999999999999999", "Exceeds all integer types", Severity.HIGH),
            ("NaN", "Not a Number literal", Severity.MEDIUM),
            ("Infinity", "Infinity literal", Severity.MEDIUM),
            ("-Infinity", "Negative Infinity", Severity.MEDIUM),

            # Type confusion
            ("true", "Boolean true (type juggling)", Severity.LOW),
            ("false", "Boolean false (type juggling)", Severity.LOW),
            ("null", "Null literal", Severity.MEDIUM),
            ("undefined", "Undefined literal", Severity.LOW),
            ("[]", "Empty array", Severity.LOW),
            ("{}", "Empty object", Severity.LOW),

            # Very long numeric strings
            ("9" * 100, "100-digit number (buffer/precision)", Severity.MEDIUM),

            # Special decimal precision
            ("0.1 + 0.2", "Floating point arithmetic string", Severity.LOW),
            ("1.0000000000000001", "Beyond float64 precision", Severity.MEDIUM),
        ]

    # =========================================================================
    # MAIN SCAN
    # =========================================================================

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Run business logic tests against the target.

        Tests are organized by OWASP WSTG-BUSL category:
        1. Numeric boundaries (BUSL-01)
        2. Request forgery detection (BUSL-02)
        3. HTTP method confusion (BUSL-02)
        4. Rate limiting (BUSL-05)
        5. Data consistency (BUSL-03)
        """
        self.log(f"Starting Business Logic scan on {context.url}")
        self.log(f"Parameters: {list(context.parameters.keys())}")

        # Test 1: Numeric boundary testing on all parameters
        async for finding in self._test_numeric_boundaries(context):
            yield finding

        # Test 2: HTTP method confusion
        async for finding in self._test_method_confusion(context):
            yield finding

        # Test 3: Parameter pollution
        async for finding in self._test_parameter_pollution(context):
            yield finding

        # Test 4: Rate limiting
        async for finding in self._test_rate_limiting(context):
            yield finding

        # Test 5: Race conditions
        async for finding in self._test_race_conditions(context):
            yield finding

        self.log("Business logic scan complete")

    async def passive_scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Passive detection of business logic indicators.

        Analyzes the response for:
        - Hidden form fields with state/price/quantity values
        - Client-side validation without server-side enforcement
        - Token/nonce patterns that may be predictable
        - Sequential identifiers vulnerable to enumeration
        """
        if context.response is None:
            return

        response_text = ""
        if hasattr(context.response, 'body'):
            response_text = context.response.body
        elif hasattr(context.response, 'text'):
            response_text = context.response.text

        # Detect hidden form fields with sensitive business data
        hidden_fields = re.findall(
            r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']',
            response_text, re.IGNORECASE
        )

        sensitive_field_patterns = {
            r'price|amount|total|cost|fee': "Price/amount field",
            r'discount|coupon|promo': "Discount/coupon field",
            r'quantity|qty|count': "Quantity field",
            r'role|admin|privilege|permission': "Role/privilege field",
            r'user_?id|account_?id|customer_?id': "User identifier field",
            r'status|state|step|phase': "Workflow state field",
        }

        for field_name, field_value in hidden_fields:
            for pattern, desc in sensitive_field_patterns.items():
                if re.search(pattern, field_name, re.IGNORECASE):
                    yield self.create_finding(
                        title=f"Hidden Form Field Contains Business Data: {field_name}",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.FIRM,
                        url=context.url,
                        description=(
                            f"A hidden form field '{field_name}' (value: '{field_value}') "
                            f"contains {desc} data. Hidden fields can be trivially "
                            f"modified by users.\n\n"
                            f"**Test:** Modify this value and submit the form. If the "
                            f"server accepts the modified value without re-validation, "
                            f"this is a business logic vulnerability.\n\n"
                            f"**Common attacks:**\n"
                            f"- Set price to 0 or negative\n"
                            f"- Change user ID to another user's\n"
                            f"- Skip workflow steps by manipulating state\n"
                            f"- Escalate privileges by changing role field"
                        ),
                        evidence=f"<input type='hidden' name='{field_name}' value='{field_value}'>",
                        references=[
                            "OWASP WSTG-BUSL-01",
                            "CWE-472: External Control of Assumed-Immutable Web Parameter",
                        ],
                    )
                    break

        # Detect sequential/predictable identifiers
        # Look for numeric IDs in URLs or parameters that could be enumerated
        for param_name, param_value in context.parameters.items():
            if re.match(r'^\d+$', param_value):
                id_val = int(param_value)
                if 1 <= id_val <= 999999:  # Reasonable ID range
                    for pattern in [r'id$', r'_id$', r'^id_', r'user', r'account', r'order']:
                        if re.search(pattern, param_name, re.IGNORECASE):
                            yield self.create_finding(
                                title=f"Sequential Identifier in Parameter: {param_name}={param_value}",
                                severity=Severity.LOW,
                                confidence=Confidence.TENTATIVE,
                                url=context.url,
                                description=(
                                    f"Parameter '{param_name}' contains a sequential numeric "
                                    f"identifier ({param_value}). Sequential IDs are vulnerable "
                                    f"to IDOR enumeration.\n\n"
                                    f"**Test:** Try {param_name}={id_val-1} and {param_name}={id_val+1} "
                                    f"to check if other users' data is accessible.\n\n"
                                    f"Consider using UUIDs instead of sequential integers."
                                ),
                                evidence=f"{param_name}={param_value}",
                                references=[
                                    "OWASP WSTG-BUSL-02",
                                    "CWE-639: Authorization Bypass Through User-Controlled Key",
                                ],
                            )
                            break

    # =========================================================================
    # NUMERIC BOUNDARY TESTING (BUSL-01)
    # =========================================================================

    async def _test_numeric_boundaries(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Test all parameters with boundary values.

        The key insight: most applications validate on the client side but
        trust values that arrive at the server. We test if the server
        accepts values that should be logically impossible.
        """
        self.log("Testing numeric boundaries (BUSL-01)")

        # Identify parameters likely to accept numeric values
        numeric_param_patterns = [
            r'quantity|qty|count|num|number|amount',
            r'price|cost|total|subtotal|fee|rate',
            r'id|user_?id|item_?id|product_?id|order_?id',
            r'page|limit|offset|size|per_page|page_size',
            r'discount|coupon_value|credits',
            r'rating|score|rank|priority|weight',
        ]

        for param_name, original_value in context.parameters.items():
            # Check if this parameter looks numeric or matches patterns
            is_numeric_param = any(
                re.search(p, param_name, re.IGNORECASE)
                for p in numeric_param_patterns
            )
            is_numeric_value = bool(re.match(r'^-?\d+(\.\d+)?$', original_value))

            if not (is_numeric_param or is_numeric_value):
                continue

            self.log(f"  Numeric testing: {param_name}={original_value}")

            # Get baseline response
            baseline_response = await self.get(
                context.base_url + urlparse(context.url).path,
                params=context.parameters,
            )
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.text)

            # Test each boundary value
            for test_value, test_desc, test_severity in self.numeric_test_values:
                try:
                    params = dict(context.parameters)
                    params[param_name] = test_value

                    response = await self.get(
                        context.base_url + urlparse(context.url).path,
                        params=params,
                    )

                    # Analyze response — look for acceptance of invalid values
                    accepted = False
                    analysis = ""

                    if response.status_code == 200:
                        # Server accepted the value — check if it actually processed it
                        # vs just ignoring it / showing error in body

                        # Look for error indicators
                        error_patterns = [
                            r'invalid|error|fail|illegal|out.of.range|not.allowed',
                            r'must be|cannot|unable|exception',
                        ]
                        has_error = any(
                            re.search(p, response.text[:2000], re.IGNORECASE)
                            for p in error_patterns
                        )

                        if not has_error:
                            # Check content-length difference
                            resp_length = len(response.text)
                            length_diff = abs(resp_length - baseline_length)

                            if length_diff < baseline_length * 0.5:
                                # Response is similar size — may have been accepted
                                accepted = True
                                analysis = (
                                    f"Server returned HTTP 200 with similar response "
                                    f"(Δ{length_diff} bytes). The {test_desc} value "
                                    f"'{test_value}' appears to have been accepted."
                                )

                    elif response.status_code == baseline_status:
                        # Same status as baseline — might have been accepted
                        accepted = True
                        analysis = (
                            f"Server returned same status ({response.status_code}) "
                            f"as baseline. The {test_desc} value may be accepted."
                        )

                    if accepted and test_value in ["-1", "-100", "0", "-999999", "0.00"]:
                        yield self.create_finding(
                            title=f"Parameter '{param_name}' Accepts {test_desc}: {test_value}",
                            severity=test_severity,
                            confidence=Confidence.TENTATIVE,
                            url=context.url,
                            description=(
                                f"**Business Logic: {test_desc}**\n\n"
                                f"Parameter '{param_name}' (original: '{original_value}') "
                                f"accepted the value '{test_value}' without error.\n\n"
                                f"{analysis}\n\n"
                                f"**Potential Impact:**\n"
                                f"- Negative quantities → negative charges (refund)\n"
                                f"- Zero prices → free items\n"
                                f"- Integer overflow → unexpected behavior\n\n"
                                f"**Manual verification required** — check if the value actually "
                                f"affected business logic (e.g., check calculated total)."
                            ),
                            evidence=f"{param_name}={test_value} → HTTP {response.status_code}",
                            request=(
                                f"GET {context.url}?{param_name}={test_value}"
                            ),
                            references=[
                                "OWASP WSTG-BUSL-01",
                                "CWE-20: Improper Input Validation",
                            ],
                        )

                    await asyncio.sleep(0.3)

                except Exception as e:
                    self.log(f"    Error testing {test_desc}: {e}")

    # =========================================================================
    # HTTP METHOD CONFUSION (BUSL-02)
    # =========================================================================

    async def _test_method_confusion(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Test if the endpoint responds differently to unexpected HTTP methods.

        Many frameworks route differently based on method. A GET endpoint
        that also responds to DELETE could be dangerous.
        """
        self.log("Testing HTTP method confusion (BUSL-02)")

        methods_to_test = ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        original_method = context.request.method.upper()

        # Baseline
        try:
            await self.request(original_method, context.url)
        except Exception:
            return

        for method in methods_to_test:
            if method == original_method:
                continue

            try:
                response = await self.request(method, context.url)

                # Interesting if: method accepted (200), or different behavior
                if response.status_code == 200 and method in ("DELETE", "PUT", "PATCH"):
                    yield self.create_finding(
                        title=f"Endpoint Accepts {method} Method (originally {original_method})",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.TENTATIVE,
                        url=context.url,
                        description=(
                            f"The endpoint at {context.url} accepts {method} requests "
                            f"in addition to {original_method}.\n\n"
                            f"If this is unintended, it could allow:\n"
                            f"- DELETE: Unauthorized data deletion\n"
                            f"- PUT/PATCH: Unauthorized data modification\n"
                            f"- POST: Replay attacks / duplicate actions\n\n"
                            f"**Manual verification:** Confirm endpoint behavior differs per method."
                        ),
                        evidence=f"{method} {context.url} → HTTP {response.status_code}",
                        remediation=(
                            "1. Explicitly restrict HTTP methods per endpoint\n"
                            "2. Return 405 Method Not Allowed for unsupported methods\n"
                            "3. Include Allow header with supported methods"
                        ),
                        references=[
                            "OWASP WSTG-BUSL-02",
                            "CWE-749: Exposed Dangerous Method or Function",
                        ],
                    )

                await asyncio.sleep(0.3)

            except Exception:
                continue

    # =========================================================================
    # PARAMETER POLLUTION (BUSL-02)
    # =========================================================================

    async def _test_parameter_pollution(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Test HTTP Parameter Pollution (HPP).

        Sending the same parameter multiple times can cause different behavior
        depending on the framework:
        - PHP/Apache: uses LAST value
        - ASP.NET/IIS: uses ALL values (comma-separated)
        - Python/Flask: uses FIRST value
        - Node.js/Express: uses FIRST value (or array)

        This inconsistency between front-end and back-end is exploitable.
        """
        self.log("Testing parameter pollution (BUSL-02)")

        for param_name, original_value in context.parameters.items():
            try:
                # Test with duplicate parameter
                # Build URL manually to include duplicate params
                base_path = context.base_url + urlparse(context.url).path
                other_params = {k: v for k, v in context.parameters.items() if k != param_name}

                # First value wins vs Last value wins
                test_url = base_path + "?"
                if other_params:
                    test_url += urlencode(other_params) + "&"
                test_url += f"{param_name}=FIRST&{param_name}=LAST"

                response = await self.get(test_url)

                if response.status_code == 200:
                    body = response.text.lower()

                    if "first" in body and "last" not in body:
                        priority = "FIRST"
                    elif "last" in body and "first" not in body:
                        priority = "LAST"
                    elif "first" in body and "last" in body:
                        priority = "BOTH (concatenated)"
                    else:
                        priority = "NEITHER (may be ignored)"

                    if priority in ("FIRST", "LAST", "BOTH (concatenated)"):
                        yield self.create_finding(
                            title=f"HTTP Parameter Pollution: {param_name} uses {priority} value",
                            severity=Severity.LOW,
                            confidence=Confidence.FIRM,
                            url=context.url,
                            description=(
                                f"When parameter '{param_name}' is sent twice, the server "
                                f"uses the {priority} value. This behavior can be exploited "
                                f"when a front-end proxy and back-end application handle "
                                f"duplicate parameters differently.\n\n"
                                f"**Attack scenario:** If a WAF validates the FIRST value "
                                f"but the application uses the LAST, the WAF check is bypassed."
                            ),
                            evidence=f"{param_name}=FIRST&{param_name}=LAST → uses {priority}",
                            references=[
                                "OWASP WSTG-BUSL-02",
                                "CWE-235: Improper Handling of Extra Parameters",
                            ],
                        )

                await asyncio.sleep(0.3)

            except Exception as e:
                self.log(f"  HPP error for {param_name}: {e}")

    # =========================================================================
    # RATE LIMITING (BUSL-05)
    # =========================================================================

    async def _test_rate_limiting(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Test if the endpoint has rate limiting.

        Sends multiple rapid requests and checks if any are blocked.
        Lack of rate limiting on sensitive endpoints enables:
        - Brute force attacks (login, OTP, password reset)
        - Coupon/promo code brute force
        - Resource exhaustion
        - Enumeration attacks
        """
        self.log(f"Testing rate limiting (BUSL-05) — sending {self.rate_test_count} requests")

        # Detect what kind of endpoint this is
        url_lower = context.url.lower()
        is_sensitive = any(p in url_lower for p in [
            'login', 'auth', 'password', 'reset', 'otp', 'verify',
            'coupon', 'promo', 'discount', 'redeem', 'checkout',
            'transfer', 'payment', 'api/v',
        ])

        if not is_sensitive:
            self.log("  Skipping rate limit test — endpoint doesn't appear sensitive")
            return

        statuses: List[int] = []
        start_time = time.monotonic()
        blocked = False

        try:
            for i in range(self.rate_test_count):
                response = await self.get(context.url, params=context.parameters)
                statuses.append(response.status_code)

                # Check for rate limit response
                if response.status_code in (429, 503):
                    blocked = True
                    self.log(f"  Rate limited at request #{i+1}")
                    break

                # Check for CAPTCHA or block page indicators
                if any(indicator in response.text.lower() for indicator in [
                    'captcha', 'rate limit', 'too many requests',
                    'please try again later', 'blocked', 'security check',
                ]):
                    blocked = True
                    self.log(f"  Soft rate limit at request #{i+1}")
                    break

                # Don't sleep — we want to test rapid-fire

            elapsed = time.monotonic() - start_time
            rps = len(statuses) / elapsed if elapsed > 0 else 0

            if not blocked and len(statuses) >= self.rate_test_count:
                yield self.create_finding(
                    title="No Rate Limiting on Sensitive Endpoint",
                    severity=Severity.HIGH if is_sensitive else Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    url=context.url,
                    description=(
                        f"**No rate limiting detected** after {len(statuses)} consecutive "
                        f"requests at {rps:.0f} requests/second.\n\n"
                        f"All requests returned similar status codes "
                        f"({', '.join(str(s) for s in set(statuses))}). "
                        f"No HTTP 429, CAPTCHA, or blocking was observed.\n\n"
                        f"**Impact on this endpoint:**\n"
                        f"- Brute force attacks on authentication\n"
                        f"- Credential stuffing at scale\n"
                        f"- OTP/verification code brute force\n"
                        f"- Coupon/promo code enumeration\n"
                        f"- API abuse / resource exhaustion"
                    ),
                    evidence=(
                        f"{len(statuses)} requests in {elapsed:.1f}s ({rps:.0f} rps), "
                        f"0 blocked"
                    ),
                    remediation=(
                        "1. Implement rate limiting (e.g., 10 req/min for auth endpoints)\n"
                        "2. Use exponential backoff after failed attempts\n"
                        "3. Implement CAPTCHA after N failures\n"
                        "4. Consider account lockout after threshold\n"
                        "5. Use a WAF with rate limiting rules\n"
                        "6. Per PCI DSS Req 8.3.4: Lock account after ≤10 invalid attempts"
                    ),
                    references=[
                        "OWASP WSTG-BUSL-05",
                        "CWE-799: Improper Control of Interaction Frequency",
                        "CWE-307: Improper Restriction of Excessive Authentication Attempts",
                        "PCI DSS v4.0.1 Req 8.3.4",
                    ],
                )

            elif blocked:
                block_point = len(statuses)
                yield self.create_finding(
                    title=f"Rate Limiting Active (after {block_point} requests)",
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    url=context.url,
                    description=(
                        f"Rate limiting kicked in after {block_point} requests. "
                        f"This is GOOD security practice.\n\n"
                        f"Consider if {block_point} is sufficiently restrictive "
                        f"for the sensitivity of this endpoint."
                    ),
                )

        except Exception as e:
            self.log(f"  Rate limit test error: {e}")

    # =========================================================================
    # RACE CONDITIONS (BUSL-04)
    # =========================================================================

    async def _test_race_conditions(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Test for race conditions (TOCTOU bugs).

        Sends multiple identical requests simultaneously to detect if
        the application properly handles concurrent access to shared state.

        Common race condition targets:
        - Coupon/discount redemption (redeem 1 code N times)
        - Balance deductions (withdraw N * balance)
        - Invite codes (use single-use code multiple times)
        - Like/vote operations (vote multiple times)
        - File uploads (overwrite race)
        """
        self.log(f"Testing race conditions (BUSL-04) — {self.race_concurrency} concurrent requests")

        # Detect if this endpoint is a state-changing operation
        url_lower = context.url.lower()
        is_state_changing = any(p in url_lower for p in [
            'redeem', 'apply', 'coupon', 'discount', 'promo',
            'transfer', 'withdraw', 'deposit', 'checkout',
            'vote', 'like', 'follow', 'invite', 'claim',
            'purchase', 'buy', 'order', 'book', 'reserve',
        ])

        if not is_state_changing and context.request.method == "GET":
            self.log("  Skipping race condition test — endpoint doesn't appear state-changing")
            return

        try:
            # Send N concurrent requests
            tasks = []
            for _ in range(self.race_concurrency):
                tasks.append(self.get(context.url, params=context.parameters))

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            # Analyze responses
            successful = [r for r in responses if isinstance(r, httpx.Response) and r.status_code == 200]
            errors = [r for r in responses if isinstance(r, Exception)]

            statuses = [r.status_code for r in responses if isinstance(r, httpx.Response)]
            unique_statuses = set(statuses)

            if len(successful) > 1 and is_state_changing:
                # Multiple successful responses to a state-changing endpoint
                # This MIGHT indicate a race condition

                # Check if response bodies are identical or different
                bodies = [r.text[:500] for r in successful]
                unique_bodies = len(set(bodies))

                yield self.create_finding(
                    title=f"Potential Race Condition ({len(successful)}/{self.race_concurrency} succeeded)",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.TENTATIVE,
                    url=context.url,
                    description=(
                        f"**Race Condition Test Results:**\n\n"
                        f"- Concurrent requests: {self.race_concurrency}\n"
                        f"- Successful (HTTP 200): {len(successful)}\n"
                        f"- Errors: {len(errors)}\n"
                        f"- Unique status codes: {unique_statuses}\n"
                        f"- Unique response bodies: {unique_bodies}\n\n"
                        f"Multiple requests to this state-changing endpoint succeeded "
                        f"simultaneously. If the endpoint performs a one-time operation "
                        f"(e.g., redeem coupon, apply discount, transfer funds), processing "
                        f"multiple instances is a **race condition vulnerability**.\n\n"
                        f"**Manual verification required:** Check if the operation was "
                        f"actually performed multiple times (e.g., check account balance, "
                        f"coupon status, order count)."
                    ),
                    evidence=(
                        f"{len(successful)} successful concurrent requests, "
                        f"{unique_bodies} unique response bodies"
                    ),
                    remediation=(
                        "1. Use database-level locking (SELECT FOR UPDATE)\n"
                        "2. Implement idempotency keys for state-changing operations\n"
                        "3. Use optimistic concurrency control (version stamps)\n"
                        "4. Apply mutex/semaphore at the application level\n"
                        "5. Use database transactions with appropriate isolation level"
                    ),
                    references=[
                        "OWASP WSTG-BUSL-04",
                        "CWE-362: Concurrent Execution using Shared Resource",
                        "CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition",
                    ],
                )

        except Exception as e:
            self.log(f"  Race condition test error: {e}")
