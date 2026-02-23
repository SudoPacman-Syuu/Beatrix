"""
BEATRIX Injection Scanner

Tests for common injection vulnerabilities:
- SQL Injection (error-based, blind, time-based)
- XSS (reflected, stored indicators)
- Command Injection
- SSTI (Server-Side Template Injection)
- Path Traversal

Uses insertion points from InsertionPointDetector.
Inspired by Burp's active scanner approach.
"""

import re
import time
from dataclasses import dataclass
from typing import AsyncIterator, Dict, List, Optional, Tuple

from beatrix.core.types import Confidence, Finding, InsertionPoint, InsertionPointType, Severity

from .base import BaseScanner, ScanContext
from .insertion import InsertionPointDetector, ParsedRequest


@dataclass
class Payload:
    """Injection test payload"""
    value: str
    name: str
    category: str  # sqli, xss, cmdi, ssti, path
    detection: str  # error, reflect, time, behavior
    patterns: List[str]  # Regex patterns to detect success
    severity: Severity
    time_threshold: float = 0  # For time-based detection


class InjectionScanner(BaseScanner):
    """
    Multi-vector injection scanner.

    Tests insertion points with payloads for:
    - SQL Injection
    - Cross-Site Scripting (XSS)
    - Command Injection
    - Server-Side Template Injection
    - Path Traversal
    """

    name = "injection"
    description = "Multi-vector injection scanner"
    version = "1.0.0"

    checks = ["sqli", "xss", "cmdi", "ssti", "path_traversal"]

    owasp_category = "A03:2021"  # Injection

    def __init__(self, config=None):
        super().__init__(config)
        self.insertion_detector = InsertionPointDetector(config)
        self._seclists = None
        self._init_seclists()
        self.payloads = self._load_payloads()

    def _init_seclists(self):
        """Initialize SecLists manager for dynamic wordlist fetching."""
        try:
            from beatrix.core.seclists_manager import get_manager
            self._seclists = get_manager(verbose=True)
            self.log("SecLists manager initialized — dynamic wordlists enabled")
        except Exception as e:
            self.log(f"SecLists manager unavailable, using built-in payloads: {e}")
            self._seclists = None

    def _load_payloads(self) -> Dict[str, List[Payload]]:
        """Load injection payloads by category, augmented with dynamic wordlists."""

        base_payloads = self._load_builtin_payloads()

        # Augment with dynamic wordlists from SecLists if available
        if self._seclists:
            self._augment_with_seclists(base_payloads)

        return base_payloads

    def _augment_with_seclists(self, payloads: Dict[str, List[Payload]]) -> None:
        """Fetch and merge external wordlists into the payload dict."""
        category_map = {
            "sqli": ("sqli", "error", Severity.HIGH),
            "xss": ("xss", "reflect", Severity.MEDIUM),
            "cmdi": ("cmdi", "reflect", Severity.CRITICAL),
            "ssti": ("ssti", "reflect", Severity.HIGH),
            "path": ("lfi", "reflect", Severity.HIGH),
        }

        detection_patterns = {
            "sqli": [
                r"SQL syntax.*MySQL", r"Warning.*mysql_", r"PostgreSQL.*ERROR",
                r"ORA-\d{5}", r"Microsoft.*ODBC.*SQL Server", r"SQLSTATE\[",
                r"Unclosed quotation mark",
            ],
            "xss": [],  # Reflection-based, payload itself is the pattern
            "cmdi": [r"uid=\d+.*gid=\d+"],
            "ssti": [r"8348842383"],  # Canary multiplication result
            "path": [r"root:.*:0:0:", r"/bin/bash", r"\[fonts\]"],
        }

        for payload_cat, (seclists_cat, detect_method, sev) in category_map.items():
            try:
                extra_payloads = self._seclists.get_by_category(seclists_cat)
                existing_values = {p.value for p in payloads.get(payload_cat, [])}
                added = 0

                for raw_payload in extra_payloads:
                    if raw_payload not in existing_values:
                        patterns = detection_patterns.get(payload_cat, [])
                        # For XSS reflection checks, use escaped payload as pattern
                        if payload_cat == "xss" and not patterns:
                            patterns = [re.escape(raw_payload)]

                        payloads.setdefault(payload_cat, []).append(Payload(
                            value=raw_payload,
                            name=f"seclists_{payload_cat}_{added}",
                            category=payload_cat,
                            detection=detect_method,
                            patterns=patterns,
                            severity=sev,
                        ))
                        existing_values.add(raw_payload)
                        added += 1

                if added:
                    self.log(f"Augmented {payload_cat} with {added} dynamic payloads from SecLists")
            except Exception as e:
                self.log(f"Failed to augment {payload_cat} from SecLists: {e}")

    def _load_builtin_payloads(self) -> Dict[str, List[Payload]]:
        """Load built-in injection payloads by category"""

        return {
            "sqli": [
                # Error-based SQLi
                Payload(
                    value="'",
                    name="single_quote",
                    category="sqli",
                    detection="error",
                    patterns=[
                        r"SQL syntax.*MySQL",
                        r"Warning.*mysql_",
                        r"PostgreSQL.*ERROR",
                        r"ORA-\d{5}",
                        r"Microsoft.*ODBC.*SQL Server",
                        r"SQLite3::SQLException",
                        r"SQLSTATE\[",
                        r"Unclosed quotation mark",
                        r"quoted string not properly terminated",
                    ],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="1' OR '1'='1",
                    name="or_true",
                    category="sqli",
                    detection="behavior",
                    patterns=[],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="1 AND 1=1--",
                    name="and_true",
                    category="sqli",
                    detection="behavior",
                    patterns=[],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="' OR ''='",
                    name="or_empty",
                    category="sqli",
                    detection="behavior",
                    patterns=[],
                    severity=Severity.HIGH,
                ),
                # Time-based blind SQLi
                Payload(
                    value="' OR SLEEP(5)--",
                    name="sleep_mysql",
                    category="sqli",
                    detection="time",
                    patterns=[],
                    severity=Severity.HIGH,
                    time_threshold=4.5,
                ),
                Payload(
                    value="'; WAITFOR DELAY '0:0:5'--",
                    name="waitfor_mssql",
                    category="sqli",
                    detection="time",
                    patterns=[],
                    severity=Severity.HIGH,
                    time_threshold=4.5,
                ),
                Payload(
                    value="' || pg_sleep(5)--",
                    name="sleep_postgres",
                    category="sqli",
                    detection="time",
                    patterns=[],
                    severity=Severity.HIGH,
                    time_threshold=4.5,
                ),
            ],

            "xss": [
                # Reflected XSS probes
                Payload(
                    value="<script>alert(1)</script>",
                    name="script_tag",
                    category="xss",
                    detection="reflect",
                    patterns=[r"<script>alert\(1\)</script>"],
                    severity=Severity.MEDIUM,
                ),
                Payload(
                    value='"><img src=x onerror=alert(1)>',
                    name="img_onerror",
                    category="xss",
                    detection="reflect",
                    patterns=[r'"><img src=x onerror=alert\(1\)>'],
                    severity=Severity.MEDIUM,
                ),
                Payload(
                    value="javascript:alert(1)",
                    name="javascript_uri",
                    category="xss",
                    detection="reflect",
                    patterns=[r"javascript:alert\(1\)"],
                    severity=Severity.MEDIUM,
                ),
                Payload(
                    value="'-alert(1)-'",
                    name="js_context",
                    category="xss",
                    detection="reflect",
                    patterns=[r"'-alert\(1\)-'"],
                    severity=Severity.MEDIUM,
                ),
                # Canary for detection
                Payload(
                    value="bx<>\"'`rx",
                    name="xss_canary",
                    category="xss",
                    detection="reflect",
                    patterns=[r"bx<>\"'`rx", r"bx&lt;&gt;", r"bx<>"],
                    severity=Severity.LOW,  # Just detection
                ),
            ],

            "cmdi": [
                # Command injection
                Payload(
                    value="; id",
                    name="semicolon_id",
                    category="cmdi",
                    detection="reflect",
                    patterns=[r"uid=\d+.*gid=\d+"],
                    severity=Severity.CRITICAL,
                ),
                Payload(
                    value="| id",
                    name="pipe_id",
                    category="cmdi",
                    detection="reflect",
                    patterns=[r"uid=\d+.*gid=\d+"],
                    severity=Severity.CRITICAL,
                ),
                Payload(
                    value="$(id)",
                    name="subshell_id",
                    category="cmdi",
                    detection="reflect",
                    patterns=[r"uid=\d+.*gid=\d+"],
                    severity=Severity.CRITICAL,
                ),
                Payload(
                    value="`id`",
                    name="backtick_id",
                    category="cmdi",
                    detection="reflect",
                    patterns=[r"uid=\d+.*gid=\d+"],
                    severity=Severity.CRITICAL,
                ),
                # Time-based
                Payload(
                    value="; sleep 5",
                    name="sleep_semicolon",
                    category="cmdi",
                    detection="time",
                    patterns=[],
                    severity=Severity.CRITICAL,
                    time_threshold=4.5,
                ),
                Payload(
                    value="| sleep 5",
                    name="sleep_pipe",
                    category="cmdi",
                    detection="time",
                    patterns=[],
                    severity=Severity.CRITICAL,
                    time_threshold=4.5,
                ),
            ],

            "ssti": [
                # Server-Side Template Injection
                # Use unique canary values to avoid false positives (NOT 7*7=49 which matches everywhere)
                Payload(
                    value="{{91371*91373}}",
                    name="jinja_multiply",
                    category="ssti",
                    detection="reflect",
                    patterns=[r"8348842383"],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="${91371*91373}",
                    name="freemarker_multiply",
                    category="ssti",
                    detection="reflect",
                    patterns=[r"8348842383"],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="<%= 91371*91373 %>",
                    name="erb_multiply",
                    category="ssti",
                    detection="reflect",
                    patterns=[r"8348842383"],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="#{91371*91373}",
                    name="ruby_multiply",
                    category="ssti",
                    detection="reflect",
                    patterns=[r"8348842383"],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="{{constructor.constructor('return this')()}}",
                    name="angular_escape",
                    category="ssti",
                    detection="error",
                    patterns=[r"\[object Window\]", r"\[object Object\]"],
                    severity=Severity.HIGH,
                ),
            ],

            "path": [
                # Path Traversal
                Payload(
                    value="../../../etc/passwd",
                    name="etc_passwd_unix",
                    category="path",
                    detection="reflect",
                    patterns=[r"root:.*:0:0:", r"/bin/bash", r"/bin/sh"],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="..\\..\\..\\windows\\win.ini",
                    name="win_ini",
                    category="path",
                    detection="reflect",
                    patterns=[r"\[fonts\]", r"\[extensions\]"],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="....//....//....//etc/passwd",
                    name="double_encoding",
                    category="path",
                    detection="reflect",
                    patterns=[r"root:.*:0:0:"],
                    severity=Severity.HIGH,
                ),
                Payload(
                    value="..%252f..%252f..%252fetc/passwd",
                    name="double_url_encode",
                    category="path",
                    detection="reflect",
                    patterns=[r"root:.*:0:0:"],
                    severity=Severity.HIGH,
                ),
            ],
        }

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Main injection scan - test all insertion points.
        """
        self.log(f"Starting injection scan on {context.url}")

        # Parse request
        request = self.insertion_detector.parse_request(
            method=context.request.method,
            url=context.url,
            headers=dict(context.headers),
            body=context.request.body,
        )

        # Detect insertion points
        insertion_points = self.insertion_detector.detect(request)
        self.log(f"Found {len(insertion_points)} insertion points")

        # Test each insertion point
        for ip in insertion_points:
            async for finding in self._test_insertion_point(request, ip):
                yield finding

    async def _test_insertion_point(
        self,
        request: ParsedRequest,
        insertion_point: InsertionPoint,
    ) -> AsyncIterator[Finding]:
        """Test a single insertion point with all relevant payloads"""

        # Determine which payload categories to test
        categories = self._select_categories(insertion_point)
        baseline_time = 0.0

        for category in categories:
            payloads = self.payloads.get(category, [])

            for payload in payloads:
                # Calculate baseline if needed and not yet done
                if payload.detection == "time" and baseline_time <= 0:
                    try:
                        bstart = time.time()
                        await self.request(
                            request.method,
                            request.url,
                            headers=dict(request.headers),
                            content=request.body if request.body else None,
                        )
                        baseline_time = time.time() - bstart
                    except Exception:
                        baseline_time = 0.5  # conservative default

                finding = await self._test_payload(request, insertion_point, payload, baseline_time)
                if finding:
                    yield finding
                    # Stop testing this category for this IP if we found something
                    break

    def _select_categories(self, ip: InsertionPoint) -> List[str]:
        """Select payload categories based on insertion point type"""

        # URL and body params get everything
        if ip.type in [InsertionPointType.URL_PARAM, InsertionPointType.BODY_PARAM, InsertionPointType.JSON_VALUE]:
            return ["sqli", "xss", "ssti", "cmdi", "path"]

        # Headers get limited testing
        if ip.type == InsertionPointType.HEADER:
            if ip.name.lower() in ["user-agent", "referer"]:
                return ["sqli", "xss", "ssti"]
            if ip.name.lower() in ["x-forwarded-for", "x-real-ip"]:
                return ["sqli", "cmdi"]
            return ["sqli"]

        # Cookies
        if ip.type == InsertionPointType.COOKIE:
            return ["sqli", "xss"]

        # Path segments
        if ip.type == InsertionPointType.URL_PATH:
            return ["path", "sqli"]

        return ["sqli", "xss"]

    async def _test_payload(
        self,
        request: ParsedRequest,
        ip: InsertionPoint,
        payload: Payload,
        baseline_time: float = 0.0,
    ) -> Optional[Finding]:
        """Test a single payload against an insertion point"""

        try:
            # Build modified request
            url, headers, body = self.insertion_detector.build_request_with_payload(
                request, ip, payload.value
            )

            # Time the request
            start = time.time()
            response = await self.request(
                request.method,
                url,
                headers=headers,
                content=body if body else None,
            )
            elapsed = time.time() - start

            # Check for vulnerability
            is_vuln, evidence = self._check_response(
                payload, response.text, elapsed, baseline_time
            )

            if is_vuln:
                # ── Confirmation pass for time-based findings ─────────────
                # A single slow response can be network jitter. Re-test 2 more
                # times and require at least 2/3 total to show consistent delay.
                if payload.detection == "time":
                    confirm_count = 1  # First test already passed
                    for _ in range(2):
                        try:
                            cstart = time.time()
                            cresp = await self.request(
                                request.method,
                                url,
                                headers=headers,
                                content=body if body else None,
                            )
                            celapsed = time.time() - cstart
                            c_vuln, _ = self._check_response(
                                payload, cresp.text, celapsed, baseline_time
                            )
                            if c_vuln:
                                confirm_count += 1
                        except Exception:
                            pass
                    if confirm_count < 2:
                        self.log(f"Time-based finding NOT confirmed ({confirm_count}/3 passed) — skipping {payload.name}")
                        return None
                    evidence += f"\nConfirmed: {confirm_count}/3 samples showed consistent delay"

                return self._create_injection_finding(
                    url, request, ip, payload, response, evidence
                )

        except Exception as e:
            self.log(f"Error testing {payload.name}: {e}")

        return None

    def _check_response(
        self,
        payload: Payload,
        response_text: str,
        elapsed: float,
        baseline_time: float = 0.0,
    ) -> Tuple[bool, str]:
        """
        Check if the response indicates a vulnerability.

        Returns (is_vulnerable, evidence)
        """

        # Time-based detection — MUST compare against baseline
        if payload.detection == "time":
            # Calculate the actual delay introduced by our payload
            injected_delay = elapsed - baseline_time

            # Only flag if the injected delay is close to the expected threshold
            # AND significantly above baseline. This prevents false positives from
            # naturally slow endpoints.
            if baseline_time > 0:
                # Require: response took at least (threshold) seconds longer than baseline
                if injected_delay >= payload.time_threshold * 0.8:
                    return True, (
                        f"Response time: {elapsed:.2f}s (baseline: {baseline_time:.2f}s, "
                        f"injected delay: {injected_delay:.2f}s, threshold: {payload.time_threshold}s)"
                    )
            else:
                # No baseline available — require very high threshold to compensate
                if elapsed >= payload.time_threshold + 3.0:
                    return True, (
                        f"Response time: {elapsed:.2f}s (no baseline, "
                        f"threshold: {payload.time_threshold}s + 3s safety buffer)"
                    )

        # Pattern-based detection
        if payload.detection in ["error", "reflect"]:
            for pattern in payload.patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    # Get context around match
                    start = max(0, match.start() - 50)
                    end = min(len(response_text), match.end() + 50)
                    context = response_text[start:end]
                    return True, f"Pattern matched: {pattern}\nContext: ...{context}..."

        return False, ""

    def _create_injection_finding(
        self,
        url: str,
        request: ParsedRequest,
        ip: InsertionPoint,
        payload: Payload,
        response,
        evidence: str,
    ) -> Finding:
        """Create an injection vulnerability finding"""

        category_names = {
            "sqli": "SQL Injection",
            "xss": "Cross-Site Scripting (XSS)",
            "cmdi": "Command Injection",
            "ssti": "Server-Side Template Injection",
            "path": "Path Traversal",
        }

        category_desc = {
            "sqli": "The application appears vulnerable to SQL injection. An attacker could extract, modify, or delete database contents.",
            "xss": "The application reflects user input without proper encoding. An attacker could execute JavaScript in victims' browsers.",
            "cmdi": "The application executes user-controlled input as system commands. An attacker could execute arbitrary commands on the server.",
            "ssti": "The application processes user input in a server-side template engine. An attacker could execute arbitrary code on the server.",
            "path": "The application allows traversing outside the intended directory. An attacker could read sensitive files from the server.",
        }

        remediation_map = {
            "sqli": "Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
            "xss": "Encode output based on context (HTML, JavaScript, URL). Use Content-Security-Policy headers.",
            "cmdi": "Avoid passing user input to system commands. If necessary, use strict allowlisting.",
            "ssti": "Avoid passing user input to template engines. Use sandboxed template engines if needed.",
            "path": "Validate and sanitize file paths. Use allowlisting for permitted files/directories.",
        }

        return self.create_finding(
            title=f"{category_names[payload.category]} in {ip.type.value}: {ip.name}",
            severity=payload.severity,
            confidence=Confidence.FIRM if payload.detection == "time" else Confidence.CERTAIN,
            url=url,
            description=f"{category_desc[payload.category]}\n\nVulnerable parameter: {ip.name}\nPayload: {payload.value}\nDetection method: {payload.detection}",
            evidence=evidence,
            request=f"{request.method} {url}\n\nPayload: {payload.value}\nInjection point: {ip.name} ({ip.type.value})",
            response=f"HTTP {response.status_code}\n\n{response.text[:1000]}...",
            remediation=remediation_map.get(payload.category, "Implement proper input validation and output encoding."),
            references=[
                f"https://owasp.org/www-community/attacks/{payload.category.upper()}_Attacks" if payload.category != "path" else "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://portswigger.net/web-security",
            ],
        )

    async def quick_sqli_check(self, url: str) -> AsyncIterator[Finding]:
        """
        Quick SQLi check - just test URL params with basic payloads.
        Useful for rapid scanning.
        """
        ScanContext.from_url(url)
        request = self.insertion_detector.parse_request(
            method="GET",
            url=url,
            headers={"User-Agent": "Mozilla/5.0"},
            body=b"",
        )

        for name, value in request.url_params.items():
            ip = InsertionPoint(
                name=name,
                value=value,
                type=InsertionPointType.URL_PARAM,
                original_request=None,
                position=(0, 0),
            )

            # Just test single quote error
            payload = self.payloads["sqli"][0]  # single quote
            finding = await self._test_payload(request, ip, payload)
            if finding:
                yield finding
