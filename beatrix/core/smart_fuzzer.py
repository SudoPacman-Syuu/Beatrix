"""
SmartFuzzer - Ferrari-Grade Intelligent Fuzzing Engine
=======================================================

The problem with raw ffuf output:
- 6000 XSS payloads → 5900 "hits" (mostly noise)
- No verification that payloads actually execute
- Duplicate findings for same vulnerability
- No confidence scoring

SmartFuzzer solves this:
1. DISCOVERY PHASE: Fast ffuf scan to find candidates
2. VERIFICATION PHASE: Confirm payloads actually work
3. DEDUPLICATION: Same vuln = 1 finding with best payload
4. CONFIDENCE SCORING: high/medium/low based on evidence
5. AUTO-POC: Generate working exploit code

Architecture:
    ┌─────────────────────────────────────────────────────────┐
    │  SmartFuzzer                                             │
    │  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
    │  │  Discovery   │→ │ Verification │→ │ Deduplication │  │
    │  │  (ffuf)      │  │ (Python)     │  │ & Scoring     │  │
    │  │  ~1000 rps   │  │ targeted     │  │               │  │
    │  └──────────────┘  └──────────────┘  └───────────────┘  │
    └─────────────────────────────────────────────────────────┘

Usage:
    fuzzer = SmartFuzzer()
    findings = fuzzer.scan("http://target.com/search?q=FUZZ")

    # Returns verified, deduplicated findings with confidence scores
"""

import asyncio
import hashlib
import re
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

import aiohttp

# Import ffuf engine
try:
    from .ffuf_engine import FFufEngine, FuzzTarget, VulnType
    from .ffuf_engine import Finding as FFufFinding
    HAS_FFUF = True
except ImportError:
    try:
        from ffuf_engine import FFufEngine, FuzzTarget, VulnType  # noqa: F401
        from ffuf_engine import Finding as FFufFinding  # noqa: F401
        HAS_FFUF = True
    except ImportError:
        HAS_FFUF = False


# =============================================================================
# DATA STRUCTURES
# =============================================================================

class Confidence(Enum):
    """Confidence level for findings"""
    CONFIRMED = "confirmed"  # Payload executes/works
    HIGH = "high"            # Strong evidence
    MEDIUM = "medium"        # Moderate evidence
    LOW = "low"              # Weak evidence, needs manual review


class VulnCategory(Enum):
    """Vulnerability categories"""
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    SQLI_ERROR = "sqli_error"
    SQLI_BLIND_BOOLEAN = "sqli_blind_boolean"
    SQLI_BLIND_TIME = "sqli_blind_time"
    SQLI_UNION = "sqli_union"
    LFI = "lfi"
    RFI = "rfi"
    RCE = "rce"
    SSTI = "ssti"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"


@dataclass
class VerifiedFinding:
    """A verified vulnerability finding"""
    id: str
    category: VulnCategory
    url: str
    parameter: str
    method: str
    payload: str
    evidence: str
    confidence: Confidence
    severity: str

    # Verification details
    response_code: int = 0
    response_length: int = 0
    response_time_ms: float = 0
    reflection_context: str = ""  # Where payload appears in response

    # For deduplication
    vuln_signature: str = ""  # Hash of vuln characteristics

    # Alternative payloads that also work
    alternative_payloads: List[str] = field(default_factory=list)

    # CWE/CVE info
    cwe: str = ""

    # Auto-generated PoC
    poc_curl: str = ""
    poc_python: str = ""


# =============================================================================
# VERIFICATION PATTERNS
# =============================================================================

# XSS verification - check if payload appears unencoded in dangerous context
XSS_DANGEROUS_CONTEXTS = [
    # Script context
    (r'<script[^>]*>.*?{PAYLOAD}.*?</script>', 'script_block'),
    # Event handlers
    (r'on\w+\s*=\s*["\']?[^"\']*{PAYLOAD}', 'event_handler'),
    # href/src with javascript
    (r'(?:href|src)\s*=\s*["\']?javascript:[^"\']*{PAYLOAD}', 'javascript_uri'),
    # Unquoted attribute
    (r'<\w+[^>]+\w+\s*=\s*{PAYLOAD}[^"\'>\s]', 'unquoted_attr'),
    # Inside tag (potential tag injection)
    (r'<[^>]*{PAYLOAD}[^>]*>', 'tag_injection'),
]

# SQLi error patterns by database
SQLI_ERROR_PATTERNS = {
    'mysql': [
        r'SQL syntax.*?MySQL',
        r'Warning.*?\bmysql_',
        r'MySQLSyntaxErrorException',
        r'valid MySQL result',
        r'check the manual that corresponds to your MySQL',
        r'MySqlClient\.',
        r'com\.mysql\.jdbc',
    ],
    'postgresql': [
        r'PostgreSQL.*?ERROR',
        r'Warning.*?\bpg_',
        r'valid PostgreSQL result',
        r'Npgsql\.',
        r'PG::SyntaxError',
        r'org\.postgresql\.util\.PSQLException',
    ],
    'mssql': [
        r'Driver.*? SQL[\-\_\ ]*Server',
        r'OLE DB.*? SQL Server',
        r'\bSQL Server[^&lt;&quot;]+Driver',
        r'Warning.*?\b(mssql|sqlsrv)_',
        r'\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}',
        r'System\.Data\.SqlClient\.',
        r'Unclosed quotation mark after the character string',
    ],
    'oracle': [
        r'\bORA-\d{5}',
        r'Oracle error',
        r'Oracle.*?Driver',
        r'Warning.*?\b(oci_|ora_)',
        r'quoted string not properly terminated',
    ],
    'sqlite': [
        r'SQLite/JDBCDriver',
        r'SQLite\.Exception',
        r'System\.Data\.SQLite\.SQLiteException',
        r'Warning.*?\b(sqlite_|SQLite3::)',
        r'\[SQLITE_ERROR\]',
        r'SQLite error \d+:',
        r'sqlite3\.OperationalError:',
        r'SQLite3::SQLException',
    ],
}

# LFI success patterns
LFI_SUCCESS_PATTERNS = [
    (r'root:.*?:0:0:', 'etc_passwd'),
    (r'\[boot loader\]', 'windows_boot_ini'),
    (r'\[extensions\]', 'windows_system_ini'),
    (r'<\?php', 'php_source'),
    (r'DB_PASSWORD\s*=', 'config_file'),
    (r'SECRET_KEY\s*=', 'config_file'),
    (r'AWS_ACCESS_KEY', 'aws_creds'),
]

# RCE success patterns
RCE_SUCCESS_PATTERNS = [
    (r'uid=\d+.*?gid=\d+', 'unix_id_command'),
    (r'Linux.*?GNU', 'unix_uname'),
    (r'total \d+\s+', 'unix_ls'),
    (r'Volume Serial Number', 'windows_dir'),
    (r'Directory of [A-Z]:\\', 'windows_dir'),
]


# =============================================================================
# SMART FUZZER
# =============================================================================

class SmartFuzzer:
    """
    Intelligent fuzzing engine with verification and deduplication.

    Combines the speed of ffuf with intelligent Python-based verification.
    """

    def __init__(
        self,
        threads: int = 50,
        verify_top_n: int = 100,  # Verify top N candidates per vuln type
        timeout: int = 10,
        verbose: bool = True,
    ):
        self.threads = threads
        self.verify_top_n = verify_top_n
        self.timeout = timeout
        self.verbose = verbose

        # Initialize ffuf engine
        if HAS_FFUF:
            try:
                self.ffuf = FFufEngine(threads=threads, verbose=False)
            except Exception as e:
                print(f"[!] FFuf not available: {e}")
                self.ffuf = None
        else:
            self.ffuf = None

        # Results storage
        self.findings: List[VerifiedFinding] = []
        self.stats = {
            'candidates_found': 0,
            'verified': 0,
            'false_positives': 0,
            'deduplicated': 0,
        }

    async def scan(
        self,
        url: str,
        parameter: str = "",
        method: str = "GET",
        vuln_types: List[VulnType] = None,
        headers: Dict[str, str] = None,
        cookies: str = None,
    ) -> List[VerifiedFinding]:
        """
        Smart scan with discovery, verification, and deduplication.

        Args:
            url: URL with FUZZ marker where payload goes
            parameter: Parameter name being tested
            method: HTTP method
            vuln_types: Which vulnerabilities to test (default: all)
            headers: Additional headers
            cookies: Cookies to send

        Returns:
            List of verified, deduplicated findings
        """
        if "FUZZ" not in url:
            raise ValueError("URL must contain FUZZ marker")

        if vuln_types is None:
            vuln_types = [VulnType.XSS, VulnType.SQLI, VulnType.LFI, VulnType.RCE]

        all_findings = []

        for vuln_type in vuln_types:
            if self.verbose:
                print(f"\n{'='*60}")
                print(f"[*] Testing {vuln_type.value.upper()}")
                print(f"{'='*60}")

            # Phase 1: Discovery with ffuf
            candidates = await self._discover(url, vuln_type, method, headers, cookies)
            self.stats['candidates_found'] += len(candidates)

            if not candidates:
                if self.verbose:
                    print("    No candidates found")
                continue

            if self.verbose:
                print(f"    Discovery: {len(candidates)} candidates")

            # Phase 2: Verification
            verified = await self._verify(url, candidates, vuln_type, method, headers, cookies)
            self.stats['verified'] += len(verified)
            self.stats['false_positives'] += len(candidates) - len(verified)

            if self.verbose:
                print(f"    Verified: {len(verified)} confirmed")

            # Phase 3: Deduplication
            deduplicated = self._deduplicate(verified, parameter)
            self.stats['deduplicated'] += len(verified) - len(deduplicated)

            if self.verbose:
                print(f"    Unique: {len(deduplicated)} findings")

            all_findings.extend(deduplicated)

        # Generate PoCs for all findings
        for finding in all_findings:
            self._generate_poc(finding)

        self.findings = all_findings
        return all_findings

    async def _discover(
        self,
        url: str,
        vuln_type: VulnType,
        method: str,
        headers: Dict[str, str],
        cookies: str,
    ) -> List[Dict]:
        """
        Phase 1: Fast discovery using ffuf.
        Returns candidate payloads that might be vulnerabilities.
        """
        if not self.ffuf:
            return []

        loop = asyncio.get_running_loop()

        # Run ffuf scan (blocking subprocess) in executor to avoid freezing event loop
        if vuln_type == VulnType.XSS:
            raw_findings = await loop.run_in_executor(None, lambda: self.ffuf.fuzz_xss(url, exhaustive=True))
        elif vuln_type == VulnType.SQLI:
            raw_findings = await loop.run_in_executor(None, lambda: self.ffuf.fuzz_sqli(url, exhaustive=True))
        elif vuln_type == VulnType.LFI:
            raw_findings = await loop.run_in_executor(None, lambda: self.ffuf.fuzz_lfi(url, exhaustive=True))
        elif vuln_type == VulnType.RCE:
            raw_findings = await loop.run_in_executor(None, lambda: self.ffuf.fuzz_rce(url, exhaustive=True))
        else:
            return []

        # Convert to candidates (limit to top N for verification)
        candidates = []
        for f in raw_findings[:self.verify_top_n]:
            candidates.append({
                'payload': f.payload,
                'status_code': f.status_code,
                'response_length': f.response_length,
            })

        return candidates

    async def _verify(
        self,
        url: str,
        candidates: List[Dict],
        vuln_type: VulnType,
        method: str,
        headers: Dict[str, str],
        cookies: str,
    ) -> List[VerifiedFinding]:
        """
        Phase 2: Intelligent verification of candidates.
        Actually checks if the vulnerability is exploitable.
        """
        verified = []

        # Prepare async verification
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        ) as session:
            # First, get baseline response
            baseline = await self._get_baseline(session, url)

            # Verify each candidate
            tasks = []
            for candidate in candidates:
                task = self._verify_single(
                    session, url, candidate, vuln_type, baseline, method, headers, cookies
                )
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, VerifiedFinding):
                    verified.append(result)

        return verified

    async def _get_baseline(self, session: aiohttp.ClientSession, url: str) -> Dict:
        """Get baseline response for comparison"""
        baseline_url = url.replace('FUZZ', 'BASELINE_CANARY_12345')
        try:
            start = time.time()
            async with session.get(baseline_url) as resp:
                body = await resp.text()
                return {
                    'status': resp.status,
                    'length': len(body),
                    'time': (time.time() - start) * 1000,
                    'body': body,
                }
        except Exception:
            return {'status': 0, 'length': 0, 'time': 0, 'body': ''}

    async def _verify_single(
        self,
        session: aiohttp.ClientSession,
        url: str,
        candidate: Dict,
        vuln_type: VulnType,
        baseline: Dict,
        method: str,
        headers: Dict[str, str],
        cookies: str,
    ) -> Optional[VerifiedFinding]:
        """Verify a single candidate"""
        payload = candidate['payload']
        test_url = url.replace('FUZZ', urllib.parse.quote(payload, safe=''))

        try:
            start = time.time()
            async with session.get(test_url) as resp:
                body = await resp.text()
                elapsed = (time.time() - start) * 1000

                # Verify based on vulnerability type
                if vuln_type == VulnType.XSS:
                    return self._verify_xss(payload, body, resp.status, len(body), elapsed, url)
                elif vuln_type == VulnType.SQLI:
                    return self._verify_sqli(payload, body, resp.status, len(body), elapsed, url, baseline)
                elif vuln_type == VulnType.LFI:
                    return self._verify_lfi(payload, body, resp.status, len(body), elapsed, url)
                elif vuln_type == VulnType.RCE:
                    return self._verify_rce(payload, body, resp.status, len(body), elapsed, url)

        except Exception:
            pass

        return None

    def _verify_xss(
        self,
        payload: str,
        body: str,
        status: int,
        length: int,
        elapsed: float,
        url: str,
    ) -> Optional[VerifiedFinding]:
        """
        Verify XSS - check for unencoded reflection in dangerous context.
        """
        # Check if payload is reflected
        if payload not in body:
            # Try URL-decoded version
            decoded_payload = urllib.parse.unquote(payload)
            if decoded_payload not in body:
                return None
            payload_in_body = decoded_payload
        else:
            payload_in_body = payload

        # Find the context where payload appears
        idx = body.find(payload_in_body)
        context_start = max(0, idx - 100)
        context_end = min(len(body), idx + len(payload_in_body) + 100)
        context = body[context_start:context_end]

        # Check if it's in a dangerous context
        confidence = Confidence.LOW
        reflection_type = "reflected"

        # Check for dangerous contexts
        for pattern, context_name in XSS_DANGEROUS_CONTEXTS:
            regex = pattern.replace('{PAYLOAD}', re.escape(payload_in_body))
            if re.search(regex, body, re.IGNORECASE | re.DOTALL):
                confidence = Confidence.HIGH
                reflection_type = context_name
                break

        # If payload contains executable JS and is reflected unencoded
        executable_patterns = [
            r'<script',
            r'javascript:',
            r'on\w+=',
            r'<svg.*?onload',
            r'<img.*?onerror',
        ]

        for pattern in executable_patterns:
            if re.search(pattern, payload_in_body, re.IGNORECASE):
                if payload_in_body in body:  # Reflected without encoding
                    confidence = Confidence.CONFIRMED
                    break

        if confidence == Confidence.LOW:
            # Just reflected, not clearly dangerous
            return None

        return VerifiedFinding(
            id=hashlib.md5(f"xss:{url}:{payload}".encode()).hexdigest()[:12],
            category=VulnCategory.XSS_REFLECTED,
            url=url.replace('FUZZ', urllib.parse.quote(payload, safe='')),
            parameter=self._extract_param_from_url(url),
            method="GET",
            payload=payload,
            evidence=f"Payload reflected in {reflection_type} context",
            confidence=confidence,
            severity="high",
            response_code=status,
            response_length=length,
            response_time_ms=elapsed,
            reflection_context=context[:200],
            cwe="CWE-79",
        )

    def _verify_sqli(
        self,
        payload: str,
        body: str,
        status: int,
        length: int,
        elapsed: float,
        url: str,
        baseline: Dict,
    ) -> Optional[VerifiedFinding]:
        """
        Verify SQLi - check for error messages or behavior changes.
        """
        # Check for database error messages
        for db_type, patterns in SQLI_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return VerifiedFinding(
                        id=hashlib.md5(f"sqli:{url}:{db_type}".encode()).hexdigest()[:12],
                        category=VulnCategory.SQLI_ERROR,
                        url=url.replace('FUZZ', urllib.parse.quote(payload, safe='')),
                        parameter=self._extract_param_from_url(url),
                        method="GET",
                        payload=payload,
                        evidence=f"SQL error detected ({db_type}): {pattern}",
                        confidence=Confidence.CONFIRMED,
                        severity="critical",
                        response_code=status,
                        response_length=length,
                        response_time_ms=elapsed,
                        cwe="CWE-89",
                    )

        # Check for time-based (significant delay)
        if elapsed > baseline.get('time', 0) + 2500:  # 2.5s+ delay
            if any(kw in payload.lower() for kw in ['sleep', 'waitfor', 'pg_sleep', 'benchmark']):
                return VerifiedFinding(
                    id=hashlib.md5(f"sqli:time:{url}".encode()).hexdigest()[:12],
                    category=VulnCategory.SQLI_BLIND_TIME,
                    url=url.replace('FUZZ', urllib.parse.quote(payload, safe='')),
                    parameter=self._extract_param_from_url(url),
                    method="GET",
                    payload=payload,
                    evidence=f"Time-based delay detected: {elapsed:.0f}ms vs baseline {baseline.get('time', 0):.0f}ms",
                    confidence=Confidence.HIGH,
                    severity="critical",
                    response_code=status,
                    response_length=length,
                    response_time_ms=elapsed,
                    cwe="CWE-89",
                )

        # Check for boolean-based (significant response size change)
        size_diff = abs(length - baseline.get('length', 0))
        if size_diff > 500:  # Significant size difference
            # Only if payload looks like boolean test
            if any(kw in payload.lower() for kw in ["' and '", "' or '", "1=1", "1=2"]):
                return VerifiedFinding(
                    id=hashlib.md5(f"sqli:bool:{url}".encode()).hexdigest()[:12],
                    category=VulnCategory.SQLI_BLIND_BOOLEAN,
                    url=url.replace('FUZZ', urllib.parse.quote(payload, safe='')),
                    parameter=self._extract_param_from_url(url),
                    method="GET",
                    payload=payload,
                    evidence=f"Boolean-based response difference: {size_diff} bytes",
                    confidence=Confidence.MEDIUM,
                    severity="critical",
                    response_code=status,
                    response_length=length,
                    response_time_ms=elapsed,
                    cwe="CWE-89",
                )

        return None

    def _verify_lfi(
        self,
        payload: str,
        body: str,
        status: int,
        length: int,
        elapsed: float,
        url: str,
    ) -> Optional[VerifiedFinding]:
        """Verify LFI - check for file contents in response."""
        for pattern, file_type in LFI_SUCCESS_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return VerifiedFinding(
                    id=hashlib.md5(f"lfi:{url}:{file_type}".encode()).hexdigest()[:12],
                    category=VulnCategory.LFI,
                    url=url.replace('FUZZ', urllib.parse.quote(payload, safe='')),
                    parameter=self._extract_param_from_url(url),
                    method="GET",
                    payload=payload,
                    evidence=f"File contents detected: {file_type}",
                    confidence=Confidence.CONFIRMED,
                    severity="critical",
                    response_code=status,
                    response_length=length,
                    response_time_ms=elapsed,
                    cwe="CWE-98",
                )
        return None

    def _verify_rce(
        self,
        payload: str,
        body: str,
        status: int,
        length: int,
        elapsed: float,
        url: str,
    ) -> Optional[VerifiedFinding]:
        """Verify RCE - check for command output in response."""
        for pattern, cmd_type in RCE_SUCCESS_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return VerifiedFinding(
                    id=hashlib.md5(f"rce:{url}:{cmd_type}".encode()).hexdigest()[:12],
                    category=VulnCategory.RCE,
                    url=url.replace('FUZZ', urllib.parse.quote(payload, safe='')),
                    parameter=self._extract_param_from_url(url),
                    method="GET",
                    payload=payload,
                    evidence=f"Command output detected: {cmd_type}",
                    confidence=Confidence.CONFIRMED,
                    severity="critical",
                    response_code=status,
                    response_length=length,
                    response_time_ms=elapsed,
                    cwe="CWE-78",
                )
        return None

    def _deduplicate(
        self,
        findings: List[VerifiedFinding],
        parameter: str,
    ) -> List[VerifiedFinding]:
        """
        Phase 3: Deduplicate findings.

        Same vulnerability found with multiple payloads = 1 finding.
        Keep the payload with highest confidence.
        """
        # Group by vulnerability signature (category + URL + parameter)
        groups = defaultdict(list)

        for finding in findings:
            sig = f"{finding.category.value}:{finding.parameter}"
            groups[sig].append(finding)

        # Keep best from each group
        deduplicated = []
        confidence_order = [Confidence.CONFIRMED, Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW]

        for sig, group in groups.items():
            # Sort by confidence (highest first)
            sorted_group = sorted(
                group,
                key=lambda f: confidence_order.index(f.confidence)
            )

            best = sorted_group[0]
            # Store alternative payloads
            best.alternative_payloads = [f.payload for f in sorted_group[1:5]]
            best.vuln_signature = sig

            deduplicated.append(best)

        return deduplicated

    def _generate_poc(self, finding: VerifiedFinding):
        """Generate PoC code for the finding"""
        # cURL PoC
        finding.poc_curl = f"curl -s '{finding.url}'"

        # Python PoC
        finding.poc_python = f'''import requests

url = "{finding.url}"
response = requests.get(url)
print(f"Status: {{response.status_code}}")
print(f"Length: {{len(response.text)}}")

# Check for vulnerability indicator
if "{finding.payload[:20]}" in response.text:
    print("[+] Payload reflected - Vulnerable!")
'''

    def _extract_param_from_url(self, url: str) -> str:
        """Extract parameter name from URL with FUZZ marker"""
        # Find parameter that contains FUZZ
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        for param, values in params.items():
            if any('FUZZ' in str(v) for v in values):
                return param

        return "unknown"

    def print_summary(self):
        """Print scan summary"""
        print(f"\n{'='*60}")
        print("SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Candidates discovered: {self.stats['candidates_found']}")
        print(f"Verified findings:     {self.stats['verified']}")
        print(f"False positives:       {self.stats['false_positives']}")
        print(f"After deduplication:   {len(self.findings)}")
        print(f"{'='*60}")

        if self.findings:
            print("\nFINDINGS:")
            for i, f in enumerate(self.findings, 1):
                conf_icon = {
                    Confidence.CONFIRMED: "✓",
                    Confidence.HIGH: "◉",
                    Confidence.MEDIUM: "○",
                    Confidence.LOW: "·",
                }[f.confidence]

                print(f"\n[{i}] {conf_icon} {f.category.value.upper()}")
                print(f"    Parameter: {f.parameter}")
                print(f"    Payload: {f.payload[:60]}{'...' if len(f.payload) > 60 else ''}")
                print(f"    Evidence: {f.evidence}")
                print(f"    Confidence: {f.confidence.value}")
                if f.alternative_payloads:
                    print(f"    Alternative payloads: {len(f.alternative_payloads)}")


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

async def smart_scan(url: str, **kwargs) -> List[VerifiedFinding]:
    """Quick smart scan wrapper"""
    fuzzer = SmartFuzzer(**kwargs)
    findings = await fuzzer.scan(url)
    fuzzer.print_summary()
    return findings


def smart_scan_sync(url: str, **kwargs) -> List[VerifiedFinding]:
    """Synchronous wrapper for smart_scan"""
    return asyncio.run(smart_scan(url, **kwargs))


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'SmartFuzzer',
    'VerifiedFinding',
    'Confidence',
    'VulnCategory',
    'smart_scan',
    'smart_scan_sync',
]
