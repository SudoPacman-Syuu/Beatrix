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


class AttackMode(Enum):
    """
    Burp Intruder-style attack modes for multi-position fuzzing.

    SNIPER:        One position at a time, same wordlist across all positions.
                   N_positions × N_payloads requests.
    BATTERING_RAM: Same payload in ALL positions simultaneously.
                   N_payloads requests.
    PITCHFORK:     Each position gets its own wordlist, iterated in lockstep.
                   min(len(list_1), len(list_2), ...) requests.
    CLUSTER_BOMB:  All combinations of all wordlists across all positions.
                   product(len(list_1) × len(list_2) × ...) requests.
    """
    SNIPER = "sniper"
    BATTERING_RAM = "battering_ram"
    PITCHFORK = "pitchfork"
    CLUSTER_BOMB = "cluster_bomb"


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

# URL path patterns belonging to WAF / CDN / bot-protection infrastructure.
# Fuzzing these yields false positives — timing delays are WAF throttling,
# body differences are challenge pages, not real injection evidence.
_WAF_CDN_PATH_PATTERNS = [
    # PerimeterX / HUMAN Security
    r'/captcha/',
    r'/captcha\.js',
    r'/px/',
    # Cloudflare
    r'/cdn-cgi/',
    # Akamai
    r'/akamai/',
    r'/akam/',
    # Imperva / Incapsula
    r'/_Incapsula_',
    # DataDome
    r'/datadome\.',
    r'/captcha-delivery\.',
    # Generic bot challenge endpoints
    r'/challenge-platform/',
    r'/bot-challenge/',
    r'/bm/px/',
]
_WAF_CDN_RE = re.compile('|'.join(_WAF_CDN_PATH_PATTERNS), re.IGNORECASE)


def _is_waf_infra_url(url: str) -> bool:
    """Return True if the URL belongs to a WAF/CDN infrastructure endpoint."""
    path = urllib.parse.urlparse(url).path
    return bool(_WAF_CDN_RE.search(path))


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

        # Skip WAF/CDN infrastructure endpoints entirely — they produce
        # only false positives (timing from throttling, body changes from
        # challenge pages).
        if _is_waf_infra_url(url):
            if self.verbose:
                print(f"    [!] Skipping WAF/CDN infrastructure URL: {url}")
            return []

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
        """Get baseline response for comparison.

        Takes 3 samples and returns the median timing to reduce
        the impact of network jitter and WAF rate-limiting spikes.
        """
        baseline_url = url.replace('FUZZ', 'BASELINE_CANARY_12345')
        samples: list = []
        last_body = ''
        last_status = 0
        for _ in range(3):
            try:
                start = time.time()
                async with session.get(baseline_url) as resp:
                    body = await resp.text()
                    elapsed = (time.time() - start) * 1000
                    samples.append(elapsed)
                    last_body = body
                    last_status = resp.status
            except Exception:
                samples.append(0)
        if not samples or all(s == 0 for s in samples):
            return {'status': 0, 'length': 0, 'time': 0, 'body': ''}
        samples.sort()
        median_time = samples[len(samples) // 2]
        return {
            'status': last_status,
            'length': len(last_body),
            'time': median_time,
            'body': last_body,
        }

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
                    return await self._verify_sqli(payload, body, resp.status, len(body), elapsed, url, baseline, session)
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

    async def _verify_sqli(
        self,
        payload: str,
        body: str,
        status: int,
        length: int,
        elapsed: float,
        url: str,
        baseline: Dict,
        session: aiohttp.ClientSession = None,
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

        # Check for time-based (significant delay) — requires confirmation
        if elapsed > baseline.get('time', 0) + 2500:  # 2.5s+ delay
            if any(kw in payload.lower() for kw in ['sleep', 'waitfor', 'pg_sleep', 'benchmark']):
                # Confirmation: re-request the same URL to rule out
                # transient WAF throttling / network jitter.
                confirm_url = url.replace('FUZZ', urllib.parse.quote(payload, safe=''))
                confirmed = False
                if session:
                    try:
                        c_start = time.time()
                        async with session.get(confirm_url) as c_resp:
                            await c_resp.text()
                            c_elapsed = (time.time() - c_start) * 1000
                            if c_elapsed > baseline.get('time', 0) + 2500:
                                confirmed = True
                    except Exception:
                        pass

                if confirmed:
                    return VerifiedFinding(
                        id=hashlib.md5(f"sqli:time:{url}".encode()).hexdigest()[:12],
                        category=VulnCategory.SQLI_BLIND_TIME,
                        url=url.replace('FUZZ', urllib.parse.quote(payload, safe='')),
                        parameter=self._extract_param_from_url(url),
                        method="GET",
                        payload=payload,
                        evidence=f"Time-based delay confirmed (2/2): {elapsed:.0f}ms, {c_elapsed:.0f}ms vs baseline {baseline.get('time', 0):.0f}ms",
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
            parsed = urllib.parse.urlparse(finding.url)
            url_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            sig = f"{finding.category.value}:{url_base}:{finding.parameter}"
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

    # =========================================================================
    # INTRUDER ATTACK MODES (Burp-inspired multi-position fuzzing)
    # =========================================================================

    async def intruder_scan(
        self,
        url_template: str,
        wordlists: Dict[str, List[str]],
        attack_mode: AttackMode = AttackMode.SNIPER,
        method: str = "GET",
        body_template: str = None,
        headers: Dict[str, str] = None,
        match_status: List[int] = None,
        filter_status: List[int] = None,
        match_size: int = None,
        filter_size: int = None,
    ) -> List[Dict]:
        """
        Multi-position fuzzing with Burp Intruder-style attack modes.

        Positions are marked with §name§ in url_template and body_template.
        Each name maps to a key in the wordlists dict.

        Args:
            url_template: URL with §markers§ (e.g., "/api/§endpoint§?id=§id§")
            wordlists: {"marker_name": ["val1", "val2", ...]}
            attack_mode: SNIPER, BATTERING_RAM, PITCHFORK, or CLUSTER_BOMB
            method: HTTP method
            body_template: Body with §markers§ (for POST/PUT/PATCH)
            headers: Additional headers
            match_status: Only return results matching these status codes
            filter_status: Filter OUT results with these status codes
            match_size: Only return results within ±10% of this size
            filter_size: Filter OUT results within ±10% of this size

        Returns:
            List of result dicts with payload, status, length, time info
        """
        import itertools

        # Find all position markers
        positions = re.findall(r'§(\w+)§', url_template + (body_template or ""))
        positions = list(dict.fromkeys(positions))  # Dedupe, preserve order

        if not positions:
            raise ValueError(
                "No position markers found. Use §name§ syntax "
                "(e.g., /api/§endpoint§?id=§id§)"
            )

        # Validate wordlists exist for all positions
        for pos in positions:
            if pos not in wordlists:
                raise ValueError(
                    f"No wordlist provided for position '§{pos}§'. "
                    f"Available: {list(wordlists.keys())}"
                )

        # Generate payload combinations based on attack mode
        combos = self._generate_combinations(
            positions, wordlists, attack_mode
        )

        results = []
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        ) as session:
            # Get baseline (all markers replaced with canary)
            baseline_url = url_template
            for pos in positions:
                baseline_url = baseline_url.replace(f"§{pos}§", "BASELINE_CANARY")
            try:
                start = time.time()
                async with session.request(method, baseline_url, headers=headers) as resp:
                    baseline_body = await resp.text()
                    baseline = {
                        "status": resp.status,
                        "length": len(baseline_body),
                        "time": (time.time() - start) * 1000,
                    }
            except Exception:
                baseline = {"status": 0, "length": 0, "time": 0}

            # Execute each combination
            for combo in combos:
                test_url = url_template
                test_body = body_template
                for pos_name, value in combo.items():
                    test_url = test_url.replace(f"§{pos_name}§", str(value))
                    if test_body:
                        test_body = test_body.replace(f"§{pos_name}§", str(value))

                try:
                    start = time.time()
                    kwargs = {"headers": headers}
                    if test_body and method.upper() in ("POST", "PUT", "PATCH"):
                        kwargs["data"] = test_body
                    async with session.request(method, test_url, **kwargs) as resp:
                        body = await resp.text()
                        elapsed = (time.time() - start) * 1000

                        result = {
                            "payloads": combo,
                            "url": test_url,
                            "status": resp.status,
                            "length": len(body),
                            "time_ms": elapsed,
                            "diff_status": resp.status != baseline["status"],
                            "diff_length": abs(len(body) - baseline["length"]),
                        }

                        # Apply filters
                        if match_status and resp.status not in match_status:
                            continue
                        if filter_status and resp.status in filter_status:
                            continue
                        if match_size and abs(len(body) - match_size) > match_size * 0.1:
                            continue
                        if filter_size and abs(len(body) - filter_size) <= filter_size * 0.1:
                            continue

                        results.append(result)

                except Exception:
                    continue

                await asyncio.sleep(0.01)  # Rate limit

        return results

    @staticmethod
    def _generate_combinations(
        positions: List[str],
        wordlists: Dict[str, List[str]],
        attack_mode: AttackMode,
    ) -> List[Dict[str, str]]:
        """Generate payload combinations for the given attack mode."""
        import itertools

        if attack_mode == AttackMode.SNIPER:
            # One position at a time, all others get baseline value
            combos = []
            for active_pos in positions:
                for payload in wordlists[active_pos]:
                    combo = {p: wordlists[p][0] if wordlists[p] else "" for p in positions}
                    combo[active_pos] = payload
                    combos.append(combo)
            return combos

        elif attack_mode == AttackMode.BATTERING_RAM:
            # Same payload in ALL positions — use first wordlist's values
            primary = wordlists[positions[0]]
            return [
                {p: payload for p in positions}
                for payload in primary
            ]

        elif attack_mode == AttackMode.PITCHFORK:
            # Lockstep iteration across wordlists
            lists = [wordlists[p] for p in positions]
            min_len = min(len(l) for l in lists)
            return [
                {positions[i]: lists[i][idx] for i in range(len(positions))}
                for idx in range(min_len)
            ]

        elif attack_mode == AttackMode.CLUSTER_BOMB:
            # All combinations (cartesian product)
            lists = [wordlists[p] for p in positions]
            return [
                {positions[i]: val for i, val in enumerate(combo)}
                for combo in itertools.product(*lists)
            ]

        return []

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
    'AttackMode',
    'smart_scan',
    'smart_scan_sync',
]
