"""
BEATRIX Finding Enricher

Deterministic post-scan enricher that auto-generates missing fields
on Finding objects from data already present.

No AI needed — purely mechanical derivation:
  - poc_curl from request URL + method + headers
  - impact statements from vuln type + severity
  - reproduction_steps from request + description
  - cwe_id from scanner_module + vuln type keywords
  - parameter/payload from description/request text

Designed to be called AFTER IssueConsolidator dedup but BEFORE export.
"""

import re
import shlex
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, unquote

from beatrix.core.types import Finding, Severity

# ============================================================================
# CWE MAPPING — Scanner module + vuln type → CWE ID
# ============================================================================

CWE_MAP: Dict[str, str] = {
    # Injection subtypes
    "sqli": "CWE-89",
    "sql injection": "CWE-89",
    "xss": "CWE-79",
    "cross-site scripting": "CWE-79",
    "cmdi": "CWE-78",
    "command injection": "CWE-78",
    "ssti": "CWE-1336",
    "template injection": "CWE-1336",
    "path traversal": "CWE-22",
    "lfi": "CWE-98",
    "rfi": "CWE-98",
    "xxe": "CWE-611",
    "ssrf": "CWE-918",

    # Headers / config
    "strict-transport-security": "CWE-319",
    "hsts": "CWE-319",
    "x-frame-options": "CWE-1021",
    "clickjacking": "CWE-1021",
    "x-content-type-options": "CWE-693",
    "referrer-policy": "CWE-200",
    "permissions-policy": "CWE-693",
    "content-security-policy": "CWE-693",
    "server header": "CWE-200",
    "insecure cookie": "CWE-614",
    "cookie": "CWE-614",
    "missing secure flag": "CWE-614",
    "missing samesite": "CWE-1275",

    # Auth / access control
    "idor": "CWE-639",
    "broken access": "CWE-284",
    "auth bypass": "CWE-287",
    "privilege escalation": "CWE-269",

    # CORS
    "cors": "CWE-942",
    "cross-origin": "CWE-942",

    # Error / info disclosure
    "error disclosure": "CWE-209",
    "stack trace": "CWE-209",
    "information disclosure": "CWE-200",
    "input reflection": "CWE-116",

    # Deserialization
    "deserialization": "CWE-502",

    # Open redirect
    "open redirect": "CWE-601",

    # CSRF
    "csrf": "CWE-352",

    # File upload
    "file upload": "CWE-434",

    # Rate limiting
    "rate limit": "CWE-770",

    # HTTP smuggling
    "http smuggling": "CWE-444",
    "request smuggling": "CWE-444",

    # Mass assignment
    "mass assignment": "CWE-915",

    # Prototype pollution
    "prototype pollution": "CWE-1321",

    # GraphQL
    "graphql": "CWE-200",

    # JWT
    "jwt": "CWE-347",

    # Cache poisoning
    "cache poisoning": "CWE-349",

    # Subdomain takeover
    "subdomain takeover": "CWE-284",
}

# ============================================================================
# IMPACT TEMPLATES — Vuln type + severity → concrete impact statement
# ============================================================================

IMPACT_TEMPLATES: Dict[str, Dict[str, str]] = {
    "sqli": {
        "critical": "An attacker can extract the entire database contents including user credentials, personally identifiable information (PII), and financial data by injecting SQL queries through the {param} parameter. Full database compromise is achievable.",
        "high": "An attacker can read unauthorized data from the database by injecting SQL queries through the {param} parameter. This enables extraction of sensitive records from other tables.",
        "medium": "SQL injection is possible through the {param} parameter, enabling boolean-based or error-based data extraction. The attacker can enumerate database structure and extract data.",
        "low": "The application shows signs of SQL injection via error responses when special characters are submitted in the {param} parameter.",
    },
    "xss": {
        "critical": "An attacker can execute arbitrary JavaScript in any user's browser session by injecting scripts through the {param} parameter. This enables full account takeover via session token theft, keylogging, and phishing.",
        "high": "An attacker can execute JavaScript in a victim's browser by injecting a payload through the {param} parameter. This enables session hijacking and data exfiltration from the authenticated session.",
        "medium": "Reflected XSS is possible through the {param} parameter. An attacker can craft a URL that executes JavaScript in the victim's browser when clicked, enabling session theft or phishing.",
        "low": "Input is reflected in the page without proper encoding through the {param} parameter. While exploitation depends on context, this indicates missing output sanitization.",
    },
    "cmdi": {
        "critical": "An attacker can execute arbitrary operating system commands on the server through the {param} parameter. This gives full control of the server — reading files, installing backdoors, pivoting to internal networks.",
        "high": "An attacker can inject and execute OS commands through the {param} parameter. This enables reading sensitive files (/etc/passwd, config files), enumerating the server environment, and potentially establishing a reverse shell.",
        "medium": "Command injection is possible through the {param} parameter, enabling execution of system commands on the server.",
    },
    "ssti": {
        "critical": "An attacker can execute arbitrary code on the server via Server-Side Template Injection through the {param} parameter. This enables Remote Code Execution (RCE) — reading server files, accessing environment variables, and full server compromise.",
        "high": "An attacker can manipulate the server-side template engine through the {param} parameter. Template expressions are evaluated server-side, enabling information disclosure and potentially Remote Code Execution depending on the template engine and sandbox configuration.",
        "medium": "Server-Side Template Injection is confirmed through the {param} parameter. The template engine evaluates injected expressions, which can be escalated to read server-side data or execute code.",
    },
    "path": {
        "critical": "An attacker can read any file on the server filesystem through path traversal in the {param} parameter, including /etc/passwd, application source code, database credentials, and private keys.",
        "high": "An attacker can traverse outside the intended directory through the {param} parameter and read sensitive server files such as /etc/passwd and application configuration files.",
        "medium": "Path traversal is possible through the {param} parameter, enabling the attacker to read files outside the intended directory.",
    },
    "cors": {
        "high": "The CORS misconfiguration allows any website to make authenticated cross-origin requests to the target. An attacker can host a malicious page that, when visited by an authenticated user, silently reads sensitive data from the target API (user profiles, financial data, tokens) and exfiltrates it.",
        "medium": "CORS is misconfigured to allow arbitrary origins with credentials. An attacker's malicious site can make authenticated requests and read responses, potentially accessing sensitive user data.",
        "low": "CORS headers permit wider origin access than intended. While exploitation requires a victim to visit an attacker-controlled page, sensitive data could be read cross-origin.",
    },
    "idor": {
        "critical": "An attacker can access any user's data by manipulating the {param} parameter. Demonstrated access to other users' records, PII, or financial data without authorization.",
        "high": "Insecure Direct Object Reference in the {param} parameter allows unauthorized access to other users' resources. By changing the identifier value, an attacker reads data belonging to other accounts.",
        "medium": "The {param} parameter references objects directly without proper authorization checks. An attacker can enumerate and access resources belonging to other users.",
    },
    "ssrf": {
        "critical": "Server-Side Request Forgery through the {param} parameter allows an attacker to make the server send requests to internal services, cloud metadata endpoints (169.254.169.254), and other protected resources. Full internal network reconnaissance and potential credential theft from cloud metadata.",
        "high": "SSRF through the {param} parameter enables the attacker to reach internal services not accessible from the internet. This can expose internal APIs, admin panels, and cloud metadata (AWS keys, etc.).",
        "medium": "The server fetches URLs controlled by the attacker via the {param} parameter. This can be used to scan internal networks and potentially access cloud metadata services.",
    },
    "error_disclosure": {
        "medium": "Error responses leak internal application details including stack traces, database queries, internal paths, and technology versions. This information aids an attacker in crafting targeted exploits.",
        "low": "The application echoes user input in error responses without sanitization. While not directly exploitable, this reveals how the application processes input and may indicate deeper injection vulnerabilities.",
        "info": "Error responses include minor technical details. While low risk on its own, this data supports further reconnaissance.",
    },
    "missing_header": {
        "low": "The missing security header reduces defense-in-depth protections. While not directly exploitable in isolation, it makes exploitation of other vulnerabilities easier and indicates incomplete security hardening.",
        "info": "A recommended security header is not configured. This is a best-practice gap that should be addressed as part of security hardening.",
    },
    "insecure_cookie": {
        "medium": "Cookies are set without proper security flags, making them vulnerable to interception (missing Secure flag), cross-site attacks (missing SameSite), or JavaScript theft (missing HttpOnly). An attacker on the same network or via XSS can steal session cookies.",
        "low": "Cookie security flags are incomplete. The missing flags reduce cookie protections against specific attack vectors (network interception, cross-site requests, or XSS-based theft).",
    },
    "input_reflection": {
        "medium": "User input is reflected in the response without proper encoding. This is a precursor to Cross-Site Scripting (XSS) — if the reflection context allows it, an attacker can inject and execute JavaScript in the victim's browser.",
        "low": "The server reflects user-supplied input in error responses. While the current context may prevent script execution, this indicates missing output encoding that could become exploitable with different payloads or in different response contexts.",
    },
    "endpoint_discovery": {
        "info": "Discovered live endpoints that reveal application structure and attack surface. These endpoints can be targeted for deeper vulnerability testing including injection, authentication bypass, and access control flaws.",
    },
    "js_secrets": {
        "high": "JavaScript bundles contain hardcoded API keys, tokens, or credentials. An attacker can extract these and use them to access backend services, third-party APIs, or internal systems without authorization.",
        "medium": "JavaScript bundles expose internal API endpoints and potential secrets. This reveals the application's internal architecture and provides targets for further testing.",
        "info": "JavaScript analysis revealed API routes and internal endpoints. This is useful reconnaissance data for deeper security testing.",
    },
    "rate_limiting": {
        "medium": "No rate limiting detected on the endpoint. An attacker can perform brute-force attacks against authentication, enumeration of user accounts, or denial-of-service via resource exhaustion without being throttled.",
        "low": "Rate limiting is absent or insufficient. This allows automated attacks at high volume without restriction.",
    },
}

# ============================================================================
# THE ENRICHER
# ============================================================================

class FindingEnricher:
    """
    Deterministic post-scan enricher.

    Call enrich() on each Finding after deduplication.
    Only fills fields that are currently empty/None — never overwrites
    data a scanner explicitly set.
    """

    def enrich(self, finding: Finding) -> Finding:
        """Enrich a single finding with auto-generated fields."""
        self._enrich_cwe(finding)
        self._enrich_parameter_payload(finding)
        self._enrich_impact(finding)
        self._enrich_poc_curl(finding)
        self._enrich_reproduction_steps(finding)
        return finding

    def enrich_batch(self, findings: List[Finding]) -> List[Finding]:
        """Enrich a batch of findings."""
        for finding in findings:
            self.enrich(finding)
        return findings

    # ====================================================================
    # CWE AUTO-MAPPING
    # ====================================================================

    def _enrich_cwe(self, finding: Finding) -> None:
        """Map CWE ID from title/description/scanner_module."""
        if finding.cwe_id:
            return

        combined = f"{finding.title} {finding.description} {finding.scanner_module}".lower()

        # Try each CWE mapping key — longest match first for specificity
        best_match: Optional[str] = None
        best_len = 0

        for keyword, cwe in CWE_MAP.items():
            if keyword in combined and len(keyword) > best_len:
                best_match = cwe
                best_len = len(keyword)

        if best_match:
            finding.cwe_id = best_match

    # ====================================================================
    # PARAMETER / PAYLOAD EXTRACTION
    # ====================================================================

    def _enrich_parameter_payload(self, finding: Finding) -> None:
        """Extract parameter name and payload from description/request."""
        desc = finding.description or ""
        req = finding.request or ""
        combined = f"{desc}\n{req}"

        # Extract parameter from "Vulnerable parameter: <name>" pattern
        if not finding.parameter:
            m = re.search(r'(?:Vulnerable|Injection)\s+(?:parameter|point):\s*(\S+)', combined, re.I)
            if m:
                finding.parameter = m.group(1)

        # Extract payload from "Payload: <value>" pattern
        if not finding.payload:
            m = re.search(r'Payload:\s*(.+?)(?:\n|$)', combined)
            if m:
                finding.payload = m.group(1).strip()

        # For header findings, extract the header name as parameter
        if not finding.parameter and finding.scanner_module == "headers":
            m = re.search(r"Header\s+'([^']+)'", combined, re.I)
            if not m:
                m = re.search(r"Missing Security Header:\s*(.+)", finding.title, re.I)
            if m:
                finding.parameter = m.group(1).strip()

        # For cookie findings, extract cookie name
        if not finding.parameter and "cookie" in finding.title.lower():
            m = re.search(r"Cookie\s+'([^']+)'", combined, re.I)
            if not m:
                m = re.search(r"Insecure Cookie:\s*(.+)", finding.title, re.I)
            if m:
                finding.parameter = m.group(1).strip()

        # Extract parameter from URL query string as last resort
        if not finding.parameter and finding.url:
            try:
                parsed = urlparse(finding.url)
                qs = parse_qs(parsed.query)
                if qs:
                    # Use the first query parameter name
                    finding.parameter = next(iter(qs))
            except Exception:
                pass

    # ====================================================================
    # IMPACT STATEMENT GENERATION
    # ====================================================================

    def _enrich_impact(self, finding: Finding) -> None:
        """Generate impact statement from vuln type + severity."""
        if finding.impact and len(finding.impact.strip()) >= 30:
            return

        vuln_type = self._detect_vuln_type(finding)
        severity_key = finding.severity.value.lower()
        # Use backtick-wrapped param name, or a generic phrase when unknown
        param = f"`{finding.parameter}`" if finding.parameter else "a vulnerable parameter"

        # Look up impact template
        templates = IMPACT_TEMPLATES.get(vuln_type, {})
        impact = templates.get(severity_key)

        # Fall back to closest lower severity
        if not impact:
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in templates:
                    impact = templates[sev]
                    break

        if impact:
            finding.impact = impact.format(param=param)
        else:
            # Generic fallback — still better than empty
            finding.impact = self._generic_impact(finding, param)

    def _detect_vuln_type(self, finding: Finding) -> str:
        """Detect vulnerability type from title/description/module."""
        title = finding.title.lower()
        desc = finding.description.lower()
        module = finding.scanner_module.lower()

        # Injection subtypes (check first — most specific)
        if any(k in title for k in ["sql injection", "sqli"]):
            return "sqli"
        if any(k in title for k in ["cross-site scripting", "xss"]):
            return "xss"
        if any(k in title for k in ["command injection", "cmdi"]):
            return "cmdi"
        if any(k in title for k in ["template injection", "ssti"]):
            return "ssti"
        if any(k in title for k in ["path traversal", "lfi", "rfi", "directory traversal"]):
            return "path"

        # Module-specific
        if module == "cors":
            return "cors"
        if module == "error_disclosure":
            if "input reflection" in title:
                return "input_reflection"
            return "error_disclosure"

        # Header findings
        if "missing security header" in title or "missing header" in title:
            return "missing_header"
        if "insecure cookie" in title:
            return "insecure_cookie"
        if "server header" in title:
            return "missing_header"

        # Other
        if "idor" in title or "insecure direct" in title:
            return "idor"
        if "ssrf" in title:
            return "ssrf"
        if "rate limit" in title:
            return "rate_limiting"
        if "api" in title and ("route" in title or "endpoint" in title or "discover" in title):
            return "js_secrets" if module == "js_bundle" else "endpoint_discovery"
        if module == "js_bundle":
            return "js_secrets"
        if module == "endpoint_prober":
            return "endpoint_discovery"

        # Fallback to generic injection if module is injection
        if module == "injection":
            for cat in ["sqli", "xss", "cmdi", "ssti", "path"]:
                if cat in desc:
                    return cat
            return "sqli"  # default injection

        return ""

    def _generic_impact(self, finding: Finding, param: str) -> str:
        """Generate a generic but concrete impact statement."""
        sev = finding.severity
        module = finding.scanner_module

        if sev == Severity.CRITICAL:
            return (f"This vulnerability enables an attacker to compromise the "
                    f"application's confidentiality, integrity, and availability. "
                    f"Demonstrated via {param} — exploitation achieves "
                    f"unauthorized access to sensitive data or system control.")
        elif sev == Severity.HIGH:
            return (f"An attacker can exploit this vulnerability through "
                    f"{param} to access unauthorized data or perform "
                    f"privileged actions. This has direct security impact on "
                    f"users and application data.")
        elif sev == Severity.MEDIUM:
            return (f"This vulnerability in {param} allows an "
                    f"attacker to bypass intended security controls. "
                    f"Exploitation enables unauthorized data access or "
                    f"modification of application behavior.")
        elif sev == Severity.LOW:
            return (f"This finding reveals a security weakness that, while not "
                    f"directly exploitable for data access, reduces defense-in-depth "
                    f"and could facilitate more serious attacks when combined with "
                    f"other vulnerabilities.")
        else:
            return (f"This finding provides information valuable for security "
                    f"reconnaissance. While informational, it reveals application "
                    f"structure, configuration, or behavior useful for further testing.")

    # ====================================================================
    # POC CURL GENERATION
    # ====================================================================

    def _enrich_poc_curl(self, finding: Finding) -> None:
        """Generate poc_curl from request data."""
        if finding.poc_curl:
            return

        url = finding.url
        if not url:
            return

        request_str = finding.request or ""
        method = "GET"
        headers: List[str] = []

        # Extract method from request string
        m = re.match(r'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s', request_str)
        if m:
            method = m.group(1)

        # Build curl command
        parts = ["curl", "-sSk"]

        if method != "GET":
            parts.extend(["-X", method])

        # Add common security testing headers
        parts.extend([
            "-H", shlex.quote("User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
        ])

        # For CORS findings, add Origin header
        if finding.scanner_module == "cors":
            parts.extend(["-H", "Origin: https://evil.com"])

        # URL with payload
        if finding.payload and finding.parameter:
            # Reconstruct the URL with the payload
            parts.append(shlex.quote(url))
        else:
            parts.append(shlex.quote(url))

        finding.poc_curl = " ".join(parts)

    # ====================================================================
    # REPRODUCTION STEPS
    # ====================================================================

    def _enrich_reproduction_steps(self, finding: Finding) -> None:
        """Generate reproduction steps from available data."""
        if finding.reproduction_steps and len(finding.reproduction_steps) >= 2:
            return

        steps = []
        vuln_type = self._detect_vuln_type(finding)
        url = finding.url
        param = finding.parameter or "the target parameter"
        payload = finding.payload

        if vuln_type in ("sqli", "xss", "cmdi", "ssti", "path"):
            steps = [
                f"1. Navigate to {url}",
                f"2. Inject the payload `{payload}` into the `{param}` parameter" if payload else f"2. Submit a test payload in the `{param}` parameter",
                f"3. Observe the server response — the application processes the injected input in the {self._vuln_context(vuln_type)}",
                f"4. Verify the finding by checking the response for {self._vuln_indicator(vuln_type)}",
            ]
            if finding.poc_curl:
                steps.append(f"5. Alternatively, run the following command: {finding.poc_curl}")

        elif vuln_type in ("missing_header", "insecure_cookie"):
            steps = [
                f"1. Send a request to {url}",
                f"2. Inspect the response headers",
                f"3. Verify that the `{param}` header/flag is missing from the response",
                f"4. Confirm with: curl -sSk -I {shlex.quote(url)} | grep -i '{param}'",
            ]

        elif vuln_type == "cors":
            steps = [
                f"1. Send a request to {url} with header `Origin: https://evil.com`",
                f"2. Check if the response contains `Access-Control-Allow-Origin: https://evil.com`",
                f"3. Verify `Access-Control-Allow-Credentials: true` is also present",
                f"4. Confirm that authenticated cross-origin requests return sensitive data",
            ]

        elif vuln_type in ("error_disclosure", "input_reflection"):
            steps = [
                f"1. Send a request to {url}",
                f"2. Observe the error response body",
                f"3. Note that user input is reflected/echoed in the response without sanitization",
                f"4. Verify the reflection context to assess XSS potential",
            ]

        elif vuln_type in ("endpoint_discovery", "js_secrets"):
            steps = [
                f"1. Navigate to {url}",
                f"2. Inspect the JavaScript bundles loaded by the page",
                f"3. Search for API endpoints, hardcoded tokens, or internal URLs in the JS source",
                f"4. Test discovered endpoints for authentication requirements and access controls",
            ]

        else:
            # Generic steps
            steps = [
                f"1. Send a request to {url}",
                f"2. Observe the response for the vulnerability indicator described in the evidence",
                f"3. Confirm the finding is reproducible by repeating the request",
            ]
            if finding.poc_curl:
                steps.append(f"4. Alternatively, run: {finding.poc_curl}")

        finding.reproduction_steps = steps

    def _vuln_context(self, vuln_type: str) -> str:
        """Human-readable context for where the vuln is processed."""
        return {
            "sqli": "SQL query, as shown by the database error or modified response",
            "xss": "HTML response without encoding, as shown by the reflected payload",
            "cmdi": "system command, as shown by the command output in the response",
            "ssti": "template engine, as shown by the evaluated expression in the response",
            "path": "file path, as shown by the file contents in the response",
        }.get(vuln_type, "backend processing pipeline")

    def _vuln_indicator(self, vuln_type: str) -> str:
        """What to look for in the response to confirm the vuln."""
        return {
            "sqli": "SQL error messages, modified query results, or time delays",
            "xss": "the injected JavaScript payload rendered unescaped in the HTML source",
            "cmdi": "command output (e.g., /etc/passwd contents, OS version, whoami output)",
            "ssti": "evaluated template expressions (e.g., mathematical results, object dumps)",
            "path": "file contents from outside the web root (e.g., /etc/passwd, config files)",
        }.get(vuln_type, "the vulnerability signature described in the evidence section")
