"""
BEATRIX Prototype Pollution Scanner

Born from: HackerOne reports + Black Hat research on JavaScript prototype pollution
https://portswigger.net/web-security/prototype-pollution

TECHNIQUE:
1. Client-side prototype pollution: inject __proto__.polluted via URL params, JSON body
2. Server-side prototype pollution (Node.js): merge/extend functions processing user input
3. Detect via gadget activation: polluted properties that trigger XSS/RCE
4. DOM-based detection: inject properties that affect DOM manipulation
5. Object.assign / lodash.merge / jQuery.extend abuse
6. Test JSON body with __proto__, constructor.prototype, __proto__[key]

CLIENT-SIDE ATTACK CHAIN:
1. Pollute Object.prototype.innerHTML (or similar)
2. Any code that reads obj[key] where key doesn't exist → gets polluted value
3. If polluted value is rendered in DOM → XSS

SERVER-SIDE ATTACK CHAIN:
1. Send JSON with {"__proto__": {"isAdmin": true}} to API
2. If server uses recursive merge (lodash.merge, etc.) → all objects get isAdmin
3. Privilege escalation or RCE via child_process.execSync options pollution

SEVERITY: HIGH-CRITICAL
- Client-side: DOM XSS at scale
- Server-side: privilege escalation, RCE in Node.js

OWASP: A03:2021 - Injection
       A08:2021 - Software and Data Integrity Failures

MITRE: T1190 (Exploit Public-Facing Application)
       T1059 (Command and Scripting Interpreter — server-side RCE)

CWE: CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)

REFERENCES:
- https://portswigger.net/web-security/prototype-pollution
- https://portswigger.net/research/server-side-prototype-pollution
- https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution
- https://github.com/nickvdp/prototype-pollution-research
"""

import json
import random
import re
import string
from dataclasses import dataclass
from enum import Enum
from typing import Any, AsyncIterator, Dict, Optional

try:
    import httpx
except ImportError:
    httpx = None

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext

# =============================================================================
# DATA MODELS
# =============================================================================

class PPollutionType(Enum):
    """Prototype pollution variant"""
    CLIENT_URL_PARAM = "client_url_param"
    CLIENT_HASH_PARAM = "client_hash_param"
    SERVER_JSON_BODY = "server_json_body"
    SERVER_QUERY_PARAM = "server_query_param"
    JSON_MERGE = "json_merge"
    CONSTRUCTOR_PROTO = "constructor_prototype"


@dataclass
class PPollutionPayload:
    """A prototype pollution test payload"""
    name: str
    variant: PPollutionType
    key: str           # The property to pollute (canary name)
    value: str         # Value to set
    delivery: str      # How the payload is delivered
    description: str


# =============================================================================
# DETECTION PROPERTIES
# =============================================================================

# Server-side: properties that affect Node.js behavior if polluted
SERVER_SIDE_GADGETS = {
    # RCE via child_process
    "shell": "/proc/self/exe",
    "NODE_OPTIONS": "--require /proc/self/environ",

    # Status code manipulation (easy detection)
    "status": "510",
    "statusCode": "510",

    # Auth bypass
    "isAdmin": "true",
    "admin": "true",
    "role": "admin",
    "verified": "true",

    # Content-Type manipulation
    "content-type": "text/html",
    "type": "text/html",

    # View engine (EJS/Pug RCE)
    "outputFunctionName": "x]});process.mainModule.require('child_process').execSync('id')//",
}

# Client-side: DOM gadgets
CLIENT_SIDE_GADGETS = [
    "innerHTML",
    "outerHTML",
    "srcdoc",
    "src",
    "href",
    "action",
    "formaction",
    "data",
    "value",
    "text",
    "textContent",
    "onclick",
    "onerror",
    "onload",
]


# =============================================================================
# SCANNER
# =============================================================================

class PrototypePollutionScanner(BaseScanner):
    """
    Prototype Pollution Scanner.

    Tests both client-side and server-side prototype pollution:

    Client-side:
    - URL parameter injection (?__proto__[key]=value)
    - Hash fragment injection (#__proto__[key]=value)
    - DOM property pollution detection

    Server-side:
    - JSON body with __proto__ key
    - constructor.prototype injection
    - Response behavior change detection (status, headers, body)
    """

    name = "prototype_pollution"
    description = "Prototype Pollution Scanner"
    version = "1.0.0"

    checks = [
        "server_proto_json",
        "server_constructor_proto",
        "server_status_pollution",
        "client_url_pollution",
        "passive_js_analysis",
    ]

    owasp_category = "A03:2021"
    mitre_technique = "T1190"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.safe_mode = self.config.get("safe_mode", True)
        self.canary = "btrx" + "".join(random.choices(string.ascii_lowercase, k=6))
        self.canary_value = "".join(random.choices(string.digits, k=8))

    # =========================================================================
    # SERVER-SIDE PROTOTYPE POLLUTION
    # =========================================================================

    async def _test_server_json_proto(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Test server-side PP via JSON body with __proto__"""

        # Phase 1: Baseline — normal request
        try:
            baseline = await self.post(
                context.url,
                json={"test": "baseline"},
                headers={"Content-Type": "application/json"},
            )
            baseline_status = baseline.status_code
            dict(baseline.headers)
            baseline_body = baseline.text
        except Exception:
            return

        # Phase 2: __proto__ injection variants
        proto_payloads = [
            # Standard __proto__
            {
                "name": "__proto__",
                "data": {"__proto__": {self.canary: self.canary_value}},
            },
            # constructor.prototype
            {
                "name": "constructor.prototype",
                "data": {"constructor": {"prototype": {self.canary: self.canary_value}}},
            },
            # Nested __proto__
            {
                "name": "nested.__proto__",
                "data": {"a": {"__proto__": {self.canary: self.canary_value}}},
            },
            # Status code pollution (detectable)
            {
                "name": "__proto__.status",
                "data": {"__proto__": {"status": 510}},
            },
            # JSON spaces pollution (detectable via response formatting)
            {
                "name": "__proto__.json_spaces",
                "data": {"__proto__": {"json spaces": "  "}},
            },
        ]

        for payload in proto_payloads:
            try:
                resp = await self.post(
                    context.url,
                    json=payload["data"],
                    headers={"Content-Type": "application/json"},
                )

                polluted = False
                evidence_detail = ""

                # Check 1: Status code changed (status pollution)
                if payload["name"] == "__proto__.status" and resp.status_code == 510:
                    polluted = True
                    evidence_detail = f"Status code changed: {baseline_status} → 510"

                # Check 2: Canary appears in response (but NOT in baseline and NOT URL echo)
                if self.canary_value in resp.text and self.canary_value not in baseline_body:
                    if not self._is_url_echo(resp.text, self.canary_value):
                        polluted = True
                        evidence_detail = f"Canary value '{self.canary_value}' reflected in response (not in baseline, not URL echo)"

                # Check 3: New headers appeared
                for h_name, h_val in resp.headers.items():
                    if self.canary in h_name.lower() or self.canary_value in h_val:
                        polluted = True
                        evidence_detail = f"Polluted value in response header: {h_name}: {h_val}"

                # Check 4: JSON formatting changed (json spaces gadget)
                if payload["name"] == "__proto__.json_spaces":
                    if resp.text != baseline_body and "  " in resp.text and "  " not in baseline_body:
                        polluted = True
                        evidence_detail = "JSON response formatting changed (json spaces gadget)"

                # Check 5: Response body structure changed significantly
                if not polluted and resp.status_code != baseline_status:
                    if resp.status_code not in (400, 422):  # Not just malformed JSON error
                        evidence_detail = f"Status changed: {baseline_status} → {resp.status_code}"
                        # Only flag as potential if not a parse error
                        if resp.status_code >= 500:
                            polluted = True

                if polluted:
                    yield self.create_finding(
                        title=f"Server-Side Prototype Pollution: {payload['name']}",
                        severity=Severity.CRITICAL if "status" not in payload["name"] else Severity.HIGH,
                        confidence=Confidence.CERTAIN if "Canary" in evidence_detail or "510" in evidence_detail else Confidence.FIRM,
                        url=context.url,
                        description=(
                            f"Server-side prototype pollution detected via {payload['name']}.\n\n"
                            f"Payload: {json.dumps(payload['data'])}\n"
                            f"Detection: {evidence_detail}\n\n"
                            "Server-side prototype pollution in Node.js can lead to:\n"
                            "- Remote Code Execution (via child_process gadgets)\n"
                            "- Authentication bypass (isAdmin, role pollution)\n"
                            "- Denial of Service (crash via type confusion)"
                        ),
                        evidence=evidence_detail,
                        request=json.dumps(payload["data"], indent=2),
                        response=resp.text[:1000],
                        remediation=(
                            "1. Use Object.create(null) for user-controlled data objects\n"
                            "2. Use Map instead of plain objects for key-value stores\n"
                            "3. Freeze Object.prototype: Object.freeze(Object.prototype)\n"
                            "4. Validate/sanitize JSON keys — reject __proto__, constructor, prototype\n"
                            "5. Use safe merge libraries (lodash >= 4.17.12)\n"
                            "6. Use --disable-proto=throw Node.js flag (v12+)"
                        ),
                        references=[
                            "https://portswigger.net/research/server-side-prototype-pollution",
                            "https://portswigger.net/web-security/prototype-pollution/server-side",
                        ],
                    )

            except Exception:
                continue

    def _is_url_echo(self, text: str, canary: str) -> bool:
        """Check if the canary value only appears inside URL-echo contexts (SSR JSON state, canonical, etc.)"""
        url_echo_patterns = [
            r'"current_url"\s*:\s*"[^"]*' + re.escape(canary),
            r'"canonical_url"\s*:\s*"[^"]*' + re.escape(canary),
            r'"url"\s*:\s*"[^"]*' + re.escape(canary),
            r'href\s*=\s*"[^"]*' + re.escape(canary),
            r'content\s*=\s*"[^"]*' + re.escape(canary),
            r'__proto__.*' + re.escape(canary),
            r'constructor.*' + re.escape(canary),
        ]
        for pat in url_echo_patterns:
            if re.search(pat, text, re.IGNORECASE):
                return True
        return False

    async def _test_server_query_proto(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Test server-side PP via query parameters (Express QS parser)"""

        # Get baseline response (no pollution payload)
        try:
            baseline = await self.get(context.url)
            baseline_body = baseline.text
        except Exception:
            return

        # Express with qs library parses: ?__proto__[key]=value
        probe_params = [
            (f"__proto__[{self.canary}]", self.canary_value),
            (f"__proto__.{self.canary}", self.canary_value),
            ("__proto__[status]", "510"),
            ("constructor[prototype][polluted]", self.canary_value),
        ]

        for param_name, param_value in probe_params:
            try:
                resp = await self.get(
                    context.url,
                    params={param_name: param_value},
                )

                # Status code pollution — definitive
                if param_value == "510" and resp.status_code == 510:
                    yield self.create_finding(
                        title=f"Server-Side Prototype Pollution via Query: {param_name}",
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        url=context.url,
                        description=(
                            f"Prototype pollution via query parameter detected.\n"
                            f"Parameter: {param_name}={param_value}\n\n"
                            "Status code changed to 510, confirming server-side prototype pollution."
                        ),
                        evidence=f"Status: {resp.status_code}",
                        remediation="Set qs parser option: app.set('query parser', 'simple') to disable nested parsing.",
                    )
                    continue

                # Canary value check — must NOT be in baseline AND must not be URL echo
                if self.canary_value in resp.text:
                    if self.canary_value in baseline_body:
                        continue  # Already in baseline — not caused by our payload
                    if self._is_url_echo(resp.text, self.canary_value):
                        continue  # URL echo — SSR reflecting the query string

                    evidence = (
                        f"Status: {resp.status_code}\n"
                        f"Canary '{self.canary_value}' reflected outside URL-echo context"
                    )

                    yield self.create_finding(
                        title=f"Server-Side Prototype Pollution via Query: {param_name}",
                        severity=Severity.HIGH,
                        confidence=Confidence.FIRM,
                        url=context.url,
                        description=(
                            f"Prototype pollution via query parameter detected.\n"
                            f"Parameter: {param_name}={param_value}\n\n"
                            "Express.js with qs parser is vulnerable to query-based prototype pollution.\n"
                            f"{evidence}"
                        ),
                        evidence=evidence,
                        remediation="Set qs parser option: app.set('query parser', 'simple') to disable nested parsing.",
                    )

            except Exception:
                continue

    # =========================================================================
    # CLIENT-SIDE PROTOTYPE POLLUTION
    # =========================================================================

    async def _test_client_url_proto(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Test client-side PP via URL parameters and hash fragments"""

        # URL parameter injection
        pp_urls = [
            f"{context.url}?__proto__[{self.canary}]={self.canary_value}",
            f"{context.url}?__proto__.{self.canary}={self.canary_value}",
            f"{context.url}?constructor.prototype.{self.canary}={self.canary_value}",
        ]

        # Get baseline response for comparison
        try:
            baseline = await self.get(context.url)
            baseline_body = baseline.text
        except Exception:
            return

        for pp_url in pp_urls:
            try:
                resp = await self.get(pp_url)

                # Client-side PP is harder to detect via HTTP alone
                # We look for: the canary value in response (some frameworks reflect)
                # or specific error messages
                if self.canary_value in resp.text:
                    # Filter out false positives:
                    # 1. Value already in baseline (not caused by our payload)
                    if self.canary_value in baseline_body:
                        continue
                    # 2. URL echo — SSR reflects the full URL including our params
                    if self._is_url_echo(resp.text, self.canary_value):
                        continue

                    yield self.create_finding(
                        title="Potential Client-Side Prototype Pollution via URL",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.TENTATIVE,
                        url=pp_url,
                        description=(
                            f"URL parameter with __proto__ payload was processed and value reflected.\n"
                            f"URL: {pp_url}\n\n"
                            "This may indicate client-side prototype pollution. "
                            "Manual verification needed with browser DevTools:\n"
                            f"1. Open: {pp_url}\n"
                            f"2. Console: Object.prototype.{self.canary}\n"
                            f"3. If returns '{self.canary_value}' → confirmed"
                        ),
                        evidence="Canary reflected in response body (not URL echo)",
                        remediation=(
                            "1. Don't use recursive merge on URL parameters\n"
                            "2. Filter __proto__, constructor, prototype from param keys\n"
                            "3. Use Object.create(null) for storing parsed params"
                        ),
                    )

            except Exception:
                continue

    # =========================================================================
    # MAIN SCAN
    # =========================================================================

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Full prototype pollution scan"""

        # Server-side: JSON body
        async for finding in self._test_server_json_proto(context):
            yield finding

        # Server-side: query params
        async for finding in self._test_server_query_proto(context):
            yield finding

        # Client-side: URL params
        async for finding in self._test_client_url_proto(context):
            yield finding

        # Passive
        async for finding in self.passive_scan(context):
            yield finding

    async def passive_scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Detect prototype pollution indicators in JavaScript code"""
        if not context.response:
            return

        body = context.response.body if hasattr(context.response, 'body') else ""

        # Detect vulnerable merge/extend patterns in JavaScript
        vuln_patterns = [
            (r'(?:lodash|_)\.merge\s*\(', "lodash.merge() detected (PP-vulnerable if < 4.17.12)"),
            (r'(?:lodash|_)\.defaultsDeep\s*\(', "lodash.defaultsDeep() detected (PP-vulnerable)"),
            (r'jQuery\.extend\s*\(\s*true', "jQuery.extend(true, ...) deep merge (PP-vulnerable)"),
            (r'\$\.extend\s*\(\s*true', "$.extend(true, ...) deep merge (PP-vulnerable)"),
            (r'Object\.assign\s*\(', "Object.assign() detected (shallow — not PP-vulnerable itself)"),
            (r'\.reduce\s*\([^)]*\{[^}]*\[', "reduce-based merge pattern (potential PP)"),
            (r'JSON\.parse\s*\([^)]*(?:query|params|body|input|data)', "JSON.parse on user input (PP surface)"),
            (r'__proto__', "__proto__ reference in source (PP-related code)"),
            (r'constructor\s*\[\s*[\'"]prototype', "constructor.prototype reference"),
        ]

        for pattern, description in vuln_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                yield self.create_finding(
                    title=f"Prototype Pollution Vector: {description.split('(')[0].strip()}",
                    severity=Severity.LOW,
                    confidence=Confidence.TENTATIVE,
                    url=context.url,
                    description=(
                        f"Potential prototype pollution vector in JavaScript:\n"
                        f"{description}\n\n"
                        "This code pattern may be vulnerable to prototype pollution "
                        "if it processes user-controlled input."
                    ),
                    evidence=f"Pattern: {pattern}",
                    remediation="Review merge/extend calls to ensure __proto__ keys are filtered.",
                )
