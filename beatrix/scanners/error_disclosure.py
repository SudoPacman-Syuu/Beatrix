"""
BEATRIX Error Disclosure Scanner

Born from: Bykea track-backend.bykea.net engagement (2026-02-05)
Report #3541088 — PostgreSQL error leak, Joi validation leak, input echo

Detects verbose error responses that leak:
- Database engine + table names (PostgreSQL, MySQL, MSSQL, MongoDB, SQLite)
- Framework internals (Joi, Express, Django, Laravel, Spring, ASP.NET)
- Stack traces and file paths
- Input reflection in error messages
- Server version headers in error responses

Technique: Probe common API patterns with invalid/edge-case inputs and
analyze error responses for information leakage. This is the exact
technique that found CVE-worthy findings on Bykea.

OWASP: A05:2021 Security Misconfiguration
CWE: CWE-209 (Generation of Error Message Containing Sensitive Information)
"""

import re
from typing import AsyncIterator, List, Tuple
from urllib.parse import urljoin, urlparse

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext


class ErrorDisclosureScanner(BaseScanner):
    """
    Probes endpoints with invalid inputs to trigger verbose error responses.

    Battle-tested on live targets. This scanner found:
    - PostgreSQL table names + error codes on Bykea
    - Joi validation internals leaking parameter names
    - Input echo in error messages (XSS stepping stone)
    """

    name = "error_disclosure"
    description = "Verbose error response scanner — leaks DB, framework, and stack info"
    version = "1.0.0"

    owasp_category = "A05:2021"

    # =========================================================================
    # PROBE PAYLOADS — paths appended to base URL to trigger errors
    # =========================================================================

    # API path patterns that commonly trigger verbose errors
    PROBE_PATHS = [
        # Invoice/payment endpoints (found Bykea's PG leak)
        "/v1/invoice/1",
        "/v1/invoice/anything",
        "/v1/invoices/1",
        "/api/invoice/1",
        "/api/v1/invoice/1",
        # Booking/order endpoints (found Bykea's Joi leak)
        "/v1/booking/1/",
        "/v1/booking/1/anything",
        "/api/booking/1",
        "/api/v1/booking/1",
        "/v1/order/1",
        "/api/order/1",
        # User/account endpoints
        "/v1/user/1",
        "/api/user/1",
        "/api/v1/user/1",
        "/v1/account/1",
        "/api/account/1",
        # Generic CRUD that often leaks on bad IDs
        "/v1/item/1",
        "/api/v1/item/1",
        "/v1/payment/1",
        "/api/payment/1",
        "/v1/transaction/1",
        "/v1/trip/1",
        "/v1/ride/1",
        "/v1/delivery/1",
        # GraphQL error probing
        "/graphql",
        "/api/graphql",
        # Admin/internal
        "/admin",
        "/api/admin",
        "/v1/admin",
        "/internal",
        "/debug",
        "/status",
        "/health",
        "/info",
        "/env",
    ]

    # Values to inject as path parameters to trigger different error types
    FUZZ_VALUES = [
        "1",                    # Valid-looking numeric ID
        "0",                    # Zero — edge case
        "-1",                   # Negative — edge case
        "999999999",            # Large number — out of range
        "anything",             # Non-numeric — type error
        "null",                 # Null string — special handling
        "undefined",            # JS undefined
        "true",                 # Boolean coercion
        "{{7*7}}",              # SSTI probe
        "'",                    # SQL single quote
        "../../../etc/passwd",  # Path traversal
        "<script>",             # XSS probe
        "",                     # Empty — trailing slash
    ]

    # =========================================================================
    # DETECTION PATTERNS — what to look for in responses
    # =========================================================================

    # Database engine signatures
    DB_PATTERNS: List[Tuple[str, str, Severity]] = [
        # PostgreSQL
        (r'"code"\s*:\s*"(\d{2}[A-Z]\d{2})"', "PostgreSQL error code", Severity.MEDIUM),
        (r'relation\s+"(\w+)"\s+does not exist', "PostgreSQL table name leak", Severity.MEDIUM),
        (r'column\s+"(\w+)"\s+does not exist', "PostgreSQL column name leak", Severity.MEDIUM),
        (r'PostgreSQL.*ERROR', "PostgreSQL error", Severity.MEDIUM),
        (r'pg_\w+', "PostgreSQL internal reference", Severity.LOW),
        (r'SQLSTATE\[(\w+)\]', "PostgreSQL SQLSTATE", Severity.MEDIUM),
        # MySQL
        (r'SQL syntax.*MySQL', "MySQL syntax error", Severity.MEDIUM),
        (r'Warning.*mysql_', "MySQL PHP warning", Severity.MEDIUM),
        (r'MySQLSyntaxErrorException', "MySQL Java exception", Severity.MEDIUM),
        (r'Table\s+\'(\w+\.\w+)\'\s+doesn\'t exist', "MySQL table name leak", Severity.MEDIUM),
        (r'Unknown column\s+\'(\w+)\'', "MySQL column name leak", Severity.MEDIUM),
        # MSSQL
        (r'Microsoft.*ODBC.*SQL Server', "MSSQL ODBC error", Severity.MEDIUM),
        (r'Unclosed quotation mark', "MSSQL quote error", Severity.MEDIUM),
        (r'SqlException', "MSSQL exception", Severity.MEDIUM),
        # MongoDB
        (r'MongoError', "MongoDB error", Severity.MEDIUM),
        (r'MongoDB.*ServerError', "MongoDB server error", Severity.MEDIUM),
        (r'BSONTypeError', "MongoDB BSON error", Severity.MEDIUM),
        (r'Cast to ObjectId failed', "MongoDB ObjectId leak", Severity.LOW),
        # SQLite
        (r'SQLite3::SQLException', "SQLite exception", Severity.MEDIUM),
        (r'SQLITE_ERROR', "SQLite error", Severity.MEDIUM),
        # Redis
        (r'WRONGTYPE Operation', "Redis type error", Severity.LOW),
        (r'ERR unknown command', "Redis command leak", Severity.LOW),
    ]

    # Framework/validation signatures
    FRAMEWORK_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Node.js / Hapi / Joi (found on Bykea)
        (r'"validation"\s*:\s*\{.*"source".*"keys"', "Joi validation internals leak", Severity.LOW),
        (r'child\s+"(\w+)"\s+fails because', "Joi parameter name leak", Severity.LOW),
        (r'hapi.*error', "Hapi.js framework error", Severity.INFO),
        # Express / Node.js
        (r'Cannot (GET|POST|PUT|DELETE|PATCH)\s+/', "Express route not found", Severity.INFO),
        (r'ReferenceError:', "Node.js ReferenceError", Severity.LOW),
        (r'TypeError:', "Node.js TypeError", Severity.LOW),
        (r'SyntaxError.*JSON', "JSON parse error leak", Severity.LOW),
        # Django
        (r'Django Version:', "Django version leak", Severity.LOW),
        (r'Traceback.*File\s+".*\.py"', "Python traceback with file path", Severity.MEDIUM),
        (r'ProgrammingError at', "Django DB error", Severity.MEDIUM),
        # Laravel / PHP
        (r'Illuminate\\.*Exception', "Laravel exception leak", Severity.MEDIUM),
        (r'SQLSTATE\[.*\].*PDOException', "Laravel PDO exception", Severity.MEDIUM),
        (r'Stack trace:.*#\d+\s+/', "PHP stack trace", Severity.MEDIUM),
        # Spring / Java
        (r'org\.springframework', "Spring framework leak", Severity.LOW),
        (r'java\.\w+\.\w+Exception', "Java exception leak", Severity.LOW),
        (r'Whitelabel Error Page', "Spring Boot default error page", Severity.INFO),
        # ASP.NET
        (r'ASP\.NET.*Version', "ASP.NET version leak", Severity.LOW),
        (r'Server Error in.*Application', "ASP.NET server error page", Severity.LOW),
        # Ruby on Rails
        (r'ActionController::RoutingError', "Rails routing error", Severity.INFO),
        (r'ActiveRecord::.*Error', "Rails ActiveRecord error", Severity.MEDIUM),
    ]

    # Stack trace / file path patterns
    STACK_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'at\s+\S+\s+\((/[^\)]+\.js:\d+:\d+)\)', "Node.js stack trace with file path", Severity.MEDIUM),
        (r'File\s+"(/[^"]+\.py)",\s+line\s+\d+', "Python file path in traceback", Severity.MEDIUM),
        (r'(/[a-zA-Z0-9_/]+\.(?:php|rb|java|go|rs))\s*(?::\d+|$)', "Server-side file path leak", Severity.MEDIUM),
        (r'/home/\w+/', "Home directory path leak", Severity.LOW),
        (r'/var/www/', "Web root path leak", Severity.LOW),
        (r'/opt/\w+/', "Install path leak", Severity.LOW),
        (r'/app/', "Container app path leak", Severity.INFO),
    ]

    # Server version patterns (from headers)
    SERVER_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'nginx/(\d+\.\d+\.\d+)', "nginx version disclosed", Severity.INFO),
        (r'Apache/(\d+\.\d+\.\d+)', "Apache version disclosed", Severity.INFO),
        (r'Microsoft-IIS/(\d+\.\d+)', "IIS version disclosed", Severity.INFO),
        (r'openresty/(\d+\.\d+\.\d+)', "OpenResty version disclosed", Severity.INFO),
    ]

    # Input reflection pattern
    INPUT_ECHO_SEVERITY = Severity.LOW

    # CORS wildcards on error pages
    CORS_WILDCARD_SEVERITY = Severity.LOW

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Probe target with error-triggering requests and analyze responses.
        """
        base = context.base_url
        self.log(f"Error disclosure scan on {base}")

        seen_findings: set = set()  # Dedup by (pattern_name, url)

        for path in self.PROBE_PATHS:
            url = urljoin(base, path)

            try:
                response = await self.get(url)
            except Exception:
                continue

            body = response.text
            headers = {k.lower(): v for k, v in response.headers.items()}
            status = response.status_code

            # Only analyze error responses (4xx, 5xx) — that's where the gold is
            if status < 400:
                continue

            # --- Database leaks ---
            for pattern, name, severity in self.DB_PATTERNS:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    key = (name, url)
                    if key not in seen_findings:
                        seen_findings.add(key)
                        yield self.create_finding(
                            title=f"Database Information Disclosure: {name}",
                            severity=severity,
                            confidence=Confidence.CERTAIN,
                            url=url,
                            description=(
                                f"The endpoint returns a verbose error response that "
                                f"exposes database internals. Detected: {name}. "
                                f"Match: `{match.group(0)}`"
                            ),
                            evidence=self._truncate_body(body, 500),
                            request=f"GET {url}",
                            response=f"HTTP {status}\n{body[:300]}",
                            remediation=(
                                "Catch database exceptions server-side and return "
                                "generic error messages. Log detailed errors internally "
                                "only. Never expose table names, column names, or "
                                "database-specific error codes to the client."
                            ),
                            references=[
                                "https://cwe.mitre.org/data/definitions/209.html",
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/",
                            ],
                        )

            # --- Framework leaks ---
            for pattern, name, severity in self.FRAMEWORK_PATTERNS:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    key = (name, url)
                    if key not in seen_findings:
                        seen_findings.add(key)
                        yield self.create_finding(
                            title=f"Framework Information Disclosure: {name}",
                            severity=severity,
                            confidence=Confidence.CERTAIN,
                            url=url,
                            description=(
                                f"Error response exposes framework/validation internals. "
                                f"Detected: {name}. Match: `{match.group(0)[:200]}`"
                            ),
                            evidence=self._truncate_body(body, 500),
                            request=f"GET {url}",
                            response=f"HTTP {status}\n{body[:300]}",
                            remediation=(
                                "Strip framework-specific error details from production "
                                "responses. Return generic error messages only."
                            ),
                        )

            # --- Stack trace / file path leaks ---
            for pattern, name, severity in self.STACK_PATTERNS:
                match = re.search(pattern, body)
                if match:
                    key = (name, url)
                    if key not in seen_findings:
                        seen_findings.add(key)
                        yield self.create_finding(
                            title=f"Stack Trace / Path Disclosure: {name}",
                            severity=severity,
                            confidence=Confidence.CERTAIN,
                            url=url,
                            description=(
                                f"Error response contains server-side file paths or "
                                f"stack traces. Leaked path: `{match.group(0)[:200]}`"
                            ),
                            evidence=self._truncate_body(body, 500),
                            request=f"GET {url}",
                            response=f"HTTP {status}",
                            remediation=(
                                "Disable stack traces in production. Set NODE_ENV=production, "
                                "DEBUG=false, or equivalent for your framework."
                            ),
                        )

            # --- Server version in headers ---
            server = headers.get("server", "")
            if server:
                for pattern, name, severity in self.SERVER_PATTERNS:
                    match = re.search(pattern, server)
                    if match:
                        key = ("server_version", match.group(0))
                        if key not in seen_findings:
                            seen_findings.add(key)
                            yield self.create_finding(
                                title=f"Server Version Disclosure: {match.group(0)}",
                                severity=severity,
                                confidence=Confidence.CERTAIN,
                                url=url,
                                description=(
                                    f"Server header exposes exact version: `{server}`. "
                                    f"Attackers can look up known CVEs for this version."
                                ),
                                evidence=f"server: {server}",
                                remediation="server_tokens off; in nginx config, or equivalent.",
                            )

            # --- CORS wildcard on error pages ---
            acao = headers.get("access-control-allow-origin", "")
            if acao == "*" and status >= 400:
                key = ("cors_wildcard_error", base)
                if key not in seen_findings:
                    seen_findings.add(key)
                    yield self.create_finding(
                        title="CORS Wildcard on Error Responses",
                        severity=self.CORS_WILDCARD_SEVERITY,
                        confidence=Confidence.CERTAIN,
                        url=url,
                        description=(
                            "Error responses are served with Access-Control-Allow-Origin: *. "
                            "Any webpage can read these error messages via JavaScript, "
                            "enabling cross-origin information gathering."
                        ),
                        evidence=f"access-control-allow-origin: {acao}",
                        remediation="Restrict CORS to trusted origins, especially on error responses.",
                    )

        # --- Fuzz with edge-case values ---
        async for finding in self._fuzz_existing_paths(context):
            yield finding

    async def _fuzz_existing_paths(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Take the target URL and fuzz path segments with edge-case values.
        Tests: /base/FUZZ and /base/FUZZ/FUZZ
        """
        base = context.base_url
        parsed = urlparse(context.url)
        path_segments = [s for s in parsed.path.split("/") if s]

        # If URL has path segments, fuzz the last one
        if path_segments:
            parent = "/".join(path_segments[:-1])
            for fuzz in self.FUZZ_VALUES[:5]:  # Limit to avoid noise
                fuzz_url = urljoin(base, f"/{parent}/{fuzz}" if parent else f"/{fuzz}")
                try:
                    response = await self.get(fuzz_url)
                    if response.status_code >= 400:
                        body = response.text
                        # Check if our input is reflected in the error
                        if fuzz in body and fuzz not in ("1", "0", "true"):
                            yield self.create_finding(
                                title="Input Reflection in Error Response",
                                severity=Severity.LOW,
                                confidence=Confidence.FIRM,
                                url=fuzz_url,
                                description=(
                                    f"The error response echoes user input back in the body. "
                                    f"Input `{fuzz}` appears in the response. This can be "
                                    f"a stepping stone for XSS if the response is HTML."
                                ),
                                evidence=f"Input: {fuzz}\nReflected in: {body[:300]}",
                                request=f"GET {fuzz_url}",
                                response=f"HTTP {response.status_code}",
                                remediation="Never echo raw user input in error messages.",
                            )
                except Exception:
                    continue

    @staticmethod
    def _truncate_body(body: str, max_len: int = 500) -> str:
        """Truncate response body for evidence"""
        if len(body) <= max_len:
            return body
        return body[:max_len] + f"\n... ({len(body) - max_len} bytes truncated)"
