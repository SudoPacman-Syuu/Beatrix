#!/usr/bin/env python3
"""
BEATRIX Mobile Traffic Interceptor

Automates the full mobile app interception workflow:
1. Launch Android emulator with proxy configuration
2. Install mitmproxy CA certificate
3. Install target APK
4. Capture and analyze all HTTP/S traffic
5. Extract secrets, API keys, tokens, endpoints from live traffic

Built for the Bykea engagement — intercept production mobile app traffic
to validate leaked credentials against live systems.

Dependencies:
    - Android SDK (emulator, adb, avdmanager)
    - mitmproxy / mitmdump
    - Python 3.10+

Author: BEATRIX
"""

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

# =============================================================================
# DATA TYPES
# =============================================================================

@dataclass
class InterceptedRequest:
    """A captured HTTP request/response pair"""
    timestamp: str
    method: str
    url: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    status_code: int
    response_headers: Dict[str, str]
    response_body: Optional[str]

    @property
    def host(self) -> str:
        from urllib.parse import urlparse
        return urlparse(self.url).hostname or ""

    @property
    def path(self) -> str:
        from urllib.parse import urlparse
        return urlparse(self.url).path


@dataclass
class MobileInterceptConfig:
    """Configuration for mobile interception session"""
    avd_name: str = "bykea_hunter"
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    apk_path: Optional[str] = None
    package_name: Optional[str] = None
    location_lat: float = 29.9688  # Sibi, Pakistan (per Bykea policy)
    location_lon: float = 67.8773
    android_home: str = ""
    capture_file: str = ""
    timeout: int = 300  # seconds to capture before auto-stop

    def __post_init__(self):
        if not self.android_home:
            self.android_home = os.environ.get(
                "ANDROID_HOME",
                os.path.expanduser("~/Android/Sdk")
            )
        if not self.capture_file:
            self.capture_file = f"/tmp/beatrix_capture_{int(time.time())}.json"


@dataclass
class TrafficAnalysis:
    """Results of analyzing intercepted traffic"""
    total_requests: int = 0
    unique_hosts: Set[str] = field(default_factory=set)
    unique_endpoints: Set[str] = field(default_factory=set)
    api_keys_found: Dict[str, str] = field(default_factory=dict)  # header_name -> value
    auth_tokens: List[str] = field(default_factory=list)
    jwt_tokens: List[str] = field(default_factory=list)
    interesting_headers: Dict[str, str] = field(default_factory=dict)
    credentials_in_body: List[Dict] = field(default_factory=list)
    matched_leaked_keys: List[Dict] = field(default_factory=list)  # Keys that match known leaks


# =============================================================================
# MITMPROXY ADDON SCRIPT (written to disk at runtime)
# =============================================================================

MITM_ADDON_SCRIPT = '''
"""BEATRIX mitmproxy addon — captures all traffic to JSON"""
import json
import os
import time
from mitmproxy import http

CAPTURE_FILE = os.environ.get("BEATRIX_CAPTURE_FILE", "/tmp/beatrix_capture.json")
captured = []

class BeatrixCapture:
    def response(self, flow: http.HTTPFlow):
        """Capture every request/response pair"""
        try:
            req_body = None
            if flow.request.content:
                try:
                    req_body = flow.request.content.decode("utf-8", errors="replace")[:10000]
                except Exception:
                    req_body = "<binary>"

            resp_body = None
            if flow.response and flow.response.content:
                try:
                    resp_body = flow.response.content.decode("utf-8", errors="replace")[:50000]
                except Exception:
                    resp_body = "<binary>"

            entry = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "request_headers": dict(flow.request.headers),
                "request_body": req_body,
                "status_code": flow.response.status_code if flow.response else 0,
                "response_headers": dict(flow.response.headers) if flow.response else {},
                "response_body": resp_body,
            }

            captured.append(entry)

            # Write to file after every 5 requests
            if len(captured) % 5 == 0:
                _flush()

        except Exception as e:
            print(f"[BEATRIX] Capture error: {e}")

    def done(self):
        """Flush on shutdown"""
        _flush()

def _flush():
    try:
        with open(CAPTURE_FILE, "w") as f:
            json.dump(captured, f, indent=2)
    except Exception as e:
        print(f"[BEATRIX] Flush error: {e}")

addons = [BeatrixCapture()]
'''


# =============================================================================
# MAIN CLASS
# =============================================================================

class MobileInterceptor:
    """
    Android emulator + mitmproxy traffic interception engine.

    Workflow:
    1. Start mitmproxy with BEATRIX capture addon
    2. Launch Android emulator with HTTP proxy pointed at mitmproxy
    3. Install CA cert for TLS interception
    4. Install target APK
    5. Set GPS location
    6. Wait for user interaction / auto-capture
    7. Analyze captured traffic for secrets
    """

    def __init__(self, config: Optional[MobileInterceptConfig] = None):
        self.config = config or MobileInterceptConfig()
        self._emulator_proc: Optional[subprocess.Popen] = None
        self._mitm_proc: Optional[subprocess.Popen] = None
        self._addon_path: Optional[str] = None
        self.captured_requests: List[InterceptedRequest] = []
        self.analysis: Optional[TrafficAnalysis] = None

        # Validate tools
        self._validate_tools()

    def _validate_tools(self):
        """Check that required tools are available"""
        tools = {
            "emulator": os.path.join(self.config.android_home, "emulator", "emulator"),
            "adb": os.path.join(self.config.android_home, "platform-tools", "adb"),
            "avdmanager": os.path.join(
                self.config.android_home, "cmdline-tools", "latest", "bin", "avdmanager"
            ),
        }

        # Also check PATH
        for name in ["emulator", "adb", "avdmanager"]:
            if not os.path.exists(tools[name]):
                path_bin = shutil.which(name)
                if path_bin:
                    tools[name] = path_bin
                else:
                    raise RuntimeError(
                        f"{name} not found at {tools[name]} or in PATH. "
                        f"Set ANDROID_HOME or install Android SDK."
                    )

        mitmdump = shutil.which("mitmdump")
        if not mitmdump:
            raise RuntimeError("mitmdump not found. Install mitmproxy.")

        self._tools = tools
        self._tools["mitmdump"] = mitmdump

    @property
    def adb(self) -> str:
        return self._tools["adb"]

    @property
    def emulator_bin(self) -> str:
        return self._tools["emulator"]

    # =========================================================================
    # LIFECYCLE
    # =========================================================================

    async def start(self):
        """Start the full interception stack"""
        print("[BEATRIX] Starting mobile interception...")

        # 1. Write the mitmproxy addon script
        self._write_addon_script()

        # 2. Start mitmproxy
        await self._start_mitmproxy()

        # 3. Launch emulator
        await self._launch_emulator()

        # 4. Wait for emulator to boot
        await self._wait_for_boot()

        # 5. Install CA certificate
        await self._install_ca_cert()

        # 6. Set location
        await self._set_location()

        # 7. Install APK if provided
        if self.config.apk_path:
            await self._install_apk()

        print("[BEATRIX] Interception stack ready. Capturing traffic...")

    async def stop(self):
        """Stop everything and collect results"""
        print("[BEATRIX] Stopping interception...")

        if self._mitm_proc:
            self._mitm_proc.terminate()
            try:
                self._mitm_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._mitm_proc.kill()

        if self._emulator_proc:
            # Graceful shutdown via adb
            subprocess.run([self.adb, "emu", "kill"], capture_output=True, timeout=10)
            try:
                self._emulator_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._emulator_proc.kill()

        # Cleanup addon script
        if self._addon_path and os.path.exists(self._addon_path):
            os.unlink(self._addon_path)

        # Load captured data
        self._load_captures()

        print(f"[BEATRIX] Captured {len(self.captured_requests)} requests")

    async def capture_session(self, duration: Optional[int] = None):
        """Run a full capture session for the specified duration"""
        try:
            await self.start()

            wait_time = duration or self.config.timeout
            print(f"[BEATRIX] Capturing for {wait_time}s, or press Ctrl+C to stop...")

            await asyncio.sleep(wait_time)
        except (KeyboardInterrupt, asyncio.CancelledError):
            print("\n[BEATRIX] Capture interrupted.")
        finally:
            await self.stop()

    # =========================================================================
    # MITMPROXY
    # =========================================================================

    def _write_addon_script(self):
        """Write the mitmproxy addon script to a temp file"""
        fd, path = tempfile.mkstemp(suffix=".py", prefix="beatrix_mitm_")
        with os.fdopen(fd, 'w') as f:
            f.write(MITM_ADDON_SCRIPT)
        self._addon_path = path

    async def _start_mitmproxy(self):
        """Start mitmdump with our capture addon"""
        env = os.environ.copy()
        env["BEATRIX_CAPTURE_FILE"] = self.config.capture_file

        cmd = [
            self._tools["mitmdump"],
            "--listen-host", self.config.proxy_host,
            "--listen-port", str(self.config.proxy_port),
            "--set", "block_global=false",
            "--set", "ssl_insecure=true",
            "-s", self._addon_path,
            "--quiet",
        ]

        self._mitm_proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for it to bind
        await asyncio.sleep(2)

        if self._mitm_proc.poll() is not None:
            stderr = self._mitm_proc.stderr.read().decode()
            raise RuntimeError(f"mitmproxy failed to start: {stderr}")

        print(f"[BEATRIX] mitmproxy listening on {self.config.proxy_host}:{self.config.proxy_port}")

    # =========================================================================
    # EMULATOR
    # =========================================================================

    async def _launch_emulator(self):
        """Launch Android emulator with proxy configured"""
        env = os.environ.copy()
        env["ANDROID_HOME"] = self.config.android_home
        env["ANDROID_SDK_ROOT"] = self.config.android_home

        cmd = [
            self.emulator_bin,
            "-avd", self.config.avd_name,
            "-http-proxy", f"http://{self.config.proxy_host}:{self.config.proxy_port}",
            "-no-snapshot-save",
            "-no-audio",
            "-gpu", "swiftshader_indirect",
            "-no-window",  # Headless — change to -gpu host for GUI
        ]

        self._emulator_proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        print(f"[BEATRIX] Emulator '{self.config.avd_name}' launching (headless)...")

    async def _wait_for_boot(self, timeout: int = 120):
        """Wait for emulator to fully boot"""
        print("[BEATRIX] Waiting for emulator boot...")

        deadline = time.time() + timeout
        while time.time() < deadline:
            result = subprocess.run(
                [self.adb, "shell", "getprop", "sys.boot_completed"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.stdout.strip() == "1":
                print("[BEATRIX] Emulator booted.")
                await asyncio.sleep(3)  # Extra settle time
                return

            await asyncio.sleep(2)

        raise TimeoutError("Emulator failed to boot within timeout")

    async def _install_ca_cert(self):
        """Install mitmproxy CA certificate for TLS interception"""
        ca_cert = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.cer")

        if not os.path.exists(ca_cert):
            # Generate it by running mitmdump briefly
            print("[BEATRIX] Generating mitmproxy CA certificate...")
            proc = subprocess.Popen(
                [self._tools["mitmdump"], "--listen-port", "18999"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            await asyncio.sleep(2)
            proc.terminate()

        if not os.path.exists(ca_cert):
            print("[BEATRIX] Warning: CA cert not found, TLS interception may fail")
            return

        # Convert to system cert format
        # Get the hash Android expects
        result = subprocess.run(
            ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", ca_cert, "-noout"],
            capture_output=True,
            text=True,
        )
        cert_hash = result.stdout.strip()

        if cert_hash:
            system_cert_name = f"{cert_hash}.0"
            tmp_cert = f"/tmp/{system_cert_name}"

            # Convert PEM to system cert format
            subprocess.run(
                ["openssl", "x509", "-inform", "PEM", "-in", ca_cert, "-out", tmp_cert],
                capture_output=True,
            )

            # Push to device and install as system CA
            subprocess.run(
                [self.adb, "root"],
                capture_output=True,
                timeout=10,
            )
            await asyncio.sleep(1)

            subprocess.run(
                [self.adb, "remount"],
                capture_output=True,
                timeout=10,
            )
            await asyncio.sleep(1)

            subprocess.run(
                [self.adb, "push", tmp_cert, f"/system/etc/security/cacerts/{system_cert_name}"],
                capture_output=True,
                timeout=10,
            )

            subprocess.run(
                [self.adb, "shell", "chmod", "644", f"/system/etc/security/cacerts/{system_cert_name}"],
                capture_output=True,
                timeout=10,
            )

            print(f"[BEATRIX] CA certificate installed as {system_cert_name}")

        # Also push to user cert store as fallback
        subprocess.run(
            [self.adb, "push", ca_cert, "/sdcard/Download/mitmproxy-ca.cer"],
            capture_output=True,
            timeout=10,
        )
        print("[BEATRIX] CA cert also pushed to /sdcard/Download/ for manual install")

    async def _set_location(self):
        """Set GPS location on emulator"""
        lat = self.config.location_lat
        lon = self.config.location_lon

        subprocess.run(
            [self.adb, "emu", "geo", "fix", str(lon), str(lat)],
            capture_output=True,
            timeout=10,
        )

        print(f"[BEATRIX] Location set to {lat}, {lon} (Sibi, Pakistan)")

    async def _install_apk(self):
        """Install APK on emulator"""
        if not self.config.apk_path or not os.path.exists(self.config.apk_path):
            print(f"[BEATRIX] APK not found: {self.config.apk_path}")
            return

        result = subprocess.run(
            [self.adb, "install", "-r", "-g", self.config.apk_path],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode == 0:
            print(f"[BEATRIX] APK installed: {self.config.apk_path}")
        else:
            print(f"[BEATRIX] APK install failed: {result.stderr}")

    async def launch_app(self, package_name: str):
        """Launch an app on the emulator"""
        subprocess.run(
            [self.adb, "shell", "monkey", "-p", package_name,
             "-c", "android.intent.category.LAUNCHER", "1"],
            capture_output=True,
            timeout=10,
        )
        print(f"[BEATRIX] Launched {package_name}")

    async def download_apk(self, package_name: str, output_dir: str = "/tmp") -> Optional[str]:
        """
        Download APK from device (if already installed) or from APK mirror.

        For testing, install the app from Play Store first, then pull the APK.
        """
        # Try pulling from device
        result = subprocess.run(
            [self.adb, "shell", "pm", "path", package_name],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0 and "package:" in result.stdout:
            apk_device_path = result.stdout.strip().split("package:")[1]
            local_path = os.path.join(output_dir, f"{package_name}.apk")

            subprocess.run(
                [self.adb, "pull", apk_device_path, local_path],
                capture_output=True,
                timeout=60,
            )

            if os.path.exists(local_path):
                print(f"[BEATRIX] APK pulled to {local_path}")
                return local_path

        print("[BEATRIX] APK not found on device. Install from Play Store first.")
        return None

    # =========================================================================
    # TRAFFIC ANALYSIS
    # =========================================================================

    def _load_captures(self):
        """Load captured requests from the JSON file"""
        if not os.path.exists(self.config.capture_file):
            print("[BEATRIX] No capture file found")
            return

        try:
            with open(self.config.capture_file) as f:
                data = json.load(f)

            self.captured_requests = [
                InterceptedRequest(**entry) for entry in data
            ]
        except Exception as e:
            print(f"[BEATRIX] Error loading captures: {e}")

    def analyze_traffic(
        self,
        known_secrets: Optional[Dict[str, str]] = None,
    ) -> TrafficAnalysis:
        """
        Analyze captured traffic for secrets, keys, and interesting patterns.

        Args:
            known_secrets: Dict of {name: value} for leaked keys to match against
                           e.g., {"bl-bkd-key": "428c2ca7210279c607be6bc45eab51e6709c3a59"}
        """
        analysis = TrafficAnalysis()
        analysis.total_requests = len(self.captured_requests)

        for req in self.captured_requests:
            # Track hosts and endpoints
            analysis.unique_hosts.add(req.host)
            analysis.unique_endpoints.add(f"{req.method} {req.host}{req.path}")

            # Extract auth headers
            for header_name, header_value in req.request_headers.items():
                hn = header_name.lower()

                # Auth tokens
                if hn == "authorization":
                    analysis.auth_tokens.append(header_value)

                    # JWT detection
                    if header_value.startswith("Bearer "):
                        token = header_value.split(" ", 1)[1]
                        if token.count(".") == 2:
                            analysis.jwt_tokens.append(token)

                # API key headers
                if any(kw in hn for kw in [
                    "api-key", "apikey", "x-api", "x-key", "token",
                    "bl-bkd-key", "x-bb-client-key", "secret", "auth",
                ]):
                    analysis.api_keys_found[header_name] = header_value

                # Any custom headers (non-standard)
                if hn.startswith("x-") or hn.startswith("bl-"):
                    analysis.interesting_headers[header_name] = header_value

            # Check response headers too
            for header_name, header_value in req.response_headers.items():
                hn = header_name.lower()
                if hn.startswith("x-") and hn not in [
                    "x-content-type-options", "x-frame-options", "x-xss-protection",
                    "x-powered-by", "x-request-id",
                ]:
                    analysis.interesting_headers[f"resp:{header_name}"] = header_value

            # Check request/response bodies for credentials
            for body, body_type in [
                (req.request_body, "request"),
                (req.response_body, "response"),
            ]:
                if not body:
                    continue

                # JSON bodies with auth-like fields
                try:
                    if body.strip().startswith("{"):
                        data = json.loads(body)
                        self._extract_creds_from_dict(
                            data, analysis, req.url, body_type
                        )
                except (json.JSONDecodeError, ValueError):
                    pass

            # Match against known leaked secrets
            if known_secrets:
                self._match_known_secrets(req, known_secrets, analysis)

        self.analysis = analysis
        return analysis

    def _extract_creds_from_dict(
        self,
        data: Any,
        analysis: TrafficAnalysis,
        url: str,
        context: str,
        prefix: str = "",
    ):
        """Recursively extract credential-like values from a dict"""
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                key_lower = key.lower()

                if isinstance(value, str) and any(kw in key_lower for kw in [
                    "password", "secret", "token", "key", "auth",
                    "credential", "jwt", "session", "api_key", "apikey",
                    "access_token", "refresh_token", "otp",
                ]):
                    analysis.credentials_in_body.append({
                        "url": url,
                        "context": context,
                        "key": full_key,
                        "value": value[:100],  # Truncate for safety
                    })

                self._extract_creds_from_dict(
                    value, analysis, url, context, full_key
                )
        elif isinstance(data, list):
            for i, item in enumerate(data):
                self._extract_creds_from_dict(
                    item, analysis, url, context, f"{prefix}[{i}]"
                )

    def _match_known_secrets(
        self,
        req: InterceptedRequest,
        known_secrets: Dict[str, str],
        analysis: TrafficAnalysis,
    ):
        """Check if any known leaked secrets appear in the traffic"""
        # Check all parts of the request
        searchable_parts = [
            ("request_headers", json.dumps(req.request_headers)),
            ("response_headers", json.dumps(req.response_headers)),
            ("request_body", req.request_body or ""),
            ("response_body", req.response_body or ""),
            ("url", req.url),
        ]

        for secret_name, secret_value in known_secrets.items():
            if len(secret_value) < 6:  # Skip very short values
                continue

            for part_name, part_content in searchable_parts:
                if secret_value in part_content:
                    analysis.matched_leaked_keys.append({
                        "secret_name": secret_name,
                        "secret_value": secret_value,
                        "found_in": part_name,
                        "url": req.url,
                        "method": req.method,
                        "status_code": req.status_code,
                        "timestamp": req.timestamp,
                    })

    # =========================================================================
    # REPORTING
    # =========================================================================

    def generate_report(self) -> str:
        """Generate a markdown report of the traffic analysis"""
        if not self.analysis:
            self.analyze_traffic()

        a = self.analysis

        lines = [
            "# BEATRIX Mobile Traffic Interception Report",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"**Total Requests Captured:** {a.total_requests}",
            f"**Unique Hosts:** {len(a.unique_hosts)}",
            f"**Unique Endpoints:** {len(a.unique_endpoints)}",
            "",
        ]

        # Matched leaked keys (THE CRITICAL SECTION)
        if a.matched_leaked_keys:
            lines.extend([
                "## CRITICAL: Leaked Keys Found in Production Traffic",
                "",
                "The following leaked credentials were found in LIVE production traffic:",
                "",
                "| Secret | Found In | URL | Status |",
                "|--------|----------|-----|--------|",
            ])
            for m in a.matched_leaked_keys:
                lines.append(
                    f"| `{m['secret_name']}` | {m['found_in']} | "
                    f"`{m['url'][:60]}` | {m['status_code']} |"
                )
            lines.append("")

        # Hosts
        lines.extend(["## Hosts Contacted", ""])
        for host in sorted(a.unique_hosts):
            lines.append(f"- `{host}`")
        lines.append("")

        # API Keys found
        if a.api_keys_found:
            lines.extend(["## API Keys in Headers", ""])
            for name, value in a.api_keys_found.items():
                lines.append(f"- **{name}:** `{value[:20]}...`")
            lines.append("")

        # JWT Tokens
        if a.jwt_tokens:
            lines.extend([
                "## JWT Tokens Captured",
                f"Found {len(a.jwt_tokens)} JWT token(s).",
                "",
            ])
            for i, token in enumerate(a.jwt_tokens[:5], 1):
                # Decode header/payload (no verification needed)
                import base64
                parts = token.split(".")
                if len(parts) == 3:
                    try:
                        header = json.loads(
                            base64.urlsafe_b64decode(parts[0] + "==").decode()
                        )
                        payload = json.loads(
                            base64.urlsafe_b64decode(parts[1] + "==").decode()
                        )
                        lines.extend([
                            f"### Token {i}",
                            f"- **Algorithm:** {header.get('alg', '?')}",
                            f"- **Payload:** `{json.dumps(payload)[:200]}`",
                            "",
                        ])
                    except Exception:
                        lines.append(f"### Token {i}: `{token[:50]}...`\n")

        # Credentials in bodies
        if a.credentials_in_body:
            lines.extend(["## Credentials in Request/Response Bodies", ""])
            for cred in a.credentials_in_body[:20]:
                lines.append(
                    f"- [{cred['context']}] `{cred['key']}` = `{cred['value'][:30]}...` "
                    f"at `{cred['url'][:60]}`"
                )
            lines.append("")

        # All endpoints
        lines.extend(["## Endpoints", ""])
        for ep in sorted(a.unique_endpoints):
            lines.append(f"- `{ep}`")

        return "\n".join(lines)

    def check_jwt_secret(self, jwt_token: str, secret: str) -> bool:
        """
        Verify if a captured JWT was signed with a specific secret.

        This is the kill shot — if a production JWT verifies against
        the leaked secret, the secret is confirmed live.
        """
        import base64
        import hashlib
        import hmac

        parts = jwt_token.split(".")
        if len(parts) != 3:
            return False

        # Decode header to get algorithm
        try:
            header = json.loads(
                base64.urlsafe_b64decode(parts[0] + "==").decode()
            )
        except Exception:
            return False

        alg = header.get("alg", "HS256")

        if alg == "HS256":
            hash_func = hashlib.sha256
        elif alg == "HS384":
            hash_func = hashlib.sha384
        elif alg == "HS512":
            hash_func = hashlib.sha512
        else:
            # RS256 etc. — can't test with a simple secret
            return False

        # Recompute signature
        message = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = hmac.new(
            secret.encode(), message, hash_func
        ).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b'=').decode()

        # Compare
        actual_sig = parts[2]

        return hmac.compare_digest(expected_sig_b64, actual_sig)


# =============================================================================
# CLI / CONVENIENCE
# =============================================================================

async def run_bykea_intercept(
    duration: int = 300,
    apk_path: Optional[str] = None,
):
    """
    Run a full Bykea interception session.

    After capturing: checks traffic for the leaked keys.
    """
    # Known leaked secrets from the Bykea node-boilerplate
    BYKEA_LEAKED_SECRETS = {
        "bl-bkd-key": "428c2ca7210279c607be6bc45eab51e6709c3a59",
        "jwt-secret": "9e06765b-93bc-4e07-bc59-2e666a51bb0b",
        "aes-key": "C1GKh@l33fF@nt@s",
        "aes-key-second": "C1GKh@l33fF@nt@a",
        "db-password": "admin1234",
    }

    config = MobileInterceptConfig(
        avd_name="bykea_hunter",
        apk_path=apk_path,
        package_name="com.bykea.pk",
        location_lat=29.9688,   # Sibi, Pakistan
        location_lon=67.8773,
    )

    interceptor = MobileInterceptor(config)

    try:
        await interceptor.start()

        # Launch the Bykea app
        await interceptor.launch_app("com.bykea.pk")

        print(f"\n[BEATRIX] Bykea app launched. Capturing for {duration}s...")
        print("[BEATRIX] Interact with the app in the emulator to generate traffic.")
        print("[BEATRIX] Press Ctrl+C to stop early.\n")

        await asyncio.sleep(duration)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n[BEATRIX] Stopping capture...")
    finally:
        await interceptor.stop()

    # Analyze
    print("\n[BEATRIX] Analyzing captured traffic...")
    analysis = interceptor.analyze_traffic(known_secrets=BYKEA_LEAKED_SECRETS)

    # Check JWT tokens against leaked secret
    if analysis.jwt_tokens:
        jwt_secret = BYKEA_LEAKED_SECRETS["jwt-secret"]
        for token in analysis.jwt_tokens:
            if interceptor.check_jwt_secret(token, jwt_secret):
                print("\n🔴 CRITICAL: Production JWT verified with leaked secret!")
                print(f"   JWT: {token[:60]}...")
                print(f"   Secret: {jwt_secret}")
                analysis.matched_leaked_keys.append({
                    "secret_name": "jwt-secret (SIGNATURE VERIFIED)",
                    "secret_value": jwt_secret,
                    "found_in": "jwt_signature_verification",
                    "url": "production_traffic",
                    "method": "JWT",
                    "status_code": 0,
                    "timestamp": datetime.now().isoformat(),
                })

    # Print results
    if analysis.matched_leaked_keys:
        print("\n" + "=" * 60)
        print("🔴 LEAKED KEYS CONFIRMED IN PRODUCTION TRAFFIC")
        print("=" * 60)
        for m in analysis.matched_leaked_keys:
            print(f"  ✓ {m['secret_name']} found in {m['found_in']}")
            print(f"    URL: {m['url']}")
        print("\nThis is the evidence needed to reopen the H1 report.")
    else:
        print("\n[BEATRIX] No leaked keys found in captured traffic.")
        if analysis.api_keys_found:
            print("  But found these API keys in headers:")
            for name, value in analysis.api_keys_found.items():
                print(f"    {name}: {value[:30]}...")

    # Save report
    report = interceptor.generate_report()
    report_path = "/tmp/beatrix_bykea_intercept_report.md"
    with open(report_path, "w") as f:
        f.write(report)
    print(f"\n[BEATRIX] Report saved to {report_path}")

    return interceptor


async def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="BEATRIX Mobile Traffic Interceptor")
    parser.add_argument("--avd", default="bykea_hunter", help="AVD name")
    parser.add_argument("--apk", help="APK file to install")
    parser.add_argument("--package", default="com.bykea.pk", help="Package name to launch")
    parser.add_argument("--duration", type=int, default=300, help="Capture duration (seconds)")
    parser.add_argument("--port", type=int, default=8080, help="Proxy port")
    parser.add_argument("--bykea", action="store_true", help="Run Bykea-specific intercept")
    parser.add_argument("--analyze-only", help="Analyze existing capture file")

    args = parser.parse_args()

    if args.analyze_only:
        config = MobileInterceptConfig(capture_file=args.analyze_only)
        interceptor = MobileInterceptor(config)
        interceptor.config.capture_file = args.analyze_only
        interceptor._load_captures()

        interceptor.analyze_traffic(
            known_secrets={
                "bl-bkd-key": "428c2ca7210279c607be6bc45eab51e6709c3a59",
                "jwt-secret": "9e06765b-93bc-4e07-bc59-2e666a51bb0b",
                "aes-key": "C1GKh@l33fF@nt@s",
            }
        )

        print(interceptor.generate_report())
        return

    if args.bykea:
        await run_bykea_intercept(
            duration=args.duration,
            apk_path=args.apk,
        )
    else:
        config = MobileInterceptConfig(
            avd_name=args.avd,
            proxy_port=args.port,
            apk_path=args.apk,
            package_name=args.package,
        )

        interceptor = MobileInterceptor(config)
        await interceptor.capture_session(duration=args.duration)

        interceptor.analyze_traffic()
        print(interceptor.generate_report())


if __name__ == "__main__":
    asyncio.run(main())
