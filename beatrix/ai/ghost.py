"""
GHOST - Generative Heuristic Offensive Security Tester

Usage:
    ghost = GhostAgent()
    await ghost.investigate(
        target_url="https://api.example.com/users?id=1",
        objective="Test for injection and access control vulnerabilities",
    )
"""

import base64
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, quote, quote_plus, urlencode, urlparse, urlunparse

import httpx

from beatrix.ai.assistant import AIAssistant, AIConfig, AIMessage
from beatrix.core.types import (
    Confidence,
    Severity,
)
from beatrix.core.types import (
    Finding as BeatrixFinding,
)

# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class StoredResponse:
    """Cached HTTP response for cross-tool reference"""
    id: int
    status_code: int
    headers: Dict[str, str]
    body: str
    response_time_ms: int
    url: str
    method: str


@dataclass
class GhostFinding:
    """A vulnerability finding discovered by GHOST"""
    title: str
    type: str
    severity: str = "MEDIUM"
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def to_beatrix_finding(self) -> BeatrixFinding:
        """Convert to framework-standard Finding"""
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }
        return BeatrixFinding(
            title=self.title,
            severity=severity_map.get(self.severity.upper(), Severity.MEDIUM),
            confidence=Confidence.FIRM,
            description=self.description,
            evidence=self.evidence,
            remediation=self.remediation,
            scanner_module="ghost",
        )


@dataclass
class ToolCall:
    """Parsed tool call from AI response"""
    name: str
    params: Dict[str, str]
    raw_json: str = ""


# =============================================================================
# CALLBACK PROTOCOL
# =============================================================================

class GhostCallback:
    """
    Callback interface for GHOST agent events.
    Override methods to handle events (logging, UI updates, etc.)
    """
    def on_thinking(self, thought: str) -> None:
        pass

    def on_tool_call(self, tool_name: str, parameters: str) -> None:
        pass

    def on_tool_result(self, tool_name: str, result: str) -> None:
        pass

    def on_finding(self, finding: GhostFinding) -> None:
        pass

    def on_response(self, response: str) -> None:
        pass

    def on_turn_complete(self, turn: int) -> None:
        pass

    def on_stored_response(self, response_id: str, status_code: int) -> None:
        pass


class PrintCallback(GhostCallback):
    """Default callback that prints to stdout with Rich formatting"""

    def on_thinking(self, thought: str) -> None:
        print(f"  [GHOST] 💭 {thought}")

    def on_tool_call(self, tool_name: str, parameters: str) -> None:
        print(f"  [GHOST] 🔧 {tool_name}({parameters[:80]}{'...' if len(parameters) > 80 else ''})")

    def on_tool_result(self, tool_name: str, result: str) -> None:
        preview = result[:200].replace('\n', ' ')
        print(f"  [GHOST] ← {preview}{'...' if len(result) > 200 else ''}")

    def on_finding(self, finding: GhostFinding) -> None:
        print(f"  [GHOST] 🎯 FINDING: [{finding.severity}] {finding.title}")

    def on_response(self, response: str) -> None:
        preview = response[:300].replace('\n', ' ')
        print(f"  [GHOST] 💬 {preview}{'...' if len(response) > 300 else ''}")

    def on_turn_complete(self, turn: int) -> None:
        print(f"  [GHOST] ── Turn {turn} ──")

    def on_stored_response(self, response_id: str, status_code: int) -> None:
        print(f"  [GHOST] 📥 Response #{response_id} (HTTP {status_code})")


# =============================================================================
# PAYLOAD PRESETS
# =============================================================================

FUZZ_PAYLOADS = {
    "sqli": [
        "'", '"', "' OR '1'='1", "1' OR '1'='1' --",
        "1; DROP TABLE users --", "' UNION SELECT NULL--",
        "1 AND 1=1", "1 AND 1=2",
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(1)", "<svg onload=alert(1)>",
        "'-alert(1)-'", '"><script>alert(1)</script>',
    ],
    "command": [
        "; id", "| id", "` id `", "$(id)",
        "; sleep 5", "| sleep 5", "&& id", "|| id",
    ],
    "general": [
        "'", '"', "<", ">", "../", "{{7*7}}", "${7*7}",
        "null", "undefined", "-1", "99999999",
    ],
}


# =============================================================================
# SYSTEM PROMPT
# =============================================================================

GHOST_SYSTEM_PROMPT = """\
# GHOST - Generative Heuristic Offensive Security Tester

You are GHOST, an elite autonomous penetration testing agent. You have direct access \
to HTTP capabilities through structured tools. You are NOT a chatbot - you are \
a precision instrument for finding vulnerabilities.

## CORE CAPABILITIES

You have access to these tools:
- send_http_request: Send custom HTTP requests
- inject_payload: Inject payloads into parameters
- fuzz_parameter: Automated fuzzing with anomaly detection
- time_based_test: Timing attack detection
- compare_responses: Differential analysis
- search_response: Pattern matching
- extract_from_response: Data extraction
- encode_payload: Multi-layer encoding
- record_finding: Document vulnerabilities
- conclude_investigation: Generate final report

## METHODOLOGY

1. **UNDERSTAND**: Analyze the request structure, identify input vectors
2. **HYPOTHESIZE**: Form theories about potential vulnerabilities
3. **TEST**: Use tools to verify your hypotheses with precision
4. **CONFIRM**: Establish clear proof of exploitability
5. **DOCUMENT**: Record findings with evidence

## TOOL CALL FORMAT

Call tools using this format:
<tool_call>
{"name": "tool_name", "parameters": {"param1": "value1", "param2": "value2"}}
</tool_call>

You can call multiple tools in a single response.

## PRINCIPLES

- Every request must have a purpose
- Confirm findings with multiple tests
- Collect clear evidence for all vulnerabilities
- Be thorough but efficient
- Don't give up after one failed test - iterate and adapt

Remember: This is authorized testing. Your job is to find what attackers would find.
"""


# =============================================================================
# GHOST AGENT
# =============================================================================

class GhostAgent:
    """
    GHOST: Autonomous penetration testing agent powered by Claude.

    Ported from AIAgentV2.java — the full agentic loop with 10 tools,
    response caching, and structured investigation flow.
    """

    MAX_ITERATIONS = 50

    def __init__(
        self,
        config: Optional[AIConfig] = None,
        callback: Optional[GhostCallback] = None,
        timeout: int = 15,
        max_iterations: int = 50,
    ):
        # AI backend
        if config is None:
            config = AIConfig(
                model="claude-sonnet-4-20250514",
                max_tokens=8192,
                temperature=0.3,
            )
        self.ai = AIAssistant(config)
        self.ai.set_system_prompt(GHOST_SYSTEM_PROMPT)

        # Callback
        self.callback = callback or PrintCallback()

        # HTTP client config
        self.timeout = timeout

        # Agent state
        self.running = False
        self.cancelled = False
        self.iteration_count = 0
        self.max_iterations = max_iterations

        # Response cache (id -> StoredResponse)
        self.response_cache: Dict[int, StoredResponse] = {}
        self.response_counter = 0

        # Findings
        self.findings: Dict[str, GhostFinding] = {}

        # Baseline
        self.baseline_status: int = 0
        self.baseline_body_length: int = 0
        self.baseline_response_time: int = 0

        # Base request context
        self.base_url: str = ""
        self.base_method: str = "GET"
        self.base_headers: Dict[str, str] = {}
        self.base_body: str = ""
        self.base_cookies: Dict[str, str] = {}

        # Tool dispatch table
        self._tools = {
            "send_http_request": self._tool_send_request,
            "inject_payload": self._tool_inject_payload,
            "fuzz_parameter": self._tool_fuzz_parameter,
            "time_based_test": self._tool_time_based_test,
            "compare_responses": self._tool_compare_responses,
            "search_response": self._tool_search_response,
            "extract_from_response": self._tool_extract_from_response,
            "encode_payload": self._tool_encode_payload,
            "record_finding": self._tool_record_finding,
            "conclude_investigation": self._tool_conclude_investigation,
        }

    # =========================================================================
    # MAIN ENTRY POINT
    # =========================================================================

    async def investigate(
        self,
        target_url: str,
        objective: str = "Find all security vulnerabilities",
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        cookies: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Run a full autonomous investigation against a target.

        Args:
            target_url: The URL to investigate
            objective: What to look for
            method: HTTP method for the base request
            headers: Custom headers
            body: Request body
            cookies: Cookies to send

        Returns:
            Dict with findings, stats, and verdict
        """
        # Set base request
        self.base_url = target_url
        self.base_method = method
        self.base_headers = headers or {}
        self.base_body = body
        self.base_cookies = cookies or {}

        # Reset state
        self.running = True
        self.cancelled = False
        self.iteration_count = 0
        self.response_counter = 0
        self.response_cache.clear()
        self.findings.clear()

        try:
            # Establish baseline
            self.callback.on_thinking("Establishing baseline response characteristics...")
            await self._establish_baseline()

            # Build initial context
            request_info = self._format_request_for_context()
            initial_prompt = self._build_initial_prompt(request_info, objective)

            # Conversation
            messages = [AIMessage(role="user", content=initial_prompt)]

            # Main agent loop
            while self.running and not self.cancelled and self.iteration_count < self.max_iterations:
                self.iteration_count += 1
                self.callback.on_turn_complete(self.iteration_count)

                # Call AI
                response = await self.ai.backend.complete(messages, system=GHOST_SYSTEM_PROMPT)
                response_text = response.content

                if not response_text:
                    self.callback.on_response("Failed to get AI response")
                    break

                # Parse tool calls
                tool_calls = self._parse_tool_calls(response_text)

                if not tool_calls:
                    # No tool calls — conversational response
                    self.callback.on_response(response_text)

                    # Check if done
                    lower = response_text.lower()
                    if "investigation complete" in lower or "no further testing" in lower:
                        break

                    # Push to continue
                    messages.append(AIMessage(role="assistant", content=response_text))
                    messages.append(AIMessage(
                        role="user",
                        content="Continue investigating. Use your tools to test for vulnerabilities.",
                    ))
                    continue

                # Execute tool calls
                tool_results = []
                for call in tool_calls:
                    if self.cancelled:
                        break

                    self.callback.on_tool_call(call.name, json.dumps(call.params))

                    result = await self._execute_tool(call)
                    self.callback.on_tool_result(call.name, result)

                    tool_results.append(f"\n[{call.name}]\n{result}\n")

                    if call.name == "conclude_investigation":
                        self.running = False
                        break

                # Add to conversation
                results_text = "".join(tool_results)
                messages.append(AIMessage(role="assistant", content=response_text))
                messages.append(AIMessage(
                    role="user",
                    content=f"Tool Results:\n{results_text}\n\nContinue your analysis based on these results.",
                ))

        except Exception as e:
            self.callback.on_response(f"Agent error: {e}")
        finally:
            self.running = False

        # Return results
        return {
            "target": target_url,
            "objective": objective,
            "findings": [f.to_beatrix_finding() for f in self.findings.values()],
            "ghost_findings": list(self.findings.values()),
            "iterations": self.iteration_count,
            "responses_analyzed": len(self.response_cache),
            "verdict": "VULNERABLE" if self.findings else "SECURE",
        }

    def stop(self) -> None:
        """Stop the investigation"""
        self.cancelled = True
        self.running = False

    # =========================================================================
    # BASELINE
    # =========================================================================

    async def _establish_baseline(self) -> None:
        """Send the base request to establish baseline response characteristics"""
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
            ) as client:
                start = time.monotonic()
                resp = await client.request(
                    method=self.base_method,
                    url=self.base_url,
                    headers={**self.base_headers, "User-Agent": "GHOST/2.0"},
                    content=self.base_body or None,
                    cookies=self.base_cookies,
                )
                elapsed = int((time.monotonic() - start) * 1000)

                self.baseline_status = resp.status_code
                self.baseline_body_length = len(resp.text)
                self.baseline_response_time = elapsed

                # Store as response #0
                self.response_cache[0] = StoredResponse(
                    id=0,
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=resp.text,
                    response_time_ms=elapsed,
                    url=self.base_url,
                    method=self.base_method,
                )
        except Exception:
            self.baseline_response_time = 1000

    # =========================================================================
    # PROMPT BUILDERS
    # =========================================================================

    def _format_request_for_context(self) -> str:
        """Format the base request for the AI's initial context"""
        lines = [
            f"Method: {self.base_method}",
            f"URL: {self.base_url}",
            "\nHeaders:",
        ]
        for k, v in self.base_headers.items():
            lines.append(f"  {k}: {v}")

        if self.base_cookies:
            lines.append("\nCookies:")
            for k, v in self.base_cookies.items():
                lines.append(f"  {k}={v}")

        if self.base_body:
            lines.append(f"\nBody:\n{self.base_body[:2000]}")

        if 0 in self.response_cache:
            baseline = self.response_cache[0]
            lines.append("\n--- BASELINE RESPONSE ---")
            lines.append(f"Status: {baseline.status_code}")
            lines.append(f"Length: {len(baseline.body)} bytes")
            lines.append(f"Time: {baseline.response_time_ms}ms")
            lines.append(f"Body Preview:\n{baseline.body[:500]}")

        return "\n".join(lines)

    def _build_initial_prompt(self, request_info: str, objective: str) -> str:
        return f"""\
## TARGET REQUEST

{request_info}

## OBJECTIVE

{objective}

## INSTRUCTIONS

Begin your systematic security analysis. Examine the request structure, identify \
potential attack vectors, and test methodically. Use your tools to:

1. Establish baseline behavior
2. Test for injection vulnerabilities (SQL, command, XSS, etc.)
3. Check for access control issues
4. Look for information disclosure
5. Document any findings with evidence

When investigation is complete, use conclude_investigation to summarize your findings.

Start now - analyze and test.
"""

    # =========================================================================
    # TOOL CALL PARSING
    # =========================================================================

    def _parse_tool_calls(self, response: str) -> List[ToolCall]:
        """Parse <tool_call>...</tool_call> blocks from AI response"""
        calls = []
        pattern = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)

        for match in pattern.finditer(response):
            try:
                raw = match.group(1)
                data = json.loads(raw)
                name = data.get("name")
                params = data.get("parameters", {})
                # Ensure all param values are strings
                str_params = {k: str(v) for k, v in params.items()}
                if name:
                    calls.append(ToolCall(name=name, params=str_params, raw_json=raw))
            except (json.JSONDecodeError, AttributeError):
                continue

        return calls

    # =========================================================================
    # TOOL EXECUTION DISPATCH
    # =========================================================================

    async def _execute_tool(self, call: ToolCall) -> str:
        """Dispatch a tool call to the appropriate handler"""
        handler = self._tools.get(call.name)
        if handler is None:
            return f"Unknown tool: {call.name}"
        try:
            return await handler(call.params)
        except Exception as e:
            return f"Tool error: {e}"

    # =========================================================================
    # HTTP HELPER
    # =========================================================================

    async def _send_http(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> StoredResponse:
        """Send an HTTP request and cache the response"""
        merged_headers = {**self.base_headers}
        if headers:
            merged_headers.update(headers)
        if "User-Agent" not in merged_headers:
            merged_headers["User-Agent"] = "GHOST/2.0"

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            start = time.monotonic()
            resp = await client.request(
                method=method,
                url=url,
                headers=merged_headers,
                content=body,
                cookies=self.base_cookies,
            )
            elapsed = int((time.monotonic() - start) * 1000)

        self.response_counter += 1
        rid = self.response_counter

        stored = StoredResponse(
            id=rid,
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text,
            response_time_ms=elapsed,
            url=url,
            method=method,
        )
        self.response_cache[rid] = stored

        self.callback.on_stored_response(str(rid), resp.status_code)
        return stored

    # =========================================================================
    # TOOL IMPLEMENTATIONS
    # =========================================================================

    async def _tool_send_request(self, params: Dict[str, str]) -> str:
        """Send a custom HTTP request"""
        method = params.get("method", "GET")
        url = params.get("url", self.base_url)
        raw_headers = params.get("headers", "")
        body = params.get("body", "")

        # Parse header lines
        extra_headers = {}
        if raw_headers:
            for line in raw_headers.split("\n"):
                line = line.strip()
                if ":" in line:
                    k, v = line.split(":", 1)
                    extra_headers[k.strip()] = v.strip()

        stored = await self._send_http(method, url, extra_headers, body or None)

        # Summarize important headers
        important = {"content-type", "server", "x-powered-by", "set-cookie",
                      "x-frame-options", "content-security-policy"}
        header_summary = "; ".join(
            f"{k}: {v}" for k, v in stored.headers.items()
            if k.lower() in important
        )

        return (
            f"Response #{stored.id}:\n"
            f"Status: {stored.status_code}\n"
            f"Time: {stored.response_time_ms}ms\n"
            f"Length: {len(stored.body)} bytes\n"
            f"Headers: {header_summary}\n"
            f"Body Preview: {stored.body[:500]}"
        )

    async def _tool_inject_payload(self, params: Dict[str, str]) -> str:
        """Inject a payload into a parameter and analyze the response"""
        parameter = params.get("parameter")
        payload = params.get("payload")
        location = params.get("location", "body")

        if not parameter or not payload:
            return "Error: parameter and payload are required"

        # Build modified request
        url = self.base_url
        body = self.base_body
        method = self.base_method

        if location in ("url", "query"):
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[parameter] = [payload]
            new_query = urlencode(qs, doseq=True)
            url = urlunparse(parsed._replace(query=new_query))
        else:
            # Body injection
            if body and f'"{parameter}"' in body:
                # JSON body
                try:
                    data = json.loads(body)
                    data[parameter] = payload
                    body = json.dumps(data)
                except json.JSONDecodeError:
                    body = re.sub(
                        rf'"{re.escape(parameter)}"\s*:\s*"[^"]*"',
                        f'"{parameter}": "{payload}"',
                        body,
                    )
            elif body and f"{parameter}=" in body:
                # Form body
                body = re.sub(
                    rf'{re.escape(parameter)}=[^&\n]*',
                    f'{parameter}={quote_plus(payload)}',
                    body,
                )
            else:
                # Append
                if body:
                    body += f"&{parameter}={quote_plus(payload)}"
                else:
                    body = f"{parameter}={quote_plus(payload)}"
                    method = "POST" if self.base_method == "GET" else self.base_method

        stored = await self._send_http(method, url, None, body or None)

        # Auto-detect vulnerability indicators
        indicators = []
        body_lower = stored.body.lower()
        if re.search(r'(sql|mysql|ora-|postgresql|syntax error|query)', body_lower):
            indicators.append("Possible SQL error detected")
        if payload in stored.body:
            indicators.append("Payload reflected in response")
        if re.search(r'(exception|stack trace|undefined|null pointer)', body_lower):
            indicators.append("Error message in response")

        indicator_str = f"\nIndicators: {', '.join(indicators)}" if indicators else ""

        return (
            f"Response #{stored.id}:\n"
            f"Status: {stored.status_code} (baseline: {self.baseline_status})\n"
            f"Time: {stored.response_time_ms}ms (baseline: {self.baseline_response_time}ms)\n"
            f"Length: {len(stored.body)} bytes"
            f"{indicator_str}\n"
            f"Body Preview: {stored.body[:500]}"
        )

    async def _tool_fuzz_parameter(self, params: Dict[str, str]) -> str:
        """Fuzz a parameter with multiple payloads and detect anomalies"""
        parameter = params.get("parameter")
        payloads_str = params.get("payloads", "")
        category = params.get("category", "general")

        if not parameter:
            return "Error: parameter is required"

        # Build payload list
        if payloads_str:
            payloads = payloads_str.split("|")
        else:
            payloads = FUZZ_PAYLOADS.get(category.lower(), FUZZ_PAYLOADS["general"])

        results = [f"Fuzzing {parameter} with {len(payloads)} payloads:\n"]
        anomalies = 0

        for payload in payloads:
            if self.cancelled:
                break

            inject_result = await self._tool_inject_payload({
                "parameter": parameter,
                "payload": payload,
            })

            # Parse result for anomalies
            try:
                status_match = re.search(r'Status: (\d+)', inject_result)
                time_match = re.search(r'Time: (\d+)ms', inject_result)
                length_match = re.search(r'Length: (\d+) bytes', inject_result)

                if status_match and time_match and length_match:
                    status = int(status_match.group(1))
                    resp_time = int(time_match.group(1))
                    length = int(length_match.group(1))

                    is_anomaly = False
                    reason = ""

                    if status != self.baseline_status:
                        is_anomaly = True
                        reason = f"Status changed: {self.baseline_status} -> {status}"
                    elif self.baseline_body_length and abs(length - self.baseline_body_length) > self.baseline_body_length * 0.2:
                        is_anomaly = True
                        reason = f"Length changed: {self.baseline_body_length} -> {length}"
                    elif self.baseline_response_time and resp_time > self.baseline_response_time * 3:
                        is_anomaly = True
                        reason = f"Response time increased: {self.baseline_response_time}ms -> {resp_time}ms"

                    if is_anomaly:
                        anomalies += 1
                        results.append(f"⚠ ANOMALY: payload='{payload[:30]}' - {reason}")
            except (ValueError, AttributeError):
                pass

        results.append(f"\nSummary: {anomalies}/{len(payloads)} anomalies detected")
        return "\n".join(results)

    async def _tool_time_based_test(self, params: Dict[str, str]) -> str:
        """Test for time-based injection vulnerabilities"""
        parameter = params.get("parameter")
        payload = params.get("payload")
        expected_delay = int(params.get("expected_delay_ms", "5000"))

        if not parameter or not payload:
            return "Error: parameter and payload are required"

        start = time.monotonic()
        inject_result = await self._tool_inject_payload({
            "parameter": parameter,
            "payload": payload,
        })
        elapsed = int((time.monotonic() - start) * 1000)

        detected = elapsed >= (expected_delay * 0.8)

        return (
            f"Time-based test:\n"
            f"Payload: {payload[:50]}\n"
            f"Expected delay: {expected_delay}ms\n"
            f"Actual time: {elapsed}ms\n"
            f"Baseline: {self.baseline_response_time}ms\n"
            f"Result: {'⚠ TIMING ANOMALY DETECTED' if detected else 'No timing anomaly'}\n\n"
            f"{inject_result}"
        )

    async def _tool_compare_responses(self, params: Dict[str, str]) -> str:
        """Compare two stored responses for differential analysis"""
        id1 = params.get("response_id_1")
        id2 = params.get("response_id_2")

        if not id1 or not id2:
            return "Error: Two response IDs required"

        r1 = self.response_cache.get(int(id1))
        r2 = self.response_cache.get(int(id2))

        if not r1 or not r2:
            return "Error: Response not found"

        lines = [f"Comparing Response #{id1} vs #{id2}:\n"]

        # Status
        lines.append(f"Status: {r1.status_code} vs {r2.status_code}")
        if r1.status_code != r2.status_code:
            lines.append(" ⚠ DIFFERENT")

        # Length
        lines.append(f"Length: {len(r1.body)} vs {len(r2.body)}")
        if r1.body and abs(len(r1.body) - len(r2.body)) > len(r1.body) * 0.1:
            lines.append(" ⚠ SIGNIFICANT DIFFERENCE")

        # Time
        lines.append(f"Time: {r1.response_time_ms}ms vs {r2.response_time_ms}ms")

        # Content comparison
        if r1.body == r2.body:
            lines.append("Content: IDENTICAL")
        else:
            lines.append("Content: DIFFERENT")
            error_patterns = ["error", "exception", "denied", "forbidden", "invalid"]
            for pattern in error_patterns:
                in1 = pattern in r1.body.lower()
                in2 = pattern in r2.body.lower()
                if in1 != in2:
                    which = "first" if in1 else "second"
                    lines.append(f"  - '{pattern}' appears in {which} only")

        return "\n".join(lines)

    async def _tool_search_response(self, params: Dict[str, str]) -> str:
        """Search for a pattern in a stored response"""
        response_id = params.get("response_id")
        pattern = params.get("pattern")
        is_regex = params.get("is_regex", "false").lower() == "true"

        if not pattern:
            return "Error: pattern is required"

        # Get content
        if response_id:
            stored = self.response_cache.get(int(response_id))
            if not stored:
                return "Error: Response not found"
            content = stored.body
        elif 0 in self.response_cache:
            content = self.response_cache[0].body
        else:
            return "Error: No response to search"

        matches = []

        if is_regex:
            try:
                for m in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                    if len(matches) >= 20:
                        break
                    matches.append(m.group())
            except re.error as e:
                return f"Regex error: {e}"
        else:
            idx = 0
            content_lower = content.lower()
            pattern_lower = pattern.lower()
            while len(matches) < 20:
                idx = content_lower.find(pattern_lower, idx)
                if idx == -1:
                    break
                start = max(0, idx - 30)
                end = min(len(content), idx + len(pattern) + 30)
                matches.append(f"...{content[start:end]}...")
                idx += len(pattern)

        if not matches:
            return f"No matches found for: {pattern}"

        return f"Found {len(matches)} matches:\n" + "\n".join(matches)

    async def _tool_extract_from_response(self, params: Dict[str, str]) -> str:
        """Extract structured data from a response"""
        response_id = params.get("response_id")
        extract_type = params.get("type", "urls")
        custom_pattern = params.get("pattern")

        # Get content
        if response_id:
            stored = self.response_cache.get(int(response_id))
            if not stored:
                return "Error: Response not found"
            content = stored.body
        elif 0 in self.response_cache:
            content = self.response_cache[0].body
        else:
            return "Error: No response"

        extracted = []
        patterns = {
            "urls": r'https?://[^\"\'\s<>]+',
            "emails": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "tokens": r'(?:token|api[_-]?key|secret|password|auth)["\'\s:=]+([a-zA-Z0-9_\-]{10,})',
        }

        max_results = 50 if extract_type != "tokens" else 20

        if extract_type == "custom" and custom_pattern:
            try:
                for m in re.finditer(custom_pattern, content):
                    if len(extracted) >= max_results:
                        break
                    extracted.append(m.group())
            except re.error as e:
                return f"Invalid pattern: {e}"
        else:
            regex = patterns.get(extract_type.lower(), patterns["urls"])
            for m in re.finditer(regex, content, re.IGNORECASE):
                if len(extracted) >= max_results:
                    break
                extracted.append(m.group())

        if not extracted:
            return f"No {extract_type} found in response"

        return f"Extracted {len(extracted)} {extract_type}:\n" + "\n".join(extracted)

    async def _tool_encode_payload(self, params: Dict[str, str]) -> str:
        """Encode a payload for WAF bypass"""
        payload = params.get("payload")
        encoding = params.get("encoding", "url")

        if not payload:
            return "Error: payload is required"

        try:
            if encoding == "url":
                encoded = quote(payload, safe="")
            elif encoding == "double_url":
                encoded = quote(quote(payload, safe=""), safe="")
            elif encoding == "base64":
                encoded = base64.b64encode(payload.encode()).decode()
            elif encoding == "html":
                encoded = "".join(f"&#{ord(c)};" for c in payload)
            elif encoding == "unicode":
                encoded = "".join(f"\\u{ord(c):04x}" for c in payload)
            elif encoding == "hex":
                encoded = "".join(f"%{b:02x}" for b in payload.encode())
            else:
                return f"Unknown encoding: {encoding}"

            return f"Original: {payload}\nEncoded ({encoding}): {encoded}"
        except Exception as e:
            return f"Encoding error: {e}"

    async def _tool_record_finding(self, params: Dict[str, str]) -> str:
        """Record a discovered vulnerability"""
        title = params.get("title")
        vuln_type = params.get("type")
        severity = params.get("severity", "MEDIUM")
        description = params.get("description")
        evidence = params.get("evidence", "")
        remediation = params.get("remediation", "")

        if not title or not vuln_type or not description:
            return "Error: title, type, and description are required"

        finding = GhostFinding(
            title=title,
            type=vuln_type,
            severity=severity.upper(),
            description=description,
            evidence=evidence,
            remediation=remediation,
        )
        self.findings[title] = finding
        self.callback.on_finding(finding)

        return (
            f"Finding recorded:\n"
            f"Title: {title}\n"
            f"Type: {vuln_type}\n"
            f"Severity: {severity}\n"
            f"Description: {description[:200]}"
        )

    async def _tool_conclude_investigation(self, params: Dict[str, str]) -> str:
        """Generate final investigation report"""
        summary = params.get("summary", "Investigation complete.")
        verdict = params.get("verdict", "VULNERABLE" if self.findings else "SECURE")

        lines = [
            "═" * 67,
            "                    GHOST INVESTIGATION REPORT",
            "═" * 67,
            "",
            f"SUMMARY: {summary}",
            "",
            f"VERDICT: {verdict}",
            "",
            f"FINDINGS ({len(self.findings)}):",
            "─" * 67,
        ]

        if not self.findings:
            lines.append("No vulnerabilities discovered.")
        else:
            for i, finding in enumerate(self.findings.values(), 1):
                lines.append(f"\n[{i}] {finding.title} ({finding.severity})")
                lines.append(f"    Type: {finding.type}")
                lines.append(f"    Description: {finding.description}")
                if finding.evidence:
                    lines.append(f"    Evidence: {finding.evidence}")
                if finding.remediation:
                    lines.append(f"    Remediation: {finding.remediation}")

        lines.extend([
            "",
            "─" * 67,
            "STATISTICS:",
            f"  • Total iterations: {self.iteration_count}",
            f"  • Responses analyzed: {len(self.response_cache)}",
            "═" * 67,
        ])

        return "\n".join(lines)

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def get_findings(self) -> List[BeatrixFinding]:
        """Get all findings as Beatrix Finding objects"""
        return [f.to_beatrix_finding() for f in self.findings.values()]

    def get_ghost_findings(self) -> List[GhostFinding]:
        """Get all findings as GHOST Finding objects"""
        return list(self.findings.values())
