"""
GHOST Agent Test Suite

Unit tests for the Generative Heuristic Offensive Security Tester.
Tests parsing, encoding, findings, callbacks, and tool dispatch
without making real network calls.
"""

import base64
from unittest.mock import MagicMock

import pytest

from beatrix.ai.ghost import (
    FUZZ_PAYLOADS,
    GHOST_SYSTEM_PROMPT,
    GhostAgent,
    GhostCallback,
    GhostFinding,
    PrintCallback,
    StoredResponse,
    ToolCall,
)
from beatrix.core.types import Confidence, Finding, Severity

# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def agent():
    """Create a GhostAgent with mocked AI backend"""
    a = GhostAgent(callback=GhostCallback())  # silent callback
    # Prevent real API calls
    a.ai = MagicMock()
    return a


@pytest.fixture
def agent_with_baseline(agent):
    """Agent with pre-populated baseline and cache"""
    agent.base_url = "https://example.com/api/users?id=1"
    agent.base_method = "GET"
    agent.base_headers = {"Authorization": "Bearer test123"}
    agent.base_body = ""
    agent.baseline_status = 200
    agent.baseline_body_length = 500
    agent.baseline_response_time = 100

    agent.response_cache[0] = StoredResponse(
        id=0,
        status_code=200,
        headers={"content-type": "application/json", "server": "nginx"},
        body='{"id": 1, "name": "Alice", "email": "alice@example.com"}',
        response_time_ms=100,
        url="https://example.com/api/users?id=1",
        method="GET",
    )
    return agent


# =============================================================================
# DATA CLASS TESTS
# =============================================================================

class TestGhostFinding:
    """Tests for GhostFinding data class"""

    def test_finding_defaults(self):
        f = GhostFinding(title="XSS in search", type="XSS")
        assert f.title == "XSS in search"
        assert f.type == "XSS"
        assert f.severity == "MEDIUM"
        assert f.description == ""
        assert f.evidence == ""
        assert f.remediation == ""
        assert f.timestamp  # auto-generated

    def test_finding_full(self):
        f = GhostFinding(
            title="SQL Injection",
            type="SQLI",
            severity="CRITICAL",
            description="Blind SQLi in user_id param",
            evidence="Response time: 5200ms vs 100ms baseline",
            remediation="Use parameterized queries",
        )
        assert f.severity == "CRITICAL"
        assert "Blind SQLi" in f.description

    def test_to_beatrix_finding(self):
        f = GhostFinding(
            title="Open Redirect",
            type="REDIRECT",
            severity="HIGH",
            description="Redirect via next param",
            evidence="Location: https://evil.com",
            remediation="Whitelist redirect targets",
        )
        bf = f.to_beatrix_finding()
        assert isinstance(bf, Finding)
        assert bf.title == "Open Redirect"
        assert bf.severity == Severity.HIGH
        assert bf.confidence == Confidence.FIRM
        assert bf.scanner_module == "ghost"
        assert bf.evidence == "Location: https://evil.com"

    def test_to_beatrix_finding_severity_mapping(self):
        """Test all severity levels map correctly"""
        for sev_str, sev_enum in [
            ("CRITICAL", Severity.CRITICAL),
            ("HIGH", Severity.HIGH),
            ("MEDIUM", Severity.MEDIUM),
            ("LOW", Severity.LOW),
            ("INFO", Severity.INFO),
        ]:
            f = GhostFinding(title="test", type="test", severity=sev_str)
            assert f.to_beatrix_finding().severity == sev_enum

    def test_to_beatrix_finding_unknown_severity_defaults_medium(self):
        f = GhostFinding(title="test", type="test", severity="BANANA")
        assert f.to_beatrix_finding().severity == Severity.MEDIUM


class TestStoredResponse:
    def test_stored_response(self):
        sr = StoredResponse(
            id=1,
            status_code=200,
            headers={"content-type": "text/html"},
            body="<html>OK</html>",
            response_time_ms=42,
            url="https://example.com",
            method="GET",
        )
        assert sr.id == 1
        assert sr.status_code == 200
        assert sr.headers["content-type"] == "text/html"


class TestToolCall:
    def test_tool_call(self):
        tc = ToolCall(name="send_http_request", params={"url": "https://a.com"})
        assert tc.name == "send_http_request"
        assert tc.raw_json == ""


# =============================================================================
# TOOL CALL PARSING TESTS
# =============================================================================

class TestParseToolCalls:
    """Tests for _parse_tool_calls"""

    def test_single_tool_call(self, agent):
        response = """Let me test this.
<tool_call>
{"name": "send_http_request", "parameters": {"url": "https://example.com", "method": "GET"}}
</tool_call>
"""
        calls = agent._parse_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].name == "send_http_request"
        assert calls[0].params["url"] == "https://example.com"
        assert calls[0].params["method"] == "GET"

    def test_multiple_tool_calls(self, agent):
        response = """I'll run two tests.
<tool_call>
{"name": "inject_payload", "parameters": {"parameter": "id", "payload": "' OR 1=1--"}}
</tool_call>
<tool_call>
{"name": "inject_payload", "parameters": {"parameter": "id", "payload": "<script>alert(1)</script>"}}
</tool_call>
"""
        calls = agent._parse_tool_calls(response)
        assert len(calls) == 2
        assert calls[0].params["payload"] == "' OR 1=1--"
        assert calls[1].params["payload"] == "<script>alert(1)</script>"

    def test_no_tool_calls(self, agent):
        response = "I don't need tools for this analysis."
        calls = agent._parse_tool_calls(response)
        assert len(calls) == 0

    def test_malformed_json_skipped(self, agent):
        response = """<tool_call>
{this is not valid json}
</tool_call>
<tool_call>
{"name": "encode_payload", "parameters": {"payload": "test"}}
</tool_call>
"""
        calls = agent._parse_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].name == "encode_payload"

    def test_missing_name_skipped(self, agent):
        response = """<tool_call>
{"parameters": {"payload": "test"}}
</tool_call>
"""
        calls = agent._parse_tool_calls(response)
        assert len(calls) == 0

    def test_params_coerced_to_strings(self, agent):
        response = """<tool_call>
{"name": "inject_payload", "parameters": {"parameter": "id", "payload": 12345, "count": true}}
</tool_call>
"""
        calls = agent._parse_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].params["payload"] == "12345"
        assert calls[0].params["count"] == "True"

    def test_raw_json_preserved(self, agent):
        raw = '{"name": "encode_payload", "parameters": {"payload": "test"}}'
        response = f"<tool_call>\n{raw}\n</tool_call>"
        calls = agent._parse_tool_calls(response)
        assert calls[0].raw_json == raw

    def test_tool_call_with_whitespace(self, agent):
        response = """<tool_call>
  {
    "name": "send_http_request",
    "parameters": {
      "url": "https://example.com"
    }
  }
</tool_call>"""
        calls = agent._parse_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].name == "send_http_request"


# =============================================================================
# ENCODE PAYLOAD TESTS
# =============================================================================

class TestEncodePayload:
    """Tests for _tool_encode_payload"""

    @pytest.mark.asyncio
    async def test_url_encoding(self, agent):
        result = await agent._tool_encode_payload({"payload": "' OR 1=1--", "encoding": "url"})
        assert "%27%20OR%201%3D1--" in result

    @pytest.mark.asyncio
    async def test_double_url_encoding(self, agent):
        result = await agent._tool_encode_payload({"payload": "<script>", "encoding": "double_url"})
        # < becomes %3C, then %3C becomes %253C
        assert "%253C" in result

    @pytest.mark.asyncio
    async def test_base64_encoding(self, agent):
        result = await agent._tool_encode_payload({"payload": "admin:password", "encoding": "base64"})
        expected = base64.b64encode(b"admin:password").decode()
        assert expected in result

    @pytest.mark.asyncio
    async def test_html_encoding(self, agent):
        result = await agent._tool_encode_payload({"payload": "<img>", "encoding": "html"})
        assert "&#60;" in result  # <
        assert "&#62;" in result  # >

    @pytest.mark.asyncio
    async def test_unicode_encoding(self, agent):
        result = await agent._tool_encode_payload({"payload": "AB", "encoding": "unicode"})
        assert "\\u0041" in result  # A
        assert "\\u0042" in result  # B

    @pytest.mark.asyncio
    async def test_hex_encoding(self, agent):
        result = await agent._tool_encode_payload({"payload": "AB", "encoding": "hex"})
        assert "%41" in result
        assert "%42" in result

    @pytest.mark.asyncio
    async def test_unknown_encoding(self, agent):
        result = await agent._tool_encode_payload({"payload": "test", "encoding": "rot13"})
        assert "Unknown encoding" in result

    @pytest.mark.asyncio
    async def test_missing_payload(self, agent):
        result = await agent._tool_encode_payload({"encoding": "url"})
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_default_encoding_is_url(self, agent):
        result = await agent._tool_encode_payload({"payload": " "})
        assert "url" in result.lower()
        assert "%20" in result


# =============================================================================
# RECORD FINDING TESTS
# =============================================================================

class TestRecordFinding:
    """Tests for _tool_record_finding"""

    @pytest.mark.asyncio
    async def test_record_valid_finding(self, agent):
        result = await agent._tool_record_finding({
            "title": "SQL Injection in login",
            "type": "SQLI",
            "severity": "CRITICAL",
            "description": "Authentication bypass via SQLi",
            "evidence": "200 OK with admin session",
            "remediation": "Use parameterized queries",
        })
        assert "Finding recorded" in result
        assert "SQL Injection in login" in result
        assert len(agent.findings) == 1
        assert "SQL Injection in login" in agent.findings

    @pytest.mark.asyncio
    async def test_record_finding_missing_required(self, agent):
        # All three of title, type, and description must be missing to error
        result = await agent._tool_record_finding({})
        assert "Error" in result
        assert len(agent.findings) == 0

    @pytest.mark.asyncio
    async def test_record_finding_partial_fields_ok(self, agent):
        # Title alone is enough — we accept partial input from AI
        result = await agent._tool_record_finding({"title": "test"})
        assert "Finding recorded" in result
        assert len(agent.findings) == 1

    @pytest.mark.asyncio
    async def test_record_multiple_findings(self, agent):
        await agent._tool_record_finding({
            "title": "XSS", "type": "XSS", "description": "Reflected XSS"
        })
        await agent._tool_record_finding({
            "title": "IDOR", "type": "IDOR", "description": "Access control bypass"
        })
        assert len(agent.findings) == 2

    @pytest.mark.asyncio
    async def test_finding_deduplication_by_title(self, agent):
        """Same title overwrites"""
        await agent._tool_record_finding({
            "title": "XSS", "type": "XSS", "description": "First version"
        })
        await agent._tool_record_finding({
            "title": "XSS", "type": "XSS", "description": "Updated version"
        })
        assert len(agent.findings) == 1
        assert agent.findings["XSS"].description == "Updated version"

    @pytest.mark.asyncio
    async def test_severity_default(self, agent):
        await agent._tool_record_finding({
            "title": "Test", "type": "TEST", "description": "Test finding"
        })
        assert agent.findings["Test"].severity == "MEDIUM"


# =============================================================================
# CONCLUDE INVESTIGATION TESTS
# =============================================================================

class TestConcludeInvestigation:
    """Tests for _tool_conclude_investigation"""

    @pytest.mark.asyncio
    async def test_conclude_no_findings(self, agent):
        result = await agent._tool_conclude_investigation({
            "summary": "No vulnerabilities found"
        })
        assert "SECURE" in result
        assert "No vulnerabilities discovered" in result
        assert "INVESTIGATION REPORT" in result

    @pytest.mark.asyncio
    async def test_conclude_with_findings(self, agent):
        agent.findings["XSS"] = GhostFinding(
            title="XSS in search",
            type="XSS",
            severity="HIGH",
            description="Reflected XSS via q param",
        )
        agent.iteration_count = 5
        result = await agent._tool_conclude_investigation({
            "summary": "Found reflected XSS"
        })
        assert "VULNERABLE" in result
        assert "XSS in search" in result
        assert "HIGH" in result
        assert "Total iterations: 5" in result

    @pytest.mark.asyncio
    async def test_conclude_verdict_override(self, agent):
        result = await agent._tool_conclude_investigation({
            "summary": "Partial test", "verdict": "INCONCLUSIVE"
        })
        assert "INCONCLUSIVE" in result


# =============================================================================
# TOOL DISPATCH TESTS
# =============================================================================

class TestToolDispatch:
    """Tests for _execute_tool"""

    @pytest.mark.asyncio
    async def test_unknown_tool(self, agent):
        call = ToolCall(name="nonexistent_tool", params={})
        result = await agent._execute_tool(call)
        assert "Unknown tool" in result

    @pytest.mark.asyncio
    async def test_tool_error_handled(self, agent):
        """Tool errors should be caught and returned as strings"""
        call = ToolCall(name="encode_payload", params={})  # missing payload
        result = await agent._execute_tool(call)
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_dispatch_table_complete(self, agent):
        """All 10 tools must be registered"""
        expected_tools = {
            "send_http_request", "inject_payload", "fuzz_parameter",
            "time_based_test", "compare_responses", "search_response",
            "extract_from_response", "encode_payload", "record_finding",
            "conclude_investigation",
        }
        assert set(agent._tools.keys()) == expected_tools


# =============================================================================
# SEARCH RESPONSE TESTS
# =============================================================================

class TestSearchResponse:
    """Tests for _tool_search_response"""

    @pytest.mark.asyncio
    async def test_search_plain_text(self, agent_with_baseline):
        result = await agent_with_baseline._tool_search_response({
            "response_id": "0",
            "pattern": "alice",
        })
        assert "Found" in result
        assert "alice" in result.lower()

    @pytest.mark.asyncio
    async def test_search_regex(self, agent_with_baseline):
        result = await agent_with_baseline._tool_search_response({
            "response_id": "0",
            "pattern": r"[a-z]+@[a-z]+\.[a-z]+",
            "is_regex": "true",
        })
        assert "Found" in result

    @pytest.mark.asyncio
    async def test_search_no_match(self, agent_with_baseline):
        result = await agent_with_baseline._tool_search_response({
            "response_id": "0",
            "pattern": "NONEXISTENT_STRING_XYZ",
        })
        assert "No matches" in result

    @pytest.mark.asyncio
    async def test_search_invalid_regex(self, agent_with_baseline):
        result = await agent_with_baseline._tool_search_response({
            "response_id": "0",
            "pattern": "[invalid",
            "is_regex": "true",
        })
        assert "error" in result.lower()

    @pytest.mark.asyncio
    async def test_search_missing_response(self, agent):
        result = await agent._tool_search_response({
            "response_id": "999",
            "pattern": "test",
        })
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_search_missing_pattern(self, agent_with_baseline):
        result = await agent_with_baseline._tool_search_response({
            "response_id": "0",
        })
        assert "Error" in result


# =============================================================================
# COMPARE RESPONSES TESTS
# =============================================================================

class TestCompareResponses:
    """Tests for _tool_compare_responses"""

    @pytest.mark.asyncio
    async def test_compare_identical(self, agent_with_baseline):
        # Add a second identical response
        agent_with_baseline.response_cache[1] = StoredResponse(
            id=1,
            status_code=200,
            headers={"content-type": "application/json"},
            body='{"id": 1, "name": "Alice", "email": "alice@example.com"}',
            response_time_ms=95,
            url="https://example.com/api/users?id=1",
            method="GET",
        )
        result = await agent_with_baseline._tool_compare_responses({
            "response_id_1": "0",
            "response_id_2": "1",
        })
        assert "IDENTICAL" in result

    @pytest.mark.asyncio
    async def test_compare_different_status(self, agent_with_baseline):
        agent_with_baseline.response_cache[1] = StoredResponse(
            id=1, status_code=403,
            headers={}, body="Forbidden",
            response_time_ms=50,
            url="https://example.com/api/admin",
            method="GET",
        )
        result = await agent_with_baseline._tool_compare_responses({
            "response_id_1": "0",
            "response_id_2": "1",
        })
        assert "DIFFERENT" in result
        assert "200" in result
        assert "403" in result

    @pytest.mark.asyncio
    async def test_compare_missing_ids(self, agent_with_baseline):
        result = await agent_with_baseline._tool_compare_responses({})
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_compare_nonexistent_response(self, agent_with_baseline):
        result = await agent_with_baseline._tool_compare_responses({
            "response_id_1": "0",
            "response_id_2": "999",
        })
        assert "Error" in result


# =============================================================================
# EXTRACT FROM RESPONSE TESTS
# =============================================================================

class TestExtractFromResponse:
    """Tests for _tool_extract_from_response"""

    @pytest.mark.asyncio
    async def test_extract_emails(self, agent_with_baseline):
        result = await agent_with_baseline._tool_extract_from_response({
            "response_id": "0",
            "type": "emails",
        })
        assert "alice@example.com" in result

    @pytest.mark.asyncio
    async def test_extract_urls(self, agent_with_baseline):
        # Add a response with URLs
        agent_with_baseline.response_cache[1] = StoredResponse(
            id=1, status_code=200, headers={},
            body='{"link": "https://api.example.com/v2", "docs": "https://docs.example.com"}',
            response_time_ms=50, url="test", method="GET",
        )
        result = await agent_with_baseline._tool_extract_from_response({
            "response_id": "1",
            "type": "urls",
        })
        assert "https://api.example.com/v2" in result

    @pytest.mark.asyncio
    async def test_extract_custom_pattern(self, agent_with_baseline):
        result = await agent_with_baseline._tool_extract_from_response({
            "response_id": "0",
            "type": "custom",
            "pattern": r'"name":\s*"(\w+)"',
        })
        assert "Extracted" in result

    @pytest.mark.asyncio
    async def test_extract_no_response(self, agent):
        result = await agent._tool_extract_from_response({
            "type": "urls",
            "response_id": "999",
        })
        assert "Error" in result


# =============================================================================
# CALLBACK TESTS
# =============================================================================

class TestCallbacks:
    """Tests for GhostCallback and PrintCallback"""

    def test_base_callback_noop(self):
        """Base callback methods should do nothing (not raise)"""
        cb = GhostCallback()
        cb.on_thinking("test")
        cb.on_tool_call("test", "test")
        cb.on_tool_result("test", "test")
        cb.on_finding(GhostFinding(title="t", type="t"))
        cb.on_response("test")
        cb.on_turn_complete(1)
        cb.on_stored_response("1", 200)

    def test_print_callback_on_finding(self, capsys):
        cb = PrintCallback()
        f = GhostFinding(title="XSS", type="XSS", severity="HIGH")
        cb.on_finding(f)
        captured = capsys.readouterr()
        assert "FINDING" in captured.out
        assert "XSS" in captured.out

    def test_print_callback_on_thinking(self, capsys):
        cb = PrintCallback()
        cb.on_thinking("Analyzing headers...")
        captured = capsys.readouterr()
        assert "Analyzing headers" in captured.out


# =============================================================================
# AGENT STATE TESTS
# =============================================================================

class TestAgentState:
    """Tests for GhostAgent state management"""

    def test_initial_state(self, agent):
        assert agent.running is False
        assert agent.cancelled is False
        assert agent.iteration_count == 0
        assert agent.max_iterations == 50
        assert len(agent.findings) == 0
        assert len(agent.response_cache) == 0

    def test_stop(self, agent):
        agent.running = True
        agent.stop()
        assert agent.cancelled is True
        assert agent.running is False

    def test_get_findings_empty(self, agent):
        assert agent.get_findings() == []
        assert agent.get_ghost_findings() == []

    def test_get_findings_returns_beatrix_findings(self, agent):
        agent.findings["XSS"] = GhostFinding(
            title="XSS", type="XSS", severity="HIGH",
            description="Reflected XSS",
        )
        findings = agent.get_findings()
        assert len(findings) == 1
        assert isinstance(findings[0], Finding)
        assert findings[0].severity == Severity.HIGH

    def test_get_ghost_findings(self, agent):
        agent.findings["XSS"] = GhostFinding(
            title="XSS", type="XSS", description="test",
        )
        gf = agent.get_ghost_findings()
        assert len(gf) == 1
        assert isinstance(gf[0], GhostFinding)

    def test_format_request_context(self, agent_with_baseline):
        result = agent_with_baseline._format_request_for_context()
        assert "GET" in result
        assert "https://example.com/api/users?id=1" in result
        assert "Authorization" in result
        assert "BASELINE RESPONSE" in result
        assert "200" in result

    def test_build_initial_prompt(self, agent):
        prompt = agent._build_initial_prompt("GET /api/test", "Find SQL injection")
        assert "GET /api/test" in prompt
        assert "Find SQL injection" in prompt
        assert "injection" in prompt.lower()
        assert "conclude_investigation" in prompt


# =============================================================================
# PAYLOAD PRESETS TESTS
# =============================================================================

class TestPayloadPresets:
    """Tests for built-in payload lists"""

    def test_sqli_payloads_exist(self):
        assert "sqli" in FUZZ_PAYLOADS
        assert len(FUZZ_PAYLOADS["sqli"]) > 0
        assert any("OR" in p for p in FUZZ_PAYLOADS["sqli"])

    def test_xss_payloads_exist(self):
        assert "xss" in FUZZ_PAYLOADS
        assert any("<script>" in p for p in FUZZ_PAYLOADS["xss"])

    def test_command_payloads_exist(self):
        assert "command" in FUZZ_PAYLOADS
        assert any("id" in p for p in FUZZ_PAYLOADS["command"])

    def test_general_payloads_exist(self):
        assert "general" in FUZZ_PAYLOADS
        assert len(FUZZ_PAYLOADS["general"]) > 0


class TestSystemPrompt:
    """Tests for GHOST system prompt"""

    def test_system_prompt_contains_tools(self):
        for tool in [
            "send_http_request", "inject_payload", "fuzz_parameter",
            "record_finding", "conclude_investigation", "encode_payload",
        ]:
            assert tool in GHOST_SYSTEM_PROMPT

    def test_system_prompt_has_format(self):
        assert "<tool_call>" in GHOST_SYSTEM_PROMPT
