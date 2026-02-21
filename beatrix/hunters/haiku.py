"""
BEATRIX Haiku Hunter

AI-assisted vulnerability hunting using Claude Haiku via AWS Bedrock.
Discovers endpoints, generates intelligent payloads, filters false positives.

Consolidated from standalone haiku_hunter.py into the framework.
Uses beatrix.ai for the Bedrock backend and beatrix.core.types for Findings.
"""

import asyncio
import json
import re
import time
from typing import Dict, List, Tuple

import httpx

from beatrix.core.types import Confidence, Finding, Severity

try:
    import boto3
    from botocore.config import Config
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False


class HaikuAnalyzer:
    """Claude Haiku for security analysis via Bedrock"""

    def __init__(self, region: str = "us-east-1"):
        if not HAS_BOTO:
            raise RuntimeError("boto3 required: pip install boto3")
        config = Config(region_name=region, retries={"max_attempts": 3})
        self.client = boto3.client("bedrock-runtime", config=config)
        self.model_id = "anthropic.claude-3-haiku-20240307-v1:0"
        self.input_tokens = 0
        self.output_tokens = 0

    async def analyze(self, prompt: str, max_tokens: int = 1000) -> str:
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        })
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self.client.invoke_model(modelId=self.model_id, body=body),
        )
        result = json.loads(response["body"].read())
        self.input_tokens += result.get("usage", {}).get("input_tokens", 0)
        self.output_tokens += result.get("usage", {}).get("output_tokens", 0)
        return result["content"][0]["text"]

    def get_cost(self) -> float:
        return (self.input_tokens / 1000) * 0.00025 + (self.output_tokens / 1000) * 0.00125


class HaikuHunter:
    """AI-Powered Bug Bounty Hunter"""

    INJECTION_TESTS: Dict[str, List[Tuple[str, str]]] = {
        "sqli": [
            ("'", "Single quote"),
            ("''", "Double quote"),
            ("' OR '1'='1", "Boolean SQLi"),
            ("' AND '1'='2", "Boolean SQLi false"),
            ("' AND SLEEP(3)--", "Time-based SQLi"),
            ("1' UNION SELECT NULL--", "UNION SQLi"),
        ],
        "xss": [
            ("<script>alert(1)</script>", "Basic script"),
            ("<img src=x onerror=alert(1)>", "Event handler"),
            ("{{7*7}}", "Template injection"),
            ("${7*7}", "Template alt syntax"),
            ("javascript:alert(1)", "JS URI"),
        ],
        "ssrf": [
            ("http://169.254.169.254/latest/meta-data/", "AWS IMDS"),
            ("http://127.0.0.1:22", "Local port scan"),
            ("http://localhost/admin", "Local admin"),
        ],
        "path": [
            ("../../../etc/passwd", "Path traversal Unix"),
            ("..\\..\\..\\windows\\win.ini", "Path traversal Windows"),
        ],
    }

    def __init__(self, use_ai: bool = True, region: str = "us-east-1"):
        self.use_ai = use_ai
        self.ai = HaikuAnalyzer(region) if use_ai and HAS_BOTO else None
        self.findings: List[Finding] = []
        self.endpoints: List[str] = []

    async def hunt(self, target: str, deep: bool = False) -> List[Finding]:
        """Main hunting workflow"""
        if not target.startswith("http"):
            target = f"https://{target}"

        await self._discover_endpoints(target)
        await self._test_all_endpoints()

        if self.ai and self.findings:
            await self._ai_analyze()

        return self.findings

    async def _discover_endpoints(self, target: str) -> None:
        common_paths = [
            "/", "/search", "/api/search", "/api/v1/search",
            "/login", "/signup", "/register",
            "/api/user", "/api/users", "/graphql",
            "/admin", "/dashboard", "/profile",
        ]

        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            for path in common_paths:
                url = f"{target.rstrip('/')}{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code < 400:
                        self.endpoints.append(url)
                except Exception:
                    pass

            try:
                resp = await client.get(target)
                links = re.findall(r'href=["\']([^"\']+\?[^"\']+)["\']', resp.text)
                for link in links[:20]:
                    if link.startswith("/"):
                        link = f"{target.rstrip('/')}{link}"
                    if target.split("/")[2] in link and link not in self.endpoints:
                        self.endpoints.append(link)
            except Exception:
                pass

    async def _test_all_endpoints(self) -> None:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
            for endpoint in self.endpoints:
                await self._test_endpoint(client, endpoint)

    async def _test_endpoint(self, client: httpx.AsyncClient, endpoint: str) -> None:
        try:
            baseline = await client.get(endpoint)
        except Exception:
            return

        if "?" in endpoint:
            base_url, query = endpoint.split("?", 1)
            params = {}
            for p in query.split("&"):
                if "=" in p:
                    k, v = p.split("=", 1)
                    params[k] = v
                else:
                    params[p] = ""
        else:
            base_url = endpoint
            params = {"q": "test", "search": "test", "id": "1"}

        for param, orig_value in params.items():
            for category, tests in self.INJECTION_TESTS.items():
                for payload, desc in tests:
                    await self._test_payload(client, base_url, param, orig_value, payload, desc, category, baseline)

    async def _test_payload(self, client, base_url, param, orig_value, payload, desc, category, baseline) -> None:
        test_value = f"{orig_value}{payload}"
        try:
            start = time.time()
            resp = await client.get(f"{base_url}?{param}={test_value}")
            elapsed = time.time() - start

            is_vuln = False
            evidence = ""

            sql_errors = ["SQL syntax", "mysql_", "pg_", "ORA-", "SQLSTATE", "syntax error", "unclosed quotation"]
            for err in sql_errors:
                if err.lower() in resp.text.lower():
                    is_vuln = True
                    evidence = f"SQL error: {err}"
                    break

            if category == "sqli" and "SLEEP" in payload and elapsed > 2.5:
                is_vuln = True
                evidence = f"Response delayed {elapsed:.2f}s"

            if category == "xss" and payload in resp.text:
                is_vuln = True
                evidence = "Payload reflected in response"

            if "{{7*7}}" in payload and "49" in resp.text:
                idx = resp.text.find("49")
                ctx = resp.text[max(0, idx - 30):idx + 10]
                if "{{7*7}}" not in ctx:
                    is_vuln = True
                    evidence = "Template evaluated (49 found)"

            lfi_indicators = ["root:x:0", "daemon:", "bin/bash", "[extensions]", "[fonts]"]
            for ind in lfi_indicators:
                if ind in resp.text:
                    is_vuln = True
                    evidence = f"File content: {ind}"
                    break

            ssrf_indicators = ["ami-id", "instance-id", "security-credentials"]
            for ind in ssrf_indicators:
                if ind in resp.text:
                    is_vuln = True
                    evidence = f"SSRF indicator: {ind}"
                    break

            if is_vuln:
                severity_map = {"sqli": Severity.CRITICAL, "xss": Severity.HIGH, "ssrf": Severity.CRITICAL, "path": Severity.HIGH}
                self.findings.append(Finding(
                    title=f"{category.upper()}: {desc} on {param}",
                    severity=severity_map.get(category, Severity.MEDIUM),
                    confidence=Confidence.TENTATIVE,
                    url=base_url,
                    scanner_module="haiku_hunter",
                    description=f"{category.upper()} detected via payload '{payload}' on parameter '{param}'",
                    evidence=evidence,
                ))
        except Exception:
            pass

    async def _ai_analyze(self) -> None:
        if not self.ai:
            return
        for finding in self.findings:
            prompt = f"""Analyze this potential security vulnerability:

Category: {finding.title.split(':')[0]}
URL: {finding.url}
Evidence: {finding.evidence}

Questions:
1. Is this likely a TRUE POSITIVE or FALSE POSITIVE? Why?
2. What is the potential severity (Critical/High/Medium/Low)?
3. What additional tests would confirm this vulnerability?

Be concise and direct."""
            try:
                analysis = await self.ai.analyze(prompt, max_tokens=500)
                is_verified = "TRUE POSITIVE" in analysis.upper()
                if is_verified:
                    finding.confidence = Confidence.CERTAIN
                finding.description += f"\n\nAI Analysis:\n{analysis}"
            except Exception:
                pass
