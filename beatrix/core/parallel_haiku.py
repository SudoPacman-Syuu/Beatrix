#!/usr/bin/env python3
"""
BEATRIX Parallel Haiku Engine
Run multiple AI-assisted analyses concurrently
"""

import asyncio
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import boto3


@dataclass
class HaikuTask:
    """A task for Haiku to analyze"""
    task_id: str
    prompt: str
    context: Optional[Dict[str, Any]] = None
    result: Optional[str] = None
    error: Optional[str] = None
    duration: float = 0


class ParallelHaiku:
    """Run multiple Haiku analyses in parallel"""

    def __init__(self, max_concurrent: int = 5, region: str = 'us-east-1'):
        self.max_concurrent = max_concurrent
        self.region = region
        self.model_id = "anthropic.claude-3-haiku-20240307-v1:0"
        self._executor = ThreadPoolExecutor(max_workers=max_concurrent)

    def _create_client(self):
        """Create a new Bedrock client (thread-safe)"""
        return boto3.client(
            service_name='bedrock-runtime',
            region_name=self.region
        )

    def _invoke_haiku(self, task: HaikuTask) -> HaikuTask:
        """Invoke Haiku for a single task"""
        start = time.time()
        try:
            client = self._create_client()

            body = json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 2000,
                "messages": [{"role": "user", "content": task.prompt}]
            })

            response = client.invoke_model(
                body=body,
                modelId=self.model_id,
                accept="application/json",
                contentType="application/json"
            )

            result = json.loads(response.get('body').read())
            task.result = result['content'][0]['text']

        except Exception as e:
            task.error = str(e)

        task.duration = time.time() - start
        return task

    def run_parallel(self, tasks: List[HaikuTask]) -> List[HaikuTask]:
        """Run multiple Haiku tasks in parallel"""
        print(f"🤖 Running {len(tasks)} Haiku analyses in parallel (max {self.max_concurrent} concurrent)...")

        start = time.time()
        futures = [self._executor.submit(self._invoke_haiku, task) for task in tasks]
        results = [f.result() for f in futures]

        total_time = time.time() - start
        successful = sum(1 for t in results if t.result)
        print(f"✅ Completed {successful}/{len(tasks)} tasks in {total_time:.2f}s")

        return results

    async def run_parallel_async(self, tasks: List[HaikuTask]) -> List[HaikuTask]:
        """Async version for integration with other async code"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.run_parallel, tasks)


class HaikuHunter:
    """AI-assisted vulnerability hunting with parallel analysis"""

    def __init__(self, max_concurrent: int = 5):
        self.haiku = ParallelHaiku(max_concurrent=max_concurrent)

    def analyze_endpoints(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze multiple endpoints for vulnerabilities"""

        tasks = []
        for i, endpoint in enumerate(endpoints):
            prompt = f"""Analyze this API endpoint for security vulnerabilities:

URL: {endpoint.get('url')}
Method: {endpoint.get('method', 'GET')}
Headers: {json.dumps(endpoint.get('headers', {}), indent=2)}
Response Status: {endpoint.get('status')}
Response Headers: {json.dumps(endpoint.get('response_headers', {}), indent=2)}
Response Body (first 500 chars): {str(endpoint.get('body', ''))[:500]}

Identify:
1. Potential IDOR vulnerabilities
2. Authentication/authorization issues
3. Information disclosure
4. Injection points
5. SSRF potential
6. Business logic flaws

For each finding, rate severity (Critical/High/Medium/Low/Info) and explain exploitation."""

            tasks.append(HaikuTask(
                task_id=f"endpoint_{i}",
                prompt=prompt,
                context=endpoint
            ))

        results = self.haiku.run_parallel(tasks)

        analyzed = []
        for task in results:
            analyzed.append({
                'endpoint': task.context,
                'analysis': task.result,
                'error': task.error,
                'duration': task.duration
            })

        return analyzed

    def analyze_responses(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Batch analyze HTTP responses for vulnerabilities"""

        tasks = []
        for i, resp in enumerate(responses):
            prompt = f"""Security analysis of HTTP response:

URL: {resp.get('url')}
Status: {resp.get('status')}
Headers: {json.dumps(dict(resp.get('headers', {})), indent=2)[:1000]}
Body snippet: {str(resp.get('body', ''))[:800]}

Look for:
1. Sensitive data exposure (emails, tokens, keys, PII)
2. Security misconfigurations
3. Version disclosure
4. Debug information
5. Error messages revealing internals
6. CORS issues
7. Missing security headers with actual impact

Output as JSON: {{"findings": [{{"type": "...", "severity": "...", "details": "...", "impact": "..."}}]}}"""

            tasks.append(HaikuTask(task_id=f"resp_{i}", prompt=prompt, context=resp))

        results = self.haiku.run_parallel(tasks)

        all_findings = []
        for task in results:
            if task.result:
                try:
                    # Try to parse JSON from response
                    if '{' in task.result:
                        json_start = task.result.find('{')
                        json_end = task.result.rfind('}') + 1
                        parsed = json.loads(task.result[json_start:json_end])
                        if 'findings' in parsed:
                            for f in parsed['findings']:
                                f['source_url'] = task.context.get('url') if task.context else None
                            all_findings.extend(parsed['findings'])
                except Exception:
                    pass

        return {
            'total_responses': len(responses),
            'findings': all_findings,
            'high_severity': [f for f in all_findings if f.get('severity', '').lower() in ['critical', 'high']]
        }


# Quick test
if __name__ == "__main__":
    print("Testing Parallel Haiku...")

    haiku = ParallelHaiku(max_concurrent=3)

    tasks = [
        HaikuTask(task_id="test1", prompt="What is 2+2? Answer in one word."),
        HaikuTask(task_id="test2", prompt="What color is the sky? Answer in one word."),
        HaikuTask(task_id="test3", prompt="What is the capital of France? Answer in one word."),
    ]

    results = haiku.run_parallel(tasks)

    for task in results:
        print(f"\n{task.task_id}: {task.result[:50] if task.result else task.error}")
        print(f"  Duration: {task.duration:.2f}s")
