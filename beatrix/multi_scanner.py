#!/usr/bin/env python3
"""
BEATRIX Multi-Target Parallel Scanner
Run scans against multiple targets concurrently
"""

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import httpx

from beatrix.core.parallel_haiku import HaikuHunter


@dataclass
class ScanTarget:
    """A target to scan"""
    name: str
    base_url: str
    endpoints: List[str]
    headers: Optional[Dict[str, str]] = None
    scan_types: Optional[List[str]] = None  # cors, headers, ssrf, idor, injection


@dataclass
class MultiScanResult:
    """Result from scanning a target (renamed to avoid shadowing core.types.ScanResult)"""
    target: str
    scan_type: str
    findings: List[Dict]
    duration: float
    errors: List[str]


class MultiScanner:
    """Run multiple scans in parallel across multiple targets"""

    def __init__(self, max_concurrent_targets: int = 5, max_concurrent_requests: int = 10):
        self.max_concurrent_targets = max_concurrent_targets
        self.max_concurrent_requests = max_concurrent_requests
        self.semaphore = asyncio.Semaphore(max_concurrent_requests)
        self.haiku = HaikuHunter(max_concurrent=5)
        self.results: List[MultiScanResult] = []

    async def _fetch(self, client: httpx.AsyncClient, url: str, method: str = 'GET', **kwargs) -> Dict:
        """Make a rate-limited HTTP request"""
        async with self.semaphore:
            try:
                if method.upper() == 'GET':
                    resp = await client.get(url, **kwargs)
                elif method.upper() == 'POST':
                    resp = await client.post(url, **kwargs)
                elif method.upper() == 'OPTIONS':
                    resp = await client.options(url, **kwargs)
                else:
                    resp = await client.request(method, url, **kwargs)

                return {
                    'url': url,
                    'status': resp.status_code,
                    'headers': dict(resp.headers),
                    'body': resp.text[:2000],
                    'length': len(resp.content)
                }
            except Exception as e:
                return {'url': url, 'error': str(e)}

    async def scan_cors(self, client: httpx.AsyncClient, url: str, origin: str = 'https://evil.com') -> Dict:
        """Test for CORS misconfiguration"""
        result = {'url': url, 'vulnerable': False, 'details': {}}

        try:
            resp = await client.get(url, headers={'Origin': origin})

            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')

            result['details'] = {
                'acao': acao,
                'acac': acac,
                'status': resp.status_code
            }

            # Check for vulnerable configurations
            if acao == '*' and acac.lower() == 'true':
                result['vulnerable'] = True
                result['severity'] = 'HIGH'
                result['description'] = 'CORS allows any origin with credentials'
            elif acao == origin:
                result['vulnerable'] = True
                result['severity'] = 'HIGH'
                result['description'] = 'CORS reflects arbitrary origin'
            elif acao == '*':
                result['severity'] = 'INFO'
                result['description'] = 'CORS allows any origin (no credentials)'

        except Exception as e:
            result['error'] = str(e)

        return result

    async def scan_headers(self, client: httpx.AsyncClient, url: str) -> Dict:
        """Check security headers"""
        result = {'url': url, 'missing': [], 'present': []}

        security_headers = {
            'Strict-Transport-Security': 'HSTS not set',
            'X-Content-Type-Options': 'No nosniff',
            'X-Frame-Options': 'No clickjacking protection',
            'Content-Security-Policy': 'No CSP',
            'X-XSS-Protection': 'No XSS filter',
        }

        try:
            resp = await client.get(url)

            for header, desc in security_headers.items():
                if header.lower() in [h.lower() for h in resp.headers]:
                    result['present'].append(header)
                else:
                    result['missing'].append({'header': header, 'description': desc})

        except Exception as e:
            result['error'] = str(e)

        return result

    async def scan_info_disclosure(self, client: httpx.AsyncClient, url: str) -> Dict:
        """Check for information disclosure"""
        result = {'url': url, 'findings': []}

        # Paths to check
        info_paths = [
            '/.git/HEAD',
            '/.git/config',
            '/.env',
            '/robots.txt',
            '/sitemap.xml',
            '/.well-known/security.txt',
            '/server-status',
            '/phpinfo.php',
            '/.DS_Store',
            '/web.config',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml',
            '/swagger.json',
            '/openapi.json',
            '/api/swagger.json',
            '/graphql',
            '/.graphql',
        ]

        base = url.rstrip('/')

        tasks = []
        for path in info_paths:
            tasks.append(self._fetch(client, f"{base}{path}"))

        responses = await asyncio.gather(*tasks)

        for resp in responses:
            if resp.get('error'):
                continue

            status = resp.get('status', 0)
            body = resp.get('body', '')

            # Check for sensitive info
            if status == 200:
                if '.git' in resp['url'] and ('ref:' in body or '[core]' in body):
                    result['findings'].append({
                        'url': resp['url'],
                        'type': 'Git exposure',
                        'severity': 'HIGH'
                    })
                elif '.env' in resp['url'] and ('=' in body and ('KEY' in body or 'SECRET' in body or 'PASSWORD' in body)):
                    result['findings'].append({
                        'url': resp['url'],
                        'type': 'Environment file exposure',
                        'severity': 'CRITICAL'
                    })
                elif 'swagger' in resp['url'].lower() or 'openapi' in resp['url'].lower():
                    result['findings'].append({
                        'url': resp['url'],
                        'type': 'API documentation exposed',
                        'severity': 'INFO'
                    })
                elif 'graphql' in resp['url'].lower():
                    result['findings'].append({
                        'url': resp['url'],
                        'type': 'GraphQL endpoint found',
                        'severity': 'INFO'
                    })

        return result

    async def scan_target(self, target: ScanTarget) -> List[MultiScanResult]:
        """Run all scans on a single target"""
        results = []
        start = datetime.now()

        print(f"🎯 Scanning {target.name} ({target.base_url})")

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=False,
            headers=target.headers or {'User-Agent': 'BEATRIX Security Scanner'}
        ) as client:

            scan_types = target.scan_types or ['cors', 'headers', 'info']

            # CORS scanning
            if 'cors' in scan_types:
                cors_findings = []
                for endpoint in target.endpoints:
                    url = f"{target.base_url.rstrip('/')}{endpoint}"
                    finding = await self.scan_cors(client, url)
                    if finding.get('vulnerable'):
                        cors_findings.append(finding)

                results.append(MultiScanResult(
                    target=target.name,
                    scan_type='cors',
                    findings=cors_findings,
                    duration=(datetime.now() - start).total_seconds(),
                    errors=[]
                ))

            # Headers scanning
            if 'headers' in scan_types:
                header_findings = []
                for endpoint in target.endpoints:
                    url = f"{target.base_url.rstrip('/')}{endpoint}"
                    finding = await self.scan_headers(client, url)
                    if finding.get('missing'):
                        header_findings.append(finding)

                results.append(MultiScanResult(
                    target=target.name,
                    scan_type='headers',
                    findings=header_findings,
                    duration=(datetime.now() - start).total_seconds(),
                    errors=[]
                ))

            # Info disclosure scanning
            if 'info' in scan_types:
                info_result = await self.scan_info_disclosure(client, target.base_url)

                results.append(MultiScanResult(
                    target=target.name,
                    scan_type='info_disclosure',
                    findings=info_result.get('findings', []),
                    duration=(datetime.now() - start).total_seconds(),
                    errors=[]
                ))

        return results

    async def scan_all(self, targets: List[ScanTarget]) -> Dict:
        """Scan all targets in parallel"""
        print(f"🚀 Starting parallel scan of {len(targets)} targets...")
        start = datetime.now()

        # Create tasks for each target
        tasks = [self.scan_target(target) for target in targets]

        # Run in parallel with semaphore limiting
        all_results = await asyncio.gather(*tasks)

        # Flatten results
        self.results = [r for target_results in all_results for r in target_results]

        total_duration = (datetime.now() - start).total_seconds()

        # Summarize
        summary = {
            'targets_scanned': len(targets),
            'total_scans': len(self.results),
            'duration_seconds': total_duration,
            'findings_by_severity': {
                'CRITICAL': [],
                'HIGH': [],
                'MEDIUM': [],
                'LOW': [],
                'INFO': []
            },
            'results': [
                {
                    'target': r.target,
                    'scan_type': r.scan_type,
                    'findings_count': len(r.findings),
                    'duration': r.duration,
                    'findings': r.findings
                }
                for r in self.results
            ]
        }

        # Categorize findings by severity
        for result in self.results:
            for finding in result.findings:
                severity = finding.get('severity', 'INFO')
                if severity in summary['findings_by_severity']:
                    summary['findings_by_severity'][severity].append({
                        'target': result.target,
                        'scan_type': result.scan_type,
                        **finding
                    })

        return summary

    async def analyze_with_ai(self, summary: Dict) -> Dict:
        """Use Haiku to analyze findings"""
        print("🤖 Analyzing findings with AI...")

        # Prepare responses for AI analysis
        responses = []
        for result in summary.get('results', []):
            for finding in result.get('findings', []):
                responses.append({
                    'url': finding.get('url', 'N/A'),
                    'status': finding.get('status', 200),
                    'headers': finding.get('details', {}),
                    'body': finding.get('description', '')
                })

        if responses:
            loop = asyncio.get_running_loop()
            analysis = await loop.run_in_executor(None, self.haiku.analyze_responses, responses)
            summary['ai_analysis'] = analysis

        return summary


# Pre-configured targets for bug bounty
BUG_BOUNTY_TARGETS = [
    ScanTarget(
        name='DoorDash Consumer API',
        base_url='https://api-consumer-client.doordash.com',
        endpoints=['/graphql', '/health', '/'],
        headers={'X-Bug-Bounty': 'HackerOne'},
        scan_types=['cors', 'headers', 'info']
    ),
    ScanTarget(
        name='DoorDash Dasher',
        base_url='https://dasher.doordash.com',
        endpoints=['/', '/api'],
        headers={'X-Bug-Bounty': 'HackerOne'},
        scan_types=['cors', 'headers', 'info']
    ),
    ScanTarget(
        name='GitLab',
        base_url='https://gitlab.com',
        endpoints=['/api/v4/projects', '/api/v4/users'],
        scan_types=['cors', 'headers', 'info']
    ),
    ScanTarget(
        name='Notion',
        base_url='https://www.notion.so',
        endpoints=['/api/v3', '/'],
        scan_types=['cors', 'headers', 'info']
    ),
]


async def run_bounty_scan():
    """Run scans on bug bounty targets"""
    scanner = MultiScanner(max_concurrent_targets=4, max_concurrent_requests=10)

    print("=" * 60)
    print("BEATRIX Multi-Target Bug Bounty Scanner")
    print("=" * 60)

    summary = await scanner.scan_all(BUG_BOUNTY_TARGETS)

    # Print summary
    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print(f"Targets: {summary['targets_scanned']}")
    print(f"Duration: {summary['duration_seconds']:.2f}s")
    print("\nFindings by Severity:")
    for severity, findings in summary['findings_by_severity'].items():
        if findings:
            print(f"  {severity}: {len(findings)}")

    # Show high/critical findings
    critical = summary['findings_by_severity']['CRITICAL']
    high = summary['findings_by_severity']['HIGH']

    if critical or high:
        print("\n🚨 HIGH PRIORITY FINDINGS:")
        for f in critical + high:
            print(f"  [{f.get('severity')}] {f.get('target')}: {f.get('type', f.get('description', 'N/A'))}")
            print(f"    URL: {f.get('url')}")

    return summary


if __name__ == "__main__":
    summary = asyncio.run(run_bounty_scan())

    # Save results
    output_path = Path(__file__).parent.parent / "scan_results.json"
    with open(output_path, 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"\n📄 Full results saved to: {output_path}")
