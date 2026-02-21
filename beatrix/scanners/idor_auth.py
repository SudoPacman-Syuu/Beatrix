#!/usr/bin/env python3
"""
BEATRIX Authenticated IDOR Scanner
Test for Insecure Direct Object References with actual credentials
"""

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import httpx

from beatrix.core.auto_register import Credential, CredentialStore
from beatrix.core.parallel_haiku import HaikuTask, ParallelHaiku


@dataclass
class IDORFinding:
    """An IDOR vulnerability finding"""
    url: str
    method: str
    parameter: str
    original_value: str
    tampered_value: str
    response_status: int
    response_length: int
    severity: str
    description: str
    proof: str

    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'method': self.method,
            'parameter': self.parameter,
            'original_value': self.original_value,
            'tampered_value': self.tampered_value,
            'response_status': self.response_status,
            'response_length': self.response_length,
            'severity': self.severity,
            'description': self.description,
            'proof': self.proof
        }


class AuthenticatedIDORScanner:
    """Scan for IDOR vulnerabilities using authenticated sessions"""

    # Common ID parameter patterns
    ID_PATTERNS = [
        r'user_?id',
        r'account_?id',
        r'profile_?id',
        r'order_?id',
        r'transaction_?id',
        r'customer_?id',
        r'member_?id',
        r'owner_?id',
        r'id',
        r'uid',
        r'pid',
        r'uuid',
    ]

    # Common ID formats
    ID_FORMATS = {
        'numeric': re.compile(r'^\d+$'),
        'uuid': re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.I),
        'hex': re.compile(r'^[a-f0-9]{16,32}$', re.I),
        'base64': re.compile(r'^[A-Za-z0-9+/]+=*$'),
    }

    def __init__(self, credentials: Optional[Credential] = None, timeout: float = 10.0):
        self.credentials = credentials
        self.timeout = timeout
        self.findings: List[IDORFinding] = []
        self.client: httpx.AsyncClient = None

    async def __aenter__(self):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
        }

        # Add authentication cookies if available
        cookies = {}
        if self.credentials and self.credentials.cookies:
            cookies = self.credentials.cookies

        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            headers=headers,
            cookies=cookies,
            follow_redirects=True
        )
        return self

    async def __aexit__(self, *args):
        if self.client:
            await self.client.aclose()

    def _detect_id_format(self, value: str) -> str:
        """Detect the format of an ID value"""
        for fmt_name, pattern in self.ID_FORMATS.items():
            if pattern.match(str(value)):
                return fmt_name
        return 'unknown'

    def _generate_tampered_values(self, original: str, id_format: str) -> List[str]:
        """Generate tampered ID values for testing"""
        tampered = []

        if id_format == 'numeric':
            num = int(original)
            # Adjacent IDs
            tampered.extend([str(num - 1), str(num + 1)])
            # Common test IDs
            tampered.extend(['1', '0', '-1', '999999', '2147483647'])

        elif id_format == 'uuid':
            # Modify last digit
            tampered.append(original[:-1] + ('0' if original[-1] != '0' else '1'))
            # Common test UUIDs
            tampered.append('00000000-0000-0000-0000-000000000000')
            tampered.append('ffffffff-ffff-ffff-ffff-ffffffffffff')

        elif id_format == 'hex':
            # Modify last character
            tampered.append(original[:-1] + ('0' if original[-1] != '0' else '1'))
            tampered.append('0' * len(original))

        else:
            # Generic tampering
            tampered.append('1')
            tampered.append('test')
            tampered.append(original + '1')

        # Remove original and duplicates
        return list(set(t for t in tampered if t != original))

    async def test_endpoint(
        self,
        url: str,
        method: str = 'GET',
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None
    ) -> List[IDORFinding]:
        """Test an endpoint for IDOR vulnerabilities"""

        findings = []

        # Find ID parameters in URL
        url_ids = re.findall(r'/(\d+)', url)

        # Find ID parameters in params
        if params:
            for param, value in params.items():
                for pattern in self.ID_PATTERNS:
                    if re.search(pattern, param, re.I):
                        id_format = self._detect_id_format(str(value))
                        tampered_values = self._generate_tampered_values(str(value), id_format)

                        for tampered in tampered_values:
                            finding = await self._test_idor(
                                url, method, 'param', param, str(value), tampered,
                                params={**params, param: tampered},
                                data=data, headers=headers
                            )
                            if finding:
                                findings.append(finding)

        # Find ID parameters in request body
        if data:
            for param, value in data.items():
                for pattern in self.ID_PATTERNS:
                    if re.search(pattern, param, re.I):
                        id_format = self._detect_id_format(str(value))
                        tampered_values = self._generate_tampered_values(str(value), id_format)

                        for tampered in tampered_values:
                            finding = await self._test_idor(
                                url, method, 'body', param, str(value), tampered,
                                params=params,
                                data={**data, param: tampered},
                                headers=headers
                            )
                            if finding:
                                findings.append(finding)

        # Test URL path IDs
        for original_id in url_ids:
            id_format = self._detect_id_format(original_id)
            tampered_values = self._generate_tampered_values(original_id, id_format)

            for tampered in tampered_values:
                tampered_url = url.replace(f'/{original_id}', f'/{tampered}', 1)
                finding = await self._test_idor(
                    tampered_url, method, 'path', 'id', original_id, tampered,
                    params=params, data=data, headers=headers
                )
                if finding:
                    findings.append(finding)

        self.findings.extend(findings)
        return findings

    async def _test_idor(
        self,
        url: str,
        method: str,
        location: str,
        param: str,
        original: str,
        tampered: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None
    ) -> Optional[IDORFinding]:
        """
        Test a single IDOR case with BASELINE COMPARISON.

        Critical fix: We MUST compare tampered response against the original
        legitimate response. Without baseline, we'd flag every 200 OK with
        data as IDOR (massive false positives).

        Two-phase approach:
        1. Get baseline: request with ORIGINAL (legitimate) ID
        2. Get tampered: request with TAMPERED ID
        3. Compare: if tampered returns different data that shouldn't be accessible
        """

        try:
            # Phase 1: Get BASELINE response (original, legitimate ID)
            baseline_url = url.replace(f'/{tampered}', f'/{original}', 1) if location == 'path' else url
            baseline_params = params
            baseline_data = data

            if location == 'param' and params:
                baseline_params = {**params, param: original}
            elif location == 'body' and data:
                baseline_data = {**data, param: original}

            if method.upper() == 'GET':
                baseline_resp = await self.client.get(baseline_url, params=baseline_params, headers=headers)
            elif method.upper() == 'POST':
                baseline_resp = await self.client.post(baseline_url, params=baseline_params, json=baseline_data, headers=headers)
            elif method.upper() == 'PUT':
                baseline_resp = await self.client.put(baseline_url, params=baseline_params, json=baseline_data, headers=headers)
            elif method.upper() == 'DELETE':
                baseline_resp = await self.client.delete(baseline_url, params=baseline_params, headers=headers)
            else:
                return None

            await asyncio.sleep(0.3)  # Rate limiting

            # Phase 2: Get TAMPERED response
            if method.upper() == 'GET':
                resp = await self.client.get(url, params=params, headers=headers)
            elif method.upper() == 'POST':
                resp = await self.client.post(url, params=params, json=data, headers=headers)
            elif method.upper() == 'PUT':
                resp = await self.client.put(url, params=params, json=data, headers=headers)
            elif method.upper() == 'DELETE':
                resp = await self.client.delete(url, params=params, headers=headers)
            else:
                return None

            # Phase 3: Compare with baseline
            is_idor, severity, description = self._analyze_response(
                baseline_resp, resp, original, tampered, location
            )

            if is_idor:
                return IDORFinding(
                    url=url,
                    method=method,
                    parameter=f"{location}:{param}",
                    original_value=original,
                    tampered_value=tampered,
                    response_status=resp.status_code,
                    response_length=len(resp.content),
                    severity=severity,
                    description=description,
                    proof=resp.text[:500] if len(resp.text) < 500 else resp.text[:500] + '...'
                )

        except Exception as e:
            print(f"  ⚠️  Error testing {url}: {e}")

        return None

    def _analyze_response(
        self,
        baseline: httpx.Response,
        tampered_resp: httpx.Response,
        original: str,
        tampered: str,
        location: str
    ) -> Tuple[bool, str, str]:
        """
        Analyze response by COMPARING tampered vs baseline.

        Key insight: IDOR means accessing DIFFERENT user's data with YOUR credentials.
        We need to prove the data changed (it's someone else's) not just that data exists.

        Rules:
        - If both return same data → NOT IDOR (might be public or own data)
        - If tampered returns 403/404 → NOT IDOR (access control works)
        - If tampered returns DIFFERENT data with 200 → SUSPICIOUS
        - If that different data contains sensitive fields → IDOR CONFIRMED
        """

        # Access denied = access control works correctly
        if tampered_resp.status_code in [401, 403, 404, 405]:
            return (False, '', '')

        # Redirect to login = access control works
        if tampered_resp.status_code in [301, 302, 303, 307, 308]:
            location_header = tampered_resp.headers.get('location', '').lower()
            if 'login' in location_header or 'auth' in location_header or 'sso' in location_header:
                return (False, '', '')

        # Only care about success responses
        if tampered_resp.status_code not in [200, 201]:
            return (False, '', '')

        # If baseline was NOT successful, we can't compare
        if baseline.status_code not in [200, 201]:
            return (False, '', '')

        # Compare response bodies
        baseline_text = baseline.text.strip()
        tampered_text = tampered_resp.text.strip()

        # If responses are identical, it's likely the same data (maybe public)
        # or the ID parameter is ignored entirely
        if baseline_text == tampered_text:
            return (False, '', '')

        # Responses differ — now analyze WHY they differ
        try:
            baseline_data = baseline.json()
            tampered_data = tampered_resp.json()
        except Exception:
            # Non-JSON responses: do simple text comparison
            # Only flag if tampered is significantly different AND contains patterns
            if len(tampered_text) < 100:
                return (False, '', '')  # Too small to be meaningful
            return (False, '', '')  # Can't meaningfully analyze non-JSON

        # Check if tampered response contains DIFFERENT user identity markers
        identity_keys = ['email', 'username', 'user_name', 'userId', 'user_id',
                         'customerId', 'customer_id', 'accountId', 'account_id',
                         'name', 'firstName', 'first_name', 'lastName', 'last_name']

        baseline_str = json.dumps(baseline_data).lower()
        tampered_str = json.dumps(tampered_data).lower()

        # Extract identity values from both responses
        baseline_identities = {}
        tampered_identities = {}

        for key in identity_keys:
            key_lower = key.lower()
            # Simple JSON key:value extraction
            for k, v in self._extract_values(baseline_data, key_lower):
                baseline_identities[k] = v
            for k, v in self._extract_values(tampered_data, key_lower):
                tampered_identities[k] = v

        # If tampered has different identity values → IDOR CONFIRMED
        identity_diff = False
        diff_details = []
        for key in baseline_identities:
            if key in tampered_identities and baseline_identities[key] != tampered_identities[key]:
                identity_diff = True
                diff_details.append(
                    f"{key}: '{baseline_identities[key]}' → '{tampered_identities[key]}'"
                )

        if identity_diff:
            # Check for sensitive data in tampered response
            sensitive_keys = ['email', 'phone', 'address', 'ssn', 'password', 'token',
                             'credit_card', 'bank', 'salary', 'balance', 'secret']
            found_sensitive = [k for k in sensitive_keys if k in tampered_str]

            if found_sensitive:
                return (True, 'HIGH',
                        f"CONFIRMED IDOR: Tampered ID returned DIFFERENT user's sensitive data. "
                        f"Identity diff: {'; '.join(diff_details)}. "
                        f"Sensitive fields exposed: {', '.join(found_sensitive)}")
            else:
                return (True, 'MEDIUM',
                        f"Likely IDOR: Tampered ID returned different user context. "
                        f"Identity diff: {'; '.join(diff_details)}")

        # Tampered data has new identity fields not in baseline
        for key in tampered_identities:
            if key not in baseline_identities:
                return (True, 'MEDIUM',
                        f"Tampered response contains identity field '{key}' "
                        f"not present in baseline — possible IDOR")

        # Responses differ but no clear identity change —
        # could be pagination, timestamps, etc. NOT flagging as IDOR.
        return (False, '', '')

    def _extract_values(self, data: Any, key_pattern: str) -> List[Tuple[str, Any]]:
        """Recursively extract values matching key pattern from nested data"""
        results = []
        if isinstance(data, dict):
            for k, v in data.items():
                if k.lower() == key_pattern or key_pattern in k.lower():
                    if isinstance(v, (str, int, float)):
                        results.append((k, str(v)))
                if isinstance(v, (dict, list)):
                    results.extend(self._extract_values(v, key_pattern))
        elif isinstance(data, list):
            for item in data:
                results.extend(self._extract_values(item, key_pattern))
        return results

    def get_report(self) -> Dict:
        """Generate a report of findings"""
        return {
            'total_findings': len(self.findings),
            'by_severity': {
                'CRITICAL': [f.to_dict() for f in self.findings if f.severity == 'CRITICAL'],
                'HIGH': [f.to_dict() for f in self.findings if f.severity == 'HIGH'],
                'MEDIUM': [f.to_dict() for f in self.findings if f.severity == 'MEDIUM'],
                'LOW': [f.to_dict() for f in self.findings if f.severity == 'LOW'],
            },
            'findings': [f.to_dict() for f in self.findings]
        }


class IDORHunter:
    """AI-assisted IDOR hunting with parallel analysis"""

    def __init__(self, platform: str):
        self.platform = platform
        self.store = CredentialStore()
        self.haiku = ParallelHaiku(max_concurrent=3)

    def get_credentials(self) -> Optional[Credential]:
        """Get credentials for the platform"""
        return self.store.get_one(self.platform)

    async def hunt_endpoints(self, endpoints: List[Dict]) -> Dict:
        """Hunt for IDOR in multiple endpoints"""

        creds = self.get_credentials()
        if not creds:
            print(f"⚠️  No credentials for {self.platform}. Run auto-registration first.")
            return {'error': 'No credentials available'}

        print(f"🎯 Hunting IDOR in {len(endpoints)} endpoints with credentials for {self.platform}")

        results = []
        async with AuthenticatedIDORScanner(creds) as scanner:
            for endpoint in endpoints:
                findings = await scanner.test_endpoint(
                    url=endpoint.get('url'),
                    method=endpoint.get('method', 'GET'),
                    params=endpoint.get('params'),
                    data=endpoint.get('data'),
                    headers=endpoint.get('headers')
                )

                results.append({
                    'endpoint': endpoint,
                    'findings': [f.to_dict() for f in findings]
                })

        # Use Haiku to analyze findings
        if results:
            analysis = await self._analyze_with_haiku(results)
            return {
                'platform': self.platform,
                'endpoints_tested': len(endpoints),
                'results': results,
                'ai_analysis': analysis
            }

        return {
            'platform': self.platform,
            'endpoints_tested': len(endpoints),
            'results': results
        }

    async def _analyze_with_haiku(self, results: List[Dict]) -> str:
        """Use Haiku to analyze IDOR findings"""

        findings_summary = json.dumps(results, indent=2)[:3000]

        task = HaikuTask(
            task_id="idor_analysis",
            prompt=f"""Analyze these potential IDOR findings from automated testing:

{findings_summary}

For each finding:
1. Assess if it's a true positive or false positive
2. Rate actual severity (Critical/High/Medium/Low/Info)
3. Explain the business impact
4. Suggest proof-of-concept steps
5. Recommend how to write a clear bug bounty report

Focus on findings that have REAL IMPACT - accessing other users' data, modifying unauthorized resources, etc."""
        )

        results = self.haiku.run_parallel([task])
        return results[0].result if results[0].result else results[0].error


# Common API patterns that are IDOR-prone (generic, no platform-specific)
IDOR_PRONE_PATTERNS = {
    'generic': [
        {'pattern': '/api/v*/users/{id}', 'method': 'GET'},
        {'pattern': '/api/v*/users/{id}/profile', 'method': 'GET'},
        {'pattern': '/api/v*/orders/{id}', 'method': 'GET'},
        {'pattern': '/api/v*/accounts/{id}', 'method': 'GET'},
        {'pattern': '/api/v*/profile/{id}', 'method': 'GET'},
        {'pattern': '/api/v*/customers/{id}', 'method': 'GET'},
        {'pattern': '/api/v*/transactions/{id}', 'method': 'GET'},
        {'pattern': '/api/v*/invoices/{id}', 'method': 'GET'},
        {'pattern': '/api/v*/addresses/{id}', 'method': 'GET'},
        {'pattern': '/api/v*/documents/{id}', 'method': 'GET'},
        {'pattern': '/api/v*/files/{id}', 'method': 'GET'},
        {'pattern': '/api/v*/messages/{id}', 'method': 'GET'},
        {'pattern': '/api/v*/payments/{id}', 'method': 'GET'},
        {'pattern': '/api/v*/subscriptions/{id}', 'method': 'GET'},
        # Checkout / cart patterns (Zooplus lesson)
        {'pattern': '/api/checkout/*/customer/*', 'method': 'POST'},
        {'pattern': '/api/*/cart/{id}', 'method': 'GET'},
        {'pattern': '/api/*/session/{id}', 'method': 'GET'},
    ]
}


if __name__ == "__main__":
    print("BEATRIX Authenticated IDOR Scanner")
    print("=" * 40)

    # Check for stored credentials
    store = CredentialStore()
    creds = store.list_all()

    if not creds:
        print("\n⚠️  No credentials stored. Run auto-registration first:")
        print("   python -m beatrix.core.auto_register register doordash consumer")
    else:
        print("\n📋 Available credentials:")
        for platform, count in creds.items():
            print(f"  {platform}: {count} account(s)")

        print("\n🎯 Ready to hunt IDOR! Example usage:")
        print("""
from beatrix.scanners.idor_auth import IDORHunter
import asyncio

hunter = IDORHunter('doordash_consumer')
endpoints = [
    {'url': 'https://api.doordash.com/v1/users/12345', 'method': 'GET'},
]
results = asyncio.run(hunter.hunt_endpoints(endpoints))
print(results)
""")
