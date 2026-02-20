"""
JWT (JSON Web Token) Analysis Module
Tests for CWE-347: Improper Verification of Cryptographic Signature
CWE-613: Insufficient Session Expiration
"""

import asyncio
import base64
import json
import re
from typing import Optional

import aiohttp

from beatrix.scanners.reconx_compat import ReconXBaseModule as BaseModule
from beatrix.utils.helpers import extract_domain
from beatrix.utils.response_validator import ResponseValidator


class JWTAnalyzer(BaseModule):
    """JWT vulnerability scanner with CDN detection"""

    # JWT regex pattern: header.payload.signature (base64url encoded)
    JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

    def __init__(self, config=None):
        super().__init__(config)
        self.findings = []
        self.seen_findings = set()  # For deduplication
        self.response_validator = ResponseValidator()
        self.jwt_endpoints = [
            '/api/login',
            '/api/auth',
            '/api/token',
            '/auth/login',
            '/login',
            '/authenticate',
            '/api/v1/auth',
            '/api/v1/login',
            '/api/v2/auth',
            '/oauth/token',
            '/api/session',
        ]
        # Statistics tracking
        self.stats = {
            'endpoints_tested': 0,
            'jwts_found': 0,
            'soft_404_skipped': 0,
            'errors': 0
        }

    async def run(self, target: str) -> dict:
        """Run JWT analysis"""
        # Reset state for new target
        self.findings = []
        self.seen_findings = set()
        self.response_validator.reset()
        self.stats = {'endpoints_tested': 0, 'jwts_found': 0, 'soft_404_skipped': 0, 'errors': 0}

        domain = extract_domain(target)
        base_url = f"https://{domain}" if not target.startswith('http') else target.rstrip('/')

        print(f"[*] Analyzing JWT implementation on {base_url}")

        # Discover JWT endpoints
        await self.discover_jwt_endpoints(base_url)

        return {
            "target": base_url,
            "total_findings": len(self.findings),
            "vulnerabilities": self.findings,
            "scan_statistics": self.stats
        }

    def _add_finding(self, finding: dict) -> bool:
        """Add finding with deduplication. Returns True if added."""
        key = f"{finding['severity']}:{finding.get('url', '')}:{finding['type']}"
        if key in self.seen_findings:
            return False
        self.seen_findings.add(key)
        self.findings.append(finding)
        return True

    async def discover_jwt_endpoints(self, base_url: str):
        """Discover endpoints that might return JWTs"""
        semaphore = asyncio.Semaphore(10)
        tasks = []

        for endpoint in self.jwt_endpoints:
            url = f"{base_url}{endpoint}"
            tasks.append(self.test_jwt_endpoint(url, semaphore))

        await asyncio.gather(*tasks)

    async def test_jwt_endpoint(self, url: str, semaphore):
        """Test endpoint for JWT vulnerabilities with CDN detection"""
        async with semaphore:
            try:
                self.stats['endpoints_tested'] += 1
                async with aiohttp.ClientSession() as session:
                    # Try with weak credentials
                    test_credentials = [
                        {'username': 'admin', 'password': 'admin'},
                        {'username': 'test', 'password': 'test'},
                        {'email': 'test@test.com', 'password': 'password'},
                    ]

                    for creds in test_credentials:
                        async with session.post(
                            url,
                            json=creds,
                            timeout=aiohttp.ClientTimeout(total=10),
                            ssl=False,
                            allow_redirects=False
                        ) as response:

                            body = await response.text()
                            headers_dict = dict(response.headers)

                            # Skip CDN soft-404 responses (HTML for API endpoint)
                            if self.response_validator.is_html_response(body, headers_dict):
                                self.stats['soft_404_skipped'] += 1
                                continue

                            if response.status == 200:
                                # Validate this is a real API response, not CDN page
                                if not self.response_validator.is_json_response(body, headers_dict):
                                    self.stats['soft_404_skipped'] += 1
                                    continue

                                # Check for JWT in response
                                jwt_token = self.extract_jwt(body, response.headers)

                                if jwt_token:
                                    self.stats['jwts_found'] += 1
                                    print(f"[+] JWT found at {url}")
                                    await self.analyze_jwt(url, jwt_token)

            except aiohttp.ClientResponseError:
                pass
            except Exception:
                self.stats['errors'] += 1

    def extract_jwt(self, body: str, headers) -> Optional[str]:
        """Extract and validate JWT token from response"""
        # JWT pattern: header.payload.signature (base64url encoded)

        # Check Authorization header
        auth_header = headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            if self.is_jwt(token):
                return token

        # Check Set-Cookie headers for JWT
        for cookie in headers.getall('Set-Cookie', []):
            match = self.JWT_PATTERN.search(cookie)
            if match:
                return match.group()

        # Check response body for JWT
        # First try JSON parsing
        try:
            data = json.loads(body)
            for key in ['token', 'access_token', 'jwt', 'accessToken', 'auth_token', 'id_token', 'refresh_token']:
                if key in data:
                    token = data[key]
                    if isinstance(token, str) and self.is_jwt(token):
                        return token
        except Exception:
            pass

        # Fallback: regex search for JWT pattern in body
        match = self.JWT_PATTERN.search(body)
        if match:
            return match.group()

        return None

    def is_jwt(self, token: str) -> bool:
        """Validate string is a proper JWT token"""
        if not isinstance(token, str):
            return False

        parts = token.split('.')
        if len(parts) != 3:
            return False

        # Validate each part is valid base64url
        try:
            for part in parts[:2]:  # Don't validate signature (can be empty for 'none' alg)
                # Add padding if needed
                padding = 4 - (len(part) % 4)
                if padding != 4:
                    part += '=' * padding
                base64.urlsafe_b64decode(part)
            return True
        except Exception:
            return False

    async def analyze_jwt(self, url: str, token: str):
        """Analyze JWT for vulnerabilities"""
        parts = token.split('.')

        if len(parts) != 3:
            return

        try:
            # Decode header
            header = self.decode_jwt_part(parts[0])
            payload = self.decode_jwt_part(parts[1])

            # Check algorithm
            alg = header.get('alg', 'unknown')

            # Critical: None algorithm
            if alg.lower() == 'none':
                finding = {
                    'severity': 'CRITICAL',
                    'type': 'JWT None Algorithm',
                    'cwe': 'CWE-347',
                    'url': url,
                    'algorithm': alg,
                    'description': 'JWT uses "none" algorithm - signature not verified',
                    'impact': 'Token can be forged without signature',
                    'recommendation': 'Disable "none" algorithm, enforce signature verification'
                }
                self._add_finding(finding)
                print(f"[!] CRITICAL: JWT with 'none' algorithm at {url}")

            # High: Weak algorithm
            elif alg in ['HS256', 'HS384', 'HS512']:
                finding = {
                    'severity': 'MEDIUM',
                    'type': 'JWT Weak Algorithm',
                    'cwe': 'CWE-326',
                    'url': url,
                    'algorithm': alg,
                    'description': f'JWT uses symmetric algorithm {alg}',
                    'impact': 'Vulnerable to key brute-force if secret is weak',
                    'recommendation': 'Use asymmetric algorithms (RS256, ES256) or strong secrets'
                }
                self._add_finding(finding)
                print(f"[!] MEDIUM: JWT uses symmetric algorithm {alg}")

            # Check for sensitive data in payload
            sensitive_keys = ['password', 'secret', 'api_key', 'ssn', 'credit_card']
            for key in sensitive_keys:
                if key in payload:
                    finding = {
                        'severity': 'HIGH',
                        'type': 'Sensitive Data in JWT',
                        'cwe': 'CWE-200',
                        'url': url,
                        'sensitive_field': key,
                        'description': f'JWT contains sensitive field: {key}',
                        'impact': 'Sensitive data exposed in token',
                        'recommendation': 'Remove sensitive data from JWT payload'
                    }
                    self._add_finding(finding)
                    print(f"[!] HIGH: JWT contains sensitive field '{key}'")

            # Check expiration
            if 'exp' not in payload:
                finding = {
                    'severity': 'HIGH',
                    'type': 'JWT No Expiration',
                    'cwe': 'CWE-613',
                    'url': url,
                    'description': 'JWT has no expiration time (exp claim)',
                    'impact': 'Token never expires - session hijacking risk',
                    'recommendation': 'Add exp claim with reasonable expiration time'
                }
                self._add_finding(finding)
                print("[!] HIGH: JWT has no expiration")

            # Check for weak/test secrets by attempting signature verification
            if alg in ['HS256', 'HS384', 'HS512']:
                await self.test_weak_secrets(url, token, alg)

            # Test alg:none bypass regardless of current algorithm
            await self.test_alg_none(url, token)

        except Exception:
            pass

    def decode_jwt_part(self, part: str) -> dict:
        """Decode JWT header or payload"""
        # Add padding if needed
        padding = 4 - (len(part) % 4)
        if padding != 4:
            part += '=' * padding

        decoded = base64.urlsafe_b64decode(part)
        return json.loads(decoded)

    async def test_weak_secrets(self, url: str, token: str, alg: str):
        """
        Test for common weak JWT secrets by actually verifying HMAC signatures.

        If we can verify the signature with a guessed secret, the secret is weak
        and we can forge arbitrary tokens → full account takeover.
        """
        import hashlib
        import hmac

        weak_secrets = [
            'secret', 'password', '123456', 'admin', 'test',
            'secret123', 'your-secret-key', 'your-256-bit-secret',
            'mysecret', 'jwt-secret', 'key', 'changeme', 'changeit',
            'qwerty', 'passw0rd', 'password123', 'jwt_secret',
            'supersecret', 'default', 'token-secret', 'my-secret',
            'application-secret', 'app-secret', 'signing-key',
            'hmac-secret', 'private-key', 'auth-secret',
            # Common in tutorials/docs
            'shhhh', 'shhhhh', 'keyboard cat', 'abc123',
            'iloveyou', 'letmein', 'welcome', 'monkey',
        ]

        # Map JWT alg → hashlib hash function
        hash_funcs = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512,
        }

        hash_func = hash_funcs.get(alg)
        if not hash_func:
            return

        # Extract signing input and signature
        parts = token.split('.')
        if len(parts) != 3:
            return

        signing_input = f"{parts[0]}.{parts[1]}".encode('utf-8')

        # Decode the actual signature
        sig_part = parts[2]
        padding = 4 - (len(sig_part) % 4)
        if padding != 4:
            sig_part += '=' * padding
        try:
            actual_sig = base64.urlsafe_b64decode(sig_part)
        except Exception:
            return

        # Try each weak secret
        for secret in weak_secrets:
            computed = hmac.new(
                secret.encode('utf-8'),
                signing_input,
                hash_func
            ).digest()

            if hmac.compare_digest(computed, actual_sig):
                finding = {
                    'severity': 'CRITICAL',
                    'type': 'JWT Weak Secret Cracked',
                    'cwe': 'CWE-798',
                    'url': url,
                    'algorithm': alg,
                    'cracked_secret': secret,
                    'description': f'JWT secret cracked! Secret is: "{secret}" — attacker can forge ANY token',
                    'impact': 'Full account takeover — attacker can sign tokens as any user',
                    'recommendation': 'Immediately rotate JWT secret to a cryptographically random value (256+ bits). Use asymmetric algorithms (RS256/ES256) for multi-service architectures.'
                }
                self._add_finding(finding)
                print(f"[!] CRITICAL: JWT secret cracked: '{secret}' at {url}")
                return  # Found it, no need to continue

    async def test_alg_none(self, url: str, token: str):
        """
        Test if the server accepts alg:none tokens (signature bypass).

        Create a forged token with alg set to 'none' and empty signature.
        If the server accepts it, we can forge tokens for any user.
        """
        parts = token.split('.')
        if len(parts) != 3:
            return

        try:
            self.decode_jwt_part(parts[1])
        except Exception:
            return

        # Create none-alg header
        none_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b'=').decode()

        # Keep same payload
        none_token = f"{none_header}.{parts[1]}."

        # Try variations
        none_tokens = [
            none_token,                    # Empty signature
            f"{none_header}.{parts[1]}..",  # Double dot
        ]

        # Also try case variations
        for alg_val in ['None', 'NONE', 'nOnE']:
            h = base64.urlsafe_b64encode(
                json.dumps({"alg": alg_val, "typ": "JWT"}).encode()
            ).rstrip(b'=').decode()
            none_tokens.append(f"{h}.{parts[1]}.")

        async with aiohttp.ClientSession() as session:
            for forged in none_tokens:
                try:
                    async with session.get(
                        url,
                        headers={'Authorization': f'Bearer {forged}'},
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            # Check if we actually got authenticated data
                            if not self.response_validator.is_html_response(body, dict(resp.headers)):
                                finding = {
                                    'severity': 'CRITICAL',
                                    'type': 'JWT Algorithm None Bypass',
                                    'cwe': 'CWE-347',
                                    'url': url,
                                    'forged_token': forged[:50] + '...',
                                    'description': 'Server accepts JWT with alg=none — signature completely bypassed',
                                    'impact': 'FULL ACCOUNT TAKEOVER: Forge any user token without knowing the secret',
                                    'recommendation': 'Reject alg=none tokens. Use a strict allowlist of accepted algorithms.'
                                }
                                self._add_finding(finding)
                                print(f"[!] CRITICAL: alg=none bypass at {url}")
                                return
                except Exception:
                    continue
