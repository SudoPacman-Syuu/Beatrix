#!/usr/bin/env python3
"""
BEATRIX Bug Bounty Hunter

Comprehensive scanner that hunts for REAL, EXPLOITABLE bugs.
Based on OWASP Top 10:2025.

FOCUS AREAS (High Bounty Potential):
1. A01 - Broken Access Control (IDOR, BAC) → $$$
2. A05 - Injection (SQLi, XSS) → $$$
3. A07 - Authentication Failures (JWT, 2FA bypass) → $$$
4. Open Redirects (OAuth abuse) → $$

STRATEGY:
- Only report bugs that can be EXPLOITED
- Provide working PoC
- Demonstrate real impact
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import httpx
except ImportError:
    print("Installing httpx...")
    os.system("pip install httpx")
    import httpx

try:
    import jwt  # noqa: F401
except ImportError:
    print("Installing pyjwt...")
    os.system("pip install pyjwt")

from beatrix.core.types import Finding, Severity
from beatrix.scanners import (
    AuthScanner,
    IDORScanner,
    OpenRedirectScanner,
    SSRFScanner,
    SubdomainTakeoverScanner,
)


class BountyHunter:
    """
    Main bug bounty hunting orchestrator.

    Runs targeted scans for high-value vulnerabilities.
    """

    def __init__(self,
                 target: str,
                 auth_headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None,
                 verbose: bool = False):
        self.target = target.rstrip('/')
        self.parsed = urlparse(target)
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.auth_headers = auth_headers or {}
        self.cookies = cookies or {}
        self.verbose = verbose
        self.findings: List[Finding] = []

    def log(self, msg: str, level: str = "INFO"):
        """Logging with levels"""
        colors = {
            "INFO": "\033[94m",
            "WARN": "\033[93m",
            "ERROR": "\033[91m",
            "SUCCESS": "\033[92m",
            "VULN": "\033[91m\033[1m",
        }
        reset = "\033[0m"

        if level == "INFO" and not self.verbose:
            return

        color = colors.get(level, "")
        print(f"{color}[{level}]{reset} {msg}")

    async def hunt_idor(self, urls: List[str]) -> List[Finding]:
        """Hunt for IDOR vulnerabilities"""
        self.log("🎯 Hunting for IDOR (A01 - Broken Access Control)...")
        findings = []

        scanner = IDORScanner(user1_auth=self.auth_headers)

        for url in urls:
            self.log(f"Testing: {url}")
            try:
                url_findings = await scanner.scan_url(url, self.auth_headers)
                findings.extend(url_findings)

                for f in url_findings:
                    self.log(f"🔴 POTENTIAL IDOR: {f.title}", "VULN")

            except Exception as e:
                self.log(f"Error scanning {url}: {e}", "ERROR")

        return findings

    async def hunt_auth_flaws(self, jwt_tokens: Optional[List[str]] = None) -> List[Finding]:
        """Hunt for authentication vulnerabilities"""
        self.log("🔐 Hunting for Auth Flaws (A07 - Authentication Failures)...")
        findings = []

        scanner = AuthScanner()

        # Analyze any JWT tokens provided
        jwt_tokens = jwt_tokens or []

        # Also look for JWTs in auth headers
        for header_value in self.auth_headers.values():
            if header_value.startswith('Bearer ') and '.' in header_value:
                jwt_tokens.append(header_value.replace('Bearer ', ''))

        for token in jwt_tokens:
            self.log(f"Analyzing JWT: {token[:30]}...")
            try:
                token_findings = await scanner.analyze_token(token)
                findings.extend(token_findings)

                for f in token_findings:
                    self.log(f"🔴 JWT ISSUE: {f.title}", "VULN")

            except Exception as e:
                self.log(f"JWT analysis error: {e}", "ERROR")

        # Test auth endpoints
        async with scanner:
            # Test rate limiting on login
            login_endpoints = [
                f"{self.base_url}/login",
                f"{self.base_url}/api/login",
                f"{self.base_url}/api/auth/login",
                f"{self.base_url}/api/v1/auth/login",
            ]

            for endpoint in login_endpoints:
                self.log(f"Testing rate limiting: {endpoint}")
                try:
                    rate_findings = await scanner.test_rate_limiting(endpoint)
                    findings.extend(rate_findings)

                    for f in rate_findings:
                        self.log(f"🔴 RATE LIMIT ISSUE: {f.title}", "VULN")

                except Exception:
                    continue

        return findings

    async def hunt_injection(self, urls: List[str]) -> List[Finding]:
        """Hunt for injection vulnerabilities"""
        self.log("💉 Hunting for Injection (A05)...")
        findings = []

        # Quick injection tests
        for url in urls:
            self.log(f"Testing: {url}")

            # Manual quick SQLi test
            sqli_payloads = ["'", "1' OR '1'='1", "1; DROP TABLE--"]

            try:
                async with httpx.AsyncClient(timeout=10, verify=False) as client:
                    for payload in sqli_payloads:
                        # Test in URL parameters
                        if '?' in url:
                            # Append to first parameter
                            test_url = url.replace('=', f'={payload}', 1)
                        else:
                            test_url = f"{url}?id={payload}"

                        response = await client.get(
                            test_url,
                            headers=self.auth_headers
                        )

                        # Check for SQL errors
                        sql_errors = [
                            "sql syntax", "mysql", "postgresql", "sqlite",
                            "ora-", "odbc", "sqlstate", "query failed",
                            "unclosed quotation"
                        ]

                        body_lower = response.text.lower()
                        for error in sql_errors:
                            if error in body_lower:
                                findings.append(Finding(
                                    title="SQL Injection - Error-based",
                                    description=f"""
SQL error detected in response!

**URL:** {test_url}
**Payload:** {payload}
**Error indicator found:** {error}

**Response excerpt:**
{response.text[:500]}

**Impact:** Database access, data exfiltration, potential RCE
""".strip(),
                                    severity=Severity.CRITICAL,
                                    url=test_url,
                                    evidence={
                                        'payload': payload,
                                        'error_pattern': error,
                                    },
                                    cwe_id=89,
                                ))
                                self.log(f"🔴 SQL INJECTION: {error} found!", "VULN")
                                break

                        await asyncio.sleep(0.2)

            except Exception as e:
                self.log(f"Injection test error: {e}", "ERROR")

        return findings

    async def hunt_open_redirect(self) -> List[Finding]:
        """Hunt for open redirect vulnerabilities"""
        self.log("↪️ Hunting for Open Redirects...")
        findings = []

        OpenRedirectScanner()

        # Common redirect parameters
        redirect_params = [
            'redirect', 'redirect_uri', 'redirect_url', 'return', 'return_to',
            'returnUrl', 'return_url', 'next', 'url', 'goto', 'destination',
            'continue', 'forward', 'target', 'rurl', 'dest', 'callback',
        ]

        # Evil destinations
        evil_urls = [
            'https://evil.com',
            '//evil.com',
            'https://evil.com@legitimate.com',
            '/\\evil.com',
            '///evil.com',
        ]

        async with httpx.AsyncClient(
            timeout=10,
            follow_redirects=False,
            verify=False
        ) as client:
            for param in redirect_params:
                for evil in evil_urls:
                    test_url = f"{self.base_url}/?{param}={evil}"

                    try:
                        response = await client.get(test_url, headers=self.auth_headers)

                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('location', '')

                            if 'evil.com' in location:
                                findings.append(Finding(
                                    title=f"Open Redirect via {param}",
                                    description=f"""
**Open Redirect Vulnerability**

The application redirects to attacker-controlled URLs.

**URL:** {test_url}
**Redirect to:** {location}
**Parameter:** {param}
**Payload:** {evil}

**Impact:**
- Phishing attacks with legitimate-looking URLs
- OAuth token theft
- Credential harvesting

**PoC:** Visit {test_url}
""".strip(),
                                    severity=Severity.MEDIUM,
                                    url=test_url,
                                    evidence={
                                        'param': param,
                                        'payload': evil,
                                        'redirect_location': location,
                                    },
                                    cwe_id=601,
                                ))
                                self.log(f"🔴 OPEN REDIRECT: {param} → {location}", "VULN")

                    except Exception:
                        continue

                    await asyncio.sleep(0.1)

        return findings

    async def hunt_ssrf(self, urls: List[str]) -> List[Finding]:
        """Hunt for SSRF vulnerabilities - HUGE BOUNTY POTENTIAL"""
        self.log("🌐 Hunting for SSRF (A10 - Server-Side Request Forgery)...")
        findings = []

        scanner = SSRFScanner()

        for url in urls:
            self.log(f"Testing: {url}")
            try:
                ssrf_findings = await scanner.quick_scan(url, self.auth_headers)
                findings.extend(ssrf_findings)

                for f in ssrf_findings:
                    self.log(f"🔴 SSRF FOUND: {f.title}", "VULN")

            except Exception as e:
                self.log(f"SSRF test error: {e}", "ERROR")

        return findings

    async def hunt_subdomain_takeover(self) -> List[Finding]:
        """Hunt for subdomain takeover vulnerabilities"""
        self.log("🏴 Hunting for Subdomain Takeover...")
        findings = []

        scanner = SubdomainTakeoverScanner()

        # Extract domain from target
        domain = self.parsed.netloc
        if domain.startswith('www.'):
            domain = domain[4:]

        # Common subdomains to check
        subdomains = [
            f"dev.{domain}",
            f"staging.{domain}",
            f"test.{domain}",
            f"beta.{domain}",
            f"api.{domain}",
            f"cdn.{domain}",
            f"static.{domain}",
            f"assets.{domain}",
            f"blog.{domain}",
            f"docs.{domain}",
            f"support.{domain}",
            f"help.{domain}",
            f"status.{domain}",
            f"admin.{domain}",
            f"portal.{domain}",
            f"app.{domain}",
            f"dashboard.{domain}",
            f"legacy.{domain}",
            f"old.{domain}",
            f"shop.{domain}",
        ]

        self.log(f"Checking {len(subdomains)} subdomains...")
        takeover_findings = await scanner.scan_subdomains(subdomains)

        for f in takeover_findings:
            self.log(f"🔴 SUBDOMAIN TAKEOVER: {f.title}", "VULN")

        findings.extend(takeover_findings)
        return findings

    async def hunt_all(self, urls: Optional[List[str]] = None, jwt_tokens: Optional[List[str]] = None):
        """Run all hunting modules"""
        urls = urls or [self.target]
        jwt_tokens = jwt_tokens or []

        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    BEATRIX BUG BOUNTY HUNTER                 ║
║                    "Silly rabbit, bugs are mine"             ║
╚══════════════════════════════════════════════════════════════╝

Target: {self.target}
URLs to scan: {len(urls)}
Auth headers: {list(self.auth_headers.keys()) if self.auth_headers else 'None'}
Time: {datetime.now().isoformat()}
        """)

        # Run all hunters
        all_findings = []

        # 1. IDOR (highest bounty potential)
        try:
            idor_findings = await self.hunt_idor(urls)
            all_findings.extend(idor_findings)
        except Exception as e:
            self.log(f"IDOR hunt failed: {e}", "ERROR")

        # 2. Authentication flaws
        try:
            auth_findings = await self.hunt_auth_flaws(jwt_tokens)
            all_findings.extend(auth_findings)
        except Exception as e:
            self.log(f"Auth hunt failed: {e}", "ERROR")

        # 3. Injection
        try:
            injection_findings = await self.hunt_injection(urls)
            all_findings.extend(injection_findings)
        except Exception as e:
            self.log(f"Injection hunt failed: {e}", "ERROR")

        # 4. Open Redirect
        try:
            redirect_findings = await self.hunt_open_redirect()
            all_findings.extend(redirect_findings)
        except Exception as e:
            self.log(f"Redirect hunt failed: {e}", "ERROR")

        # 5. SSRF
        try:
            ssrf_findings = await self.hunt_ssrf(urls)
            all_findings.extend(ssrf_findings)
        except Exception as e:
            self.log(f"SSRF hunt failed: {e}", "ERROR")

        # 6. Subdomain Takeover
        try:
            takeover_findings = await self.hunt_subdomain_takeover()
            all_findings.extend(takeover_findings)
        except Exception as e:
            self.log(f"Subdomain takeover hunt failed: {e}", "ERROR")

        self.findings = all_findings

        # ================================================================
        # VALIDATION GATE — Filter out theoretical / unsubmittable findings
        # Born from Bykea informative closures. Every finding must prove impact.
        # ================================================================
        validated_findings = []
        killed_findings = []
        needs_work_findings = []

        try:
            from beatrix.validators import ImpactValidator, ReportReadinessGate
            impact_validator = ImpactValidator()
            readiness_gate = ReportReadinessGate()

            for finding in all_findings:
                try:
                    impact = impact_validator.validate(finding, None)
                    readiness = readiness_gate.check(finding)

                    if impact.kill_checks:
                        killed_findings.append((finding, impact))
                        self.log(f"🗑️  KILLED: {finding.title} — {impact.reason}", "WARN")
                    elif impact.passed and readiness.ready:
                        validated_findings.append(finding)
                        self.log(f"✅ VALIDATED: {finding.title}", "SUCCESS")
                    else:
                        needs_work_findings.append((finding, impact, readiness))
                        self.log(f"⚠️  NEEDS WORK: {finding.title} — score {readiness.score}/100", "WARN")
                except Exception as e:
                    # Validator crash shouldn't lose findings
                    validated_findings.append(finding)
                    self.log(f"⚠️  Validator error on {finding.title}: {e}", "WARN")
        except ImportError:
            # Validators not installed — pass all findings through
            validated_findings = all_findings

        # Print summary
        print("""
╔══════════════════════════════════════════════════════════════╗
║                         HUNT COMPLETE                         ║
╚══════════════════════════════════════════════════════════════╝
""")

        if all_findings:
            total = len(all_findings)
            print(f"🎯 Found {total} potential vulnerabilities")
            print(f"   ✅ Validated (submittable):  {len(validated_findings)}")
            print(f"   ⚠️  Needs work:              {len(needs_work_findings)}")
            print(f"   🗑️  Killed (no real impact): {len(killed_findings)}")

            if validated_findings:
                print(f"\n{'='*60}")
                print("SUBMITTABLE FINDINGS:")
                print(f"{'='*60}")

                # Group by severity
                by_severity = {}
                for f in validated_findings:
                    sev = f.severity.value
                    if sev not in by_severity:
                        by_severity[sev] = []
                    by_severity[sev].append(f)

                for severity in ['critical', 'high', 'medium', 'low', 'info']:
                    if severity in by_severity:
                        print(f"\n{'🔴' if severity in ['critical', 'high'] else '🟡' if severity == 'medium' else '🟢'} {severity.upper()} ({len(by_severity[severity])}):")
                        for f in by_severity[severity]:
                            print(f"   • {f.title}")
                            print(f"     URL: {f.url}")

            if needs_work_findings:
                print(f"\n{'='*60}")
                print("NEEDS WORK (fix before submitting):")
                print(f"{'='*60}")
                for finding, impact, readiness in needs_work_findings:
                    print(f"   ⚠️  {finding.title}")
                    if not impact.passed:
                        print(f"      Impact: {impact.reason}")
                    if not readiness.ready:
                        for c in readiness.failed_required:
                            print(f"      ❌ {c.name}: {c.reason}")

            if killed_findings:
                print(f"\n[dim]Killed {len(killed_findings)} findings (no real impact):[/dim]")
                for finding, impact in killed_findings:
                    print(f"   🗑️  {finding.title} — {impact.reason}")
        else:
            print("No vulnerabilities found. Keep hunting!")

        # Return only validated findings — don't let theoretical bugs leak out
        self.findings = validated_findings
        return validated_findings

    def export_report(self, filename: Optional[str] = None):
        """Export findings to JSON"""
        if not filename:
            filename = f"beatrix_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        report = {
            'target': self.target,
            'scan_time': datetime.now().isoformat(),
            'findings_count': len(self.findings),
            'findings': [
                {
                    'title': f.title,
                    'description': f.description,
                    'severity': f.severity.value,
                    'url': f.url,
                    'evidence': f.evidence,
                    'cwe_id': f.cwe_id,
                    'owasp': f.owasp_category,
                }
                for f in self.findings
            ]
        }

        with open(filename, 'w') as fp:
            json.dump(report, fp, indent=2)

        print(f"\n📄 Report saved to: {filename}")
        return filename


async def main():
    parser = argparse.ArgumentParser(
        description='BEATRIX Bug Bounty Hunter - OWASP Top 10:2025',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python bounty_hunter.py https://api.example.com

  # With authentication
  python bounty_hunter.py https://api.example.com -H "Authorization: Bearer token123"

  # Scan multiple URLs
  python bounty_hunter.py https://api.example.com -u /users/123 /orders/456 /profile

  # Analyze JWT tokens
  python bounty_hunter.py https://api.example.com --jwt "eyJhbGc..."
        """
    )

    parser.add_argument('target', help='Target base URL')
    parser.add_argument('-u', '--urls', nargs='*', help='Additional URL paths to scan')
    parser.add_argument('-H', '--header', action='append', help='Add header (format: "Name: Value")')
    parser.add_argument('--jwt', action='append', help='JWT tokens to analyze')
    parser.add_argument('-o', '--output', help='Output report filename')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Parse headers
    headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                name, value = h.split(':', 1)
                headers[name.strip()] = value.strip()

    # Build URL list
    urls = [args.target]
    if args.urls:
        for u in args.urls:
            if u.startswith('/'):
                urls.append(f"{args.target.rstrip('/')}{u}")
            else:
                urls.append(u)

    # Run hunter
    hunter = BountyHunter(
        target=args.target,
        auth_headers=headers,
        verbose=args.verbose
    )

    findings = await hunter.hunt_all(urls=urls, jwt_tokens=args.jwt or [])

    if findings and args.output:
        hunter.export_report(args.output)
    elif findings:
        hunter.export_report()


if __name__ == "__main__":
    asyncio.run(main())
