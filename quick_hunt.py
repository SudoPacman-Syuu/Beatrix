#!/usr/bin/env python3
"""
BEATRIX Quick Hunt Script
⚠️  NOTE: Browser-based scanner (Playwright). Not consolidated into CLI
    due to Playwright dependency. Use directly: python quick_hunt.py <url>

Run this to quickly scan a target for common vulnerabilities

Usage:
    python quick_hunt.py <target_url> [--auth email:password]
"""

import argparse
import asyncio
from datetime import datetime

import httpx
from playwright.async_api import async_playwright


class QuickHunter:
    def __init__(self, target: str, email: str = None, password: str = None):
        self.target = target.rstrip('/')
        self.email = email
        self.password = password
        self.findings = []

    async def run(self):
        print(f"""
╔════════════════════════════════════════════════════════════╗
║              BEATRIX QUICK HUNT                            ║
║              Target: {self.target[:40]:<40} ║
╚════════════════════════════════════════════════════════════╝
        """)

        # Phase 1: HTTP-based checks
        print("\n[Phase 1] HTTP Security Checks...")
        await self.check_security_headers()
        await self.check_cors()
        await self.check_methods()

        # Phase 2: Browser-based checks
        print("\n[Phase 2] Browser-based Checks...")
        await self.browser_scan()

        # Report
        self.report()

    async def check_security_headers(self):
        """Check security headers"""
        print("  Checking security headers...")
        async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
            try:
                resp = await client.get(self.target)
                h = resp.headers

                missing = []
                if not h.get('x-frame-options'):
                    missing.append('X-Frame-Options')
                if not h.get('content-security-policy'):
                    missing.append('Content-Security-Policy')
                if not h.get('strict-transport-security'):
                    missing.append('Strict-Transport-Security')
                if not h.get('x-content-type-options'):
                    missing.append('X-Content-Type-Options')

                if missing:
                    self.findings.append({
                        'type': 'Missing Security Headers',
                        'severity': 'Low',
                        'details': f"Missing: {', '.join(missing)}"
                    })
                    print(f"    ⚠️ Missing: {', '.join(missing)}")
                else:
                    print("    ✓ All security headers present")

            except Exception as e:
                print(f"    ✗ Error: {e}")

    async def check_cors(self):
        """Check CORS configuration"""
        print("  Checking CORS...")
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            try:
                resp = await client.options(
                    self.target,
                    headers={'Origin': 'https://evil.com'}
                )

                acao = resp.headers.get('access-control-allow-origin')
                if acao == '*':
                    self.findings.append({
                        'type': 'Permissive CORS',
                        'severity': 'Medium',
                        'details': 'Access-Control-Allow-Origin: * allows any origin'
                    })
                    print("    🔴 CORS allows any origin!")
                elif acao == 'https://evil.com':
                    self.findings.append({
                        'type': 'CORS Origin Reflection',
                        'severity': 'High',
                        'details': 'Origin is reflected in ACAO header'
                    })
                    print("    🔴 CORS reflects arbitrary origins!")
                else:
                    print("    ✓ CORS appears properly configured")

            except Exception as e:
                print(f"    - Could not test CORS: {e}")

    async def check_methods(self):
        """Check allowed HTTP methods"""
        print("  Checking HTTP methods...")
        dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE']
        allowed = []

        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            for method in dangerous_methods:
                try:
                    resp = await client.request(method, self.target)
                    if resp.status_code not in [405, 501]:
                        allowed.append(method)
                except Exception:
                    pass

        if allowed:
            print(f"    ⚠️ Potentially dangerous methods allowed: {allowed}")
        else:
            print("    ✓ No dangerous HTTP methods exposed")

    async def browser_scan(self):
        """Browser-based vulnerability scanning"""
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                )
                page = await context.new_page()

                # Navigate and handle cookie consent
                print("  Loading target...")
                await page.goto(self.target, wait_until='networkidle')
                await asyncio.sleep(2)

                # Try to dismiss cookie consent
                for selector in ['#onetrust-accept-btn-handler', '.cookie-accept', '[data-action="accept"]']:
                    try:
                        btn = page.locator(selector)
                        if await btn.is_visible(timeout=1000):
                            await btn.click()
                            await asyncio.sleep(1)
                            break
                    except Exception:
                        continue

                # Login if credentials provided
                if self.email and self.password:
                    print("  Attempting login...")
                    # Try common login patterns
                    try:
                        await page.fill('input[type="email"], input[name="email"], #email, #username', self.email)
                        await page.fill('input[type="password"], input[name="password"], #password', self.password)
                        await page.click('button[type="submit"], input[type="submit"]')
                        await asyncio.sleep(3)
                        print(f"    Current URL: {page.url}")
                    except Exception as e:
                        print(f"    Could not login: {e}")

                # Check for exposed data in page
                print("  Checking for exposed sensitive data...")
                page_content = await page.content()

                sensitive_patterns = [
                    ('API Key', r'api[_-]?key["\']?\s*[:=]\s*["\']?[\w-]{20,}'),
                    ('AWS Key', r'AKIA[0-9A-Z]{16}'),
                    ('Private Key', r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),
                    ('JWT', r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
                ]

                import re
                for name, pattern in sensitive_patterns:
                    if re.search(pattern, page_content, re.I):
                        self.findings.append({
                            'type': f'Exposed {name}',
                            'severity': 'High',
                            'details': f'{name} found in page source'
                        })
                        print(f"    🔴 Found exposed {name}!")

                # Check forms for CSRF
                print("  Checking forms for CSRF tokens...")
                forms = await page.query_selector_all('form')
                for form in forms:
                    action = await form.get_attribute('action')
                    method = await form.get_attribute('method') or 'get'
                    if method.lower() == 'post':
                        form_html = await form.inner_html()
                        if 'csrf' not in form_html.lower() and '_token' not in form_html.lower():
                            print(f"    ⚠️ POST form without CSRF token: {action}")

                await browser.close()

        except Exception as e:
            print(f"  Browser scan error: {e}")

    def report(self):
        """Print findings report"""
        print(f"""
{'=' * 60}
SCAN COMPLETE - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'=' * 60}
        """)

        if self.findings:
            print(f"Found {len(self.findings)} potential issues:\n")
            for i, f in enumerate(self.findings, 1):
                print(f"  [{f['severity'].upper()}] {f['type']}")
                print(f"    {f['details']}\n")
        else:
            print("No significant vulnerabilities found.")
            print("Consider manual testing for business logic flaws.")


async def main():
    parser = argparse.ArgumentParser(description='BEATRIX Quick Hunt')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('--auth', help='Authentication credentials (email:password)')
    args = parser.parse_args()

    email, password = None, None
    if args.auth:
        parts = args.auth.split(':', 1)
        if len(parts) == 2:
            email, password = parts

    hunter = QuickHunter(args.target, email, password)
    await hunter.run()


if __name__ == '__main__':
    asyncio.run(main())
