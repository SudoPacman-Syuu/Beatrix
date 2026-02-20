#!/usr/bin/env python3
"""
BEATRIX Browser Scanner using Playwright

Real browser automation for WAF bypass and authenticated testing.
This allows us to:
1. Bypass WAF that blocks automated tools
2. Test client-side vulnerabilities (DOM XSS, etc.)
3. Capture authenticated sessions
4. Execute JavaScript for dynamic testing
"""

import asyncio
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from playwright.async_api import Browser, BrowserContext, Page, async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    print("⚠️  Playwright not installed. Run: pip install playwright && playwright install chromium")


@dataclass
class BrowserFinding:
    """Finding discovered via browser automation"""
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    url: str
    evidence: Dict[str, Any]
    reproduction_steps: List[str]


@dataclass
class PageState:
    """Captured state of a page"""
    url: str
    title: str
    html: str
    cookies: List[Dict]
    local_storage: Dict[str, str]
    session_storage: Dict[str, str]
    console_logs: List[str]
    network_requests: List[Dict]


class BrowserScanner:
    """
    Real browser-based security scanner using Playwright.

    This bypasses WAFs and allows for client-side testing.
    """

    def __init__(
        self,
        headless: bool = True,
        slow_mo: int = 0,
        timeout: int = 30000
    ):
        self.headless = headless
        self.slow_mo = slow_mo
        self.timeout = timeout
        self._playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.findings: List[BrowserFinding] = []

    async def __aenter__(self):
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError("Playwright not available. Install with: pip install playwright && playwright install chromium")

        self._playwright = await async_playwright().start()
        self.browser = await self._playwright.chromium.launch(
            headless=self.headless,
            slow_mo=self.slow_mo
        )
        return self

    async def __aexit__(self, *args):
        if self.browser:
            await self.browser.close()
        if self._playwright:
            await self._playwright.stop()

    async def create_context(
        self,
        cookies: Optional[List[Dict]] = None,
        headers: Optional[Dict[str, str]] = None,
        storage_state: Optional[str] = None
    ) -> BrowserContext:
        """Create a new browser context with optional auth state"""
        context_options = {
            "viewport": {"width": 1920, "height": 1080},
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }

        if storage_state and Path(storage_state).exists():
            context_options["storage_state"] = storage_state

        if headers:
            context_options["extra_http_headers"] = headers

        self.context = await self.browser.new_context(**context_options)

        if cookies:
            await self.context.add_cookies(cookies)

        return self.context

    async def login(
        self,
        login_url: str,
        email_selector: str,
        password_selector: str,
        submit_selector: str,
        email: str,
        password: str,
        success_url_pattern: Optional[str] = None,
        save_state_path: Optional[str] = None
    ) -> bool:
        """
        Perform login and optionally save authentication state.

        Returns True if login was successful.
        """
        if not self.context:
            await self.create_context()

        page = await self.context.new_page()

        try:
            print(f"🔐 Navigating to login page: {login_url}")
            await page.goto(login_url, wait_until="networkidle")
            await asyncio.sleep(1)

            # Fill credentials
            print("📝 Filling credentials...")
            await page.fill(email_selector, email)
            await asyncio.sleep(0.3)
            await page.fill(password_selector, password)
            await asyncio.sleep(0.3)

            # Submit
            print("🚀 Submitting login form...")
            await page.click(submit_selector)

            # Wait for navigation
            try:
                await page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass

            await asyncio.sleep(2)

            # Check success
            current_url = page.url
            print(f"📍 Current URL: {current_url}")

            success = True
            if success_url_pattern:
                success = bool(re.search(success_url_pattern, current_url))
            else:
                # Check we're not still on login page
                success = login_url not in current_url

            if success:
                print("✅ Login successful!")

                # Save state if requested
                if save_state_path:
                    await self.context.storage_state(path=save_state_path)
                    print(f"💾 Saved auth state to: {save_state_path}")

            else:
                print("❌ Login failed - still on login page or pattern didn't match")

            return success

        finally:
            await page.close()

    async def capture_page_state(self, page: Page) -> PageState:
        """Capture the full state of a page"""
        console_logs = []

        # Capture console logs
        page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))

        # Get storage
        local_storage = await page.evaluate("() => { return JSON.parse(JSON.stringify(localStorage)); }")
        session_storage = await page.evaluate("() => { return JSON.parse(JSON.stringify(sessionStorage)); }")

        # Get cookies
        cookies = await self.context.cookies() if self.context else []

        return PageState(
            url=page.url,
            title=await page.title(),
            html=await page.content(),
            cookies=cookies,
            local_storage=local_storage or {},
            session_storage=session_storage or {},
            console_logs=console_logs,
            network_requests=[]  # Would need to set up route interception
        )

    async def test_dom_xss(self, url: str, payloads: Optional[List[str]] = None) -> List[BrowserFinding]:
        """Test for DOM-based XSS vulnerabilities"""
        findings = []

        if not payloads:
            payloads = [
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "'-alert('XSS')-'",
                "\"><script>alert('XSS')</script>",
                "<svg onload=alert('XSS')>",
                "{{constructor.constructor('alert(1)')()}}",  # Angular
                "${alert('XSS')}",  # Template literal
            ]

        page = await self.context.new_page()

        try:
            # Set up dialog handler to detect XSS
            xss_triggered = False
            xss_payload = ""

            async def handle_dialog(dialog):
                nonlocal xss_triggered, xss_payload
                xss_triggered = True
                xss_payload = dialog.message
                await dialog.dismiss()

            page.on("dialog", handle_dialog)

            # Parse URL for injection points
            from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            for param in params.keys():
                for payload in payloads:
                    xss_triggered = False

                    # Inject payload
                    test_params = params.copy()
                    test_params[param] = [payload]

                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))

                    try:
                        await page.goto(test_url, wait_until="domcontentloaded", timeout=5000)
                        await asyncio.sleep(1)  # Wait for any delayed execution

                        if xss_triggered:
                            findings.append(BrowserFinding(
                                title=f"DOM XSS in parameter '{param}'",
                                description=f"""
DOM-based Cross-Site Scripting (XSS) vulnerability found.

**Vulnerable Parameter:** {param}
**Payload:** {payload}
**Alert Content:** {xss_payload}

This allows arbitrary JavaScript execution in the context of the victim's session.

**Impact:**
- Session hijacking
- Credential theft
- Defacement
- Malware distribution
                                """.strip(),
                                severity="high",
                                url=test_url,
                                evidence={
                                    "parameter": param,
                                    "payload": payload,
                                    "alert_content": xss_payload,
                                },
                                reproduction_steps=[
                                    f"1. Navigate to: {test_url}",
                                    "2. Observe JavaScript alert popup",
                                    "3. This confirms XSS execution"
                                ]
                            ))
                            break  # Found XSS for this param, move to next

                    except Exception:
                        continue

        finally:
            await page.close()

        return findings

    async def test_open_redirect(self, url: str) -> List[BrowserFinding]:
        """Test for open redirect vulnerabilities"""
        findings = []

        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "https://evil.com%00",
            "https://evil.com%0d%0a",
            "//google.com%2f%2e%2e",
            "///evil.com",
            "\\/evil.com",
            "https:evil.com",
        ]

        page = await self.context.new_page()

        try:
            from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            # Common redirect parameters
            redirect_params = ['redirect', 'url', 'next', 'return', 'returnUrl',
                             'redirect_uri', 'return_to', 'goto', 'target', 'dest']

            test_params = list(params.keys()) + redirect_params

            for param in test_params:
                for payload in redirect_payloads:
                    test_params_dict = params.copy()
                    test_params_dict[param] = [payload]

                    new_query = urlencode(test_params_dict, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))

                    try:
                        await page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                        await asyncio.sleep(1)

                        final_url = page.url

                        # Check if we were redirected to evil.com
                        if "evil.com" in final_url:
                            findings.append(BrowserFinding(
                                title=f"Open Redirect via '{param}' parameter",
                                description=f"""
Open Redirect vulnerability allowing arbitrary URL redirection.

**Parameter:** {param}
**Payload:** {payload}
**Final URL:** {final_url}

**Impact:**
- Phishing attacks using trusted domain
- OAuth token theft
- Credential harvesting
                                """.strip(),
                                severity="medium",
                                url=test_url,
                                evidence={
                                    "parameter": param,
                                    "payload": payload,
                                    "final_url": final_url,
                                },
                                reproduction_steps=[
                                    f"1. Navigate to: {test_url}",
                                    f"2. Observe redirect to: {final_url}",
                                ]
                            ))
                            break  # Found redirect for this param

                    except Exception:
                        continue

        finally:
            await page.close()

        return findings

    async def test_clickjacking(self, url: str) -> List[BrowserFinding]:
        """Test if page is vulnerable to clickjacking"""
        findings = []

        page = await self.context.new_page()

        try:
            response = await page.goto(url, wait_until="domcontentloaded")

            if response:
                headers = response.headers

                # Check X-Frame-Options
                x_frame = headers.get('x-frame-options', '').lower()

                # Check CSP frame-ancestors
                csp = headers.get('content-security-policy', '')
                has_frame_ancestors = 'frame-ancestors' in csp.lower()

                if not x_frame and not has_frame_ancestors:
                    findings.append(BrowserFinding(
                        title="Missing Clickjacking Protection",
                        description=f"""
The page is missing clickjacking protection headers.

**URL:** {url}
**X-Frame-Options:** Not set
**CSP frame-ancestors:** Not set

This allows the page to be embedded in an iframe on a malicious site,
enabling clickjacking attacks.

**Impact:**
- UI redress attacks
- Trick users into clicking hidden elements
- Unauthorized actions on behalf of users
                        """.strip(),
                        severity="low",
                        url=url,
                        evidence={
                            "x_frame_options": x_frame or "Not set",
                            "csp": csp or "Not set",
                        },
                        reproduction_steps=[
                            f"1. Create HTML: <iframe src='{url}'></iframe>",
                            "2. The page loads in the iframe without restriction",
                        ]
                    ))

        finally:
            await page.close()

        return findings

    async def scan_authenticated(
        self,
        base_url: str,
        endpoints: List[str],
        tests: Optional[List[str]] = None
    ) -> List[BrowserFinding]:
        """
        Run authenticated scans against endpoints.

        Args:
            base_url: Base URL of the target
            endpoints: List of endpoints to test
            tests: List of test types ('xss', 'redirect', 'clickjacking')
        """
        findings = []

        if not tests:
            tests = ['xss', 'redirect', 'clickjacking']

        for endpoint in endpoints:
            url = base_url.rstrip('/') + '/' + endpoint.lstrip('/')
            print(f"🔍 Scanning: {url}")

            if 'xss' in tests:
                findings.extend(await self.test_dom_xss(url))

            if 'redirect' in tests:
                findings.extend(await self.test_open_redirect(url))

            if 'clickjacking' in tests:
                findings.extend(await self.test_clickjacking(url))

        self.findings.extend(findings)
        return findings

    async def extract_api_calls(self, url: str, actions: Optional[List[Dict]] = None) -> List[Dict]:
        """
        Navigate to a page and capture all API calls made.

        Optionally perform actions (clicks, form fills) to trigger more calls.
        """
        api_calls = []

        page = await self.context.new_page()

        # Intercept all requests
        async def capture_request(request):
            if '/api/' in request.url or 'graphql' in request.url.lower():
                api_calls.append({
                    'method': request.method,
                    'url': request.url,
                    'headers': dict(request.headers),
                    'post_data': request.post_data,
                })

        page.on("request", capture_request)

        try:
            await page.goto(url, wait_until="networkidle")
            await asyncio.sleep(2)

            # Perform actions if specified
            if actions:
                for action in actions:
                    action_type = action.get('type')
                    selector = action.get('selector')
                    value = action.get('value')

                    if action_type == 'click' and selector:
                        await page.click(selector)
                    elif action_type == 'fill' and selector and value:
                        await page.fill(selector, value)
                    elif action_type == 'wait':
                        await asyncio.sleep(action.get('duration', 1))

                    await asyncio.sleep(0.5)

            # Scroll to trigger lazy loading
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(1)

        finally:
            await page.close()

        return api_calls


async def quick_browser_scan(
    url: str,
    email: Optional[str] = None,
    password: Optional[str] = None,
    login_url: Optional[str] = None,
    headless: bool = True
) -> List[BrowserFinding]:
    """Quick browser-based scan with optional authentication"""

    async with BrowserScanner(headless=headless) as scanner:
        await scanner.create_context()

        # Login if credentials provided
        if email and password and login_url:
            logged_in = await scanner.login(
                login_url=login_url,
                email_selector="input[type='email'], input[name='email'], #email",
                password_selector="input[type='password'], input[name='password'], #password",
                submit_selector="button[type='submit'], input[type='submit'], .login-button",
                email=email,
                password=password
            )
            if not logged_in:
                print("⚠️  Login failed, continuing without authentication")

        # Run scans
        findings = await scanner.scan_authenticated(
            base_url=url,
            endpoints=["/", "/account", "/profile", "/settings", "/dashboard"],
            tests=['xss', 'redirect', 'clickjacking']
        )

        return findings


# CLI
if __name__ == "__main__":
    import sys

    async def main():
        if len(sys.argv) < 2:
            print("Usage: python browser_scanner.py <url> [--visible]")
            print("Example: python browser_scanner.py https://example.com --visible")
            return

        url = sys.argv[1]
        headless = "--visible" not in sys.argv

        print(f"""
╔════════════════════════════════════════════════════════════════╗
║           BEATRIX Browser Scanner (Playwright)                 ║
║           "WAF? Never heard of her."                           ║
╚════════════════════════════════════════════════════════════════╝

Target: {url}
Mode: {'Headless' if headless else 'Visible Browser'}
        """)

        findings = await quick_browser_scan(url, headless=headless)

        if findings:
            print(f"\n🎯 Found {len(findings)} issues:\n")
            for f in findings:
                print(f"  [{f.severity.upper()}] {f.title}")
                print(f"  URL: {f.url}")
                print()
        else:
            print("\n✅ No client-side vulnerabilities detected")

    asyncio.run(main())
