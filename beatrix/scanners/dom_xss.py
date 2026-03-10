"""
BEATRIX DOM XSS Scanner
========================

Detects DOM-based Cross-Site Scripting (XSS) using Playwright browser automation.

DOM XSS differs from reflected/stored XSS because the payload never reaches
the server — it's processed entirely by client-side JavaScript.  Sources
include location.hash, location.search, document.referrer, postMessage, etc.

This scanner:
1. Opens each URL in a headless Chromium browser
2. Injects XSS payloads into URL parameters and fragment
3. Monitors for JavaScript alert() / prompt() / confirm() dialogs
4. Monitors for DOM mutations that inject attacker-controlled HTML
5. Checks common DOM XSS sources → sinks patterns

Requires: playwright (pip install playwright && playwright install chromium)

OWASP: A03:2021 — Injection
CWE: CWE-79 — Improper Neutralization of Input During Web Page Generation
"""

import asyncio
import logging
import re
from typing import AsyncIterator, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext

logger = logging.getLogger("beatrix.scanners.dom_xss")

try:
    from playwright.async_api import async_playwright, Dialog, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class DOMXSSScanner(BaseScanner):
    """
    DOM-based XSS scanner using headless browser automation.

    Tests for client-side XSS by injecting payloads into URL parameters
    and the URL fragment, then monitoring for JavaScript execution.
    """

    name = "dom_xss"
    description = "DOM-based XSS scanner (browser-based)"
    version = "1.0.0"

    checks = ["dom_xss_param", "dom_xss_fragment", "dom_xss_source_sink"]

    owasp_category = "A03:2021"
    mitre_technique = "T1059.007"  # JavaScript execution

    # Payloads optimized for DOM XSS (processed by JS, not HTML parser)
    DOM_XSS_PAYLOADS = [
        # Direct injection payloads
        "<img src=x onerror=alert('BXDOM')>",
        "<svg onload=alert('BXDOM')>",
        "javascript:alert('BXDOM')",
        "'-alert('BXDOM')-'",
        '"><script>alert("BXDOM")</script>',
        # Template injection
        "{{constructor.constructor('alert(\"BXDOM\")')()}}",
        "${alert('BXDOM')}",
        # Event handler injection
        '" onfocus="alert(\'BXDOM\')" autofocus="',
        "' onfocus='alert(`BXDOM`)' autofocus='",
    ]

    # Fragment-specific payloads (for location.hash sinks)
    FRAGMENT_PAYLOADS = [
        "<img src=x onerror=alert('BXDOM')>",
        "<svg onload=alert('BXDOM')>",
        "javascript:alert('BXDOM')",
        "'-alert('BXDOM')-'",
        # Raw JS payloads for eval()/Function()/setTimeout() sinks
        "alert('BXDOM')",
        "1;alert('BXDOM')",
        "BXDOM';alert('BXDOM');//",
    ]

    # Payloads for JS-execution sinks (eval, Function, setTimeout)
    JS_EXEC_PAYLOADS = [
        "alert('BXDOM')",
        "1;alert('BXDOM')",
    ]

    # Sentinel value used to detect dialog() calls
    CANARY = "BXDOM"

    # Max time to wait for page + dialog after navigation (ms)
    PAGE_TIMEOUT = 8000
    DIALOG_WAIT = 1500  # extra ms to wait for delayed JS execution

    def __init__(self, config=None):
        super().__init__(config)
        self._browser = None
        self._playwright = None
        self._browser_context = None

    async def _ensure_browser(self) -> bool:
        """Launch browser if not already running. Returns False if unavailable."""
        if not PLAYWRIGHT_AVAILABLE:
            self.log("Playwright not installed — DOM XSS scanning disabled")
            return False

        if self._browser is not None:
            return True

        try:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--disable-web-security",  # Allow cross-origin for testing
                ],
            )
            self._browser_context = await self._browser.new_context(
                ignore_https_errors=True,
                java_script_enabled=True,
            )
            return True
        except Exception as e:
            self.log(f"Failed to launch browser: {e}")
            return False

    async def _cleanup_browser(self):
        """Close browser resources."""
        try:
            if self._browser_context:
                await self._browser_context.close()
                self._browser_context = None
            if self._browser:
                await self._browser.close()
                self._browser = None
            if self._playwright:
                await self._playwright.stop()
                self._playwright = None
        except Exception:
            pass

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Scan URL for DOM-based XSS vulnerabilities."""
        if not await self._ensure_browser():
            return

        parsed = urlparse(context.url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # Test parameter-based DOM XSS
        for param in params:
            for payload in self.DOM_XSS_PAYLOADS:
                finding = await self._test_dom_xss(
                    context.url, param, payload, inject_fragment=False
                )
                if finding:
                    yield finding
                    break  # One finding per param is enough

        # Test fragment-based DOM XSS (location.hash sinks)
        for payload in self.FRAGMENT_PAYLOADS:
            finding = await self._test_dom_xss(
                context.url, None, payload, inject_fragment=True
            )
            if finding:
                yield finding
                break

        # Test cookie-based DOM XSS (document.cookie sources)
        finding = await self._test_cookie_dom_xss(context.url)
        if finding:
            yield finding

        # Test storage-based DOM XSS (localStorage/sessionStorage sources)
        finding = await self._test_storage_dom_xss(context.url)
        if finding:
            yield finding

        # Test referrer-based DOM XSS (document.referrer sources)
        finding = await self._test_referrer_dom_xss(context.url)
        if finding:
            yield finding

        # Passive: check for dangerous source→sink patterns in page JS
        async for finding in self._check_source_sink_patterns(context):
            yield finding

    async def _test_dom_xss(
        self,
        base_url: str,
        param: Optional[str],
        payload: str,
        inject_fragment: bool = False,
    ) -> Optional[Finding]:
        """
        Test a single DOM XSS payload by navigating the browser and
        checking for alert() execution.
        """
        if not self._browser_context:
            return None

        # Build test URL
        if inject_fragment:
            test_url = f"{base_url}#{payload}"
        elif param:
            parsed = urlparse(base_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment,
            ))
        else:
            return None

        page = await self._browser_context.new_page()
        xss_triggered = False
        dialog_message = ""

        async def _on_dialog(dialog: Dialog):
            nonlocal xss_triggered, dialog_message
            if self.CANARY in dialog.message:
                xss_triggered = True
                dialog_message = dialog.message
            await dialog.dismiss()

        page.on("dialog", _on_dialog)

        try:
            await page.goto(test_url, wait_until="domcontentloaded", timeout=self.PAGE_TIMEOUT)
            # Wait for delayed JS execution
            await asyncio.sleep(self.DIALOG_WAIT / 1000)

            if xss_triggered:
                injection_point = f"fragment (#)" if inject_fragment else f"parameter '{param}'"
                return self.create_finding(
                    title=f"DOM XSS in {injection_point}",
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    url=test_url,
                    description=(
                        f"DOM-based Cross-Site Scripting (XSS) confirmed via browser execution.\n\n"
                        f"Injection point: {injection_point}\n"
                        f"Payload: {payload}\n"
                        f"Dialog content: {dialog_message}\n\n"
                        f"DOM XSS is processed entirely by client-side JavaScript — the payload "
                        f"never reaches the server, making it invisible to server-side WAFs."
                    ),
                    evidence=f"JavaScript alert() triggered with content: {dialog_message}",
                    request=f"GET {test_url}",
                    response="(browser-rendered — no raw HTTP response)",
                    remediation=(
                        "1. Sanitize all client-side inputs before inserting into the DOM\n"
                        "2. Use textContent instead of innerHTML for untrusted data\n"
                        "3. Use DOMPurify to sanitize HTML from URL parameters\n"
                        "4. Avoid using eval(), document.write(), innerHTML with URL-derived data\n"
                        "5. Implement Content-Security-Policy to block inline scripts"
                    ),
                    references=[
                        "https://portswigger.net/web-security/cross-site-scripting/dom-based",
                        "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                    ],
                    parameter=param or "#fragment",
                    payload=payload,
                    cwe_id="CWE-79",
                    poc_curl=f"# Open in browser: {test_url}",
                )
        except Exception as e:
            self.log(f"DOM XSS test error: {e}")
        finally:
            await page.close()

        return None

    async def _test_cookie_dom_xss(self, url: str) -> Optional[Finding]:
        """
        Test DOM XSS via document.cookie source.

        Some pages read from specific cookies and pass them to sinks like
        eval(), innerHTML, document.write(). We set cookies with payloads
        before navigating.
        """
        if not self._browser_context:
            return None

        parsed = urlparse(url)
        domain = parsed.hostname
        # Common cookie names used in DOM XSS test pages + generic names
        cookie_names = [
            "ThisCookieIsTotallyRandomAndCantPossiblyBeSet",  # FR-specific
            "xss", "test", "payload", "data", "user", "token", "name",
        ]

        for payload in self.DOM_XSS_PAYLOADS + self.JS_EXEC_PAYLOADS:
            page = await self._browser_context.new_page()
            xss_triggered = False
            dialog_message = ""

            async def _on_dialog(dialog: Dialog):
                nonlocal xss_triggered, dialog_message
                if self.CANARY in dialog.message:
                    xss_triggered = True
                    dialog_message = dialog.message
                await dialog.dismiss()

            page.on("dialog", _on_dialog)

            try:
                # Set cookies before navigation
                cookies = [
                    {
                        "name": name,
                        "value": payload,
                        "domain": domain,
                        "path": "/",
                    }
                    for name in cookie_names
                ]
                await self._browser_context.add_cookies(cookies)
                await page.goto(url, wait_until="domcontentloaded", timeout=self.PAGE_TIMEOUT)
                await asyncio.sleep(self.DIALOG_WAIT / 1000)

                if xss_triggered:
                    return self.create_finding(
                        title="DOM XSS via document.cookie",
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        url=url,
                        description=(
                            f"DOM-based XSS confirmed via cookie injection.\n\n"
                            f"Payload: {payload}\n"
                            f"Dialog content: {dialog_message}\n\n"
                            f"The page reads from document.cookie and passes the value to "
                            f"a dangerous sink (e.g., eval, innerHTML, document.write)."
                        ),
                        evidence=f"JavaScript alert() triggered with content: {dialog_message}",
                        request=f"GET {url} (with cookie payload)",
                        response="(browser-rendered — no raw HTTP response)",
                        remediation=(
                            "1. Never pass cookie values directly to eval(), innerHTML, or document.write()\n"
                            "2. Sanitize cookie data before using it in the DOM\n"
                            "3. Use HttpOnly cookies where possible to prevent JS access"
                        ),
                        parameter="cookie",
                        payload=payload,
                        cwe_id="CWE-79",
                    )
            except Exception as e:
                self.log(f"Cookie DOM XSS test error: {e}")
            finally:
                await page.close()
                # Clear cookies to avoid cross-contamination
                await self._browser_context.clear_cookies()

        return None

    async def _test_storage_dom_xss(self, url: str) -> Optional[Finding]:
        """
        Test DOM XSS via localStorage/sessionStorage sources.

        Some pages read from storage and pass values to sinks.
        We pre-populate storage with payloads before page JS executes.
        """
        if not self._browser_context:
            return None

        storage_keys = [
            "xss", "test", "payload", "data", "user", "name", "token",
            "message", "value", "input", "key",
        ]

        for payload in self.DOM_XSS_PAYLOADS + self.JS_EXEC_PAYLOADS:
            page = await self._browser_context.new_page()
            xss_triggered = False
            dialog_message = ""

            async def _on_dialog(dialog: Dialog):
                nonlocal xss_triggered, dialog_message
                if self.CANARY in dialog.message:
                    xss_triggered = True
                    dialog_message = dialog.message
                await dialog.dismiss()

            page.on("dialog", _on_dialog)

            try:
                # Navigate first to set the origin for storage, then inject
                await page.goto(url, wait_until="domcontentloaded", timeout=self.PAGE_TIMEOUT)

                # Populate localStorage and sessionStorage with payloads
                storage_js = ""
                for key in storage_keys:
                    escaped = payload.replace("\\", "\\\\").replace("'", "\\'")
                    storage_js += f"try {{ localStorage.setItem('{key}', '{escaped}'); sessionStorage.setItem('{key}', '{escaped}'); }} catch(e) {{}}\n"
                await page.evaluate(storage_js)

                # Re-navigate to let page JS read the stored payloads
                await page.goto(url, wait_until="domcontentloaded", timeout=self.PAGE_TIMEOUT)
                await asyncio.sleep(self.DIALOG_WAIT / 1000)

                if xss_triggered:
                    return self.create_finding(
                        title="DOM XSS via localStorage/sessionStorage",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CERTAIN,
                        url=url,
                        description=(
                            f"DOM-based XSS confirmed via web storage injection.\n\n"
                            f"Payload: {payload}\n"
                            f"Dialog content: {dialog_message}\n\n"
                            f"The page reads from localStorage or sessionStorage and passes "
                            f"the value to a dangerous sink."
                        ),
                        evidence=f"JavaScript alert() triggered with content: {dialog_message}",
                        request=f"GET {url} (with storage payload)",
                        response="(browser-rendered — no raw HTTP response)",
                        remediation=(
                            "1. Never pass storage values directly to eval(), innerHTML, or document.write()\n"
                            "2. Sanitize storage data before DOM insertion\n"
                            "3. Validate storage contents against expected formats"
                        ),
                        parameter="localStorage/sessionStorage",
                        payload=payload,
                        cwe_id="CWE-79",
                    )
            except Exception as e:
                self.log(f"Storage DOM XSS test error: {e}")
            finally:
                await page.close()

        return None

    async def _test_referrer_dom_xss(self, url: str) -> Optional[Finding]:
        """
        Test DOM XSS via document.referrer source.

        Navigate from an intermediate page to set document.referrer to a payload.
        """
        if not self._browser_context:
            return None

        for payload in self.DOM_XSS_PAYLOADS[:3] + self.JS_EXEC_PAYLOADS:
            page = await self._browser_context.new_page()
            xss_triggered = False
            dialog_message = ""

            async def _on_dialog(dialog: Dialog):
                nonlocal xss_triggered, dialog_message
                if self.CANARY in dialog.message:
                    xss_triggered = True
                    dialog_message = dialog.message
                await dialog.dismiss()

            page.on("dialog", _on_dialog)

            try:
                # Use page.goto with referer header to simulate document.referrer
                await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=self.PAGE_TIMEOUT,
                    referer=payload,
                )
                await asyncio.sleep(self.DIALOG_WAIT / 1000)

                if xss_triggered:
                    return self.create_finding(
                        title="DOM XSS via document.referrer",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CERTAIN,
                        url=url,
                        description=(
                            f"DOM-based XSS confirmed via referrer injection.\n\n"
                            f"Payload in referrer: {payload}\n"
                            f"Dialog content: {dialog_message}\n\n"
                            f"The page reads document.referrer and passes it to a dangerous sink."
                        ),
                        evidence=f"JavaScript alert() triggered with content: {dialog_message}",
                        request=f"GET {url} (Referer: {payload})",
                        response="(browser-rendered — no raw HTTP response)",
                        remediation=(
                            "1. Never pass document.referrer directly to eval(), innerHTML, or document.write()\n"
                            "2. Sanitize referrer data before DOM insertion\n"
                            "3. Use referrer-policy headers to control referrer exposure"
                        ),
                        parameter="referrer",
                        payload=payload,
                        cwe_id="CWE-79",
                    )
            except Exception as e:
                self.log(f"Referrer DOM XSS test error: {e}")
            finally:
                await page.close()

        return None

    async def _check_source_sink_patterns(self, context: ScanContext) -> AsyncIterator[Finding]:
        """
        Passive check: look for dangerous JavaScript source→sink patterns
        that indicate potential DOM XSS even without payload execution.
        """
        if not self._browser_context:
            return

        page = await self._browser_context.new_page()
        try:
            await page.goto(context.url, wait_until="domcontentloaded", timeout=self.PAGE_TIMEOUT)

            # Get all inline script content
            scripts = await page.evaluate("""() => {
                const scripts = document.querySelectorAll('script:not([src])');
                return Array.from(scripts).map(s => s.textContent).join('\\n');
            }""")

            if not scripts:
                return

            # Check for source→sink patterns
            _SOURCES = [
                r"location\.(hash|search|href|pathname)",
                r"document\.(URL|documentURI|referrer|cookie)",
                r"window\.(name|location)",
                r"location\.hash\.substr",
                r"decodeURIComponent\s*\(",
                r"\.getParameter\s*\(",
            ]
            _SINKS = [
                r"\.innerHTML\s*=",
                r"\.outerHTML\s*=",
                r"document\.write\s*\(",
                r"document\.writeln\s*\(",
                r"eval\s*\(",
                r"setTimeout\s*\(",
                r"setInterval\s*\(",
                r"Function\s*\(",
                r"\.insertAdjacentHTML\s*\(",
                r"\.href\s*=",
                r"location\s*=",
                r"location\.replace\s*\(",
                r"location\.assign\s*\(",
                r"jQuery\s*\(",
                r"\$\s*\(",
            ]

            found_sources = []
            found_sinks = []
            for pattern in _SOURCES:
                if re.search(pattern, scripts):
                    found_sources.append(pattern)
            for pattern in _SINKS:
                if re.search(pattern, scripts):
                    found_sinks.append(pattern)

            if found_sources and found_sinks:
                yield self.create_finding(
                    title="Potential DOM XSS: Dangerous source→sink pattern",
                    severity=Severity.LOW,
                    confidence=Confidence.TENTATIVE,
                    url=context.url,
                    description=(
                        f"Client-side JavaScript reads from attacker-controllable sources "
                        f"and writes to dangerous sinks. This pattern may indicate DOM XSS.\n\n"
                        f"Sources found: {', '.join(found_sources)}\n"
                        f"Sinks found: {', '.join(found_sinks)}\n\n"
                        f"Manual verification required — automated payload testing did not "
                        f"trigger execution, but the code pattern is risky."
                    ),
                    evidence=f"Sources: {found_sources}\nSinks: {found_sinks}",
                    remediation=(
                        "Review the identified source→sink data flows.\n"
                        "Sanitize data from URL parameters, hash, and referrer before "
                        "passing to innerHTML, eval(), document.write(), or other sinks."
                    ),
                )
        except Exception as e:
            self.log(f"Source-sink analysis error: {e}")
        finally:
            await page.close()

    async def __aexit__(self, *args):
        """Clean up browser on scanner exit."""
        await self._cleanup_browser()
        if hasattr(super(), '__aexit__'):
            await super().__aexit__(*args)
