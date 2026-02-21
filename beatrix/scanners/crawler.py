"""
BEATRIX Target Crawler

Crawls the target to build a proper attack surface before scanners run.
This is the FOUNDATION — without crawling, scanners only see a bare URL
with zero parameters, zero endpoints, zero forms. Useless.

What this does:
1. Fetch the target (following redirects, with proper User-Agent)
2. Extract all links from HTML
3. Extract form actions and parameters
4. Extract script src attributes (JS bundles)
5. Follow same-origin links (depth-limited)
6. Build a map of: URLs, parameters, forms, JS files, technologies
7. Feed everything into ScanContext for downstream scanners
"""

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

# Browser-like User-Agent — critical for SPAs that serve different content to bots
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


@dataclass
class CrawlResult:
    """Everything discovered during crawling"""
    # The final resolved URL (after redirects)
    resolved_url: str = ""
    base_url: str = ""

    # Discovered URLs with their parameters
    urls: Set[str] = field(default_factory=set)
    urls_with_params: Set[str] = field(default_factory=set)  # URLs that have query params

    # Parameters discovered (param_name -> set of URLs where it appears)
    parameters: Dict[str, Set[str]] = field(default_factory=dict)

    # Forms discovered
    forms: List[Dict] = field(default_factory=list)

    # JavaScript files
    js_files: Set[str] = field(default_factory=set)

    # Technology fingerprints
    technologies: List[str] = field(default_factory=list)

    # Response data from the initial fetch
    initial_response_headers: Dict[str, str] = field(default_factory=dict)
    initial_response_body: str = ""
    initial_status_code: int = 0

    # Cookies set by the target
    cookies: Dict[str, str] = field(default_factory=dict)

    # Interesting paths (from link extraction)
    paths: Set[str] = field(default_factory=set)

    # Soft-404 signature for dedup
    soft_404_hash: str = ""

    # Stats
    pages_crawled: int = 0
    total_links_found: int = 0


class TargetCrawler:
    """
    Crawls a target to build the attack surface.

    This is NOT a vulnerability scanner — it's the recon phase that
    feeds data INTO scanners. Without this, scanners see nothing.
    """

    def __init__(
        self,
        max_depth: int = 3,
        max_pages: int = 50,
        timeout: int = 15,
        rate_limit: int = 10,
        follow_redirects: bool = True,
    ):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.follow_redirects = follow_redirects
        self.semaphore = asyncio.Semaphore(rate_limit)
        self._visited: Set[str] = set()
        self._log_callback = None

    def set_log_callback(self, callback):
        """Set a callback for progress logging"""
        self._log_callback = callback

    def log(self, message: str):
        if self._log_callback:
            self._log_callback(message)
        else:
            print(f"[crawler] {message}")

    async def crawl(self, target: str) -> CrawlResult:
        """
        Crawl the target and build the attack surface.

        Args:
            target: URL or domain to crawl

        Returns:
            CrawlResult with all discovered data
        """
        result = CrawlResult()

        # Normalize target
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed = urlparse(target)
        result.base_url = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=self.follow_redirects,
            verify=False,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                # Do NOT set Accept-Encoding — httpx handles this automatically.
                # Manually setting it causes some servers (Pinterest, etc.) to serve
                # stripped/compressed responses that httpx then can't decompress.
            },
        ) as client:
            # Initial fetch
            self.log(f"Fetching {target}")
            try:
                response = await client.get(target)
                result.resolved_url = str(response.url)
                result.initial_status_code = response.status_code
                result.initial_response_headers = dict(response.headers)
                result.initial_response_body = response.text
                result.urls.add(result.resolved_url)

                # Update base URL to resolved URL (handle redirects)
                resolved_parsed = urlparse(result.resolved_url)
                result.base_url = f"{resolved_parsed.scheme}://{resolved_parsed.netloc}"

                # Extract cookies
                for cookie_name, cookie_value in client.cookies.items():
                    result.cookies[cookie_name] = cookie_value

                # Fingerprint technologies
                self._fingerprint_tech(response, result)

                # Enrich with external tools (whatweb, webanalyze) — non-blocking
                try:
                    await self._enrich_tech_fingerprint(result.resolved_url or target, result)
                except Exception:
                    pass  # External tools are optional

                # Build soft-404 signature
                await self._build_soft_404(client, result)

            except Exception as e:
                self.log(f"Initial fetch failed: {e}")
                return result

            # Parse the initial page
            if response.status_code == 200 and "text/html" in response.headers.get("content-type", ""):
                self._extract_from_html(response.text, result.resolved_url, result)
                self.log(f"Extracted {len(result.urls)} URLs, {len(result.js_files)} JS files, {len(result.forms)} forms from initial page")

            # Crawl discovered same-origin links (depth-limited)
            await self._crawl_links(client, result, depth=1)

            result.pages_crawled = len(self._visited)
            result.total_links_found = len(result.urls)

        self.log(
            f"Crawl complete: {result.pages_crawled} pages, "
            f"{len(result.urls)} URLs, {len(result.urls_with_params)} with params, "
            f"{len(result.js_files)} JS files, {len(result.forms)} forms"
        )

        return result

    async def _crawl_links(self, client: httpx.AsyncClient, result: CrawlResult, depth: int):
        """Crawl same-origin links up to max_depth"""
        if depth > self.max_depth:
            return

        base_parsed = urlparse(result.base_url)

        # Get URLs to crawl (same origin, not yet visited)
        to_crawl = []
        for url in list(result.urls):
            if url in self._visited:
                continue
            parsed = urlparse(url)
            if parsed.netloc != base_parsed.netloc:
                continue
            # Skip non-HTML resources
            if any(url.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map']):
                continue
            to_crawl.append(url)

        if not to_crawl:
            return

        # Limit pages to crawl
        to_crawl = to_crawl[:self.max_pages - len(self._visited)]

        if to_crawl:
            self.log(f"Crawling {len(to_crawl)} pages (depth {depth})")

        for url in to_crawl:
            if len(self._visited) >= self.max_pages:
                break

            self._visited.add(url)

            try:
                async with self.semaphore:
                    resp = await client.get(url)

                if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
                    # Check for soft-404
                    body_hash = hashlib.md5(resp.text[:2000].encode()).hexdigest()
                    if body_hash == result.soft_404_hash:
                        continue

                    self._extract_from_html(resp.text, str(resp.url), result)

            except Exception:
                continue

        # Recurse for newly discovered links
        if depth < self.max_depth and len(self._visited) < self.max_pages:
            await self._crawl_links(client, result, depth + 1)

    def _extract_from_html(self, html: str, page_url: str, result: CrawlResult):
        """Extract URLs, forms, and JS files from HTML"""
        base_parsed = urlparse(result.base_url)

        # Extract links from <a href="...">
        for match in re.finditer(r'<a[^>]+href=["\']([^"\'#]+)["\']', html, re.IGNORECASE):
            href = match.group(1)
            if href.startswith("javascript:") or href.startswith("mailto:") or href.startswith("tel:"):
                continue
            full_url = urljoin(page_url, href)
            parsed = urlparse(full_url)

            # Track same-origin URLs
            if parsed.netloc == base_parsed.netloc:
                result.urls.add(full_url)
                result.paths.add(parsed.path)

                # Track URLs with parameters
                if parsed.query:
                    result.urls_with_params.add(full_url)
                    for param_name in parse_qs(parsed.query).keys():
                        if param_name not in result.parameters:
                            result.parameters[param_name] = set()
                        result.parameters[param_name].add(full_url)

        # Extract script src
        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = match.group(1)
            full_url = urljoin(page_url, src)
            if full_url.endswith(('.js', '.mjs')) or '.js?' in full_url:
                result.js_files.add(full_url)

        # Extract inline script references to JS files
        for match in re.finditer(r'["\']((?:https?://[^"\']+|/[^"\']+)\.(?:js|mjs)(?:\?[^"\']*)?)["\']', html):
            src = match.group(1)
            if src.startswith('/'):
                src = urljoin(page_url, src)
            if src.startswith('http'):
                result.js_files.add(src)

        # Extract forms
        for form_match in re.finditer(
            r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE
        ):
            form_html = form_match.group(0)
            form_data = self._parse_form(form_html, page_url)
            if form_data:
                result.forms.append(form_data)
                # Track form parameters
                for param in form_data.get("params", []):
                    if param["name"] not in result.parameters:
                        result.parameters[param["name"]] = set()
                    result.parameters[param["name"]].add(form_data.get("action", page_url))

        # Extract links from common JS patterns (React Router, Angular, etc.)
        for match in re.finditer(r'["\'](/[a-zA-Z0-9_\-/]+)["\']', html):
            path = match.group(1)
            if len(path) > 1 and not path.endswith(('.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico')):
                if re.match(r'^/[a-z]', path):  # Starts with lowercase letter after /
                    result.paths.add(path)

    def _parse_form(self, form_html: str, page_url: str) -> Optional[Dict]:
        """Parse a form element for action, method, and parameters"""
        action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)

        action = urljoin(page_url, action_match.group(1)) if action_match else page_url
        method = method_match.group(1).upper() if method_match else "GET"

        params = []
        for input_match in re.finditer(
            r'<(?:input|textarea|select)[^>]+name=["\']([^"\']+)["\']([^>]*)',
            form_html, re.IGNORECASE
        ):
            name = input_match.group(1)
            attrs = input_match.group(2)

            input_type = "text"
            type_match = re.search(r'type=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            if type_match:
                input_type = type_match.group(1)

            value = ""
            value_match = re.search(r'value=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            if value_match:
                value = value_match.group(1)

            params.append({
                "name": name,
                "type": input_type,
                "value": value,
            })

        if params:
            return {
                "action": action,
                "method": method,
                "params": params,
            }
        return None

    def _fingerprint_tech(self, response: httpx.Response, result: CrawlResult):
        """Fingerprint technologies from response"""
        headers = response.headers
        body = response.text[:10000] if response.text else ""

        # Header-based
        if "x-powered-by" in headers:
            result.technologies.append(headers["x-powered-by"])

        server = headers.get("server", "").lower()
        if "nginx" in server:
            result.technologies.append("nginx")
        elif "apache" in server:
            result.technologies.append("Apache")
        elif "cloudflare" in server:
            result.technologies.append("Cloudflare")

        if "x-aspnet-version" in headers:
            result.technologies.append(f"ASP.NET {headers['x-aspnet-version']}")

        # Body-based fingerprinting
        if "__NEXT_DATA__" in body:
            result.technologies.append("Next.js")
        if "react" in body.lower() or "_reactRootContainer" in body:
            result.technologies.append("React")
        if "ng-app" in body or "ng-controller" in body:
            result.technologies.append("Angular")
        if "vue" in body.lower() and "__vue__" in body:
            result.technologies.append("Vue.js")
        if "wp-content" in body:
            result.technologies.append("WordPress")
        if "drupal" in body.lower():
            result.technologies.append("Drupal")
        if "laravel" in body.lower() or "csrf-token" in body:
            result.technologies.append("Laravel")

        # Cookie-based
        cookies_str = headers.get("set-cookie", "").lower()
        if "aspnet" in cookies_str or "asp.net" in cookies_str:
            result.technologies.append("ASP.NET")
        if "phpsessid" in cookies_str:
            result.technologies.append("PHP")
        if "jsessionid" in cookies_str:
            result.technologies.append("Java")

        # Deduplicate
        result.technologies = list(set(result.technologies))

    async def _enrich_tech_fingerprint(self, url: str, result: 'CrawlResult'):
        """
        Enrich technology fingerprints using external tools (whatweb, webanalyze).
        Called after the initial crawl to add deeper fingerprinting.
        """
        try:
            from beatrix.core.external_tools import WhatwebRunner, WebanalyzeRunner

            existing = set(result.technologies)

            # WhatWeb — 1800+ plugin fingerprinting
            whatweb = WhatwebRunner()
            if whatweb.available:
                try:
                    techs = await whatweb.fingerprint(url)
                    for name, version in techs.items():
                        entry = f"{name} {version}".strip() if version else name
                        if entry not in existing:
                            result.technologies.append(entry)
                            existing.add(entry)
                except Exception:
                    pass

            # Webanalyze — Wappalyzer fingerprint database
            webanalyze = WebanalyzeRunner()
            if webanalyze.available:
                try:
                    techs = await webanalyze.fingerprint(url)
                    for name, version in techs.items():
                        entry = f"{name} {version}".strip() if version else name
                        if entry not in existing:
                            result.technologies.append(entry)
                            existing.add(entry)
                except Exception:
                    pass

        except ImportError:
            pass  # external_tools module not available

    async def _build_soft_404(self, client: httpx.AsyncClient, result: CrawlResult):
        """Build a soft-404 signature to filter out false endpoint discoveries"""
        try:
            canary = f"{result.base_url}/beatrix-nonexistent-{hashlib.md5(b'canary').hexdigest()[:8]}"
            resp = await client.get(canary)
            if resp.status_code == 200:
                result.soft_404_hash = hashlib.md5(resp.text[:2000].encode()).hexdigest()
        except Exception:
            pass
