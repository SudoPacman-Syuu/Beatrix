#!/usr/bin/env python3
"""
BEATRIX Quick Recon
⚠️  DEPRECATED: Consolidated into beatrix.recon module.
    Use: beatrix recon <domain>
    Or:  from beatrix.recon import ReconRunner

Fast reconnaissance to find attack surface:
- Subdomain enumeration (via crt.sh, SecurityTrails)
- Tech stack detection
- JavaScript file enumeration
- API endpoint discovery
- Parameter mining

Usage:
    python recon.py target.com
    python recon.py target.com --deep
"""

import argparse
import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import httpx
except ImportError:
    print("Installing httpx...")
    os.system("pip install httpx")
    import httpx


@dataclass
class ReconResult:
    """Reconnaissance results"""
    domain: str
    subdomains: Set[str] = field(default_factory=set)
    endpoints: Set[str] = field(default_factory=set)
    js_files: Set[str] = field(default_factory=set)
    parameters: Set[str] = field(default_factory=set)
    technologies: Dict[str, str] = field(default_factory=dict)
    interesting_findings: List[str] = field(default_factory=list)


class QuickRecon:
    """Fast reconnaissance scanner"""

    def __init__(self, domain: str, verbose: bool = False):
        self.domain = domain.lower().strip()
        if self.domain.startswith('http'):
            self.domain = urlparse(self.domain).netloc
        self.domain = self.domain.replace('www.', '')

        self.verbose = verbose
        self.result = ReconResult(domain=self.domain)
        self.visited_urls: Set[str] = set()

    def log(self, msg: str, level: str = "INFO"):
        """Log messages"""
        colors = {
            "INFO": "\033[94m",
            "WARN": "\033[93m",
            "SUCCESS": "\033[92m",
            "FOUND": "\033[95m",
        }
        reset = "\033[0m"

        if level == "INFO" and not self.verbose:
            return

        color = colors.get(level, "")
        print(f"{color}[{level}]{reset} {msg}")

    async def enum_subdomains_crtsh(self) -> Set[str]:
        """Enumerate subdomains using crt.sh"""
        self.log(f"🔍 Querying crt.sh for {self.domain}...")
        subdomains = set()

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"https://crt.sh/?q=%.{self.domain}&output=json"
                )
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        # Handle wildcards and multiple entries
                        for sub in name.split('\n'):
                            sub = sub.strip().lower()
                            if sub.startswith('*.'):
                                sub = sub[2:]
                            if sub.endswith(self.domain) and sub:
                                subdomains.add(sub)

                    self.log(f"Found {len(subdomains)} subdomains via crt.sh", "SUCCESS")
        except Exception as e:
            self.log(f"crt.sh error: {e}", "WARN")

        return subdomains

    async def enum_subdomains_hackertarget(self) -> Set[str]:
        """Enumerate subdomains using HackerTarget"""
        self.log(f"🔍 Querying HackerTarget for {self.domain}...")
        subdomains = set()

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
                )
                if response.status_code == 200 and 'error' not in response.text.lower():
                    for line in response.text.split('\n'):
                        if ',' in line:
                            sub = line.split(',')[0].strip().lower()
                            if sub.endswith(self.domain):
                                subdomains.add(sub)

                    self.log(f"Found {len(subdomains)} subdomains via HackerTarget", "SUCCESS")
        except Exception as e:
            self.log(f"HackerTarget error: {e}", "WARN")

        return subdomains

    async def enumerate_subdomains(self) -> Set[str]:
        """Enumerate all subdomains"""
        self.log("📡 Starting subdomain enumeration...")

        # Run multiple sources in parallel
        results = await asyncio.gather(
            self.enum_subdomains_crtsh(),
            self.enum_subdomains_hackertarget(),
            return_exceptions=True
        )

        all_subdomains = set()
        for result in results:
            if isinstance(result, set):
                all_subdomains.update(result)

        # Add base domain
        all_subdomains.add(self.domain)
        all_subdomains.add(f"www.{self.domain}")

        self.result.subdomains = all_subdomains
        self.log(f"Total unique subdomains: {len(all_subdomains)}", "SUCCESS")

        return all_subdomains

    async def detect_technologies(self, url: str) -> Dict[str, str]:
        """Detect technologies used by target"""
        self.log(f"🔧 Detecting technologies for {url}...")
        techs = {}

        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                response = await client.get(url)
                headers = response.headers
                content = response.text.lower()

                # Server header
                if 'server' in headers:
                    techs['Server'] = headers['server']

                # X-Powered-By
                if 'x-powered-by' in headers:
                    techs['Powered-By'] = headers['x-powered-by']

                # Framework detection from headers
                framework_headers = {
                    'x-aspnet-version': 'ASP.NET',
                    'x-aspnetmvc-version': 'ASP.NET MVC',
                    'x-drupal-cache': 'Drupal',
                    'x-generator': 'Generator',
                    'x-shopify-stage': 'Shopify',
                    'x-wix-request-id': 'Wix',
                }

                for header, tech in framework_headers.items():
                    if header in headers:
                        techs[tech] = headers[header]

                # Content-based detection
                content_patterns = {
                    'wp-content': 'WordPress',
                    'wp-includes': 'WordPress',
                    'drupal.js': 'Drupal',
                    'joomla': 'Joomla',
                    'laravel': 'Laravel',
                    'django': 'Django',
                    'flask': 'Flask',
                    'express': 'Express.js',
                    'next.js': 'Next.js',
                    'nuxt': 'Nuxt.js',
                    'react': 'React',
                    'angular': 'Angular',
                    'vue': 'Vue.js',
                    'jquery': 'jQuery',
                    'bootstrap': 'Bootstrap',
                    'cloudflare': 'Cloudflare',
                    'akamai': 'Akamai',
                    'fastly': 'Fastly',
                    'aws': 'AWS',
                    'azure': 'Azure',
                    'graphql': 'GraphQL',
                }

                for pattern, tech in content_patterns.items():
                    if pattern in content:
                        techs[tech] = 'Detected'

                # Meta generator
                gen_match = re.search(r'<meta[^>]+generator[^>]+content=["\']([^"\']+)', content)
                if gen_match:
                    techs['Generator'] = gen_match.group(1)

                self.log(f"Detected {len(techs)} technologies", "SUCCESS")

        except Exception as e:
            self.log(f"Tech detection error: {e}", "WARN")

        self.result.technologies = techs
        return techs

    async def find_js_files(self, url: str) -> Set[str]:
        """Find JavaScript files for analysis"""
        self.log("📜 Finding JavaScript files...")
        js_files = set()

        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                response = await client.get(url)
                content = response.text

                # Find JS files in script tags
                script_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
                matches = re.findall(script_pattern, content, re.IGNORECASE)

                for match in matches:
                    if match.startswith('//'):
                        match = 'https:' + match
                    elif match.startswith('/'):
                        match = urljoin(url, match)
                    elif not match.startswith('http'):
                        match = urljoin(url, match)

                    js_files.add(match)

                # Also look in inline scripts for interesting patterns
                inline_patterns = [
                    r'api[_\-]?key\s*[:=]\s*["\']([^"\']+)',
                    r'api[_\-]?secret\s*[:=]\s*["\']([^"\']+)',
                    r'token\s*[:=]\s*["\']([^"\']+)',
                    r'/api/v\d+/\w+',
                    r'graphql',
                ]

                for pattern in inline_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self.result.interesting_findings.append(
                            f"Potential sensitive data pattern: {pattern}"
                        )

                self.log(f"Found {len(js_files)} JavaScript files", "SUCCESS")

        except Exception as e:
            self.log(f"JS enumeration error: {e}", "WARN")

        self.result.js_files = js_files
        return js_files

    async def mine_js_endpoints(self, js_url: str) -> Set[str]:
        """Extract API endpoints from JavaScript files"""
        endpoints = set()

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(js_url)
                content = response.text

                # API endpoint patterns
                patterns = [
                    r'["\']/(api|v\d)/[^"\']+["\']',
                    r'["\']https?://[^"\']+/api/[^"\']+["\']',
                    r'fetch\s*\(\s*["\']([^"\']+)["\']',
                    r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
                    r'url:\s*["\']([^"\']+)["\']',
                    r'endpoint:\s*["\']([^"\']+)["\']',
                ]

                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        # Clean up the endpoint
                        endpoint = match.strip('"\'')
                        if endpoint and not endpoint.startswith('data:'):
                            endpoints.add(endpoint)

                # Find potential parameters
                param_patterns = [
                    r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=',
                    r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:',
                ]

                for pattern in param_patterns:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        if len(match) > 2 and len(match) < 30:
                            self.result.parameters.add(match)

        except Exception:
            pass

        return endpoints

    async def analyze_js_files(self) -> Set[str]:
        """Analyze all JS files for endpoints"""
        self.log("🔬 Analyzing JavaScript files for endpoints...")
        all_endpoints = set()

        tasks = [self.mine_js_endpoints(js) for js in list(self.result.js_files)[:20]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, set):
                all_endpoints.update(result)

        self.result.endpoints = all_endpoints
        self.log(f"Found {len(all_endpoints)} potential endpoints", "SUCCESS")
        self.log(f"Extracted {len(self.result.parameters)} unique parameters", "SUCCESS")

        return all_endpoints

    async def check_common_endpoints(self, base_url: str) -> List[str]:
        """Check for common sensitive endpoints"""
        self.log("🎯 Checking common endpoints...")

        common_paths = [
            # APIs
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/graphql', '/graphiql', '/playground',
            '/swagger', '/swagger-ui', '/swagger.json',
            '/openapi.json', '/api-docs', '/docs',

            # Admin
            '/admin', '/administrator', '/admin.php',
            '/wp-admin', '/wp-login.php',
            '/phpmyadmin', '/pma',

            # Config
            '/.git', '/.git/config', '/.gitignore',
            '/.env', '/config.json', '/config.yml',
            '/web.config', '/server-status', '/server-info',
            '/.htaccess', '/.htpasswd',

            # Backup
            '/backup', '/backup.zip', '/backup.sql',
            '/db.sql', '/database.sql',

            # Debug
            '/debug', '/trace', '/actuator',
            '/actuator/health', '/actuator/env',
            '/metrics', '/health', '/status',

            # Auth
            '/login', '/signin', '/auth', '/oauth',
            '/register', '/signup', '/forgot-password',
            '/reset-password', '/api/auth',

            # Robots/Sitemap
            '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',

            # Well-known
            '/.well-known/security.txt',
            '/.well-known/openid-configuration',
        ]

        found = []

        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            for path in common_paths:
                try:
                    url = f"{base_url.rstrip('/')}{path}"
                    response = await client.get(url)

                    if response.status_code in [200, 301, 302, 401, 403]:
                        found.append(f"{path} ({response.status_code})")

                        # Check for particularly interesting responses
                        if response.status_code == 200:
                            content = response.text.lower()
                            if any(x in content for x in ['password', 'secret', 'api_key', 'token']):
                                self.result.interesting_findings.append(
                                    f"SENSITIVE: {path} may contain secrets"
                                )
                            if 'swagger' in content or 'openapi' in content:
                                self.result.interesting_findings.append(
                                    f"API DOCS: {path} - Swagger/OpenAPI detected"
                                )
                            if '.git' in path:
                                self.result.interesting_findings.append(
                                    f"GIT EXPOSED: {path} - Potential source code leak"
                                )

                        if response.status_code in [401, 403]:
                            self.result.interesting_findings.append(
                                f"PROTECTED: {path} exists but requires auth"
                            )

                except Exception:
                    pass

        self.log(f"Found {len(found)} accessible endpoints", "SUCCESS")
        return found

    async def check_subdomain_alive(self, subdomain: str) -> bool:
        """Check if subdomain is alive"""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                for scheme in ['https', 'http']:
                    try:
                        await client.get(f"{scheme}://{subdomain}")
                        return True
                    except Exception:
                        continue
        except Exception:
            pass
        return False

    async def run(self, deep: bool = False) -> ReconResult:
        """Run full reconnaissance"""
        print(f"""
╔═══════════════════════════════════════════════════════════════╗
║  🐰 BEATRIX Quick Recon - {self.domain:^30}  ║
╚═══════════════════════════════════════════════════════════════╝
""")

        base_url = f"https://{self.domain}"

        # 1. Enumerate subdomains
        await self.enumerate_subdomains()

        # 2. Detect technologies
        await self.detect_technologies(base_url)

        # 3. Find JS files
        await self.find_js_files(base_url)

        # 4. Analyze JS for endpoints
        await self.analyze_js_files()

        # 5. Check common endpoints
        found_endpoints = await self.check_common_endpoints(base_url)

        # 6. If deep scan, check subdomain status
        alive_subdomains = set()
        if deep and len(self.result.subdomains) <= 50:
            self.log("🔍 Checking subdomain availability (deep scan)...")
            tasks = [self.check_subdomain_alive(sub) for sub in self.result.subdomains]
            results = await asyncio.gather(*tasks)

            for sub, is_alive in zip(self.result.subdomains, results):
                if is_alive:
                    alive_subdomains.add(sub)

            self.log(f"Found {len(alive_subdomains)} alive subdomains", "SUCCESS")

        # Print results
        self._print_results(found_endpoints, alive_subdomains)

        return self.result

    def _print_results(self, found_endpoints: List[str], alive_subdomains: Set[str]):
        """Print reconnaissance results"""
        print("\n" + "="*60)
        print("📊 RECONNAISSANCE RESULTS")
        print("="*60)

        print(f"\n🌐 Domain: {self.domain}")
        print(f"📡 Subdomains Found: {len(self.result.subdomains)}")

        if self.result.subdomains:
            print("\n  Top subdomains:")
            for sub in sorted(list(self.result.subdomains))[:15]:
                status = " ✓" if sub in alive_subdomains else ""
                print(f"    - {sub}{status}")
            if len(self.result.subdomains) > 15:
                print(f"    ... and {len(self.result.subdomains) - 15} more")

        if self.result.technologies:
            print("\n🔧 Technologies Detected:")
            for tech, version in self.result.technologies.items():
                print(f"    - {tech}: {version}")

        if found_endpoints:
            print("\n🎯 Accessible Endpoints:")
            for endpoint in found_endpoints[:15]:
                print(f"    - {endpoint}")

        if self.result.js_files:
            print(f"\n📜 JavaScript Files: {len(self.result.js_files)}")
            for js in list(self.result.js_files)[:5]:
                print(f"    - {js}")

        if self.result.endpoints:
            print(f"\n🔗 API Endpoints from JS: {len(self.result.endpoints)}")
            for endpoint in list(self.result.endpoints)[:10]:
                print(f"    - {endpoint}")

        if self.result.parameters:
            print(f"\n📝 Parameters Mined: {len(self.result.parameters)}")
            params = list(self.result.parameters)[:20]
            print(f"    {', '.join(params)}")

        if self.result.interesting_findings:
            print("\n⚠️  INTERESTING FINDINGS:")
            for finding in self.result.interesting_findings:
                print(f"    🔴 {finding}")

        print("\n" + "="*60)
        print("💡 NEXT STEPS:")
        print("="*60)
        print("""
1. Check subdomains for takeover:
   python -c "from beatrix.scanners import SubdomainTakeoverScanner; ..."

2. Scan for SSRF on URL parameters:
   python bounty_hunter.py https://target.com?url=test --ssrf

3. Check API endpoints for IDOR:
   python bounty_hunter.py https://target.com/api/users/123

4. Analyze JWT tokens:
   python bounty_hunter.py https://target.com --jwt "eyJ..."
""")


async def main():
    parser = argparse.ArgumentParser(
        description='BEATRIX Quick Recon - Fast reconnaissance tool'
    )
    parser.add_argument('domain', help='Target domain (e.g., target.com)')
    parser.add_argument('--deep', '-d', action='store_true',
                        help='Deep scan (check subdomain availability)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    parser.add_argument('--output', '-o', help='Output file (JSON)')

    args = parser.parse_args()

    recon = QuickRecon(args.domain, verbose=args.verbose)
    result = await recon.run(deep=args.deep)

    if args.output:
        output = {
            "domain": result.domain,
            "subdomains": list(result.subdomains),
            "endpoints": list(result.endpoints),
            "js_files": list(result.js_files),
            "parameters": list(result.parameters),
            "technologies": result.technologies,
            "interesting_findings": result.interesting_findings,
            "timestamp": datetime.now().isoformat(),
        }

        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"\n📁 Results saved to: {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
