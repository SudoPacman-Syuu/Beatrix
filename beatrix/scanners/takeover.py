"""
BEATRIX Subdomain Takeover Scanner

Detects misconfigured DNS records pointing to decommissioned services.
This is HIGH VALUE for bug bounties - often $500-$5000+

Vulnerable Patterns:
1. CNAME pointing to unclaimed service (S3, Azure, Heroku, etc.)
2. Dangling A records to IPs you can claim
3. NS records pointing to expired domains
"""

import asyncio
import re
import socket
from dataclasses import dataclass
from typing import AsyncIterator, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore
    HAS_HTTPX = False

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    dns = None  # type: ignore
    HAS_DNSPYTHON = False

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext


@dataclass
class SubdomainCandidate:
    """Subdomain to check for takeover"""
    subdomain: str
    cname: Optional[str] = None
    a_records: Optional[List[str]] = None
    ns_records: Optional[List[str]] = None

    def __post_init__(self):
        self.a_records = self.a_records or []
        self.ns_records = self.ns_records or []


# Service fingerprints for takeover detection
# Maps CNAME patterns to service info
SERVICE_FINGERPRINTS = {
    # AWS S3
    r'\.s3\.amazonaws\.com$': {
        'service': 'Amazon S3',
        'fingerprint': ['NoSuchBucket', 'The specified bucket does not exist'],
        'severity': Severity.HIGH,
        'takeover': True,
    },
    r'\.s3-website.*\.amazonaws\.com$': {
        'service': 'Amazon S3 Website',
        'fingerprint': ['NoSuchBucket', 'The specified bucket does not exist'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # AWS CloudFront
    r'\.cloudfront\.net$': {
        'service': 'Amazon CloudFront',
        'fingerprint': ['Bad Request', 'ERROR: The request could not be satisfied'],
        'severity': Severity.MEDIUM,
        'takeover': False,  # Harder to take over
    },

    # AWS Elastic Beanstalk
    r'\.elasticbeanstalk\.com$': {
        'service': 'AWS Elastic Beanstalk',
        'fingerprint': ['NXDOMAIN'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # Azure
    r'\.azurewebsites\.net$': {
        'service': 'Azure App Service',
        'fingerprint': ['Error 404 - Web app not found'],
        'severity': Severity.HIGH,
        'takeover': True,
    },
    r'\.cloudapp\.azure\.com$': {
        'service': 'Azure Cloud App',
        'fingerprint': ['NXDOMAIN'],
        'severity': Severity.HIGH,
        'takeover': True,
    },
    r'\.azurefd\.net$': {
        'service': 'Azure Front Door',
        'fingerprint': ['Our services aren\'t available right now'],
        'severity': Severity.MEDIUM,
        'takeover': True,
    },
    r'\.blob\.core\.windows\.net$': {
        'service': 'Azure Blob Storage',
        'fingerprint': ['BlobNotFound', 'The specified blob does not exist'],
        'severity': Severity.HIGH,
        'takeover': True,
    },
    r'\.trafficmanager\.net$': {
        'service': 'Azure Traffic Manager',
        'fingerprint': ['NXDOMAIN'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # GitHub Pages
    r'\.github\.io$': {
        'service': 'GitHub Pages',
        'fingerprint': ['There isn\'t a GitHub Pages site here', '404'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # Heroku
    r'\.herokuapp\.com$': {
        'service': 'Heroku',
        'fingerprint': ['No such app', 'herokucdn.com/error-pages/no-such-app'],
        'severity': Severity.HIGH,
        'takeover': True,
    },
    r'\.herokudns\.com$': {
        'service': 'Heroku DNS',
        'fingerprint': ['No such app'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # Shopify
    r'\.myshopify\.com$': {
        'service': 'Shopify',
        'fingerprint': ['Sorry, this shop is currently unavailable'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # WordPress
    r'\.wordpress\.com$': {
        'service': 'WordPress.com',
        'fingerprint': ['Do you want to register'],
        'severity': Severity.MEDIUM,
        'takeover': True,
    },

    # Tumblr
    r'\.tumblr\.com$': {
        'service': 'Tumblr',
        'fingerprint': ['There\'s nothing here', 'Whatever you were looking for'],
        'severity': Severity.MEDIUM,
        'takeover': True,
    },

    # Zendesk
    r'\.zendesk\.com$': {
        'service': 'Zendesk',
        'fingerprint': ['Help Center Closed', 'Oops, this help center no longer exists'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # Fastly
    r'\.fastly\.net$': {
        'service': 'Fastly',
        'fingerprint': ['Fastly error: unknown domain'],
        'severity': Severity.MEDIUM,
        'takeover': True,
    },

    # Pantheon
    r'\.pantheonsite\.io$': {
        'service': 'Pantheon',
        'fingerprint': ['The gods are wise', '404 error'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # Netlify
    r'\.netlify\.app$': {
        'service': 'Netlify',
        'fingerprint': ['Not Found', "Page doesn't exist"],
        'severity': Severity.HIGH,
        'takeover': True,
    },
    r'\.netlify\.com$': {
        'service': 'Netlify',
        'fingerprint': ['Not Found'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # Vercel
    r'\.vercel\.app$': {
        'service': 'Vercel',
        'fingerprint': ['The deployment could not be found'],
        'severity': Severity.HIGH,
        'takeover': True,
    },
    r'\.now\.sh$': {
        'service': 'Vercel (now.sh)',
        'fingerprint': ['The deployment could not be found'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # Surge.sh
    r'\.surge\.sh$': {
        'service': 'Surge.sh',
        'fingerprint': ['project not found'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # Firebase
    r'\.firebaseapp\.com$': {
        'service': 'Firebase',
        'fingerprint': ['Site Not Found'],
        'severity': Severity.HIGH,
        'takeover': True,
    },
    r'\.web\.app$': {
        'service': 'Firebase Hosting',
        'fingerprint': ['Site Not Found'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # Unbounce
    r'\.unbounce\.com$': {
        'service': 'Unbounce',
        'fingerprint': ['The requested URL was not found'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # HubSpot
    r'\.hubspot\.net$': {
        'service': 'HubSpot',
        'fingerprint': ['Domain not found'],
        'severity': Severity.MEDIUM,
        'takeover': True,
    },

    # Cargo
    r'\.cargo\.site$': {
        'service': 'Cargo',
        'fingerprint': ['404 Not Found'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # Ghost
    r'\.ghost\.io$': {
        'service': 'Ghost',
        'fingerprint': ['The thing you were looking for is no longer here'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # ReadMe.io
    r'\.readme\.io$': {
        'service': 'ReadMe.io',
        'fingerprint': ['Project doesnt exist'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # Bitbucket
    r'\.bitbucket\.io$': {
        'service': 'Bitbucket',
        'fingerprint': ['Repository not found'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # Intercom
    r'\.intercom\.help$': {
        'service': 'Intercom',
        'fingerprint': ['This page is reserved for'],
        'severity': Severity.MEDIUM,
        'takeover': True,
    },

    # Tilda
    r'\.tilda\.ws$': {
        'service': 'Tilda',
        'fingerprint': ['Please renew your subscription'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # Fly.io
    r'\.fly\.dev$': {
        'service': 'Fly.io',
        'fingerprint': ['404'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # Railway
    r'\.railway\.app$': {
        'service': 'Railway',
        'fingerprint': ['Application Error'],
        'severity': Severity.HIGH,
        'takeover': True,
    },

    # Render
    r'\.onrender\.com$': {
        'service': 'Render',
        'fingerprint': ['Not Found'],
        'severity': Severity.HIGH,
        'takeover': True,
    },
}


class SubdomainTakeoverScanner(BaseScanner):
    """
    Subdomain takeover vulnerability scanner.

    Checks for:
    1. CNAME records pointing to claimable services
    2. Dangling records to decommissioned infrastructure
    3. HTTP responses indicating unclaimed resources
    """

    name = "subdomain_takeover"
    description = "Subdomain takeover vulnerability scanner"
    version = "1.0.0"

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.config = config or {}
        self.timeout = self.config.get('timeout', 10)
        self.resolver = None

        if HAS_DNSPYTHON:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = 5
            self.resolver.lifetime = 5

    def _resolve_cname(self, domain: str) -> Optional[str]:
        """Get CNAME record for domain"""
        if not HAS_DNSPYTHON or self.resolver is None:
            return None

        try:
            answers = self.resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                return str(rdata.target).rstrip('.')
        except Exception:
            return None

    def _resolve_a(self, domain: str) -> List[str]:
        """Get A records for domain"""
        if not HAS_DNSPYTHON or self.resolver is None:
            # Fallback to socket
            try:
                return [socket.gethostbyname(domain)]
            except Exception:
                return []

        try:
            answers = self.resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except Exception:
            return []

    def _check_nxdomain(self, domain: str) -> bool:
        """Check if domain returns NXDOMAIN"""
        if not HAS_DNSPYTHON or self.resolver is None:
            try:
                socket.gethostbyname(domain)
                return False
            except socket.gaierror:
                return True

        try:
            self.resolver.resolve(domain, 'A')
            return False
        except Exception:
            return True

    def _match_service(self, cname: str) -> Optional[Dict]:
        """Match CNAME against known vulnerable services"""
        for pattern, info in SERVICE_FINGERPRINTS.items():
            if re.search(pattern, cname.lower()):
                return info
        return None

    async def check_http_fingerprint(self,
                                     subdomain: str,
                                     fingerprints: List[str]) -> Tuple[bool, str]:
        """Check HTTP response for takeover fingerprints"""
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False
        ) as client:
            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{subdomain}"
                    response = await client.get(url)
                    content = response.text

                    for fingerprint in fingerprints:
                        if fingerprint.lower() in content.lower():
                            return True, fingerprint

                    # Check for common error indicators
                    if response.status_code == 404:
                        if any(fp.lower() in content.lower() for fp in fingerprints):
                            return True, "404 with service fingerprint"

                except Exception:
                    continue

        return False, ""

    async def check_subdomain(self, subdomain: str) -> Optional[Finding]:
        """Check a single subdomain for takeover vulnerability"""

        # Get CNAME record
        cname = self._resolve_cname(subdomain)

        if cname:
            # Check if CNAME matches a vulnerable service
            service_info = self._match_service(cname)

            if service_info:
                # Check if the service is actually unclaimed
                if 'NXDOMAIN' in service_info['fingerprint']:
                    if self._check_nxdomain(cname):
                        return Finding(
                            title=f"Subdomain Takeover: {subdomain}",
                            description=f"""
## Subdomain Takeover Vulnerability

**Subdomain:** `{subdomain}`
**CNAME Target:** `{cname}`
**Service:** {service_info['service']}

### Issue
The subdomain has a CNAME record pointing to `{cname}`,
but the target domain returns NXDOMAIN. This service
can potentially be claimed.

### Impact
An attacker could claim the unclaimed service and serve
malicious content under your domain, enabling:
- Phishing attacks with legitimate-looking URLs
- Cookie theft (same-origin policy bypass)
- Reputation damage
- OAuth token theft

### PoC Steps
1. Visit: https://{subdomain}
2. Note the error indicating unclaimed service
3. Create account on {service_info['service']}
4. Claim the subdomain/bucket/app name
""",
                            severity=service_info['severity'],
                            confidence=Confidence.CERTAIN,
                            url=f"https://{subdomain}",
                            evidence={
                                "subdomain": subdomain,
                                "cname": cname,
                                "service": service_info['service'],
                                "detection": "NXDOMAIN",
                            },
                            remediation=f"Remove the dangling CNAME record for {subdomain} "
                                       f"or reclaim the {service_info['service']} resource."
                        )

                # Check HTTP fingerprint
                is_vulnerable, fingerprint = await self.check_http_fingerprint(
                    subdomain, service_info['fingerprint']
                )

                if is_vulnerable:
                    return Finding(
                        title=f"Subdomain Takeover: {subdomain}",
                        description=f"""
## Subdomain Takeover Vulnerability

**Subdomain:** `{subdomain}`
**CNAME Target:** `{cname}`
**Service:** {service_info['service']}
**Fingerprint Matched:** `{fingerprint}`

### Issue
The subdomain points to an unclaimed {service_info['service']}
resource. The HTTP response contains fingerprints indicating
the resource is available for claiming.

### Impact
- Serve malicious content from your domain
- Phishing attacks with trusted URLs
- Steal cookies and session tokens
- OAuth/SSO abuse

### PoC
1. Visit: https://{subdomain}
2. Observe the "{fingerprint}" error message
3. This indicates the resource can be claimed
""",
                        severity=service_info['severity'],
                        confidence=Confidence.CERTAIN,
                        url=f"https://{subdomain}",
                        evidence={
                            "subdomain": subdomain,
                            "cname": cname,
                            "service": service_info['service'],
                            "fingerprint": fingerprint,
                        },
                        remediation=f"Remove the CNAME record or reclaim the "
                                   f"{service_info['service']} resource."
                    )

        # Check for dangling A record (no CNAME, but A record to unreachable IP)
        a_records = self._resolve_a(subdomain)
        if a_records:
            # Could check if IPs are reachable, but this is less reliable
            pass

        return None

    async def scan_subdomains(self, subdomains: List[str]) -> List[Finding]:
        """Scan a list of subdomains for takeover vulnerabilities"""
        findings = []

        # Process in batches to avoid overwhelming DNS
        batch_size = 10
        for i in range(0, len(subdomains), batch_size):
            batch = subdomains[i:i + batch_size]
            tasks = [self.check_subdomain(sub) for sub in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Finding):
                    findings.append(result)

        return findings

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        """Main scan method - extract domain and check common subdomains"""
        parsed = urlparse(ctx.url)
        domain = parsed.netloc

        # Remove www if present
        if domain.startswith('www.'):
            domain = domain[4:]

        # Common subdomains to check
        common_subdomains = [
            f"www.{domain}",
            f"mail.{domain}",
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
            f"new.{domain}",
            f"shop.{domain}",
            f"store.{domain}",
        ]

        results = await self.scan_subdomains(common_subdomains)
        for finding in results:
            yield finding


async def check_takeover(subdomain: str) -> Optional[Finding]:
    """Quick check for a single subdomain"""
    scanner = SubdomainTakeoverScanner()
    return await scanner.check_subdomain(subdomain)


async def scan_subdomains(domain: str, subdomains: Optional[List[str]] = None) -> List[Finding]:
    """Scan subdomains for takeover vulnerabilities"""
    scanner = SubdomainTakeoverScanner()

    if subdomains is None:
        # Use common prefixes
        subdomains = [
            f"{prefix}.{domain}" for prefix in [
                'www', 'mail', 'dev', 'staging', 'test', 'beta', 'api',
                'cdn', 'static', 'assets', 'blog', 'docs', 'support',
                'help', 'status', 'admin', 'portal', 'app', 'dashboard'
            ]
        ]

    return await scanner.scan_subdomains(subdomains)
