"""
BEATRIX Scanner Modules

"Silly rabbit, Trix are for kids."

OWASP Top 10:2025 Coverage:
- A01: Broken Access Control → IDORScanner, BACScanner, EndpointProber, MassAssignmentScanner
- A02: Security Misconfiguration → HeaderSecurityScanner, CORSScanner, GraphQLScanner
- A03: Injection → InjectionScanner, SSTIScanner, XXEScanner, DeserializationScanner
- A04: Insecure Design → PaymentScanner, BusinessLogicScanner, FileUploadScanner
- A05: Security Misconfiguration → ErrorDisclosureScanner, JSBundleAnalyzer, CachePoisoningScanner
- A06: Vulnerable Components → NucleiScanner (CVE templates)
- A07: Authentication Failures → AuthScanner
- A08: Software & Data Integrity → PrototypePollutionScanner, DeserializationScanner
- A09: Logging & Monitoring → (covered via error_disclosure probing)
- A10: SSRF → SSRFScanner
- Subdomain Takeover → SubdomainTakeoverScanner
- Redirect issues → OpenRedirectScanner, OAuthRedirectScanner
- Transport → HTTPSmugglingScanner, WebSocketScanner
- DoS → ReDoSScanner
"""

from .auth import AuthScanner
from .base import BaseScanner, ScanContext
from .business_logic import BusinessLogicScanner
from .cache_poisoning import CachePoisoningScanner
from .cors import CORSScanner
from .crawler import CrawlResult, TargetCrawler
from .deserialization import DeserializationScanner
from .endpoint_prober import EndpointProber
from .error_disclosure import ErrorDisclosureScanner
from .file_upload import FileUploadScanner
from .github_recon import GitHubRecon
from .graphql import GraphQLScanner
from .headers import HeaderSecurityScanner
from .http_smuggling import HTTPSmugglingScanner
from .idor import BACScanner, IDORScanner
from .injection import InjectionScanner
from .insertion import InsertionPointDetector
from .js_bundle import JSBundleAnalyzer
from .mass_assignment import MassAssignmentScanner
from .nuclei import NucleiScanner
from .payment_scanner import PaymentScanner
from .prototype_pollution import PrototypePollutionScanner
from .redirect import OAuthRedirectScanner, OpenRedirectScanner
from .redos import ReDoSScanner
from .ssrf import SSRFScanner

# === Expanded scanner modules (all BaseScanner subclasses) ===
from .ssti import SSTIScanner
from .takeover import SubdomainTakeoverScanner
from .websocket import WebSocketScanner
from .xxe import XXEScanner

# === Extended modules (not BaseScanner subclasses — imported on demand) ===
# from .credential_validator import CredentialValidator  # Leaked cred validation
# from .mobile_interceptor import MobileInterceptor     # Android traffic capture
# from .power_injector import PowerInjector       # SQLi/XSS/CMDi advanced
# from .browser_scanner import BrowserScanner     # Playwright-based scanning
# from .origin_ip_discovery import OriginIPDiscovery  # WAF bypass via origin IP
# from .polyglot_generator import PolyglotGenerator   # XSS polyglot payloads
# from .css_exfiltrator import CSSExfiltrator     # CSS injection + exfil
# from .idor_auth import AuthenticatedIDORScanner # Multi-role IDOR testing (AI)
# from .jwt_analyzer import JWTAnalyzer           # JWT deep analysis (ReconX)

__all__ = [
    # Base
    "BaseScanner",
    "ScanContext",
    # Crawler + Nuclei
    "TargetCrawler",
    "CrawlResult",
    "NucleiScanner",
    # A01: Broken Access Control
    "IDORScanner",
    "BACScanner",
    "MassAssignmentScanner",
    # A02: Security Misconfiguration
    "CORSScanner",
    "HeaderSecurityScanner",
    # A03: Injection
    "InjectionScanner",
    "InsertionPointDetector",
    "SSTIScanner",
    "XXEScanner",
    "DeserializationScanner",
    # A04: Insecure Design
    "PaymentScanner",
    "BusinessLogicScanner",
    "FileUploadScanner",
    # A05: Security Misconfiguration
    "ErrorDisclosureScanner",
    "JSBundleAnalyzer",
    "CachePoisoningScanner",
    # A07: Authentication
    "AuthScanner",
    # A08: Integrity Failures
    "PrototypePollutionScanner",
    # A10: SSRF
    "SSRFScanner",
    # Subdomain Takeover
    "SubdomainTakeoverScanner",
    # Redirects
    "OpenRedirectScanner",
    "OAuthRedirectScanner",
    # Transport
    "HTTPSmugglingScanner",
    "WebSocketScanner",
    # DoS
    "ReDoSScanner",
    # Recon
    "EndpointProber",
    "GitHubRecon",
    # GraphQL
    "GraphQLScanner",
]
