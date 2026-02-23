"""
BEATRIX Utilities

Imported from ReconX v1.4 + Beatrix originals.
"""

from .helpers import extract_domain
from .response_validator import ResponseValidator

# VRT classifier (Bugcrowd taxonomy + CVSS 3.1)
try:
    from .vrt_classifier import VRTClassifier, classify_finding, filter_and_classify_findings
except ImportError:
    VRTClassifier = None
    classify_finding = None
    filter_and_classify_findings = None

# WAF bypass modules
try:
    from .advanced_waf_bypass import get_waf_bypass_payloads, AdvancedWAFBypass
except ImportError:
    get_waf_bypass_payloads = None
    AdvancedWAFBypass = None

__all__ = [
    "extract_domain",
    "ResponseValidator",
    "VRTClassifier",
    "classify_finding",
    "filter_and_classify_findings",
    "get_waf_bypass_payloads",
    "AdvancedWAFBypass",
]
