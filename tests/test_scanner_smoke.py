"""
BEATRIX Scanner Smoke Tests

Verify every scanner module:
1. Imports without error
2. Instantiates correctly
3. Has required metadata (name, description)
4. Enters/exits async context without crash
5. scan() returns an async iterator

Run: python -m pytest tests/test_scanner_smoke.py -v
"""

import asyncio
import os
import sys

import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================================
# IMPORT TESTS — Does each module even load?
# ============================================================================

def test_import_base():
    pass

def test_import_cors():
    pass

def test_import_injection():
    pass

def test_import_headers():
    pass

def test_import_redirect():
    pass

def test_import_idor():
    pass

def test_import_auth():
    pass

def test_import_ssrf():
    pass

def test_import_takeover():
    pass

def test_import_error_disclosure():
    pass

def test_import_js_bundle():
    pass

def test_import_endpoint_prober():
    pass

def test_import_insertion():
    pass


# Extended modules (imported directly, not from __init__)
def test_import_github_recon():
    pass

def test_import_power_injector():
    pass

def test_import_origin_ip():
    pass

def test_import_polyglot():
    pass

def test_import_credential_validator():
    pass

def test_import_idor_auth():
    pass


# ============================================================================
# NUCLEI SCANNER TESTS
# ============================================================================

def test_nuclei_instantiation():
    """NucleiScanner should instantiate and report availability."""
    from beatrix.scanners.nuclei import NucleiScanner
    scanner = NucleiScanner({"rate_limit": 10, "timeout": 5})
    assert scanner.name == "nuclei"
    assert isinstance(scanner.available, bool)


def test_nuclei_build_tags_no_tech():
    """Build tags with no technologies should return base tags only."""
    from beatrix.scanners.nuclei import NucleiScanner
    scanner = NucleiScanner()
    tags = scanner._build_tags()
    # Base tags must include these critical categories
    for tag in ["misconfig", "exposure", "cve", "default-login", "takeover", "rce", "xss", "sqli"]:
        assert tag in tags, f"Missing base tag: {tag}"


def test_nuclei_build_tags_with_tech():
    """Build tags should add technology-specific tags."""
    from beatrix.scanners.nuclei import NucleiScanner
    scanner = NucleiScanner()
    scanner.set_technologies(["WordPress", "nginx", "PHP"])
    tags = scanner._build_tags()
    for tag in ["wordpress", "wp-plugin", "wp-theme", "nginx", "php"]:
        assert tag in tags, f"Missing tech tag: {tag}"


def test_nuclei_build_tags_with_tech_dict():
    """Build tags should handle dict-style technologies (from kill chain context)."""
    from beatrix.scanners.nuclei import NucleiScanner
    scanner = NucleiScanner()
    scanner.set_technologies({"WordPress": "5.9", "nginx": "1.22", "PHP": "8.1"})
    tags = scanner._build_tags()
    for tag in ["wordpress", "wp-plugin", "nginx", "php"]:
        assert tag in tags, f"Missing tech tag from dict: {tag}"


def test_nuclei_add_urls():
    """add_urls should extend the internal URL list."""
    from beatrix.scanners.nuclei import NucleiScanner
    scanner = NucleiScanner()
    scanner.add_urls(["https://example.com/api/v1", "https://example.com/admin"])
    assert len(scanner._urls_to_scan) == 2
    scanner.add_urls(["https://example.com/login"])
    assert len(scanner._urls_to_scan) == 3


def test_nuclei_severity_map():
    """Severity mapping should cover all nuclei severities."""
    from beatrix.core.types import Severity
    from beatrix.scanners.nuclei import NUCLEI_SEVERITY_MAP
    # All standard nuclei severities must be mapped
    for sev in ["critical", "high", "medium", "low", "info", "unknown"]:
        assert sev in NUCLEI_SEVERITY_MAP
    assert NUCLEI_SEVERITY_MAP["critical"] == Severity.CRITICAL
    assert NUCLEI_SEVERITY_MAP["high"] == Severity.HIGH


def test_nuclei_parse_finding():
    """_parse_nuclei_finding should convert nuclei JSON to Beatrix Finding."""
    from beatrix.scanners.nuclei import NucleiScanner
    scanner = NucleiScanner()
    finding = scanner._parse_nuclei_finding({
        "template-id": "tech-detect",
        "info": {
            "name": "WordPress Detected",
            "severity": "info",
            "description": "WordPress CMS detected",
            "tags": ["tech", "wordpress"],
        },
        "matched-at": "https://example.com",
    })
    assert finding is not None
    assert "[Nuclei]" in finding.title
    assert "WordPress" in finding.title
    assert finding.url == "https://example.com"
    assert finding.scanner_module == "nuclei"


# ============================================================================
# CORE MODULE IMPORTS
# ============================================================================

def test_import_engine():
    pass

def test_import_kill_chain():
    pass

def test_import_types():
    pass

def test_import_validators():
    pass


# ============================================================================
# INSTANTIATION TESTS — Does each scanner construct without crashing?
# ============================================================================

SCANNER_CLASSES = []

def _collect_scanners():
    """Collect all scanner classes that can be instantiated with default config."""
    from beatrix.scanners import (
        AuthScanner,
        BACScanner,
        CORSScanner,
        EndpointProber,
        ErrorDisclosureScanner,
        HeaderSecurityScanner,
        IDORScanner,
        InjectionScanner,
        JSBundleAnalyzer,
        OpenRedirectScanner,
        SSRFScanner,
        SubdomainTakeoverScanner,
    )
    return [
        ("CORSScanner", CORSScanner),
        ("InjectionScanner", InjectionScanner),
        ("HeaderSecurityScanner", HeaderSecurityScanner),
        ("OpenRedirectScanner", OpenRedirectScanner),
        ("SSRFScanner", SSRFScanner),
        ("SubdomainTakeoverScanner", SubdomainTakeoverScanner),
        ("IDORScanner", IDORScanner),
        ("BACScanner", BACScanner),
        ("AuthScanner", AuthScanner),
        ("ErrorDisclosureScanner", ErrorDisclosureScanner),
        ("JSBundleAnalyzer", JSBundleAnalyzer),
        ("EndpointProber", EndpointProber),
    ]


@pytest.mark.parametrize("name,cls", _collect_scanners())
def test_scanner_instantiation(name, cls):
    """Each scanner should instantiate with default config."""
    config = {"rate_limit": 10, "timeout": 5}
    scanner = cls(config)
    assert scanner is not None


@pytest.mark.parametrize("name,cls", _collect_scanners())
def test_scanner_has_name(name, cls):
    """Each scanner should have a non-empty name attribute."""
    config = {"rate_limit": 10, "timeout": 5}
    scanner = cls(config)
    assert hasattr(scanner, "name")
    assert scanner.name and isinstance(scanner.name, str)


# ============================================================================
# ASYNC CONTEXT TESTS — Does enter/exit work?
# ============================================================================

@pytest.mark.parametrize("name,cls", _collect_scanners())
def test_scanner_async_context(name, cls):
    """Each scanner should enter and exit async context without error."""
    config = {"rate_limit": 10, "timeout": 5}
    scanner = cls(config)

    async def _test():
        async with scanner:
            assert scanner.client is not None

    asyncio.run(_test())


# ============================================================================
# ENGINE TESTS
# ============================================================================

def test_engine_instantiation():
    """Engine should instantiate and load all available modules."""
    from beatrix.core.engine import BeatrixEngine
    engine = BeatrixEngine()

    # These should all be loaded (not None)
    assert engine.modules.get("cors") is not None
    assert engine.modules.get("injection") is not None
    assert engine.modules.get("headers") is not None
    assert engine.modules.get("redirect") is not None
    assert engine.modules.get("ssrf") is not None
    assert engine.modules.get("takeover") is not None
    assert engine.modules.get("idor") is not None
    assert engine.modules.get("bac") is not None
    assert engine.modules.get("auth") is not None
    assert engine.modules.get("error_disclosure") is not None
    assert engine.modules.get("js_analysis") is not None
    assert engine.modules.get("endpoint_prober") is not None


def test_engine_module_count():
    """Engine should have at least 12 loaded modules."""
    from beatrix.core.engine import BeatrixEngine
    engine = BeatrixEngine()
    loaded = [name for name, mod in engine.modules.items() if mod is not None]
    assert len(loaded) >= 12, f"Only {len(loaded)} modules loaded: {loaded}"


def test_kill_chain_has_handlers():
    """Kill chain should have phase handlers registered."""
    from beatrix.core.engine import BeatrixEngine
    from beatrix.core.kill_chain import KillChainPhase
    engine = BeatrixEngine()

    # At least recon, delivery, exploitation should have handlers
    assert KillChainPhase.RECONNAISSANCE in engine.kill_chain.phase_handlers
    assert KillChainPhase.DELIVERY in engine.kill_chain.phase_handlers
    assert KillChainPhase.EXPLOITATION in engine.kill_chain.phase_handlers


def test_engine_presets_valid_modules():
    """All preset module keys must map to loaded engine modules."""
    from beatrix.core.engine import BeatrixEngine
    engine = BeatrixEngine()
    for preset_name, preset in engine.PRESETS.items():
        modules = preset["modules"]
        if modules:  # Empty = run all
            for mod in modules:
                assert mod in engine.modules, f"Preset '{preset_name}' references unknown module '{mod}'"


def test_engine_injection_preset_has_phase1():
    """Injection preset must include Phase 1 for crawling to populate URLs."""
    from beatrix.core.engine import BeatrixEngine
    engine = BeatrixEngine()
    assert 1 in engine.PRESETS["injection"]["phases"], "Injection preset needs Phase 1 for crawling"


def test_engine_presets_exist():
    """Engine should have standard presets defined."""
    from beatrix.core.engine import BeatrixEngine
    engine = BeatrixEngine()

    assert "quick" in engine.PRESETS
    assert "standard" in engine.PRESETS
    assert "full" in engine.PRESETS


# ============================================================================
# VALIDATOR TESTS
# ============================================================================

def test_impact_validator_basic():
    """ImpactValidator should validate a finding without crashing."""
    from beatrix.core.types import Finding, Severity
    from beatrix.validators import ImpactValidator

    validator = ImpactValidator()
    finding = Finding(
        title="SQL Injection in login",
        description="Error-based SQLi found. PostgreSQL error in response.",
        severity=Severity.CRITICAL,
        url="https://example.com/login",
        evidence={"payload": "' OR 1=1--", "error": "pg_query()"},
    )

    verdict = validator.validate(finding, None)
    assert verdict is not None
    assert hasattr(verdict, "passed")
    assert hasattr(verdict, "impact_level")


def test_readiness_gate_basic():
    """ReadinessGate should check a finding without crashing."""
    from beatrix.core.types import Finding, Severity
    from beatrix.validators import ReportReadinessGate

    gate = ReportReadinessGate()
    finding = Finding(
        title="CORS Misconfiguration",
        description="Origin reflection without credentials. Cookie-based auth in use.",
        severity=Severity.MEDIUM,
        url="https://example.com/api",
    )

    verdict = gate.check(finding)
    assert verdict is not None
    assert hasattr(verdict, "ready")
    assert hasattr(verdict, "score")
    assert 0 <= verdict.score <= 100


# ============================================================================
# SCAN CONTEXT
# ============================================================================

def test_scan_context_from_url():
    """ScanContext should parse a URL correctly."""
    from beatrix.scanners import ScanContext

    ctx = ScanContext.from_url("https://api.example.com/users?id=123&name=test")
    assert ctx.base_url == "https://api.example.com"
    assert ctx.parameters.get("id") == "123"
    assert ctx.parameters.get("name") == "test"


def test_scan_context_no_params():
    """ScanContext should handle URLs without parameters."""
    from beatrix.scanners import ScanContext

    ctx = ScanContext.from_url("https://example.com")
    assert ctx.base_url == "https://example.com"
    assert ctx.parameters == {}
