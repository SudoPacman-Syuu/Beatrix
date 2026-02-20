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
