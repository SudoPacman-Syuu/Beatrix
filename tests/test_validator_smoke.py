#!/usr/bin/env python3
"""Smoke test: replay all 3 Bykea informative closures through the validator"""

from beatrix.core.types import Confidence, Finding, Severity
from beatrix.validators import ImpactValidator, ReportReadinessGate
from beatrix.validators.impact_validator import TargetContext

validator = ImpactValidator()
gate = ReportReadinessGate()

bykea_ctx = TargetContext(
    domain="api.bykea.net",
    mobile_only=True,
    uses_token_auth=True,
    uses_cookie_auth=False,
    public_data_endpoints=["/nominatim"],
    requires_booking_id=True,
)

# === Test 1: WAF bypass + PostgreSQL error (Report #3541158) ===
f1 = Finding(
    title="WAF Bypass + PostgreSQL Error Disclosure",
    severity=Severity.MEDIUM,
    confidence=Confidence.FIRM,
    url="https://track-backend.bykea.net/api/tracking",
    description="WAF bypass reveals PostgreSQL error messages.",
    impact="An attacker could potentially learn database structure.",
    evidence="ERROR: invalid input syntax for type integer",
)

v1 = validator.validate(f1, bykea_ctx)
print(f"Test 1 (Error disclosure): {v1}")
print()

# === Test 2: CORS on Socket.IO ===
f2 = Finding(
    title="CORS Misconfiguration on Socket.IO",
    severity=Severity.HIGH,
    confidence=Confidence.FIRM,
    url="https://api.bykea.net/socket.io/",
    description="Origin header reflected in ACAO.",
    impact="Could steal user data cross-origin.",
    evidence="Access-Control-Allow-Origin: https://evil.com",
)

v2 = validator.validate(f2, bykea_ctx)
print(f"Test 2 (CORS mobile-only): {v2}")
print()

# === Test 3: Nominatim + CORS ===
f3 = Finding(
    title="CORS on Nominatim Geocoding Endpoint",
    severity=Severity.MEDIUM,
    confidence=Confidence.TENTATIVE,
    url="https://tomoe.bykea.net/nominatim/search",
    description="Nominatim geocoding exposed with CORS misconfiguration.",
    impact="Could access geocoding data cross-origin.",
    evidence="Access-Control-Allow-Origin: *",
)

v3 = validator.validate(f3, bykea_ctx)
print(f"Test 3 (Nominatim public): {v3}")
print()

# === Summary ===
print("=" * 60)
all_passed = [v1.passed, v2.passed, v3.passed]
print(f"Results: {sum(all_passed)}/3 passed (should be 0/3)")
if not any(all_passed):
    print("✅ ALL THREE correctly BLOCKED. Validator works.")
else:
    print("❌ PROBLEM: Some findings slipped through!")
