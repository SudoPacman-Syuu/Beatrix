#!/usr/bin/env python3
"""
OPERATION BREACH — Beatrix Full Arsenal Deployment Against OpenSea
Big-Bro coordinated strike using every applicable scanner module
"""
import asyncio
import json
import os
import sys
import time
from datetime import datetime

# Add beatrix to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from beatrix.scanners.auth import AuthScanner
from beatrix.scanners.base import ScanContext
from beatrix.scanners.business_logic import BusinessLogicScanner
from beatrix.scanners.cors import CORSScanner
from beatrix.scanners.endpoint_prober import EndpointProber
from beatrix.scanners.error_disclosure import ErrorDisclosureScanner
from beatrix.scanners.graphql import GraphQLScanner
from beatrix.scanners.headers import HeaderSecurityScanner
from beatrix.scanners.injection import InjectionScanner
from beatrix.scanners.js_bundle import JSBundleAnalyzer
from beatrix.scanners.mass_assignment import MassAssignmentScanner
from beatrix.scanners.ssrf import SSRFScanner
from beatrix.scanners.websocket import WebSocketScanner

# Target configuration
OPENSEA_TARGETS = {
    "graphql_direct": "https://gql.opensea.io/graphql",
    "graphql_proxy": "https://opensea.io/__api/graphql",
    "main": "https://opensea.io",
    "auth_siwe_nonce": "https://opensea.io/__api/auth/siwe/nonce",
    "auth_siwe_verify": "https://opensea.io/__api/auth/siwe/verify",
    "auth_session_refresh": "https://opensea.io/__api/auth/session/refresh",
    "auth_session_me": "https://opensea.io/__api/auth/session/me",
    "auth_exchange_privy": "https://opensea.io/__api/auth/exchange/privy",
    "auth_accounts_merge": "https://opensea.io/__api/auth/accounts/merge",
    "auth_wallets_siwx": "https://opensea.io/__api/auth/accounts/wallets/siwx",
    "websocket": "wss://stream.openseabeta.com/ws",
}

HEADERS = {
    "x-app-id": "os2-web",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Origin": "https://opensea.io",
    "Referer": "https://opensea.io/",
}

SCANNER_CONFIG = {
    "rate_limit": 15,  # Conservative to avoid WAF
    "timeout": 20,
    "max_retries": 2,
}

all_findings = []

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = {"INFO": "ℹ️", "WARN": "⚠️", "CRIT": "🚨", "OK": "✅", "SCAN": "🔍"}.get(level, "")
    print(f"[{ts}] {prefix} {msg}")

async def run_scanner(scanner_class, label, url, extra_config=None):
    """Run a single scanner and collect findings"""
    config = {**SCANNER_CONFIG}
    if extra_config:
        config.update(extra_config)

    findings = []
    log(f"DEPLOYING {label} against {url}", "SCAN")
    start = time.time()

    try:
        async with scanner_class(config) as scanner:
            ctx = ScanContext.from_url(url)
            ctx.headers = HEADERS.copy()

            async for finding in scanner.scan(ctx):
                findings.append(finding)
                severity = getattr(finding, 'severity', 'UNKNOWN')
                title = getattr(finding, 'title', str(finding))
                log(f"  [{severity}] {title}", "CRIT" if severity in ('CRITICAL', 'HIGH') else "WARN")
    except Exception as e:
        log(f"  {label} error: {type(e).__name__}: {e}", "WARN")

    elapsed = time.time() - start
    log(f"  {label} complete — {len(findings)} findings in {elapsed:.1f}s", "OK")
    return findings

async def run_graphql_deep():
    """GraphQL scanner — the main event"""
    log("=" * 60)
    log("PHASE 1: GRAPHQL DEEP SCAN", "SCAN")
    log("=" * 60)

    findings = []

    # Hit both endpoints
    for label, url in [("GraphQL-Direct", OPENSEA_TARGETS["graphql_direct"]),
                        ("GraphQL-Proxy", OPENSEA_TARGETS["graphql_proxy"])]:
        f = await run_scanner(GraphQLScanner, label, url)
        findings.extend(f)

    return findings

async def run_jsbundle():
    """JS Bundle analysis — find secrets, endpoints, Privy app ID"""
    log("=" * 60)
    log("PHASE 2: JS BUNDLE ANALYSIS", "SCAN")
    log("=" * 60)

    return await run_scanner(JSBundleAnalyzer, "JSBundleAnalyzer", OPENSEA_TARGETS["main"],
                             {"timeout": 60})

async def run_auth_scan():
    """Auth scanner — JWT analysis, session testing, 2FA bypass"""
    log("=" * 60)
    log("PHASE 3: AUTH SCANNER", "SCAN")
    log("=" * 60)

    findings = []

    # Scan main site for auth endpoints
    f = await run_scanner(AuthScanner, "AuthScanner-Main", OPENSEA_TARGETS["main"])
    findings.extend(f)

    # Scan specific auth endpoints
    for name in ["auth_siwe_nonce", "auth_siwe_verify", "auth_exchange_privy"]:
        f = await run_scanner(AuthScanner, f"AuthScanner-{name}", OPENSEA_TARGETS[name])
        findings.extend(f)

    return findings

async def run_injection_scan():
    """Injection scanner against GraphQL and auth endpoints"""
    log("=" * 60)
    log("PHASE 4: INJECTION SCAN", "SCAN")
    log("=" * 60)

    findings = []

    # GraphQL injection
    f = await run_scanner(InjectionScanner, "Injection-GraphQL", OPENSEA_TARGETS["graphql_direct"])
    findings.extend(f)

    # Auth endpoint injection
    for name in ["auth_siwe_verify", "auth_exchange_privy", "auth_accounts_merge"]:
        f = await run_scanner(InjectionScanner, f"Injection-{name}", OPENSEA_TARGETS[name])
        findings.extend(f)

    return findings

async def run_business_logic():
    """Business logic scanner — race conditions, workflow bypass"""
    log("=" * 60)
    log("PHASE 5: BUSINESS LOGIC SCAN", "SCAN")
    log("=" * 60)

    findings = []

    # Focus on auth endpoints for race conditions
    f = await run_scanner(BusinessLogicScanner, "BizLogic-Auth", OPENSEA_TARGETS["auth_siwe_verify"])
    findings.extend(f)

    # GraphQL for numeric boundary & rate limit bypass
    f = await run_scanner(BusinessLogicScanner, "BizLogic-GraphQL", OPENSEA_TARGETS["graphql_direct"])
    findings.extend(f)

    return findings

async def run_cors_deep():
    """CORS scanner — deeper than manual testing"""
    log("=" * 60)
    log("PHASE 6: CORS DEEP SCAN", "SCAN")
    log("=" * 60)

    findings = []
    for label, url in [("CORS-GraphQL", OPENSEA_TARGETS["graphql_direct"]),
                        ("CORS-Proxy", OPENSEA_TARGETS["graphql_proxy"]),
                        ("CORS-Main", OPENSEA_TARGETS["main"]),
                        ("CORS-Auth", OPENSEA_TARGETS["auth_siwe_nonce"])]:
        f = await run_scanner(CORSScanner, label, url)
        findings.extend(f)

    return findings

async def run_websocket_scan():
    """WebSocket scanner — CSWSH, injection via WS"""
    log("=" * 60)
    log("PHASE 7: WEBSOCKET SCAN", "SCAN")
    log("=" * 60)

    return await run_scanner(WebSocketScanner, "WebSocket-Stream", OPENSEA_TARGETS["websocket"])

async def run_mass_assignment():
    """Mass assignment against profile/settings endpoints"""
    log("=" * 60)
    log("PHASE 8: MASS ASSIGNMENT SCAN", "SCAN")
    log("=" * 60)

    findings = []

    # Test GraphQL mutations via mass assignment logic
    f = await run_scanner(MassAssignmentScanner, "MassAssign-GraphQL", OPENSEA_TARGETS["graphql_direct"])
    findings.extend(f)

    return findings

async def run_error_disclosure():
    """Error disclosure and info leak scanner"""
    log("=" * 60)
    log("PHASE 9: ERROR DISCLOSURE & ENDPOINT PROBING", "SCAN")
    log("=" * 60)

    findings = []

    f = await run_scanner(ErrorDisclosureScanner, "ErrorDisclosure-Main", OPENSEA_TARGETS["main"])
    findings.extend(f)

    f = await run_scanner(EndpointProber, "EndpointProber-Main", OPENSEA_TARGETS["main"])
    findings.extend(f)

    return findings

async def run_ssrf_scan():
    """SSRF scanner against endpoints that accept URLs"""
    log("=" * 60)
    log("PHASE 10: SSRF SCAN", "SCAN")
    log("=" * 60)

    return await run_scanner(SSRFScanner, "SSRF-Main", OPENSEA_TARGETS["main"])

async def run_headers_scan():
    """Security headers analysis"""
    log("=" * 60)
    log("PHASE 11: SECURITY HEADERS", "SCAN")
    log("=" * 60)

    findings = []
    for label, url in [("Headers-Main", OPENSEA_TARGETS["main"]),
                        ("Headers-GraphQL", OPENSEA_TARGETS["graphql_direct"]),
                        ("Headers-Auth", OPENSEA_TARGETS["auth_siwe_nonce"])]:
        f = await run_scanner(HeaderSecurityScanner, label, url)
        findings.extend(f)

    return findings

async def main():
    log("🔥 OPERATION BREACH — BEATRIX FULL ARSENAL DEPLOYMENT 🔥")
    log("Target: OpenSea (opensea.io, gql.opensea.io)")
    log("Scanner count: 11 modules")
    log(f"Started: {datetime.now().isoformat()}")
    log("")

    global all_findings

    # Run scanners in phases
    # Phase 1-3: Critical scanners (sequential to avoid WAF triggers)
    phase1 = await run_graphql_deep()
    all_findings.extend(phase1)

    phase2 = await run_jsbundle()
    all_findings.extend(phase2)

    phase3 = await run_auth_scan()
    all_findings.extend(phase3)

    # Phase 4-6: Attack scanners
    phase4 = await run_injection_scan()
    all_findings.extend(phase4)

    phase5 = await run_business_logic()
    all_findings.extend(phase5)

    phase6 = await run_cors_deep()
    all_findings.extend(phase6)

    # Phase 7-11: Supplementary scanners
    phase7 = await run_websocket_scan()
    all_findings.extend(phase7)

    phase8 = await run_mass_assignment()
    all_findings.extend(phase8)

    phase9 = await run_error_disclosure()
    all_findings.extend(phase9)

    phase10 = await run_ssrf_scan()
    all_findings.extend(phase10)

    phase11 = await run_headers_scan()
    all_findings.extend(phase11)

    # Summary
    log("")
    log("=" * 60)
    log("🏁 OPERATION BREACH — FINAL RESULTS", "CRIT")
    log("=" * 60)
    log(f"Total findings: {len(all_findings)}")

    # Categorize by severity
    severity_counts = {}
    for f in all_findings:
        sev = getattr(f, 'severity', 'UNKNOWN')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for sev, count in sorted(severity_counts.items(), key=lambda x: str(x[0])):
        log(f"  {sev}: {count}")

    # Print all findings
    log("")
    log("=== ALL FINDINGS ===")
    for i, f in enumerate(all_findings):
        severity = getattr(f, 'severity', '?')
        title = getattr(f, 'title', str(f)[:100])
        detail = getattr(f, 'detail', getattr(f, 'description', ''))
        url = getattr(f, 'url', '')
        evidence = getattr(f, 'evidence', getattr(f, 'proof', ''))

        print(f"\n--- Finding {i+1} ---")
        print(f"Severity: {severity}")
        print(f"Title: {title}")
        if url:
            print(f"URL: {url}")
        if detail:
            print(f"Detail: {str(detail)[:500]}")
        if evidence:
            print(f"Evidence: {str(evidence)[:300]}")

    # Save to file
    output = []
    for f in all_findings:
        output.append({
            "severity": str(getattr(f, 'severity', '?')),
            "title": str(getattr(f, 'title', str(f)[:100])),
            "detail": str(getattr(f, 'detail', getattr(f, 'description', '')))[:1000],
            "url": str(getattr(f, 'url', '')),
            "evidence": str(getattr(f, 'evidence', getattr(f, 'proof', '')))[:500],
            "scanner": str(getattr(f, 'scanner', '')),
            "cwe": str(getattr(f, 'cwe', '')),
        })

    with open("opensea_breach_results.json", "w") as fp:
        json.dump(output, fp, indent=2)
    log("\nResults saved to opensea_breach_results.json")

    log(f"\n🏁 OPERATION BREACH COMPLETE — {datetime.now().isoformat()}")

if __name__ == "__main__":
    asyncio.run(main())
