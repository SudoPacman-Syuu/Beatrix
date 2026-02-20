#!/usr/bin/env python3
"""
OpenSea Bug Bounty Hunt — Beatrix Full Engagement

Targets:
  - opensea.io (P1: $50K)
  - gql.opensea.io (GraphQL API)
  - wallet.opensea.io (P1: $50K)
  - features.opensea.io (Unleash feature flags)

Strategy:
  1. Run active scanner modules on all targets
  2. Focus on CORS, headers, auth, IDOR, BAC
  3. Deep GraphQL analysis
  4. Report findings
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from beatrix.core.engine import BeatrixEngine, EngineConfig

TARGETS = [
    "https://opensea.io",
    "https://gql.opensea.io/graphql",
    "https://wallet.opensea.io",
    "https://features.opensea.io",
]

# Modules worth running against each target
MODULE_PLAN = {
    "https://opensea.io": [
        "cors", "headers", "redirect", "error_disclosure",
        "js_analysis", "endpoint_prober", "auth",
    ],
    "https://gql.opensea.io/graphql": [
        "cors", "headers", "error_disclosure",
    ],
    "https://wallet.opensea.io": [
        "cors", "headers", "redirect", "auth", "error_disclosure",
    ],
    "https://features.opensea.io": [
        "cors", "headers", "error_disclosure",
    ],
}


async def run_module(engine, target, module_name):
    """Run a single module and return results"""
    print(f"\n{'='*60}")
    print(f"[STRIKE] {module_name} → {target}")
    print(f"{'='*60}")

    try:
        result = await engine.strike(target, module_name)

        if result.findings:
            for f in result.findings:
                sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                print(f"  🔴 [{sev}] {f.title}")
                if hasattr(f, 'description') and f.description:
                    print(f"     {f.description[:200]}")
        else:
            print("  ✅ No findings")

        if result.errors:
            for e in result.errors:
                print(f"  ⚠️  Error: {e[:200]}")

        return result
    except Exception as e:
        print(f"  ❌ Exception: {e}")
        import traceback
        traceback.print_exc()
        return None


async def main():
    print("""
╔══════════════════════════════════════════════════════════╗
║          BEATRIX — OpenSea Bug Bounty Hunt              ║
║          Target: opensea.io (Bugcrowd)                  ║
║          P1 Payout: $50,000                             ║
╚══════════════════════════════════════════════════════════╝
    """)

    # Init engine
    config = EngineConfig(
        threads=10,
        rate_limit=20,  # Conservative rate to avoid WAF
        timeout=15,
        verbose=True,
    )
    engine = BeatrixEngine(config)

    all_findings = []
    all_results = []

    # Run each module against its planned targets
    for target, modules in MODULE_PLAN.items():
        print(f"\n{'#'*60}")
        print(f"# TARGET: {target}")
        print(f"# Modules: {', '.join(modules)}")
        print(f"{'#'*60}")

        for module_name in modules:
            result = await run_module(engine, target, module_name)
            if result:
                all_results.append({
                    "target": target,
                    "module": module_name,
                    "findings_count": len(result.findings),
                    "errors": result.errors,
                })
                all_findings.extend(result.findings)

    # Summary
    print(f"\n{'='*60}")
    print(f"HUNT COMPLETE — {len(all_findings)} total findings")
    print(f"{'='*60}")

    for f in all_findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        print(f"  [{sev}] {f.title}")
        if hasattr(f, 'url') and f.url:
            print(f"      URL: {f.url}")

    # Save results
    report_path = Path("./findings/opensea_hunt_report.json")
    report_path.parent.mkdir(exist_ok=True)

    report = {
        "hunt_date": datetime.now().isoformat(),
        "targets": list(MODULE_PLAN.keys()),
        "total_findings": len(all_findings),
        "results": all_results,
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                "description": getattr(f, 'description', ''),
                "url": getattr(f, 'url', ''),
                "evidence": getattr(f, 'evidence', ''),
                "confidence": getattr(f, 'confidence', ''),
            }
            for f in all_findings
        ]
    }

    with open(report_path, 'w') as out:
        json.dump(report, out, indent=2, default=str)

    print(f"\nReport saved to: {report_path}")
    return all_findings


if __name__ == "__main__":
    findings = asyncio.run(main())
