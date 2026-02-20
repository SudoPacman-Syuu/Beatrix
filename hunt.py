#!/usr/bin/env python3
"""
BEATRIX Quick Hunt - Fast automated bug hunting

Usage:
    python hunt.py target.com
    python hunt.py target.com --with-ai  # Use Haiku for analysis
"""

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bounty_hunter import BountyHunter
from recon import QuickRecon


async def hunt(domain: str, use_ai: bool = False, deep: bool = False):
    """Quick hunt on a target"""

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  🐰 BEATRIX QUICK HUNT                                       ║
║  Target: {domain:<50} ║
╚══════════════════════════════════════════════════════════════╝
""")

    # Phase 1: Recon
    print("\n[PHASE 1] 🔍 RECONNAISSANCE\n")
    recon = QuickRecon(domain, verbose=True)
    recon_result = await recon.run(deep=deep)

    # Phase 2: Hunt on discovered endpoints
    print("\n[PHASE 2] 🎯 VULNERABILITY HUNTING\n")

    base_url = f"https://{domain}"
    hunter = BountyHunter(base_url, verbose=True)

    # Build URL list from recon
    urls = [base_url]
    for endpoint in list(recon_result.endpoints)[:10]:
        if endpoint.startswith('/'):
            urls.append(f"{base_url}{endpoint}")
        elif endpoint.startswith('http'):
            urls.append(endpoint)

    findings = await hunter.hunt_all(urls=urls)

    # Phase 3: AI Analysis (if enabled)
    if use_ai and findings:
        print("\n[PHASE 3] 🤖 AI ANALYSIS\n")
        try:
            from beatrix.ai import HaikuGrunt
            grunt = HaikuGrunt()

            for finding in findings:
                enriched = await grunt.classify_vulnerability({
                    "title": finding.title,
                    "description": finding.description[:500],
                    "url": finding.url,
                })
                print(f"  📋 {enriched.get('owasp_category', 'N/A')}: {finding.title}")
        except Exception as e:
            print(f"  ⚠️ AI analysis skipped: {e}")

    # Summary
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  HUNT COMPLETE                                               ║
╠══════════════════════════════════════════════════════════════╣
║  Subdomains Found: {len(recon_result.subdomains):<40} ║
║  Endpoints Found:  {len(recon_result.endpoints):<40} ║
║  JS Files:         {len(recon_result.js_files):<40} ║
║  Vulnerabilities:  {len(findings):<40} ║
╚══════════════════════════════════════════════════════════════╝
""")

    if findings:
        print("🔴 FINDINGS:")
        for f in findings:
            print(f"   • [{f.severity.value.upper()}] {f.title}")

    return findings


def main():
    parser = argparse.ArgumentParser(description='BEATRIX Quick Hunt')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--with-ai', action='store_true', help='Use Haiku for analysis')
    parser.add_argument('--deep', '-d', action='store_true', help='Deep scan')

    args = parser.parse_args()

    asyncio.run(hunt(args.domain, use_ai=args.with_ai, deep=args.deep))


if __name__ == "__main__":
    main()
