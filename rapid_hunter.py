#!/usr/bin/env python3
"""
BEATRIX Rapid Hunter - Quick vulnerability scanner
⚠️  DEPRECATED: Consolidated into beatrix.hunters.rapid module.
    Use: beatrix rapid [-d domain] [-t targets.txt]
    Or:  from beatrix.hunters.rapid import RapidHunter

Run this periodically to scan for:
- Subdomain takeovers
- Exposed debug endpoints
- CORS misconfigurations
- Open redirects

Usage:
    python rapid_hunter.py
    python rapid_hunter.py --targets targets.txt
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import httpx
except ImportError:
    os.system("pip install httpx")
    import httpx


# Bug bounty programs with good payouts
DEFAULT_TARGETS = [
    "shopify.com",
    "gitlab.com",
    "github.com",
    "dropbox.com",
    "uber.com",
    "airbnb.com",
    "yahoo.com",
    "verizon.com",
    "att.com",
    "paypal.com",
    "twitch.tv",
    "twitter.com",
    "spotify.com",
]

# Subdomain takeover fingerprints
TAKEOVER_FINGERPRINTS = {
    "amazon s3": ["NoSuchBucket", "The specified bucket does not exist"],
    "github pages": ["There isn't a GitHub Pages site here"],
    "heroku": ["No such app", "herokucdn.com/error-pages"],
    "azure": ["Error 404 - Web app not found"],
    "fastly": ["Fastly error: unknown domain"],
    "netlify": ["Not Found - Request ID"],
    "vercel": ["The deployment could not be found"],
    "shopify": ["Sorry, this shop is currently unavailable"],
    "tumblr": ["There's nothing here"],
    "wordpress": ["Do you want to register"],
}


class RapidHunter:
    def __init__(self, targets=None, verbose=True):
        self.targets = targets or DEFAULT_TARGETS
        self.verbose = verbose
        self.findings = []

    def log(self, msg, level="INFO"):
        if self.verbose or level != "INFO":
            colors = {"INFO": "\033[94m", "WARN": "\033[93m", "VULN": "\033[91m\033[1m", "SUCCESS": "\033[92m"}
            print(f"{colors.get(level, '')}[{level}]\033[0m {msg}")

    async def get_subdomains(self, domain: str) -> list:
        """Get subdomains from crt.sh"""
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
                if resp.status_code == 200:
                    data = resp.json()
                    subs = set()
                    for entry in data[:100]:
                        name = entry.get("name_value", "")
                        for s in name.split("\n"):
                            s = s.strip().lower().replace("*.", "")
                            if s.endswith(domain) and s != domain:
                                subs.add(s)
                    return list(subs)
            except Exception as e:
                self.log(f"crt.sh error for {domain}: {e}", "WARN")
        return []

    async def check_takeover(self, subdomain: str) -> dict:
        """Check subdomain for takeover"""
        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
            for scheme in ["https", "http"]:
                try:
                    resp = await client.get(f"{scheme}://{subdomain}")
                    body = resp.text.lower()

                    for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
                        for fp in fingerprints:
                            if fp.lower() in body:
                                return {
                                    "type": "subdomain_takeover",
                                    "subdomain": subdomain,
                                    "service": service,
                                    "fingerprint": fp,
                                    "severity": "HIGH",
                                }
                except Exception:
                    pass
        return None

    async def check_debug_endpoints(self, domain: str) -> list:
        """Check for exposed debug/admin endpoints"""
        findings = []
        paths = [
            "/.git/config", "/.env", "/debug", "/trace",
            "/actuator/env", "/actuator/heapdump", "/server-status",
            "/phpinfo.php", "/elmah.axd", "/swagger.json",
        ]

        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            for path in paths:
                for scheme in ["https", "http"]:
                    try:
                        resp = await client.get(f"{scheme}://{domain}{path}")
                        if resp.status_code == 200:
                            # Verify it's actually exposed
                            content = resp.text.lower()
                            if path == "/.git/config" and "[core]" in content:
                                findings.append({
                                    "type": "exposed_git",
                                    "url": f"{scheme}://{domain}{path}",
                                    "severity": "CRITICAL",
                                })
                            elif path == "/.env" and "=" in resp.text:
                                findings.append({
                                    "type": "exposed_env",
                                    "url": f"{scheme}://{domain}{path}",
                                    "severity": "CRITICAL",
                                })
                            elif "swagger" in path and ("swagger" in content or "openapi" in content):
                                findings.append({
                                    "type": "exposed_swagger",
                                    "url": f"{scheme}://{domain}{path}",
                                    "severity": "LOW",
                                })
                    except Exception:
                        pass
        return findings

    async def check_cors(self, domain: str) -> dict:
        """Check for CORS misconfiguration"""
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            try:
                resp = await client.get(
                    f"https://{domain}",
                    headers={"Origin": "https://evil.com"}
                )
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                if acao == "https://evil.com" and acac.lower() == "true":
                    return {
                        "type": "cors_misconfiguration",
                        "domain": domain,
                        "acao": acao,
                        "acac": acac,
                        "severity": "HIGH",
                    }
            except Exception:
                pass
        return None

    async def scan_domain(self, domain: str):
        """Full scan of a domain"""
        self.log(f"Scanning {domain}...")

        # Get subdomains
        subs = await self.get_subdomains(domain)
        self.log(f"  Found {len(subs)} subdomains")

        # Check main domain
        debug_findings = await self.check_debug_endpoints(domain)
        self.findings.extend(debug_findings)

        cors_finding = await self.check_cors(domain)
        if cors_finding:
            self.findings.append(cors_finding)
            self.log(f"  🔴 CORS VULN: {domain}", "VULN")

        # Check subdomains for takeover
        for sub in subs[:20]:  # Limit to avoid rate limiting
            finding = await self.check_takeover(sub)
            if finding:
                self.findings.append(finding)
                self.log(f"  🔴 TAKEOVER: {sub} ({finding['service']})", "VULN")

    async def run(self):
        """Run full scan"""
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║  🐰 BEATRIX RAPID HUNTER                                     ║
║  Scanning {len(self.targets)} targets                                       ║
╚══════════════════════════════════════════════════════════════╝
""")

        for target in self.targets:
            await self.scan_domain(target)
            await asyncio.sleep(1)  # Be nice to servers

        # Print summary
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║  SCAN COMPLETE                                               ║
║  Findings: {len(self.findings):<48} ║
╚══════════════════════════════════════════════════════════════╝
""")

        if self.findings:
            print("🔴 VULNERABILITIES FOUND:\n")
            for f in self.findings:
                print(f"  [{f.get('severity', 'UNKNOWN')}] {f.get('type', 'unknown')}")
                print(f"      {f}")
                print()

        # Save to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"rapid_hunt_{timestamp}.json"
        with open(filename, "w") as fp:
            json.dump({
                "timestamp": timestamp,
                "targets": self.targets,
                "findings": self.findings,
            }, fp, indent=2)
        print(f"📁 Results saved to: {filename}")

        return self.findings


async def main():
    parser = argparse.ArgumentParser(description="BEATRIX Rapid Hunter")
    parser.add_argument("--targets", "-t", help="File with target domains (one per line)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    args = parser.parse_args()

    targets = None
    if args.targets:
        with open(args.targets) as f:
            targets = [line.strip() for line in f if line.strip()]

    hunter = RapidHunter(targets=targets, verbose=not args.quiet)
    await hunter.run()


if __name__ == "__main__":
    asyncio.run(main())
