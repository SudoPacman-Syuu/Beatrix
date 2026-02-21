"""
BEATRIX CLI — The Black Mamba

Human-centric command-line interface for the Beatrix bug bounty hunting framework.
Built for operators who prefer a terminal over a GUI.

"Those of you lucky enough to have your lives, take them with you.
 However, leave the limbs you've lost. They belong to me now."

Usage:
    beatrix hunt example.com                    # Standard hunt
    beatrix hunt example.com --preset full      # Full kill chain
    beatrix strike api.example.com -m cors      # Single module strike
    beatrix probe example.com                   # Quick alive check
    beatrix recon example.com --deep            # Deep reconnaissance
    beatrix list --modules                      # Show available weapons
    beatrix help hunt                           # Detailed command help
"""

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from beatrix import __version__
from beatrix.core import BeatrixEngine, Confidence, Severity

console = Console()


# =============================================================================
# BANNER & THEME
# =============================================================================

BANNER = r"""
[bright_yellow]
    ____             __       _
   / __ )___  ____ _/ /______(_)  __
  / __  / _ \/ __ `/ __/ ___/ / |/_/
 / /_/ /  __/ /_/ / /_/ /  / />  <
/_____/\___/\__,_/\__/_/  /_/_/|_|
[/bright_yellow]
[dim]v{version} — "Revenge is a dish best served with a working PoC"[/dim]
[dim]The Black Mamba — Bug Bounty Hunting Framework[/dim]
"""

DEATH_LIST_HEADER = r"""[bright_yellow]
╔══════════════════════════════════════════╗
║          ☠  THE DEATH LIST  ☠           ║
╚══════════════════════════════════════════╝
[/bright_yellow]"""

KILL_BILL_QUOTES = [
    '"Wiggle your big toe."',
    '"You and I have unfinished business."',
    '"Revenge is a dish best served cold."',
    '"Those of you lucky enough to have your lives, take them with you."',
    '"It\'s mercy, compassion, and forgiveness I lack. Not rationality."',
    '"Silly rabbit, Trix are for kids."',
    '"When fortune smiles on something as violent as revenge, it seems proof like no other, that not only does God exist — you\'re doing his will."',
]


def print_banner():
    """Print the BEATRIX banner"""
    console.print(BANNER.format(version=__version__))


# =============================================================================
# HELP TEXT — Kill Bill themed, human readable
# =============================================================================

COMMAND_HELP = {
    "hunt": """
[bright_yellow]⚔️  HUNT — Full Vulnerability Scan[/bright_yellow]

[bold]The Main Event.[/bold] Runs Beatrix against a target using the kill chain methodology.
Think of it as unleashing the Bride on a room full of Crazy 88s.

[bold cyan]USAGE:[/bold cyan]
  beatrix hunt TARGET [OPTIONS]

[bold cyan]ARGUMENTS:[/bold cyan]
  TARGET    Domain, URL, or IP to hunt. Examples:
              example.com
              https://api.example.com/v1
              192.168.1.1

[bold cyan]OPTIONS:[/bold cyan]
  -p, --preset TEXT    Scan intensity preset:
                         [green]quick[/green]      — Surface scan, ~5 min (recon only)
                         [yellow]standard[/yellow]  — Balanced scan, ~15 min (DEFAULT)
                         [red]full[/red]       — Complete kill chain, ~30 min
                         [dim]stealth[/dim]    — Low-noise passive recon, ~10 min
                         [bright_red]injection[/bright_red] — Injection-focused, ~20 min
                         [cyan]api[/cyan]        — API security testing, ~15 min

  --ai                Enable AI-powered analysis (Claude Haiku via Bedrock)
  -m, --modules TEXT   Run specific modules only (can repeat)
  -o, --output PATH    Save results to directory

[bold cyan]EXAMPLES:[/bold cyan]
  [dim]# Quick surface scan[/dim]
  beatrix hunt example.com --preset quick

  [dim]# Full assault with AI[/dim]
  beatrix hunt example.com --preset full --ai

  [dim]# Just CORS and IDOR modules[/dim]
  beatrix hunt api.example.com -m cors -m idor

  [dim]# Save results[/dim]
  beatrix hunt example.com -o ./results

[bold cyan]KILL CHAIN PHASES:[/bold cyan]
  1. 🔍 Reconnaissance  — Subdomain enum, port scan, service detection
  2. ⚔️  Weaponization   — Payload crafting, WAF fingerprinting
  3. 📦 Delivery        — Endpoint discovery, parameter fuzzing
  4. 💥 Exploitation    — Injection, auth bypass, IDOR, CORS, SSRF
  5. 🔧 Installation    — Persistence testing
  6. 📡 Command & Ctrl  — Data exfiltration, OOB channels
  7. 🎯 Objectives      — Impact assessment, PoC generation
""",
    "strike": """
[bright_yellow]⚔️  STRIKE — Single Module Attack[/bright_yellow]

[bold]Surgical precision.[/bold] Execute one specific scanner against a target.
Like choosing your Hattori Hanzo sword for a specific fight.

[bold cyan]USAGE:[/bold cyan]
  beatrix strike TARGET -m MODULE

[bold cyan]ARGUMENTS:[/bold cyan]
  TARGET    URL to strike

[bold cyan]OPTIONS:[/bold cyan]
  -m, --module TEXT   [bold](required)[/bold] Scanner module to execute

[bold cyan]AVAILABLE MODULES:[/bold cyan]
  [green]cors[/green]             — CORS misconfiguration (origin reflection, null, wildcard)
  [green]injection[/green]        — SQL injection, XSS, command injection
  [green]headers[/green]          — Security header analysis (CSP, HSTS, X-Frame, etc.)
  [green]redirect[/green]         — Open redirect detection
  [green]ssrf[/green]             — Server-side request forgery (44 payloads, cloud metadata)
  [green]takeover[/green]         — Subdomain takeover (30+ services checked)
  [green]idor[/green]             — Insecure Direct Object Reference
  [green]bac[/green]              — Broken Access Control
  [green]auth[/green]             — Authentication bypass, JWT attacks
  [green]error_disclosure[/green] — Error message / stack trace leaks
  [green]js_analysis[/green]      — JavaScript bundle analysis (API routes, secrets)
  [green]endpoint_prober[/green]  — Endpoint discovery & probing

[bold cyan]EXAMPLES:[/bold cyan]
  [dim]# Test for CORS issues[/dim]
  beatrix strike https://api.example.com -m cors

  [dim]# Check for injection vulns[/dim]
  beatrix strike https://example.com/login -m injection

  [dim]# Analyze JS bundles[/dim]
  beatrix strike https://app.example.com -m js_analysis

  [dim]# Look for SSRF[/dim]
  beatrix strike https://example.com/fetch?url=test -m ssrf
""",
    "probe": """
[bright_yellow]🔍 PROBE — Quick Target Check[/bright_yellow]

[bold]"Wiggle your big toe."[/bold]

The first step. Check if your target is alive, what server it runs,
and what technologies are in play. Fast and quiet.

[bold cyan]USAGE:[/bold cyan]
  beatrix probe TARGET

[bold cyan]WHAT IT CHECKS:[/bold cyan]
  • HTTP status code
  • Server header
  • Technology fingerprinting (X-Powered-By, etc.)
  • Page title
  • WAF detection

[bold cyan]EXAMPLES:[/bold cyan]
  beatrix probe example.com
  beatrix probe https://api.example.com
  beatrix probe 192.168.1.1
""",
    "recon": """
[bright_yellow]🔍 RECON — Reconnaissance[/bright_yellow]

[bold]Know thy enemy.[/bold] Full reconnaissance on a target domain.
Subdomain enumeration, technology detection, JS analysis, endpoint discovery.

[bold cyan]USAGE:[/bold cyan]
  beatrix recon DOMAIN [OPTIONS]

[bold cyan]OPTIONS:[/bold cyan]
  -d, --deep         Deep scan (probe subdomain liveness)
  -j, --json-output  Output as JSON
  -o, --output PATH  Save results to file

[bold cyan]WHAT IT DISCOVERS:[/bold cyan]
  • Subdomains (via crt.sh, HackerTarget, DNS brute-force)
  • Live hosts (with --deep)
  • JavaScript files & inline scripts
  • API endpoints extracted from JS
  • URL parameters
  • Technology stack
  • Interesting patterns (debug endpoints, admin panels, etc.)

[bold cyan]EXAMPLES:[/bold cyan]
  [dim]# Quick recon[/dim]
  beatrix recon example.com

  [dim]# Deep scan with JSON output[/dim]
  beatrix recon example.com --deep -j -o recon.json
""",
    "batch": """
[bright_yellow]📋 BATCH — Mass Scanning[/bright_yellow]

[bold]Unleash the Crazy 88.[/bold] Scan multiple targets from a file with one command.

[bold cyan]USAGE:[/bold cyan]
  beatrix batch TARGETS_FILE -m MODULE [OPTIONS]

[bold cyan]ARGUMENTS:[/bold cyan]
  TARGETS_FILE   Text file with one target per line (# for comments)

[bold cyan]OPTIONS:[/bold cyan]
  -m, --module TEXT     [bold](required)[/bold] Module to run against all targets
  -o, --output PATH    Output directory (default: ./reports)
  -t, --threads INT    Concurrent scans (default: 5)

[bold cyan]EXAMPLES:[/bold cyan]
  [dim]# Scan all targets for CORS issues[/dim]
  beatrix batch targets.txt -m cors

  [dim]# Mass injection testing with reports[/dim]
  beatrix batch targets.txt -m injection -o ./reports

[bold cyan]TARGETS FILE FORMAT:[/bold cyan]
  # My targets
  https://api.example.com
  https://app.example.com
  https://dev.example.com
""",
    "ghost": """
[bright_yellow]👻 GHOST — Autonomous AI Pentester[/bright_yellow]

[bold]GHOST = Generative Heuristic Offensive Security Tester[/bold]

An AI-powered autonomous agent that thinks like a pentester. Give it a
target and an objective — it will investigate, test, and chain findings
on its own using 10 built-in tools.

[bold cyan]USAGE:[/bold cyan]
  beatrix ghost TARGET [OPTIONS]

[bold cyan]OPTIONS:[/bold cyan]
  -o, --objective TEXT    Investigation goal (default: "Find all security vulnerabilities")
  -X, --method TEXT       HTTP method for base request (default: GET)
  -H, --header TEXT       Add request header (repeatable)
  -d, --data TEXT         Request body
  -t, --max-turns INT     Max investigation iterations (default: 30)
  --model TEXT             Claude model (default: claude-sonnet-4-20250514)
  --api-key TEXT           Anthropic API key ($ANTHROPIC_API_KEY)
  --bedrock               Use AWS Bedrock instead of Anthropic API

[bold cyan]EXAMPLES:[/bold cyan]
  [dim]# Basic investigation[/dim]
  beatrix ghost https://api.example.com/users?id=1

  [dim]# SQLi focused with POST data[/dim]
  beatrix ghost https://api.example.com -X POST -d '{{"user":"admin"}}' -o "Test for SQLi"

  [dim]# With auth header[/dim]
  beatrix ghost https://example.com -H "Authorization: Bearer token" --max-turns 50

[bold cyan]GHOST'S TOOLS:[/bold cyan]
  • HTTP requests (GET, POST, PUT, DELETE)
  • Payload fuzzing & injection testing
  • Response analysis & diff comparison
  • Authentication testing
  • Error-based probing
  • Attack chain reasoning
""",
    "bounty-hunt": """
[bright_yellow]💰 BOUNTY-HUNT — Full Bug Bounty Pipeline[/bright_yellow]

[bold]The whole enchilada.[/bold] OWASP Top 10 scanning with validation.
Runs IDOR, auth, injection, redirect, SSRF, and takeover scanners,
then validates all findings through ImpactValidator + ReadinessGate.

[bold cyan]USAGE:[/bold cyan]
  beatrix bounty-hunt TARGET [OPTIONS]

[bold cyan]OPTIONS:[/bold cyan]
  -H, --header TEXT    Add header (format: "Name: Value"), repeatable
  -u, --urls TEXT      Additional URL paths to scan (repeatable)
  --jwt TEXT           JWT tokens to analyze (repeatable)
  -o, --output PATH    Output report filename
  -v, --verbose        Verbose output

[bold cyan]EXAMPLES:[/bold cyan]
  [dim]# Basic hunt[/dim]
  beatrix bounty-hunt https://api.example.com

  [dim]# With auth and extra endpoints[/dim]
  beatrix bounty-hunt https://api.example.com -H "Authorization: Bearer TOKEN" -u /users/123 -u /orders/456
""",
    "rapid": """
[bright_yellow]⚡ RAPID — Multi-Target Quick Sweep[/bright_yellow]

[bold]Speed blitz.[/bold] Takeover checks, debug endpoint discovery, CORS scanning
across multiple targets simultaneously.

[bold cyan]USAGE:[/bold cyan]
  beatrix rapid [OPTIONS]

[bold cyan]OPTIONS:[/bold cyan]
  -t, --targets PATH    File with target domains (one per line)
  -d, --domain TEXT     Individual target domain (repeatable)
  -q, --quiet           Suppress verbose output
  -o, --output PATH     Save findings JSON to file

[bold cyan]EXAMPLES:[/bold cyan]
  beatrix rapid -d shopify.com -d gitlab.com
  beatrix rapid -t targets.txt -o findings.json
""",
    "haiku-hunt": """
[bright_yellow]🤖 HAIKU-HUNT — AI-Assisted Vulnerability Hunting[/bright_yellow]

[bold]Let Lil Bro do the grunt work.[/bold] Uses Claude Haiku via AWS Bedrock
for cheap (~$0.004/burst), fast AI-assisted vulnerability detection.

[bold cyan]USAGE:[/bold cyan]
  beatrix haiku-hunt TARGET [OPTIONS]

[bold cyan]OPTIONS:[/bold cyan]
  --no-ai              Disable AI analysis (scanners only)
  -d, --deep           Deep scan mode
  --region TEXT         AWS region for Bedrock (default: us-east-1)
  -o, --output PATH    Save findings JSON to file

[bold cyan]EXAMPLES:[/bold cyan]
  beatrix haiku-hunt example.com
  beatrix haiku-hunt example.com --deep -o results.json
""",
    "github-recon": """
[bright_yellow]🔍 GITHUB-RECON — GitHub Secret Scanner[/bright_yellow]

[bold]Dig through the trash.[/bold] Scan a GitHub org/user for leaked secrets:
API keys, passwords, tokens, database credentials, private keys.

[bold cyan]USAGE:[/bold cyan]
  beatrix github-recon ORG [OPTIONS]

[bold cyan]OPTIONS:[/bold cyan]
  --repo TEXT           Specific repo (org/repo format)
  --token TEXT          GitHub personal access token
  --quick               Quick scan (skip git history)
  -o, --output PATH    Save report to file

[bold cyan]WHAT IT SCANS:[/bold cyan]
  • Hardcoded API keys, passwords, tokens
  • Database credentials in config files
  • Secrets committed then sanitized (git history)
  • Private keys, cloud credentials

[bold cyan]EXAMPLES:[/bold cyan]
  beatrix github-recon acme-corp
  beatrix github-recon acme-corp --quick
  beatrix github-recon acme-corp --repo acme-corp/api-server -o report.md
""",
    "h1": """
[bright_yellow]🎯 H1 — HackerOne Operations[/bright_yellow]

[bold]Report management.[/bold] Submit reports, check for duplicates, list programs.

[bold cyan]SUBCOMMANDS:[/bold cyan]
  beatrix h1 programs               List available programs
  beatrix h1 programs -s "target"   Search for a specific program
  beatrix h1 dupecheck PROGRAM KWS  Check for duplicate reports
  beatrix h1 submit PROGRAM [OPTS]  Submit a report

[bold cyan]EXAMPLES:[/bold cyan]
  [dim]# Search for a program[/dim]
  beatrix h1 programs -s "example"

  [dim]# Check for dupes before submitting[/dim]
  beatrix h1 dupecheck example cors misconfiguration

  [dim]# Submit a report[/dim]
  beatrix h1 submit example -t "CORS Misconfig" -f report.md -i "Account takeover" -s high

  [dim]# Dry run submission[/dim]
  beatrix h1 submit example -t "CORS Misconfig" -f report.md -i "ATO" -s high --dry-run
""",
    "validate": """
[bright_yellow]✅ VALIDATE — Finding Validation[/bright_yellow]

[bold]The Readiness Gate.[/bold] Run ImpactValidator + ReadinessGate on previously
discovered findings. Prevents you from submitting theoretical garbage.

[bold cyan]USAGE:[/bold cyan]
  beatrix validate FINDINGS_FILE

[bold cyan]ARGUMENTS:[/bold cyan]
  FINDINGS_FILE    JSON report file with findings

[bold cyan]WHAT IT CHECKS:[/bold cyan]
  • Real exploitable impact (not theoretical)
  • Reproducible PoC
  • Proper evidence
  • Report completeness
  • Would it survive hostile triage?

[bold cyan]EXAMPLES:[/bold cyan]
  beatrix validate beatrix_report_20260206.json
""",
    "config": """
[bright_yellow]⚙️  CONFIG — Configuration Management[/bright_yellow]

Settings are stored in [bold]~/.beatrix/config.yaml[/bold].

[bold cyan]USAGE:[/bold cyan]
  beatrix config --show                   Show current config
  beatrix config --set KEY VALUE          Set a config value

[bold cyan]CONFIG KEYS:[/bold cyan]
  scanning.threads      Number of concurrent threads (default: 50)
  scanning.rate_limit   Requests per second (default: 100)
  scanning.timeout      HTTP timeout in seconds (default: 10)
  ai.enabled            Enable AI features (true/false)
  ai.provider           AI provider: "bedrock" or "anthropic"
  ai.model              Model name
  output.dir            Default output directory
  output.verbose        Verbose logging (true/false)

[bold cyan]EXAMPLES:[/bold cyan]
  beatrix config --show
  beatrix config --set scanning.rate_limit 50
  beatrix config --set ai.enabled true
  beatrix config --set output.dir ./my_results
""",
    "mobile": """
[bright_yellow]📱 MOBILE — Mobile App Traffic Interception[/bright_yellow]

[bold]Intercept and analyze mobile app traffic.[/bold]

[bold cyan]SUBCOMMANDS:[/bold cyan]
  beatrix mobile intercept    Launch emulator with proxy, capture traffic
  beatrix mobile analyze      Analyze previously captured traffic
  beatrix mobile bykea        Bykea-specific interception

[bold cyan]EXAMPLES:[/bold cyan]
  beatrix mobile intercept --avd my_emulator -p com.example.app
  beatrix mobile analyze capture.json --secrets known_secrets.json
""",
    "arsenal": """
[bright_yellow]⚔️  ARSENAL — The Weapons Cache[/bright_yellow]

[bold]Full reference for every scanner module in Beatrix.[/bold]
Run [green]beatrix arsenal[/green] to see the full table with payload counts and OWASP mapping.

Each module can be used with:
  [green]beatrix strike TARGET -m MODULE[/green]
  [green]beatrix hunt TARGET -m MODULE -m MODULE[/green]
""",
    "list": """
[bright_yellow]📋 LIST — Available Modules & Presets[/bright_yellow]

Show what weapons and configurations are available.

[bold cyan]USAGE:[/bold cyan]
  beatrix list --modules     Show loaded scanner modules
  beatrix list --presets     Show scan presets
  beatrix list               Show both

[bold cyan]SEE ALSO:[/bold cyan]
  beatrix arsenal            Detailed module reference with payload counts
""",
}


# =============================================================================
# MODULE REFERENCE
# =============================================================================

MODULE_REFERENCE = {
    # ── Phase 1: Reconnaissance ───────────────────────────────────────────────
    "crawl": {
        "name": "Target Crawler",
        "category": "Reconnaissance",
        "description": "Builds attack surface — discovers URLs, parameters, forms, JS files, technologies",
        "payloads": "Link extraction, form parsing, JS URL discovery, tech fingerprinting",
    },
    "endpoint_prober": {
        "name": "Endpoint Prober",
        "category": "Reconnaissance",
        "description": "Discovers and probes API endpoints, admin panels, debug routes",
        "payloads": "Common path wordlist, status code analysis, response fingerprinting",
    },
    "js_analysis": {
        "name": "JS Bundle Analyzer",
        "category": "Reconnaissance",
        "description": "Extracts API routes, secrets, internal hostnames from JavaScript bundles",
        "payloads": "Regex pattern matching, entropy analysis for secrets",
    },
    "headers": {
        "name": "Header Security Scanner",
        "category": "A02: Cryptographic Failures",
        "description": "Analyzes security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.",
        "payloads": "Passive analysis, no active payloads",
    },
    "github_recon": {
        "name": "GitHub Recon Scanner",
        "category": "Reconnaissance",
        "description": "Searches GitHub repos for leaked API keys, DB creds, private keys",
        "payloads": "30+ secret patterns, git history analysis, org-wide scanning",
    },
    # ── Phase 2: Weaponization ────────────────────────────────────────────────
    "takeover": {
        "name": "Subdomain Takeover Scanner",
        "category": "Subdomain Takeover",
        "description": "Checks for dangling CNAME records pointing to claimable services",
        "payloads": "30+ service fingerprints (AWS S3, Heroku, Azure, GitHub Pages, Netlify, etc.)",
    },
    "error_disclosure": {
        "name": "Error Disclosure Scanner",
        "category": "A05: Security Misconfiguration",
        "description": "Triggers error responses to find stack traces, SQL errors, debug info",
        "payloads": "Malformed requests, invalid types, boundary values, special characters",
    },
    "cache_poisoning": {
        "name": "Cache Poisoning Scanner",
        "category": "A05: Security Misconfiguration",
        "description": "Web cache poisoning: CDN fingerprint, unkeyed headers, param cloaking",
        "payloads": "Fat GET, unkeyed header injection, cache deception, parameter cloaking",
    },
    "prototype_pollution": {
        "name": "Prototype Pollution Scanner",
        "category": "A08: Integrity Failures",
        "description": "Server-side __proto__ injection, Express QS pollution, client-side URL tests",
        "payloads": "JSON __proto__, constructor.prototype, Express query string variants",
    },
    # ── Phase 3: Delivery ─────────────────────────────────────────────────────
    "cors": {
        "name": "CORS Scanner",
        "category": "A02: Cryptographic Failures",
        "description": "Tests for CORS misconfigurations: origin reflection, null origin, wildcard, credential leaks",
        "payloads": "17+ test origins including subdomain tricks, null, protocol downgrade",
    },
    "redirect": {
        "name": "Open Redirect Scanner",
        "category": "Redirect Issues",
        "description": "Detects open redirects in URL parameters, valuable in OAuth chains",
        "payloads": "30+ redirect payloads including double-encoding, protocol-relative",
    },
    "oauth_redirect": {
        "name": "OAuth Redirect Scanner",
        "category": "A07: Authentication Failures",
        "description": "Tests OAuth redirect_uri manipulation for token theft",
        "payloads": "Path traversal, subdomain bypass, fragment tricks, open redirect chains",
    },
    "http_smuggling": {
        "name": "HTTP Smuggling Scanner",
        "category": "Transport Security",
        "description": "CL.TE/TE.CL timing, H2 desync, CRLF injection, 20+ TE obfuscation variants",
        "payloads": "CL.TE, TE.CL, CL.0, H2 smuggling, TE header obfuscation",
    },
    "websocket": {
        "name": "WebSocket Scanner",
        "category": "Transport Security",
        "description": "WebSocket upgrade checks, CSWSH origin validation, auth bypass, plaintext WS",
        "payloads": "Origin manipulation, cookie/token relay, protocol downgrade",
    },
    # ── Phase 4: Exploitation ─────────────────────────────────────────────────
    "injection": {
        "name": "Injection Scanner",
        "category": "A03: Injection",
        "description": "SQL injection, XSS, command injection with WAF bypass payloads",
        "payloads": "50+ SQLi, 30+ XSS, 20+ CMDi payloads with encoding variants",
    },
    "ssti": {
        "name": "SSTI Scanner",
        "category": "A03: Injection",
        "description": "Server-Side Template Injection for 16+ engines (Jinja2, Twig, FreeMarker, etc.)",
        "payloads": "Detection → ID → exploit chain for each template engine",
    },
    "xxe": {
        "name": "XXE Scanner",
        "category": "A03: Injection",
        "description": "XML External Entity: classic, OOB, error-based, XInclude, SSRF via cloud metadata",
        "payloads": "Classic XXE, OOB DNS/HTTP, parameter entities, encoding bypass",
    },
    "deserialization": {
        "name": "Deserialization Scanner",
        "category": "A08: Integrity Failures",
        "description": "Insecure deserialization: Java, PHP, Python pickle, .NET, Ruby, Node, YAML",
        "payloads": "Format detection + gadget chain signatures for 7 languages",
    },
    "ssrf": {
        "name": "SSRF Scanner",
        "category": "A10: SSRF",
        "description": "Server-Side Request Forgery with cloud metadata extraction",
        "payloads": "44 payloads: 16 localhost bypass, 16 cloud metadata (AWS/GCP/Azure), 4 internal, 8 protocol",
    },
    "idor": {
        "name": "IDOR Scanner",
        "category": "A01: Broken Access Control",
        "description": "Insecure Direct Object Reference testing with ID manipulation",
        "payloads": "Sequential, negative, zero, large value, UUID, and path traversal IDs",
    },
    "bac": {
        "name": "Broken Access Control Scanner",
        "category": "A01: Broken Access Control",
        "description": "Tests for broken access controls across endpoints",
        "payloads": "Method override, force browsing, privilege escalation patterns",
    },
    "auth": {
        "name": "Authentication Scanner",
        "category": "A07: Authentication Failures",
        "description": "JWT attacks, 2FA bypass, rate limiting, session management",
        "payloads": "Algorithm none, weak secrets, missing expiration, brute force checks",
    },
    "graphql": {
        "name": "GraphQL Scanner",
        "category": "A02: Cryptographic Failures",
        "description": "GraphQL endpoint discovery, introspection bypass, schema parsing, depth attack, batch",
        "payloads": "Introspection, field suggestion, alias overloading, batch query attacks",
    },
    "mass_assignment": {
        "name": "Mass Assignment Scanner",
        "category": "A01: Broken Access Control",
        "description": "Tests for mass assignment: privilege, financial, account takeover fields",
        "payloads": "30+ payload fields via JSON body + query param injection",
    },
    "business_logic": {
        "name": "Business Logic Scanner",
        "category": "A04: Insecure Design",
        "description": "Numeric boundaries, INT overflow, method confusion, race conditions",
        "payloads": "INT32/64 overflow, parameter pollution, HTTP method tampering",
    },
    "redos": {
        "name": "ReDoS Scanner",
        "category": "Denial of Service",
        "description": "Timing-based Regular Expression DoS with escalating payloads",
        "payloads": "Evil regex patterns for email, URL, numeric handlers",
    },
    "payment": {
        "name": "Payment Scanner",
        "category": "A04: Insecure Design",
        "description": "Checkout flow: price manipulation, coupon abuse, race conditions, IDOR, stage skip",
        "payloads": "Negative price, zero-cent, coupon replay, race condition, stage skipping",
    },
    "nuclei": {
        "name": "Nuclei Scanner",
        "category": "A06: Vulnerable Components",
        "description": "8000+ community templates: CVEs, misconfigs, default logins, exposed panels",
        "payloads": "Dynamic template selection based on target fingerprint",
    },
    # ── Phase 5: Installation ─────────────────────────────────────────────────
    "file_upload": {
        "name": "File Upload Scanner",
        "category": "A04: Insecure Design",
        "description": "Extension bypass (double, null byte), polyglots (GIF/PNG), SVG XSS, path traversal",
        "payloads": "Double extension, null byte, alt extensions, magic bytes, SVG XSS, zip traversal",
    },
}


# =============================================================================
# MAIN CLI GROUP
# =============================================================================

@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="beatrix")
@click.option("--quiet", "-q", is_flag=True, help="Suppress banner")
@click.pass_context
def cli(ctx, quiet):
    """
    \b
    ⚔️  BEATRIX — The Black Mamba
    Bug Bounty Hunting Framework

    \b
    QUICK START:
      beatrix hunt example.com              Scan a target
      beatrix strike example.com -m cors    Run one scanner
      beatrix probe example.com             Check if alive
      beatrix list --modules                See available weapons

    \b
    HELP:
      beatrix help <command>                Detailed command help
      beatrix manual                        Open the full HTML manual
      beatrix arsenal                       Full module reference
      beatrix setup                         Install all external tools
      beatrix --version                     Show version

    \b
    "Revenge is a dish best served with a working PoC."
    """
    ctx.ensure_object(dict)
    ctx.obj["quiet"] = quiet

    if not quiet and ctx.invoked_subcommand is None:
        print_banner()
        _show_quick_reference()
    elif not quiet and ctx.invoked_subcommand not in ("help", "arsenal"):
        print_banner()


def _show_quick_reference():
    """Show quick reference when beatrix is called with no command"""
    console.print()

    table = Table(
        title="[bright_yellow]The Death List — Command Reference[/bright_yellow]",
        show_header=True,
        header_style="bold cyan",
        border_style="bright_yellow",
        pad_edge=True,
    )
    table.add_column("Command", style="bold green", min_width=25)
    table.add_column("Description", style="white")
    table.add_column("Example", style="dim")

    table.add_row("hunt TARGET", "Full vulnerability scan", "beatrix hunt example.com")
    table.add_row("strike TARGET -m MOD", "Single module attack", "beatrix strike api.com -m cors")
    table.add_row("probe TARGET", "Quick alive check", "beatrix probe example.com")
    table.add_row("recon DOMAIN", "Reconnaissance", "beatrix recon example.com --deep")
    table.add_row("batch FILE -m MOD", "Mass scanning", "beatrix batch targets.txt -m cors")
    table.add_row("bounty-hunt TARGET", "OWASP Top 10 pipeline", "beatrix bounty-hunt https://api.com")
    table.add_row("rapid", "Multi-target quick sweep", "beatrix rapid -d shopify.com")
    table.add_row("haiku-hunt TARGET", "AI-assisted hunting", "beatrix haiku-hunt example.com")
    table.add_row("ghost TARGET", "AI autonomous pentester", "beatrix ghost https://api.com")
    table.add_row("github-recon ORG", "GitHub secret scanner", "beatrix github-recon acme-corp")
    table.add_row("validate FILE", "Validate findings", "beatrix validate report.json")
    table.add_row("h1 [sub]", "HackerOne operations", "beatrix h1 programs")
    table.add_row("mobile [sub]", "Mobile traffic intercept", "beatrix mobile intercept")
    table.add_row("config", "Configuration", "beatrix config --show")
    table.add_row("list", "List modules/presets", "beatrix list --modules")
    table.add_row("arsenal", "Full module reference", "beatrix arsenal")
    table.add_row("help CMD", "Detailed command help", "beatrix help hunt")
    table.add_row("manual", "Open HTML manual in browser", "beatrix manual")
    table.add_row("setup", "Install all external tools", "beatrix setup")

    console.print(table)
    console.print()
    console.print('[dim]Run [bold]beatrix help <command>[/bold] for detailed usage on any command.[/dim]')
    console.print()


# =============================================================================
# HELP COMMAND — Detailed per-command help
# =============================================================================

@cli.command("help")
@click.argument("command", required=False)
@click.pass_context
def help_cmd(ctx, command):
    """
    Show detailed help for a command.

    \b
    Examples:
        beatrix help hunt
        beatrix help strike
        beatrix help ghost
    """
    if command is None:
        # Show top-level help
        print_banner()
        _show_quick_reference()
        return

    command = command.lower().strip()

    if command in COMMAND_HELP:
        console.print(Panel(
            COMMAND_HELP[command],
            title=f"[bold bright_yellow]beatrix {command}[/bold bright_yellow]",
            border_style="bright_yellow",
            padding=(1, 2),
        ))
    else:
        console.print(f"[yellow]Unknown command: '{command}'[/yellow]")
        console.print(f"[dim]Available commands: {', '.join(sorted(COMMAND_HELP.keys()))}[/dim]")


# =============================================================================
# ARSENAL — Full module reference
# =============================================================================

@cli.command("arsenal")
@click.pass_context
def arsenal(ctx):
    """
    Display the full BEATRIX arsenal — all scanner modules with details.

    \b
    "Every weapon has a purpose."
    """
    console.print()
    console.print(Panel(
        "[bold bright_yellow]⚔️  THE ARSENAL — Available Weapons[/bold bright_yellow]\n\n"
        "[dim]Each module is a battle-tested scanner that can be used with:[/dim]\n"
        "  [green]beatrix strike TARGET -m MODULE[/green]\n"
        "  [green]beatrix hunt TARGET -m MODULE -m MODULE[/green]",
        border_style="bright_yellow",
    ))
    console.print()

    table = Table(
        show_header=True,
        header_style="bold cyan",
        border_style="bright_yellow",
        pad_edge=True,
    )
    table.add_column("Module", style="bold green", min_width=18)
    table.add_column("OWASP Category", style="yellow", min_width=22)
    table.add_column("Description", style="white")
    table.add_column("Payloads", style="dim", min_width=20)

    for mod_name, mod_info in MODULE_REFERENCE.items():
        table.add_row(
            mod_name,
            mod_info["category"],
            mod_info["description"],
            mod_info["payloads"],
        )

    console.print(table)

    # Show external tool integrations
    console.print()
    console.print("[bold bright_yellow]🔧 External Tool Integrations[/bold bright_yellow]")
    ext_table = Table(show_header=True, header_style="bold cyan", border_style="dim", pad_edge=True)
    ext_table.add_column("Tool", style="bold green", min_width=15)
    ext_table.add_column("Status", style="white", min_width=12)
    ext_table.add_column("Purpose", style="dim")

    import shutil
    tools = [
        ("nuclei", "CVE scanning, misconfigs, default logins, 8000+ templates"),
        ("subfinder", "Passive subdomain enumeration from multiple sources"),
        ("httpx", "Rapid live-host probing and fingerprinting"),
        ("ffuf", "Directory fuzzing, parameter discovery, content brute-forcing"),
        ("katana", "Deep crawling and JavaScript analysis"),
        ("sqlmap", "Advanced database takeover and SQL injection exploitation"),
        ("nmap", "Port scanning, service detection, vulnerability scripts"),
        ("adb", "Android Debug Bridge for mobile app interception"),
        ("mitmproxy", "SSL/TLS traffic interception for mobile testing"),
        ("playwright", "Browser automation for DOM XSS and WAF evasion"),
        ("amass", "Advanced subdomain enumeration and attack surface mapping"),
        ("whatweb", "Technology fingerprinting and version detection"),
        ("webanalyze", "Technology fingerprinting and version detection (Wappalyzer engine)"),
        ("gospider", "Fast web spidering and URL discovery"),
        ("hakrawler", "Web crawler for discovering endpoints and assets"),
        ("gau", "Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl"),
        ("dirsearch", "Web path scanner and directory brute-forcing"),
        ("dalfox", "Parameter analysis and XSS scanning"),
        ("commix", "Automated command injection exploitation"),
        ("jwt_tool", "JSON Web Token manipulation and vulnerability testing"),
        ("msfconsole", "Metasploit Framework for advanced exploitation and post-exploitation"),
    ]
    for tool_name, purpose in tools:
        found = shutil.which(tool_name)
        status = "[green]✓ installed[/green]" if found else "[dim]○ not found[/dim]"
        ext_table.add_row(tool_name, status, purpose)

    console.print(ext_table)

    # Show standalone CLI-only modules
    console.print()
    console.print("[dim]Standalone modules (CLI-only, not in kill chain):[/dim]")
    standalone = [
        ("mobile_interceptor", "Android traffic capture via mitmproxy"),
        ("browser_scanner", "Playwright-based DOM XSS, clickjacking (needs playwright)"),
        ("credential_validator", "Validates leaked creds: AWS keys, GitHub tokens, Stripe, etc."),
        ("origin_ip_discovery", "WAF bypass via origin IP discovery"),
        ("power_injector", "Advanced SQLi/XSS/CMDi with 2000+ payloads"),
        ("polyglot_generator", "XSS polyglot & mXSS payload generator"),
    ]
    standalone_table = Table(show_header=False, border_style="dim", pad_edge=True)
    standalone_table.add_column("Module", style="dim green", min_width=22)
    standalone_table.add_column("Description", style="dim")
    for name, desc in standalone:
        standalone_table.add_row(name, desc)
    console.print(standalone_table)
    console.print()


# =============================================================================
# MANUAL — Open the comprehensive HTML manual in the user's browser
# =============================================================================

def _find_manual() -> Path | None:
    """Locate the manual HTML across all installation methods."""
    candidates = []

    # 1. Shipped inside the package wheel (pipx / pip install)
    pkg_dir = Path(__file__).resolve().parent.parent  # beatrix/
    candidates.append(pkg_dir / "_manual" / "index.html")

    # 2. Relative to source tree (editable / git clone)
    src_root = pkg_dir.parent  # repo root
    candidates.append(src_root / "docs" / "manual" / "index.html")

    # 3. Try git rev-parse if we're anywhere inside the repo
    try:
        import subprocess
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            repo = Path(result.stdout.strip())
            candidates.append(repo / "docs" / "manual" / "index.html")
    except Exception:
        pass

    for path in candidates:
        if path.exists():
            return path
    return None


@cli.command("manual")
@click.pass_context
def manual_cmd(ctx):
    """
    Open the BEATRIX manual in your default browser.

    \b
    Launches the comprehensive HTML reference manual covering
    all commands, modules, presets, and workflows.

    \b
    Examples:
        beatrix manual
    """
    import webbrowser

    manual_path = _find_manual()

    if manual_path is None:
        console.print("[red]✗ Manual not found.[/red]")
        console.print("[dim]Try reinstalling Beatrix: pipx install --force .[/dim]")
        raise SystemExit(1)

    url = manual_path.as_uri()
    console.print(f"[bright_yellow]📖 Opening manual in your browser...[/bright_yellow]")
    console.print(f"[dim]{url}[/dim]")
    webbrowser.open(url)


# =============================================================================
# SETUP — Install all external dependencies automatically
# =============================================================================

def _find_install_sh() -> Path | None:
    """Locate install.sh across all installation methods."""
    candidates = []

    pkg_dir = Path(__file__).resolve().parent.parent  # beatrix/
    src_root = pkg_dir.parent  # repo root

    # Editable / git clone
    candidates.append(src_root / "install.sh")

    # Try git rev-parse
    try:
        import subprocess
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            repo = Path(result.stdout.strip())
            candidates.append(repo / "install.sh")
    except Exception:
        pass

    for path in candidates:
        if path.exists():
            return path
    return None


@cli.command("setup")
@click.option("--check", is_flag=True, help="Only check tool status, don't install")
@click.pass_context
def setup_cmd(ctx, check):
    """
    Install all external security tools (the full arsenal).

    \b
    Automatically installs all 21 external dependencies:
    nuclei, httpx, subfinder, ffuf, katana, sqlmap, nmap,
    adb, mitmproxy, playwright, amass, whatweb, webanalyze,
    gospider, hakrawler, gau, dirsearch, dalfox, commix,
    jwt_tool, and metasploit.

    \b
    Uses the best method for each tool:
      • System packages (apt/dnf/pacman) for nmap, sqlmap, etc.
      • Go install for nuclei, subfinder, httpx, ffuf, etc.
      • pip for mitmproxy, playwright, dirsearch, commix
      • Go install for webanalyze
      • Official installer for metasploit

    \b
    Examples:
        beatrix setup           Install all missing tools
        beatrix setup --check   Just show what's installed
    """
    import shutil
    import subprocess

    tools = [
        "nuclei", "httpx", "subfinder", "ffuf", "katana", "sqlmap",
        "nmap", "adb", "mitmproxy", "playwright", "amass", "whatweb",
        "webanalyze", "gospider", "hakrawler", "gau", "dirsearch",
        "dalfox", "commix", "jwt_tool", "msfconsole",
    ]

    if check:
        # Check-only mode
        from rich.table import Table
        table = Table(title="External Tools Status", border_style="bright_yellow")
        table.add_column("Tool", style="bold")
        table.add_column("Status", justify="center")
        table.add_column("Path", style="dim")

        found = 0
        for tool in tools:
            path = shutil.which(tool)
            if path:
                table.add_row(tool, "[green]✓ installed[/green]", path)
                found += 1
            else:
                table.add_row(tool, "[red]✗ missing[/red]", "")

        console.print(table)
        console.print(f"\n[bold]{found}/{len(tools)}[/bold] tools available.")
        if found < len(tools):
            console.print("[dim]Run [bold]beatrix setup[/bold] (without --check) to install missing tools.[/dim]")
        return

    # Install mode — delegate to install.sh
    install_sh = _find_install_sh()

    if install_sh is None:
        # Fallback: download install.sh from GitHub
        console.print("[bright_yellow]Downloading installer from GitHub...[/bright_yellow]")
        try:
            result = subprocess.run(
                ["curl", "-sSL", "https://raw.githubusercontent.com/SudoPacman-Syuu/Beatrix/main/install.sh"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and "install_external_tools" in result.stdout:
                import tempfile
                with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
                    f.write(result.stdout)
                    install_sh = Path(f.name)
                install_sh.chmod(0o755)
            else:
                console.print("[red]✗ Could not download installer.[/red]")
                raise SystemExit(1)
        except Exception as e:
            console.print(f"[red]✗ Failed to fetch installer: {e}[/red]")
            raise SystemExit(1)

    console.print("[bright_yellow]⚔️  Arming the full arsenal...[/bright_yellow]")
    console.print(f"[dim]Using {install_sh}[/dim]\n")

    # Source install.sh and call install_external_tools directly
    bash_cmd = f'source "{install_sh}" && install_external_tools'
    try:
        proc = subprocess.run(
            ["bash", "-c", bash_cmd],
            env={**__import__("os").environ, "PYTHON": shutil.which("python3") or "python3"},
        )
        raise SystemExit(proc.returncode)
    except FileNotFoundError:
        console.print("[red]✗ bash not found.[/red]")
        raise SystemExit(1)


# =============================================================================
# HUNT — Main scanning command
# =============================================================================

@cli.command()
@click.argument("target")
@click.option(
    "--preset", "-p",
    type=click.Choice(["quick", "standard", "full", "stealth", "injection", "api", "web", "recon"]),
    default="standard",
    help="Scan preset (run 'beatrix help hunt' for details)"
)
@click.option("--ai", is_flag=True, help="Enable AI analysis (Claude Haiku)")
@click.option("--modules", "-m", multiple=True, help="Specific modules to run (repeatable)")
@click.option("--output", "-o", type=click.Path(), help="Output directory")
@click.pass_context
def hunt(ctx, target, preset, ai, modules, output):
    """
    Hunt for vulnerabilities on TARGET.

    \b
    Examples:
        beatrix hunt example.com
        beatrix hunt example.com --preset full --ai
        beatrix hunt api.example.com -m cors -m idor

    \b
    Run 'beatrix help hunt' for full documentation.
    """
    from datetime import datetime


    console.print(f"\n[bright_green]⚔️  Initiating hunt on [bold]{target}[/bold][/bright_green]")
    console.print(f"[dim]   Preset: {preset} | AI: {'enabled' if ai else 'disabled'}[/dim]")
    if modules:
        console.print(f"[dim]   Modules: {', '.join(modules)}[/dim]")
    console.print()

    # ── Real-time progress state ──────────────────────────────────────────
    progress_state = {
        "phase": "",
        "phase_icon": "",
        "scanner": "",
        "status": "Initializing...",
        "findings_count": 0,
        "crawl_stats": None,
        "log": [],          # Last N events
        "start_time": datetime.now(),
    }

    def _on_event(event: str, data: dict) -> None:
        """Handle real-time progress events from the kill chain."""
        if event == "phase_start":
            progress_state["phase"] = data.get("phase", "")
            progress_state["phase_icon"] = data.get("icon", "")
            progress_state["status"] = f"Phase: {data.get('phase', '')}"
            progress_state["log"].append(
                f"{data.get('icon', '🔧')} [bold]{data.get('phase', '')}[/bold] — {data.get('description', '')}"
            )
        elif event == "phase_done":
            dur = data.get("duration", 0)
            n = data.get("findings", 0)
            progress_state["log"].append(
                f"  ✓ {data.get('phase', '')} complete — {n} finding{'s' if n != 1 else ''} ({dur:.1f}s)"
            )
        elif event == "crawl_start":
            progress_state["status"] = f"Crawling {data.get('target', '')}..."
            progress_state["log"].append("  🕷️  Crawling target...")
        elif event == "crawl_done":
            stats = {
                "pages": data.get("pages", 0),
                "urls": data.get("urls", 0),
                "params_urls": data.get("params_urls", 0),
                "js_files": data.get("js_files", 0),
                "forms": data.get("forms", 0),
                "technologies": data.get("technologies", []),
                "resolved_url": data.get("resolved_url", ""),
            }
            progress_state["crawl_stats"] = stats
            progress_state["log"].append(
                f"  🕷️  Crawl complete — {stats['pages']} pages, {stats['urls']} URLs, "
                f"{stats['params_urls']} with params, {stats['js_files']} JS files"
            )
            if stats["technologies"]:
                progress_state["log"].append(
                    f"  🔬 Technologies: {', '.join(stats['technologies'])}"
                )
        elif event == "crawl_error":
            progress_state["log"].append(f"  [red]✗ Crawl error: {data.get('error', '')}[/red]")
        elif event == "scanner_start":
            progress_state["scanner"] = data.get("scanner", "")
            progress_state["status"] = f"Running {data.get('scanner', '')} on {data.get('target', '')}"
            progress_state["log"].append(f"  ▸ {data.get('scanner', '')} → {data.get('target', '')}")
        elif event == "scanner_done":
            n = data.get("findings", 0)
            if n > 0:
                progress_state["log"].append(
                    f"  [yellow]  ⚡ {data.get('scanner', '')} found {n} issue{'s' if n != 1 else ''}[/yellow]"
                )
        elif event == "scanner_error":
            progress_state["log"].append(
                f"  [dim]  ✗ {data.get('scanner', '')}: {data.get('error', '')}[/dim]"
            )
        elif event == "finding":
            progress_state["findings_count"] += 1
            f = data.get("finding")
            if f:
                sev = getattr(f, 'severity', None)
                icon = sev.icon if sev else "•"
                color = sev.color if sev else "white"
                progress_state["log"].append(
                    f"    {icon} [{color}]{getattr(f, 'title', 'Finding')}[/{color}]"
                )
        elif event == "info":
            progress_state["log"].append(f"  ℹ  {data.get('message', '')}")

        # Keep log to last 50 entries
        if len(progress_state["log"]) > 50:
            progress_state["log"] = progress_state["log"][-50:]

    engine = BeatrixEngine(on_event=_on_event)

    try:
        # Print events to console in real-time (non-blocking)
        import threading
        _printed_count = [0]
        _stop_printer = threading.Event()

        def _printer():
            """Background thread that prints new log entries."""
            while not _stop_printer.is_set():
                while _printed_count[0] < len(progress_state["log"]):
                    line = progress_state["log"][_printed_count[0]]
                    console.print(line)
                    _printed_count[0] += 1
                _stop_printer.wait(0.1)
            # Flush remaining
            while _printed_count[0] < len(progress_state["log"]):
                line = progress_state["log"][_printed_count[0]]
                console.print(line)
                _printed_count[0] += 1

        printer_thread = threading.Thread(target=_printer, daemon=True)
        printer_thread.start()

        state = asyncio.run(engine.hunt(
            target=target,
            preset=preset,
            ai=ai,
            modules=list(modules) if modules else None,
        ))

        _stop_printer.set()
        printer_thread.join(timeout=2)

        console.print()

        # Calculate duration and modules
        duration = (datetime.now() - state.started_at).total_seconds()
        modules_run = set()
        for pr in state.phase_results.values():
            modules_run.update(pr.modules_run)

        # Auto-save to findings database
        hunt_id = None
        try:
            from beatrix.core.findings_db import FindingsDB
            db = FindingsDB()
            hunt_id = db.save_hunt(
                target=target,
                preset=preset,
                findings=engine.findings,
                duration=duration,
                modules_run=sorted(modules_run),
                ai_enabled=ai,
                started_at=state.started_at,
            )
            db.close()
        except Exception:
            pass  # DB save is best-effort

        _display_hunt_results(state, engine, hunt_id=hunt_id)

        # Handle output format
        if output:
            output_path = Path(output)
            if output_path.suffix == ".json" or str(output) == "-":
                # JSON output: to file or stdout
                _export_json(engine.findings, output_path if str(output) != "-" else None)
            else:
                # Directory output: full reports
                from beatrix.reporters import ReportGenerator
                reporter = ReportGenerator(output_dir=output_path)

                batch_path = reporter.generate_batch_report(
                    engine.findings, target, program="Beatrix Hunt"
                )
                console.print(f"\n[green]📄 Batch report saved: {batch_path}[/green]")

                for finding in engine.findings:
                    if finding.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                        report_path = reporter.generate_report(finding, program="Beatrix Hunt")
                        console.print(f"  [dim]→ {report_path.name}[/dim]")

                json_path = output_path / "findings.json"
                reporter.export_json(engine.findings, json_path)
                console.print(f"[green]📦 JSON export saved: {json_path}[/green]")
    except KeyboardInterrupt:
        _stop_printer.set()
        console.print("\n[yellow]Hunt interrupted. Partial results may be available.[/yellow]")
        sys.exit(1)
    except Exception as e:
        _stop_printer.set()
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def _display_hunt_results(state, engine, hunt_id=None):
    """Display hunt results with full detail for each finding."""
    from datetime import datetime

    stats = engine.get_stats()
    duration = (datetime.now() - state.started_at).total_seconds()

    # Count modules actually run
    modules_run = set()
    for pr in state.phase_results.values():
        modules_run.update(pr.modules_run)

    # ── Summary panel ─────────────────────────────────────────────────
    db_line = f"\n[bold]Hunt ID:[/bold]   #{hunt_id}  [dim](beatrix findings -h {hunt_id})[/dim]" if hunt_id else ""
    summary = f"""
[bold]Target:[/bold]     {state.target}
[bold]Duration:[/bold]   {duration:.1f}s
[bold]Scanners:[/bold]   {len(modules_run)} modules executed
[bold]Findings:[/bold]   {stats['total_findings']}
[bold]Validated:[/bold]  {stats['validated']}{db_line}
    """

    console.print(Panel(summary.strip(), title="[green]Hunt Complete[/green]", border_style="green"))

    if stats["total_findings"] == 0:
        console.print("[dim]No findings discovered. Target appears clean (or try --preset full).[/dim]")
        return

    # ── Severity breakdown table ──────────────────────────────────────
    table = Table(title="Findings by Severity")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    for sev in Severity:
        count = stats["by_severity"].get(sev.value, 0)
        if count > 0:
            table.add_row(
                f"{sev.icon} {sev.value.upper()}",
                str(count),
                style=sev.color
            )

    console.print(table)

    # ── Detailed findings ─────────────────────────────────────────────
    console.print()

    for i, finding in enumerate(engine.findings, 1):
        _render_finding_card(finding, index=i, total=len(engine.findings))

    # ── Module breakdown ──────────────────────────────────────────────
    if stats["by_module"]:
        console.print()
        mod_table = Table(title="Findings by Module", show_header=True)
        mod_table.add_column("Module", style="cyan")
        mod_table.add_column("Count", justify="right")
        for mod, count in sorted(stats["by_module"].items(), key=lambda x: -x[1]):
            mod_table.add_row(mod, str(count))
        console.print(mod_table)

    # ── Footer hints ──────────────────────────────────────────────────
    console.print()
    hints = []
    if hunt_id:
        hints.append(f"[dim]  Query findings:  beatrix findings -h {hunt_id}[/dim]")
        hints.append("[dim]  Finding detail:  beatrix findings show <ID>[/dim]")
        hints.append(f"[dim]  Export JSON:     beatrix findings export -h {hunt_id}[/dim]")
    hints.append("[dim]  All hunts:       beatrix findings hunts[/dim]")
    console.print("\n".join(hints))


def _render_finding_card(finding, index=None, total=None, full=False):
    """
    Render a single finding as a rich panel with key details.

    Args:
        finding: Finding object or dict (from DB)
        index: Finding number in sequence
        total: Total findings count
        full: If True, show full evidence/request/response
    """
    # Handle both Finding objects and dicts from DB
    if isinstance(finding, dict):
        title = finding.get("title", "")
        severity_val = finding.get("severity", "info")
        confidence_val = finding.get("confidence", "tentative")
        url = finding.get("url", "")
        description = finding.get("description", "")
        evidence = finding.get("evidence", "")
        remediation = finding.get("remediation", "")
        scanner = finding.get("scanner_module", "")
        parameter = finding.get("parameter")
        payload = finding.get("payload")
        poc_curl = finding.get("poc_curl")
        request = finding.get("request")
        response = finding.get("response")
        refs = finding.get("refs", [])
        if isinstance(refs, str):
            try:
                refs = json.loads(refs)
            except (json.JSONDecodeError, TypeError):
                refs = []
        owasp = finding.get("owasp_category")
        cwe = finding.get("cwe_id")
        finding_id = finding.get("id")

        # Resolve severity/confidence to enums for display
        try:
            severity = Severity(severity_val)
        except (ValueError, KeyError):
            severity = Severity.INFO
        try:
            confidence = Confidence(confidence_val)
        except (ValueError, KeyError):
            confidence = Confidence.TENTATIVE
    else:
        title = finding.title
        severity = finding.severity
        confidence = finding.confidence
        url = finding.url
        description = finding.description
        evidence = finding.evidence
        remediation = finding.remediation
        scanner = finding.scanner_module
        parameter = finding.parameter
        payload = finding.payload
        poc_curl = finding.poc_curl
        request = finding.request
        response = finding.response
        refs = finding.references or []
        owasp = finding.owasp_category
        cwe = finding.cwe_id
        finding_id = getattr(finding, 'id', None)

    icon = severity.icon
    color = severity.color
    conf_icon = confidence.icon if hasattr(confidence, 'icon') else "?"

    # Build the card content
    lines = []

    # Header: severity + confidence + module
    meta_parts = [
        f"[{color}]{severity.value.upper()}[/{color}]",
        f"Confidence: {confidence.value} {conf_icon}",
    ]
    if scanner:
        meta_parts.append(f"Module: [cyan]{scanner}[/cyan]")
    if finding_id:
        meta_parts.append(f"ID: #{finding_id}")
    lines.append("  ".join(meta_parts))

    # URL
    lines.append(f"[dim]URL:[/dim] {url}")

    # Parameter + Payload (if applicable)
    if parameter:
        lines.append(f"[dim]Parameter:[/dim] {parameter}")
    if payload:
        lines.append(f"[dim]Payload:[/dim] {payload}")

    # Description (always show full)
    if description:
        lines.append("")
        # Wrap long descriptions but don't truncate
        desc_text = description.strip()
        if len(desc_text) > 500 and not full:
            desc_text = desc_text[:500] + "..."
        lines.append(desc_text)

    # Evidence (show key portion)
    if evidence:
        evidence_str = str(evidence)
        lines.append("")
        lines.append("[bold]Evidence:[/bold]")
        if len(evidence_str) > 300 and not full:
            lines.append(f"[dim]{evidence_str[:300]}...[/dim]")
        else:
            lines.append(f"[dim]{evidence_str}[/dim]")

    # Remediation
    if remediation:
        lines.append("")
        lines.append(f"[bold]Remediation:[/bold] {remediation}")

    # PoC curl command
    if poc_curl:
        lines.append("")
        lines.append("[bold]PoC:[/bold]")
        lines.append(f"[dim]  $ {poc_curl}[/dim]")

    # Request/Response (only in full mode)
    if full:
        if request:
            lines.append("")
            lines.append("[bold]Request:[/bold]")
            req_text = request[:2000] if len(request) > 2000 else request
            lines.append(f"[dim]{req_text}[/dim]")
        if response:
            lines.append("")
            lines.append("[bold]Response:[/bold]")
            resp_text = response[:2000] if len(response) > 2000 else response
            lines.append(f"[dim]{resp_text}[/dim]")

    # Classification footer
    class_parts = []
    if owasp:
        class_parts.append(f"OWASP: {owasp}")
    if cwe:
        class_parts.append(f"CWE: {cwe}")
    if refs:
        class_parts.append(f"Refs: {len(refs)}")
    if class_parts:
        lines.append("")
        lines.append(f"[dim]{' | '.join(class_parts)}[/dim]")

    # Build title
    panel_title = f"{icon} [{color}][bold]{title}[/bold][/{color}]"
    if index and total:
        panel_title += f" [{index}/{total}]"

    console.print(Panel(
        "\n".join(lines),
        title=panel_title,
        border_style=color,
        padding=(0, 1),
    ))


def _export_json(findings, filepath=None):
    """Export findings as JSON to file or stdout."""
    import json as _json

    data = []
    for f in findings:
        d = {
            "title": f.title,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "url": f.url,
            "parameter": f.parameter,
            "payload": f.payload,
            "description": f.description,
            "evidence": f.evidence if isinstance(f.evidence, str) else str(f.evidence) if f.evidence else None,
            "request": f.request,
            "response": f.response,
            "impact": f.impact,
            "remediation": f.remediation,
            "poc_curl": f.poc_curl,
            "poc_python": f.poc_python,
            "reproduction_steps": f.reproduction_steps,
            "references": f.references,
            "owasp_category": f.owasp_category,
            "mitre_technique": f.mitre_technique,
            "cwe_id": str(f.cwe_id) if f.cwe_id else None,
            "scanner_module": f.scanner_module,
            "found_at": f.found_at.isoformat(),
            "validated": f.validated,
        }
        data.append(d)

    json_str = _json.dumps(data, indent=2, default=str)

    if filepath:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        Path(filepath).write_text(json_str)
        console.print(f"[green]📦 JSON saved: {filepath}[/green]")
    else:
        # stdout mode
        click.echo(json_str)


# =============================================================================
# FINDINGS — Query, inspect, compare, and export stored findings
# =============================================================================

@cli.group(invoke_without_command=True)
@click.option("--hunt", "-h", "hunt_id", type=int, help="Filter to specific hunt ID")
@click.option("--severity", "-s", type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help="Filter by severity")
@click.option("--module", "-m", help="Filter by scanner module")
@click.option("--target", "-t", help="Filter by target (substring match)")
@click.option("--search", "-q", help="Search title/description/evidence")
@click.option("--limit", "-n", type=int, default=50, help="Max results (default: 50)")
@click.pass_context
def findings(ctx, hunt_id, severity, module, target, search, limit):
    """
    Query and inspect stored findings from past hunts.

    \b
    "The lioness has rejoined her cub, and all is right in the jungle."

    \b
    Every hunt is auto-saved. Use this command to query, drill into,
    compare, and export findings at any time.

    \b
    Examples:
        beatrix findings                          # Recent findings
        beatrix findings -h 3                     # All findings from hunt #3
        beatrix findings -s high                  # All HIGH severity findings
        beatrix findings -m cors                  # All CORS findings
        beatrix findings -t pinterest.com         # All findings for a target
        beatrix findings -q "unsafe-eval"         # Search across all fields
        beatrix findings show 42                  # Full detail for finding #42
        beatrix findings hunts                    # List all past hunts
        beatrix findings export -h 3              # Export hunt #3 as JSON
        beatrix findings diff 2 3                 # Compare two hunts
        beatrix findings delete 1                 # Delete hunt #1
    """
    if ctx.invoked_subcommand is not None:
        return  # Subcommand will handle it

    from beatrix.core.findings_db import FindingsDB

    try:
        db = FindingsDB()
    except Exception as e:
        console.print(f"[red]Database error: {e}[/red]")
        sys.exit(1)

    results = db.get_findings(
        hunt_id=hunt_id,
        severity=severity,
        module=module,
        target=target,
        search=search,
        limit=limit,
    )

    if not results:
        console.print("[dim]No findings match your query.[/dim]")
        if not hunt_id:
            console.print("[dim]Run a hunt first: beatrix hunt example.com[/dim]")
        db.close()
        return

    # Group header
    filter_desc = []
    if hunt_id:
        filter_desc.append(f"hunt #{hunt_id}")
    if severity:
        filter_desc.append(f"severity={severity}")
    if module:
        filter_desc.append(f"module={module}")
    if target:
        filter_desc.append(f"target={target}")
    if search:
        filter_desc.append(f'search="{search}"')

    header = f"[bold]{len(results)} finding{'s' if len(results) != 1 else ''}[/bold]"
    if filter_desc:
        header += f" [dim]({', '.join(filter_desc)})[/dim]"
    console.print(f"\n{header}\n")

    # Render findings table
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("ID", style="dim", width=5, justify="right")
    table.add_column("Sev", width=3)
    table.add_column("Conf", width=4, style="dim")
    table.add_column("Title", min_width=30)
    table.add_column("Module", style="cyan", width=16)
    table.add_column("URL", style="dim", max_width=40)

    for f in results:
        try:
            sev = Severity(f["severity"])
        except (ValueError, KeyError):
            sev = Severity.INFO
        try:
            conf = Confidence(f["confidence"])
        except (ValueError, KeyError):
            conf = Confidence.TENTATIVE

        # Truncate URL for table display
        url = f.get("url", "")
        if len(url) > 40:
            url = url[:37] + "..."

        table.add_row(
            str(f["id"]),
            sev.icon,
            conf.icon,
            f"[{sev.color}]{f['title']}[/{sev.color}]",
            f.get("scanner_module", ""),
            url,
        )

    console.print(table)
    console.print("\n[dim]Tip: beatrix findings show <ID> for full detail[/dim]")

    db.close()


@findings.command("show")
@click.argument("finding_id", type=int)
def findings_show(finding_id):
    """
    Show full detail for a specific finding.

    \b
    Examples:
        beatrix findings show 42
        beatrix findings show 1
    """
    from beatrix.core.findings_db import FindingsDB

    db = FindingsDB()
    f = db.get_finding_detail(finding_id)
    db.close()

    if not f:
        console.print(f"[red]Finding #{finding_id} not found.[/red]")
        sys.exit(1)

    _render_finding_card(f, full=True)


@findings.command("hunts")
@click.option("--target", "-t", help="Filter by target")
@click.option("--limit", "-n", type=int, default=20, help="Max results")
def findings_hunts(target, limit):
    """
    List all past hunts.

    \b
    Examples:
        beatrix findings hunts
        beatrix findings hunts -t pinterest
    """
    from beatrix.core.findings_db import FindingsDB

    db = FindingsDB()
    hunts = db.list_hunts(target=target, limit=limit)
    db.close()

    if not hunts:
        console.print("[dim]No hunts recorded yet. Run: beatrix hunt example.com[/dim]")
        return

    table = Table(title="[bright_yellow]Hunt History[/bright_yellow]", show_header=True)
    table.add_column("ID", style="bold cyan", justify="right", width=5)
    table.add_column("Target", min_width=20)
    table.add_column("Preset", width=10)
    table.add_column("Findings", justify="right", width=9)
    table.add_column("Duration", justify="right", width=9)
    table.add_column("Date", style="dim", width=19)
    table.add_column("AI", width=3)

    for h in hunts:
        dur = h.get("duration_secs", 0)
        dur_str = f"{dur:.1f}s" if dur < 120 else f"{dur/60:.1f}m"
        date_str = h.get("started_at", "")[:19]
        ai_str = "✓" if h.get("ai_enabled") else ""

        table.add_row(
            str(h["id"]),
            h.get("target", ""),
            h.get("preset", ""),
            str(h.get("total_findings", 0)),
            dur_str,
            date_str,
            ai_str,
        )

    console.print(table)
    console.print("\n[dim]Tip: beatrix findings -h <ID> to see findings from a specific hunt[/dim]")


@findings.command("export")
@click.option("--hunt", "-h", "hunt_id", type=int, help="Export specific hunt")
@click.option("--severity", "-s", type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("--module", "-m", help="Filter by module")
@click.option("--target", "-t", help="Filter by target")
@click.option("--output", "-o", type=click.Path(), help="Output file (default: stdout)")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "jsonl", "csv"]),
              default="json", help="Export format")
def findings_export(hunt_id, severity, module, target, output, fmt):
    """
    Export findings as JSON, JSONL, or CSV.

    \b
    Examples:
        beatrix findings export -h 3                    # JSON to stdout
        beatrix findings export -h 3 -o results.json    # JSON to file
        beatrix findings export -s high -f csv -o h.csv # CSV of high findings
        beatrix findings export -f jsonl | jq .title    # Pipe JSONL to jq
    """
    from beatrix.core.findings_db import FindingsDB

    db = FindingsDB()
    results = db.get_findings(
        hunt_id=hunt_id,
        severity=severity,
        module=module,
        target=target,
        limit=10000,
    )
    db.close()

    if not results:
        console.print("[dim]No findings match your query.[/dim]", err=True)
        sys.exit(1)

    # Parse JSON fields
    for f in results:
        for key in ("refs", "reproduction_steps"):
            try:
                f[key] = json.loads(f.get(key, "[]") or "[]")
            except (json.JSONDecodeError, TypeError):
                f[key] = []

    if fmt == "json":
        output_str = json.dumps(results, indent=2, default=str)
    elif fmt == "jsonl":
        output_str = "\n".join(json.dumps(f, default=str) for f in results)
    elif fmt == "csv":
        import csv
        import io
        buf = io.StringIO()
        fields = ["id", "hunt_id", "severity", "confidence", "title", "url",
                   "scanner_module", "description", "evidence", "remediation"]
        writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
        output_str = buf.getvalue()

    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(output_str)
        console.print(f"[green]📦 Exported {len(results)} findings to {output}[/green]", err=True)
    else:
        click.echo(output_str)


@findings.command("diff")
@click.argument("hunt_a", type=int)
@click.argument("hunt_b", type=int)
def findings_diff(hunt_a, hunt_b):
    """
    Compare findings between two hunts.

    \b
    Shows what's new, fixed, and unchanged between two runs.

    \b
    Examples:
        beatrix findings diff 1 3
    """
    from beatrix.core.findings_db import FindingsDB

    db = FindingsDB()

    ha = db.get_hunt(hunt_a)
    hb = db.get_hunt(hunt_b)
    if not ha or not hb:
        missing = hunt_a if not ha else hunt_b
        console.print(f"[red]Hunt #{missing} not found.[/red]")
        db.close()
        sys.exit(1)

    fa = db.get_findings(hunt_id=hunt_a, limit=10000)
    fb = db.get_findings(hunt_id=hunt_b, limit=10000)
    db.close()

    # Fingerprint findings by title+url+module for comparison
    def fingerprint(f):
        return (f["title"], f["url"], f["scanner_module"])

    set_a = {fingerprint(f): f for f in fa}
    set_b = {fingerprint(f): f for f in fb}

    keys_a = set(set_a.keys())
    keys_b = set(set_b.keys())

    new_findings = keys_b - keys_a
    fixed_findings = keys_a - keys_b
    unchanged = keys_a & keys_b

    console.print(Panel(
        f"[bold]Hunt #{hunt_a}[/bold] ({ha['target']}, {ha.get('total_findings', 0)} findings)\n"
        f"  vs\n"
        f"[bold]Hunt #{hunt_b}[/bold] ({hb['target']}, {hb.get('total_findings', 0)} findings)",
        title="[bright_yellow]Hunt Diff[/bright_yellow]",
        border_style="yellow",
    ))

    if new_findings:
        console.print(f"\n[red]⊕ {len(new_findings)} NEW findings in hunt #{hunt_b}:[/red]")
        for key in sorted(new_findings):
            f = set_b[key]
            sev = Severity(f["severity"]) if f["severity"] in [s.value for s in Severity] else Severity.INFO
            console.print(f"  {sev.icon} [{sev.color}]{f['title']}[/{sev.color}]  [dim]{f['url']}[/dim]")

    if fixed_findings:
        console.print(f"\n[green]⊖ {len(fixed_findings)} FIXED (gone from hunt #{hunt_b}):[/green]")
        for key in sorted(fixed_findings):
            f = set_a[key]
            console.print(f"  [strikethrough dim]{f['title']}  {f['url']}[/strikethrough dim]")

    if unchanged:
        console.print(f"\n[dim]═ {len(unchanged)} unchanged[/dim]")

    console.print()


@findings.command("delete")
@click.argument("hunt_id", type=int)
@click.confirmation_option(prompt="Delete this hunt and all its findings?")
def findings_delete(hunt_id):
    """Delete a hunt and all its findings."""
    from beatrix.core.findings_db import FindingsDB

    db = FindingsDB()
    hunt = db.get_hunt(hunt_id)
    if not hunt:
        console.print(f"[red]Hunt #{hunt_id} not found.[/red]")
        db.close()
        sys.exit(1)

    db.delete_hunt(hunt_id)
    db.close()
    console.print(f"[green]Deleted hunt #{hunt_id} ({hunt['target']}, {hunt.get('total_findings', 0)} findings)[/green]")


@findings.command("summary")
@click.argument("hunt_id", type=int)
def findings_summary(hunt_id):
    """
    Show detailed summary for a specific hunt.

    \b
    Examples:
        beatrix findings summary 3
    """
    from beatrix.core.findings_db import FindingsDB

    db = FindingsDB()
    summary = db.get_hunt_summary(hunt_id)
    db.close()

    if not summary:
        console.print(f"[red]Hunt #{hunt_id} not found.[/red]")
        sys.exit(1)

    # Parse modules_run
    try:
        modules = json.loads(summary.get("modules_run", "[]"))
    except (json.JSONDecodeError, TypeError):
        modules = []

    dur = summary.get("duration_secs", 0)
    dur_str = f"{dur:.1f}s" if dur < 120 else f"{dur/60:.1f}m"

    info = f"""
[bold]Hunt #{hunt_id}[/bold]
[bold]Target:[/bold]     {summary.get('target', '')}
[bold]Preset:[/bold]     {summary.get('preset', '')}
[bold]Date:[/bold]       {summary.get('started_at', '')[:19]}
[bold]Duration:[/bold]   {dur_str}
[bold]AI:[/bold]         {'enabled' if summary.get('ai_enabled') else 'disabled'}
[bold]Modules:[/bold]    {', '.join(modules) if modules else 'unknown'}
[bold]Findings:[/bold]   {summary.get('total_findings', 0)}
    """
    console.print(Panel(info.strip(), border_style="cyan"))

    # Severity breakdown
    by_sev = summary.get("by_severity", {})
    if by_sev:
        table = Table(title="By Severity", show_header=True)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        for sev in Severity:
            count = by_sev.get(sev.value, 0)
            if count > 0:
                table.add_row(f"{sev.icon} {sev.value.upper()}", str(count), style=sev.color)
        console.print(table)

    # Module breakdown
    by_mod = summary.get("by_module", {})
    if by_mod:
        mod_table = Table(title="By Module", show_header=True)
        mod_table.add_column("Module", style="cyan")
        mod_table.add_column("Count", justify="right")
        for mod, count in sorted(by_mod.items(), key=lambda x: -x[1]):
            mod_table.add_row(mod, str(count))
        console.print(mod_table)

    console.print(f"\n[dim]See findings: beatrix findings -h {hunt_id}[/dim]")


# =============================================================================
# PROBE — Quick target check
# =============================================================================

@cli.command()
@click.argument("target")
@click.pass_context
def probe(ctx, target):
    """
    Quick probe to check if TARGET is alive.

    \b
    "Wiggle your big toe."

    Run 'beatrix help probe' for details.
    """
    console.print(f"\n[cyan]🔍 Probing {target}...[/cyan]\n")

    engine = BeatrixEngine()

    try:
        result = asyncio.run(engine.probe(target))

        if result["alive"]:
            console.print("[green]✓ Target is alive[/green]")
            console.print(f"  Status: {result['status_code']}")
            if result.get("title"):
                console.print(f"  Title:  {result['title']}")
            if result.get("server"):
                console.print(f"  Server: {result['server']}")
            if result.get("technologies"):
                console.print(f"  Tech:   {', '.join(result['technologies'])}")
        else:
            console.print("[red]✗ Target is not responding[/red]")
            if result.get("error"):
                console.print(f"  Error: {result['error']}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


# =============================================================================
# STRIKE — Single module execution
# =============================================================================

@cli.command()
@click.argument("target")
@click.option("--module", "-m", required=True,
              help="Module to execute (run 'beatrix arsenal' for list)")
@click.pass_context
def strike(ctx, target, module):
    """
    Execute a single attack MODULE against TARGET.

    \b
    Examples:
        beatrix strike api.example.com -m cors
        beatrix strike example.com/login -m injection

    \b
    Run 'beatrix arsenal' to see all available modules.
    """
    console.print(f"\n[red]⚔️  Striking {target} with [bold]{module}[/bold][/red]\n")

    engine = BeatrixEngine()

    try:
        result = asyncio.run(engine.strike(target, module))

        if result.errors:
            for error in result.errors:
                console.print(f"[red]Error: {error}[/red]")

        console.print("\n[bold]Results:[/bold]")
        console.print(f"  Findings: {len(result.findings)}")
        console.print(f"  Duration: {result.duration:.2f}s")

        for finding in result.findings:
            console.print(f"\n  {finding.severity.icon} [{finding.severity.color}]{finding.title}[/{finding.severity.color}]")
            if finding.url:
                console.print(f"      [dim]{finding.url}[/dim]")
            if finding.evidence:
                evidence_str = str(finding.evidence)[:200]
                console.print(f"      [dim]Evidence: {evidence_str}[/dim]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


# =============================================================================
# LIST — Show available modules/presets
# =============================================================================

@cli.command("list")
@click.option("--modules", "-m", is_flag=True, help="List available modules")
@click.option("--presets", "-p", is_flag=True, help="List available presets")
@click.pass_context
def list_cmd(ctx, modules, presets):
    """
    List available modules or presets.

    \b
    Examples:
        beatrix list --presets
        beatrix list --modules
        beatrix list  (shows both)
    """
    engine = BeatrixEngine()

    if presets or (not modules and not presets):
        table = Table(title="[bright_yellow]Available Presets[/bright_yellow]")
        table.add_column("Preset", style="cyan bold")
        table.add_column("Description")
        table.add_column("Kill Chain Phases", justify="right")

        for name, cfg in engine.PRESETS.items():
            table.add_row(
                name,
                cfg["description"],
                str(cfg["phases"]),
            )

        console.print(table)
        console.print()

    if modules or (not modules and not presets):
        table = Table(title="[bright_yellow]Available Modules[/bright_yellow]")
        table.add_column("Module", style="cyan bold", min_width=18)
        table.add_column("Status")

        for name, mod in engine.modules.items():
            status = "[green]✓ loaded[/green]" if mod else "[dim]— not loaded[/dim]"
            table.add_row(name, status)

        console.print(table)
        console.print()
        console.print("[dim]Tip: Run 'beatrix arsenal' for detailed module documentation.[/dim]")


# =============================================================================
# CONFIG — Configuration management
# =============================================================================

@cli.command()
@click.option("--show", is_flag=True, help="Show current configuration")
@click.option("--set", "set_opt", nargs=2, multiple=True, help="Set config option (KEY VALUE)")
@click.pass_context
def config(ctx, show, set_opt):
    """
    Manage BEATRIX configuration.

    \b
    Configuration is stored in ~/.beatrix/config.yaml

    \b
    Examples:
        beatrix config --show
        beatrix config --set ai.enabled true
        beatrix config --set scanning.rate_limit 50

    \b
    Run 'beatrix help config' for all available keys.
    """
    config_path = Path.home() / ".beatrix" / "config.yaml"

    if show or (not show and not set_opt):
        if config_path.exists():
            console.print(f"[bold]Config file:[/bold] {config_path}")
            console.print()
            console.print(config_path.read_text())
        else:
            console.print(f"[bold]Config file:[/bold] {config_path} [dim](not created yet)[/dim]")
            console.print()
            console.print("[dim]Using defaults. Set a value to create the config file:[/dim]")
            console.print("[dim]  beatrix config --set scanning.rate_limit 50[/dim]")

    if set_opt:
        import yaml

        config_path.parent.mkdir(parents=True, exist_ok=True)

        if config_path.exists():
            data = yaml.safe_load(config_path.read_text()) or {}
        else:
            data = {}

        for key, value in set_opt:
            if value.lower() == "true":
                value = True
            elif value.lower() == "false":
                value = False
            elif value.lower() in ("null", "none"):
                value = None
            else:
                try:
                    value = int(value)
                except ValueError:
                    try:
                        value = float(value)
                    except ValueError:
                        pass

            parts = key.split(".")
            node = data
            for part in parts[:-1]:
                if part not in node or not isinstance(node[part], dict):
                    node[part] = {}
                node = node[part]
            node[parts[-1]] = value
            console.print(f"  [green]✓[/green] {key} = {value!r}")

        config_path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
        console.print(f"\n[bold]Saved to[/bold] {config_path}")


# =============================================================================
# BATCH — Mass scanning
# =============================================================================

@cli.command()
@click.argument("targets_file", type=click.Path(exists=True))
@click.option("--module", "-m", required=True, help="Module to run")
@click.option("--output", "-o", type=click.Path(), default="./reports", help="Output directory")
@click.option("--threads", "-t", default=5, help="Concurrent scans")
@click.pass_context
def batch(ctx, targets_file, module, output, threads):
    """
    Batch scan multiple targets from a file.

    \b
    Examples:
        beatrix batch targets.txt -m cors -o ./reports
        beatrix batch domains.txt -m injection -t 3
    """
    from beatrix.reporters import ReportGenerator

    targets = Path(targets_file).read_text().strip().split("\n")
    targets = [t.strip() for t in targets if t.strip() and not t.startswith("#")]

    console.print(f"\n[bold cyan]📋 Batch scanning {len(targets)} targets with [bold]{module}[/bold][/bold cyan]\n")

    engine = BeatrixEngine()
    reporter = ReportGenerator(Path(output))
    all_findings = []

    for i, target in enumerate(targets, 1):
        console.print(f"[{i}/{len(targets)}] {target}...", end=" ")

        try:
            result = asyncio.run(engine.strike(target, module))

            if result.findings:
                console.print(f"[red]🎯 {len(result.findings)} findings![/red]")
                all_findings.extend(result.findings)

                for finding in result.findings:
                    if finding.severity.value in ["critical", "high"]:
                        report_path = reporter.generate_report(finding)
                        console.print(f"    [dim]Report: {report_path}[/dim]")
            else:
                console.print("[green]✓ clean[/green]")
        except Exception as e:
            console.print(f"[yellow]⚠ {e}[/yellow]")

    console.print("\n[bold]Batch Complete:[/bold]")
    console.print(f"  Targets scanned: {len(targets)}")
    console.print(f"  Total findings:  {len(all_findings)}")

    if all_findings:
        batch_report = reporter.generate_batch_report(all_findings, targets_file)
        console.print(f"  Batch report:    {batch_report}")

        json_path = Path(output) / "findings.json"
        reporter.export_json(all_findings, json_path)
        console.print(f"  JSON export:     {json_path}")


# =============================================================================
# GITHUB RECON
# =============================================================================

@cli.command("github-recon")
@click.argument("org")
@click.option("--repo", help="Specific repo (org/repo format)")
@click.option("--token", help="GitHub personal access token")
@click.option("--quick", is_flag=True, help="Quick scan (skip git history)")
@click.option("--output", "-o", type=click.Path(), help="Output report file (markdown)")
@click.pass_context
def github_recon(ctx, org, repo, token, quick, output):
    """
    Scan a GitHub org/user for leaked secrets.

    \b
    Run 'beatrix help github-recon' for details.
    """
    from beatrix.scanners.github_recon import GitHubRecon

    console.print(f"\n[bright_green]🔍 GitHub Recon on [bold]{org}[/bold][/bright_green]")
    mode = "Quick (no git history)" if quick else "Full (includes git history)"
    console.print(f"[dim]   Mode: {mode}[/dim]\n")

    scanner = GitHubRecon(org_name=org, github_token=token)

    try:
        async def _run():
            async with scanner:
                if quick:
                    return await scanner.quick_scan(repo)
                else:
                    findings = []
                    async for finding in scanner.full_recon():
                        findings.append(finding)
                        console.print(
                            f"  {finding.severity.icon} [{finding.severity.color}]"
                            f"{finding.title}[/{finding.severity.color}]"
                        )
                    return findings

        findings = asyncio.run(_run())

        console.print(f"\n[bold]Results:[/bold] {len(findings)} secrets found")

        if quick:
            for sf in scanner.secret_findings:
                sev_color = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "blue"}.get(
                    sf.severity.value, "white"
                )
                console.print(
                    f"  [{sev_color}][{sf.severity.value.upper()}][/{sev_color}] "
                    f"{sf.secret_type} in {sf.file_path}"
                )
                console.print(f"    [dim]→ {sf.evidence_url}[/dim]")

        if output:
            report = scanner.generate_report()
            Path(output).write_text(report)
            console.print(f"\n[green]Report saved to {output}[/green]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


# =============================================================================
# H1 — HackerOne operations
# =============================================================================

@cli.group()
@click.pass_context
def h1(ctx):
    """
    HackerOne operations — submit, dupecheck, list programs.

    \b
    Run 'beatrix help h1' for details.
    """
    pass


@h1.command("programs")
@click.option("--search", "-s", help="Search for a specific program")
@click.pass_context
def h1_programs(ctx, search):
    """List available HackerOne programs."""
    from beatrix.integrations.hackerone import HackerOneClient

    try:
        client = HackerOneClient()
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    if not client.verify_auth():
        console.print("[red]Authentication failed. Check credentials.[/red]")
        console.print("[dim]Set credentials in ~/.beatrix/config.yaml or config/hackerone_credentials.csv[/dim]")
        sys.exit(1)

    console.print(f"[green]Authenticated as: {client.username}[/green]\n")

    if search:
        program = client.search_program(search)
        if program:
            attrs = program.get("attributes", {})
            console.print(f"[bold]{attrs.get('name')}[/bold] ({attrs.get('handle')})")
            console.print(f"  State:  {attrs.get('state')}")
            console.print(f"  Bounty: {'Yes' if attrs.get('offers_bounties') else 'No'}")
        else:
            console.print(f"[yellow]No program found matching '{search}'[/yellow]")
    else:
        programs = client.get_programs()

        table = Table(title=f"HackerOne Programs ({len(programs)})")
        table.add_column("Handle", style="cyan bold")
        table.add_column("Name")
        table.add_column("State")
        table.add_column("Bounty")

        for p in programs[:25]:
            attrs = p.get("attributes", {})
            table.add_row(
                attrs.get("handle", ""),
                attrs.get("name", ""),
                attrs.get("state", ""),
                "💰" if attrs.get("offers_bounties") else "—",
            )

        console.print(table)
        if len(programs) > 25:
            console.print(f"[dim]  ... and {len(programs) - 25} more[/dim]")


@h1.command("dupecheck")
@click.argument("program")
@click.argument("keywords", nargs=-1, required=True)
@click.pass_context
def h1_dupecheck(ctx, program, keywords):
    """
    Check for duplicate reports before submitting.

    \b
    Examples:
        beatrix h1 dupecheck bykea github leaked credentials
    """
    from beatrix.integrations.hackerone import HackerOneClient

    try:
        client = HackerOneClient()
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    console.print(f"[cyan]Checking for duplicates on '{program}'...[/cyan]")
    console.print(f"[dim]Keywords: {', '.join(keywords)}[/dim]\n")

    dupes = client.check_duplicates(program, list(keywords))

    if dupes:
        console.print(f"[yellow]⚠️  Found {len(dupes)} potential duplicates:[/yellow]\n")
        for d in dupes:
            console.print(f"  [{d['source']}] #{d['id']} — {d['title']}")
            console.print(f"    State: {d.get('state', '?')}, Severity: {d.get('severity', '?')}")
    else:
        console.print("[green]✅ No duplicates found. Clear to submit.[/green]")


@h1.command("submit")
@click.argument("program")
@click.option("--title", "-t", required=True, help="Report title")
@click.option("--body-file", "-f", type=click.Path(exists=True), required=True, help="Report body (markdown file)")
@click.option("--impact", "-i", required=True, help="Impact statement")
@click.option("--severity", "-s", type=click.Choice(["none", "low", "medium", "high", "critical"]), default="high")
@click.option("--cwe", type=int, help="CWE ID")
@click.option("--dry-run", is_flag=True, help="Show what would be submitted without submitting")
@click.pass_context
def h1_submit(ctx, program, title, body_file, impact, severity, cwe, dry_run):
    """
    Submit a report to HackerOne.

    \b
    Examples:
        beatrix h1 submit example -t "CORS Misconfig" -f report.md -i "Account takeover" -s high
        beatrix h1 submit example -t "CORS" -f report.md -i "ATO" --dry-run
    """
    from beatrix.integrations.hackerone import HackerOneClient

    try:
        client = HackerOneClient()
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    body = Path(body_file).read_text()

    if dry_run:
        console.print("[yellow]DRY RUN — not submitting[/yellow]\n")
        console.print(f"[bold]Program:[/bold]  {program}")
        console.print(f"[bold]Title:[/bold]    {title}")
        console.print(f"[bold]Severity:[/bold] {severity}")
        console.print(f"[bold]CWE:[/bold]      {cwe or 'none'}")
        console.print(f"[bold]Impact:[/bold]   {impact}")
        console.print(f"[bold]Body:[/bold]     {len(body)} chars from {body_file}")
        return

    console.print(f"[bright_green]Submitting report to {program}...[/bright_green]")

    result = client.submit_report(
        program_handle=program,
        title=title,
        vulnerability_information=body,
        impact=impact,
        severity_rating=severity,
        weakness_id=cwe,
    )

    if result:
        report_id = result.get("data", {}).get("id", "?")
        console.print(f"\n[bold green]✅ Report #{report_id} submitted![/bold green]")
    else:
        console.print("\n[bold red]❌ Submission failed[/bold red]")
        sys.exit(1)


# =============================================================================
# MOBILE INTERCEPT COMMANDS
# =============================================================================

@cli.group()
@click.pass_context
def mobile(ctx):
    """
    Mobile app traffic interception.

    \b
    Run 'beatrix help mobile' for details.
    """
    pass


@mobile.command("intercept")
@click.option("--avd", default="bykea_hunter", help="AVD name")
@click.option("--apk", help="APK file to install")
@click.option("--package", "-p", default="com.bykea.pk", help="Package to launch")
@click.option("--duration", "-d", type=int, default=300, help="Capture duration (seconds)")
@click.option("--port", type=int, default=8080, help="Proxy port")
@click.pass_context
def mobile_intercept(ctx, avd, apk, package, duration, port):
    """Launch emulator with proxy and capture traffic."""
    from beatrix.scanners.mobile_interceptor import MobileInterceptConfig, MobileInterceptor

    config_obj = MobileInterceptConfig(
        avd_name=avd, proxy_port=port, apk_path=apk, package_name=package,
    )

    interceptor = MobileInterceptor(config_obj)

    console.print(Panel.fit(
        f"[bold]AVD:[/bold]      {avd}\n"
        f"[bold]Proxy:[/bold]    127.0.0.1:{port}\n"
        f"[bold]Package:[/bold]  {package}\n"
        f"[bold]Duration:[/bold] {duration}s",
        title="[bold bright_yellow]📱 Mobile Intercept[/bold bright_yellow]",
    ))

    asyncio.run(interceptor.capture_session(duration=duration))

    analysis = interceptor.analyze_traffic()

    table = Table(title="Traffic Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Total Requests", str(analysis.total_requests))
    table.add_row("Unique Hosts", str(len(analysis.unique_hosts)))
    table.add_row("API Keys Found", str(len(analysis.api_keys_found)))
    table.add_row("JWT Tokens", str(len(analysis.jwt_tokens)))
    table.add_row("Credentials in Bodies", str(len(analysis.credentials_in_body)))
    console.print(table)


@mobile.command("bykea")
@click.option("--apk", help="Bykea APK file path")
@click.option("--duration", "-d", type=int, default=300, help="Capture duration")
@click.pass_context
def mobile_bykea(ctx, apk, duration):
    """Run Bykea-specific interception with leaked key matching."""
    from beatrix.scanners.mobile_interceptor import run_bykea_intercept

    console.print(Panel.fit(
        "[bold red]Bykea Credential Validation[/bold red]\n"
        "Intercepting production traffic to check for leaked keys:\n"
        "  • bl-bkd-key\n"
        "  • JWT secret\n"
        "  • AES encryption keys",
        title="[bold bright_yellow]BEATRIX × Bykea[/bold bright_yellow]",
    ))

    asyncio.run(run_bykea_intercept(duration=duration, apk_path=apk))


@mobile.command("analyze")
@click.argument("capture_file")
@click.option("--secrets", help="JSON file with known secrets to match")
@click.pass_context
def mobile_analyze(ctx, capture_file, secrets):
    """Analyze a previously captured traffic file."""
    import json as _json

    from beatrix.scanners.mobile_interceptor import MobileInterceptConfig, MobileInterceptor

    config_obj = MobileInterceptConfig(capture_file=capture_file)
    interceptor = MobileInterceptor(config_obj)
    interceptor._load_captures()

    known_secrets = None
    if secrets:
        with open(secrets) as f:
            known_secrets = _json.load(f)

    analysis = interceptor.analyze_traffic(known_secrets=known_secrets)
    report = interceptor.generate_report()
    console.print(report)

    if analysis.matched_leaked_keys:
        console.print("\n[bold red]⚠️  LEAKED KEYS CONFIRMED IN TRAFFIC[/bold red]")
        for m in analysis.matched_leaked_keys:
            console.print(f"  [red]✓[/red] {m['secret_name']} → {m['found_in']}")


# =============================================================================
# BOUNTY-HUNT — Full bounty pipeline
# =============================================================================

@cli.command("bounty-hunt")
@click.argument("target")
@click.option("--header", "-H", multiple=True, help='Add header (format: "Name: Value")')
@click.option("--urls", "-u", multiple=True, help="Additional URL paths to scan")
@click.option("--jwt", multiple=True, help="JWT tokens to analyze")
@click.option("--output", "-o", type=click.Path(), help="Output report filename")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.pass_context
def bounty_hunt(ctx, target, header, urls, jwt, output, verbose):
    """
    Full OWASP Top 10 bug bounty hunt with validation.

    \b
    Run 'beatrix help bounty-hunt' for details.
    """
    import importlib.util

    _spec = importlib.util.spec_from_file_location(
        "bounty_hunter", str(Path(__file__).parent.parent.parent / "bounty_hunter.py"))
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    BountyHunter = _mod.BountyHunter

    headers = {}
    for h in header:
        if ':' in h:
            name, value = h.split(':', 1)
            headers[name.strip()] = value.strip()

    url_list = [target]
    for u in urls:
        if u.startswith('/'):
            url_list.append(f"{target.rstrip('/')}{u}")
        else:
            url_list.append(u)

    console.print(f"\n[bright_green]💰 Full bounty hunt on [bold]{target}[/bold][/bright_green]")
    console.print(f"[dim]   URLs: {len(url_list)} | Auth: {list(headers.keys()) or 'None'}[/dim]\n")

    hunter = BountyHunter(target=target, auth_headers=headers, verbose=verbose)

    try:
        findings = asyncio.run(hunter.hunt_all(urls=url_list, jwt_tokens=list(jwt)))

        if findings and output:
            hunter.export_report(output)
        elif findings:
            hunter.export_report()
    except KeyboardInterrupt:
        console.print("\n[yellow]Hunt interrupted.[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


# =============================================================================
# VALIDATE
# =============================================================================

@cli.command("validate")
@click.argument("findings_file", type=click.Path(exists=True))
@click.pass_context
def validate_findings(ctx, findings_file):
    """
    Validate findings from a JSON report file.

    \b
    Run 'beatrix help validate' for details.
    """
    import json as _json

    from beatrix.core.types import Finding, Severity
    from beatrix.validators import ImpactValidator, ReportReadinessGate

    with open(findings_file) as f:
        report = _json.load(f)

    raw_findings = report.get("findings", [])
    console.print(f"\n[cyan]Validating {len(raw_findings)} findings from {findings_file}[/cyan]\n")

    validator = ImpactValidator()
    gate = ReportReadinessGate()

    submittable = 0
    killed = 0
    needs_work = 0

    for rf in raw_findings:
        finding = Finding(
            title=rf.get("title", ""),
            description=rf.get("description", ""),
            severity=Severity(rf.get("severity", "info")),
            url=rf.get("url", ""),
            evidence=rf.get("evidence"),
            cwe_id=rf.get("cwe_id"),
            owasp_category=rf.get("owasp"),
        )

        impact = validator.validate(finding, None)
        readiness = gate.check(finding)

        if impact.kill_checks:
            console.print(f"  [red]🗑️  KILLED[/red]  {finding.title} — {impact.reason}")
            killed += 1
        elif impact.passed and readiness.ready:
            console.print(f"  [green]✅ READY[/green]  {finding.title} (score: {readiness.score}/100)")
            submittable += 1
        else:
            console.print(f"  [yellow]⚠️  WORK[/yellow]  {finding.title}")
            if not impact.passed:
                console.print(f"           Impact: {impact.reason}")
            for c in readiness.failed_required:
                console.print(f"           ❌ {c.name}: {c.reason}")
            needs_work += 1

    console.print("\n[bold]Summary:[/bold]")
    console.print(f"  ✅ Submittable: {submittable}")
    console.print(f"  ⚠️  Needs work:  {needs_work}")
    console.print(f"  🗑️  Killed:      {killed}")


# =============================================================================
# GHOST — Autonomous AI pentester
# =============================================================================

@cli.command("ghost")
@click.argument("target")
@click.option("--objective", "-o", default="Find all security vulnerabilities",
              help="Investigation objective")
@click.option("--method", "-X", default="GET", help="HTTP method for base request")
@click.option("--header", "-H", multiple=True, help='Add header (format: "Name: Value")')
@click.option("--data", "-d", default="", help="Request body")
@click.option("--max-turns", "-t", type=int, default=30, help="Maximum investigation turns")
@click.option("--model", default="claude-sonnet-4-20250514", help="Claude model to use")
@click.option("--api-key", envvar="ANTHROPIC_API_KEY", help="Anthropic API key")
@click.option("--bedrock", is_flag=True, help="Use AWS Bedrock instead of Anthropic API")
@click.pass_context
def ghost(ctx, target, objective, method, header, data, max_turns, model, api_key, bedrock):
    """
    Launch GHOST autonomous penetration testing agent.

    \b
    Run 'beatrix help ghost' for details.
    """
    from beatrix.ai.assistant import AIConfig, AIProvider
    from beatrix.ai.ghost import GhostAgent, PrintCallback

    headers = {}
    for h in header:
        if ':' in h:
            name, value = h.split(':', 1)
            headers[name.strip()] = value.strip()

    if bedrock:
        ai_config = AIConfig(
            provider=AIProvider.BEDROCK, model=model,
            max_tokens=8192, temperature=0.3,
        )
    else:
        ai_config = AIConfig(
            provider=AIProvider.ANTHROPIC, api_key=api_key,
            model=model, max_tokens=8192, temperature=0.3,
        )

    console.print(Panel.fit(
        f"[bold]Target:[/bold]    {target}\n"
        f"[bold]Objective:[/bold] {objective}\n"
        f"[bold]Method:[/bold]    {method}\n"
        f"[bold]Max Turns:[/bold] {max_turns}\n"
        f"[bold]Model:[/bold]     {model}\n"
        f"[bold]Provider:[/bold]  {'Bedrock' if bedrock else 'Anthropic'}",
        title="[bold bright_red]👻 GHOST[/bold bright_red]",
        border_style="red",
    ))

    agent = GhostAgent(config=ai_config, callback=PrintCallback(), max_iterations=max_turns)

    try:
        result = asyncio.run(agent.investigate(
            target_url=target, objective=objective,
            method=method, headers=headers, body=data,
        ))

        verdict_color = "red" if result["verdict"] == "VULNERABLE" else "green"
        console.print(f"\n[bold {verdict_color}]Verdict: {result['verdict']}[/bold {verdict_color}]")
        console.print(f"[dim]Iterations: {result['iterations']} | Responses: {result['responses_analyzed']}[/dim]")

        if result["findings"]:
            console.print(f"\n[bold]Findings ({len(result['findings'])}):[/bold]")
            for finding in result["findings"]:
                console.print(f"  {finding.severity.icon} [{finding.severity.color}]{finding.title}[/{finding.severity.color}]")

    except KeyboardInterrupt:
        agent.stop()
        console.print("\n[yellow]Investigation interrupted.[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


# =============================================================================
# RECON COMMAND
# =============================================================================

@cli.command()
@click.argument("domain")
@click.option("--deep", "-d", is_flag=True, help="Deep scan (check subdomain liveness)")
@click.option("--json-output", "-j", "json_out", is_flag=True, help="Output as JSON")
@click.option("--output", "-o", type=click.Path(), help="Save results to file")
def recon(domain, deep, json_out, output):
    """
    Reconnaissance: subdomain enum, tech detection, JS analysis, endpoint discovery.

    \b
    Run 'beatrix help recon' for details.
    """
    from beatrix.recon import ReconRunner

    console.print(Panel.fit(
        f"[bold]Domain:[/bold] {domain}\n"
        f"[bold]Deep:[/bold]   {deep}",
        title="[bold cyan]🔍 Reconnaissance[/bold cyan]",
        border_style="cyan",
    ))

    runner = ReconRunner(domain, verbose=True)
    result = asyncio.run(runner.run(deep=deep))

    table = Table(title="Recon Results")
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="green")
    table.add_row("Subdomains", str(len(result.subdomains)))
    table.add_row("Endpoints", str(len(result.endpoints)))
    table.add_row("JS Files", str(len(result.js_files)))
    table.add_row("Parameters", str(len(result.parameters)))
    table.add_row("Technologies", str(len(result.technologies)))
    table.add_row("Interesting Findings", str(len(result.interesting_findings)))
    if deep:
        table.add_row("Alive Subdomains", str(len(result.alive_subdomains)))
    console.print(table)

    if result.technologies:
        tech_table = Table(title="Technologies Detected")
        tech_table.add_column("Tech", style="yellow")
        tech_table.add_column("Value", style="dim")
        for tech, val in result.technologies.items():
            tech_table.add_row(tech, val)
        console.print(tech_table)

    if result.interesting_findings:
        console.print("\n[bold]Interesting Findings:[/bold]")
        for note in result.interesting_findings:
            console.print(f"  • {note}")

    if json_out or output:
        import json as jsonlib
        data = result.to_dict()
        if output:
            with open(output, "w") as f:
                jsonlib.dump(data, f, indent=2)
            console.print(f"\n[green]Results saved to {output}[/green]")
        if json_out:
            console.print(jsonlib.dumps(data, indent=2))


# =============================================================================
# RAPID COMMAND
# =============================================================================

@cli.command()
@click.option("--targets", "-t", type=click.Path(exists=True), help="File with target domains")
@click.option("--domain", "-d", multiple=True, help="Individual target domain (repeatable)")
@click.option("--quiet", "-q", is_flag=True, help="Suppress verbose output")
@click.option("--output", "-o", type=click.Path(), help="Save findings JSON to file")
def rapid(targets, domain, quiet, output):
    """
    Rapid multi-target sweep: takeover, debug endpoints, CORS.

    \b
    Run 'beatrix help rapid' for details.
    """
    from beatrix.hunters.rapid import RapidHunter

    target_list = list(domain) if domain else None
    if targets:
        with open(targets) as f:
            target_list = [line.strip() for line in f if line.strip()]

    hunter = RapidHunter(targets=target_list, verbose=not quiet)
    findings = asyncio.run(hunter.run())

    console.print(f"\n[bold]Total findings: {len(findings)}[/bold]")
    if findings:
        for f_item in findings:
            sev = f_item.severity.value.upper()
            console.print(f"  [{sev}] {f_item.title}")
            console.print(f"    {f_item.url}")

    if output:
        import json as jsonlib
        data = [{"title": f_item.title, "severity": f_item.severity.value, "url": f_item.url,
                 "evidence": f_item.evidence, "description": f_item.description}
                for f_item in findings]
        with open(output, "w") as fp:
            jsonlib.dump(data, fp, indent=2)
        console.print(f"\n[green]Results saved to {output}[/green]")


# =============================================================================
# HAIKU-HUNT COMMAND
# =============================================================================

@cli.command("haiku-hunt")
@click.argument("target")
@click.option("--no-ai", is_flag=True, help="Disable AI analysis")
@click.option("--deep", "-d", is_flag=True, help="Deep scan")
@click.option("--region", default="us-east-1", help="AWS region for Bedrock")
@click.option("--output", "-o", type=click.Path(), help="Save findings JSON")
def haiku_hunt(target, no_ai, deep, region, output):
    """
    AI-assisted vulnerability hunting using Claude Haiku via Bedrock.

    \b
    Run 'beatrix help haiku-hunt' for details.
    """
    from beatrix.hunters.haiku import HaikuHunter

    console.print(Panel.fit(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]AI:[/bold]     {'Disabled' if no_ai else 'Enabled'}\n"
        f"[bold]Region:[/bold] {region}",
        title="[bold magenta]🤖 Haiku Hunt[/bold magenta]",
        border_style="magenta",
    ))

    hunter = HaikuHunter(use_ai=not no_ai, region=region)
    findings = asyncio.run(hunter.hunt(target, deep=deep))

    console.print(f"\n[bold]Findings: {len(findings)}[/bold]")
    for f_item in findings:
        sev = f_item.severity.value.upper()
        conf = f_item.confidence.value if hasattr(f_item, 'confidence') else "?"
        console.print(f"  [{sev}|{conf}] {f_item.title}")

    if output:
        import json as jsonlib
        data = [{"title": f_item.title, "severity": f_item.severity.value, "url": f_item.url,
                 "evidence": f_item.evidence or ""}
                for f_item in findings]
        with open(output, "w") as fp:
            jsonlib.dump(data, fp, indent=2)
        console.print(f"\n[green]Results saved to {output}[/green]")


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    """Main entry point"""
    cli()


if __name__ == "__main__":
    main()
