# ⚔️ BEATRIX CLI — The Black Mamba

> *"Revenge is a dish best served with a working PoC."*

A command-line bug bounty hunting framework. 29 scanner modules, 13 external tool integrations, full OWASP Top 10 coverage, 7-phase Kill Chain methodology, AI-assisted analysis, and HackerOne integration — all from your terminal.

Globally installable on any Linux system. Call it from anywhere.

---

## 📖 The Manual

Beatrix ships with an interactive, comprehensive HTML manual covering every command, every module, all flags, presets, and real-world workflows:

```bash
beatrix manual
```

This opens the full manual in your default browser — no internet required. You can also open it directly at [`docs/manual/index.html`](docs/manual/index.html).

---

## Install (One Command)

```bash
git clone https://github.com/SudoPacman-Syuu/Beatrix.git && cd Beatrix && ./install.sh
```

That's it. The installer auto-detects your Python, picks the best install method, puts `beatrix` on your PATH, and **automatically installs all 21 external security tools** (nuclei, nmap, sqlmap, subfinder, ffuf, etc.).

### Other Install Methods

```bash
# Using make
git clone https://github.com/SudoPacman-Syuu/Beatrix.git && cd Beatrix
make install

# Using pipx (recommended for isolation)
pipx install .

# Using pip (user-level, no sudo)
pip install --user .

# System-wide
sudo pip install .

# Dedicated venv + symlink to /usr/local/bin
make install-venv

# For development
make install-dev
```

### Uninstall

```bash
./uninstall.sh        # or: make uninstall
```

---

## Quick Start

```bash
beatrix                              # show all commands
beatrix hunt example.com             # scan a target
beatrix strike api.com -m cors       # single module attack
beatrix help hunt                    # detailed command help
beatrix arsenal                      # full module reference
```

---

## The Death List — Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `hunt TARGET` | Full vulnerability scan | `beatrix hunt example.com` |
| `strike TARGET -m MOD` | Single module attack | `beatrix strike api.com -m cors` |
| `probe TARGET` | Quick alive check | `beatrix probe example.com` |
| `recon DOMAIN` | Reconnaissance | `beatrix recon example.com --deep` |
| `batch FILE -m MOD` | Mass scanning | `beatrix batch targets.txt -m cors` |
| `bounty-hunt TARGET` | OWASP Top 10 pipeline | `beatrix bounty-hunt https://api.com` |
| `rapid` | Multi-target quick sweep | `beatrix rapid -d shopify.com` |
| `haiku-hunt TARGET` | AI-assisted hunting | `beatrix haiku-hunt example.com` |
| `ghost TARGET` | AI autonomous pentester | `beatrix ghost https://api.com` |
| `github-recon ORG` | GitHub secret scanner | `beatrix github-recon acme-corp` |
| `validate FILE` | Validate findings | `beatrix validate report.json` |
| `h1 [sub]` | HackerOne operations | `beatrix h1 programs` |
| `mobile [sub]` | Mobile traffic intercept | `beatrix mobile intercept` |
| `config` | Configuration | `beatrix config --show` |
| `list` | List modules/presets | `beatrix list --modules` |
| `arsenal` | Full module reference | `beatrix arsenal` |
| `help CMD` | Detailed command help | `beatrix help hunt` |
| `manual` | Open HTML manual in browser | `beatrix manual` |
| `setup` | Install all external tools | `beatrix setup` |

---

## Requirements

- **Python 3.11+** (the installer checks this for you)
- **Linux** (Debian, Ubuntu, Fedora, Arch, etc.)
- 21 external tools are **automatically installed** by `./install.sh` and `beatrix setup`

All external tools are installed automatically during setup. To reinstall or update them later:

```bash
beatrix setup            # install all missing tools
beatrix setup --check    # just show what's installed
```

### Verify installation

```bash
beatrix --version
beatrix list --modules
```

---

## Core Concepts

### The Kill Chain

Every `hunt` follows the Cyber Kill Chain methodology:

1. 🔍 **Reconnaissance** — Subdomain enum (`subfinder`, `amass`), crawling (`katana`, `gospider`, `hakrawler`, `gau`), port scan (`nmap`), JS analysis, endpoint probing, tech fingerprinting (`whatweb`, `webanalyze`)
2. ⚔️ **Weaponization** — Subdomain takeover, error disclosure, cache poisoning, prototype pollution
3. 📦 **Delivery** — CORS, open redirects, OAuth redirect, HTTP smuggling, WebSocket testing
4. 💥 **Exploitation** — Injection (SQLi/XSS/CMDi) with response_analyzer behavioral detection and WAF bypass fallback, SSRF, IDOR, BAC, auth bypass, SSTI, XXE, deserialization, GraphQL, mass assignment, business logic, ReDoS, payment, nuclei CVE scan. SmartFuzzer runs ffuf-verified fuzzing on parameterized URLs. Confirmed findings are escalated to deep exploitation tools (`sqlmap`, `dalfox`, `commix`, `jwt_tool`)
5. 🔧 **Installation** — File upload bypass, polyglot uploads, path traversal
6. 📡 **Command & Control** — OOB callback correlation via built-in `PoCServer` (pure asyncio HTTP server, auto-binds free port) or external `interact.sh`. Blind SSRF/XXE/RCE confirmation from callbacks registered during Phase 4. `LocalPoCClient` provides offset-based dedup polling.
7. 🎯 **Objectives** — VRT classification (Bugcrowd VRT + CVSS 3.1), exploit chain generation via PoCChainEngine (correlates ≥2 findings), finding aggregation, deduplication, impact assessment

### Presets

| Preset | Description | Time |
|--------|-------------|------|
| `quick` | Surface scan, recon only | ~5 min |
| `standard` | Balanced scan (**default**) | ~15 min |
| `full` | Complete kill chain | ~30 min |
| `stealth` | Low-noise passive recon | ~10 min |
| `injection` | Injection-focused testing | ~20 min |
| `api` | API security testing | ~15 min |

```bash
beatrix hunt example.com --preset full
beatrix hunt example.com --preset injection
```

### Scanner Modules (Arsenal)

Run `beatrix arsenal` for the full table. 29 registered modules across 5 kill chain phases:

**Phase 1 — Reconnaissance:**

| Module | What It Does |
|--------|-------------|
| `crawl` | Depth-limited spider with soft-404 detection, form/param extraction |
| `endpoint_prober` | Probes 200+ common API/admin/debug paths |
| `js_analysis` | Extracts API routes, secrets, source maps from JS bundles |
| `headers` | CSP, HSTS, X-Frame-Options, security header analysis |
| `github_recon` | GitHub org secret scanning, git history analysis |

**Phase 2 — Weaponization:**

| Module | What It Does |
|--------|-------------|
| `takeover` | Dangling CNAME detection for 30+ cloud services |
| `error_disclosure` | Stack traces, SQL errors, framework debug info leaks |
| `cache_poisoning` | Unkeyed header injection, fat GET, parameter cloaking |
| `prototype_pollution` | Server-side + client-side JS prototype pollution |

**Phase 3 — Delivery:**

| Module | What It Does |
|--------|-------------|
| `cors` | 6 bypass techniques, credential leak detection |
| `redirect` | Open redirect detection |
| `oauth_redirect` | OAuth redirect URI manipulation |
| `http_smuggling` | CL.TE / TE.CL / TE.TE desync |
| `websocket` | WebSocket origin, CSWSH, message injection |

**Phase 4 — Exploitation:**

| Module | What It Does |
|--------|-------------|
| `injection` | SQLi, XSS, CMDi, LFI, SSTI — 57K+ payloads via SecLists + PayloadsAllTheThings, response_analyzer behavioral detection, WAF bypass fallback |
| `ssrf` | 44+ payloads, cloud metadata, internal service access |
| `idor` | Sequential/UUID/negative ID manipulation |
| `bac` | Method override, force browsing, privilege escalation |
| `auth` | JWT attacks, 2FA bypass, session management |
| `ssti` | Server-side template injection (Jinja2, Twig, etc.) |
| `xxe` | XML external entity injection |
| `deserialization` | Insecure deserialization (Java, PHP, Python, .NET) |
| `graphql` | Introspection, batching, injection |
| `mass_assignment` | Hidden field binding exploitation |
| `business_logic` | Race conditions, boundary testing |
| `redos` | Regular expression denial of service |
| `payment` | Checkout flow manipulation, price tampering |
| `nuclei` | 12,600+ CVE/misconfig templates |

**Phase 5 — Installation:**

| Module | What It Does |
|--------|-------------|
| `file_upload` | Extension bypass, polyglot uploads, path traversal |

### External Tool Integrations (13 Runners)

Beatrix wraps 13 external security tools via async subprocess runners with timeouts and structured output parsing. These are used by kill chain phases to augment the internal scanners:

| Tool | Used In | Purpose |
|------|---------|---------|
| `subfinder` | Recon | Passive subdomain enumeration |
| `amass` | Recon | Active/passive subdomain enum |
| `nmap` | Recon | Port scanning, service detection |
| `katana` | Recon | Deep crawling, JS rendering |
| `gospider` | Recon | Fast crawling, form/JS extraction |
| `hakrawler` | Recon | URL discovery |
| `gau` | Recon | Historical URL harvesting |
| `whatweb` | Recon | Technology fingerprinting |
| `webanalyze` | Recon | Wappalyzer-based tech detection |
| `dirsearch` | Recon | Directory brute-forcing (adaptive extensions) |
| `sqlmap` | Exploitation | Deep SQLi exploitation, DB takeover |
| `dalfox` | Exploitation | XSS validation, WAF bypass |
| `commix` | Exploitation | OS command injection exploitation |
| `jwt_tool` | Exploitation | JWT vulnerability analysis, role escalation |
| `metasploit` | PoC Chain | Exploit search, module suggestions |

Use a specific module with `strike`:

```bash
beatrix strike https://api.example.com -m cors
beatrix strike https://example.com/login -m injection
```

Or combine modules during a `hunt`:

```bash
beatrix hunt example.com -m cors -m idor -m ssrf
```

---

## Usage Examples

### Basic Hunting

```bash
# Quick surface scan
beatrix hunt example.com --preset quick

# Full assault
beatrix hunt example.com --preset full

# AI-assisted
beatrix hunt example.com --preset full --ai
```

### Targeted Strikes

```bash
# Test a single endpoint for CORS
beatrix strike https://api.example.com/v1/users -m cors

# Check for SSRF
beatrix strike https://example.com/fetch?url=test -m ssrf

# Analyze JavaScript bundles
beatrix strike https://app.example.com -m js_analysis
```

### Reconnaissance

```bash
# Basic recon
beatrix recon example.com

# Deep scan (probes all discovered subdomains)
beatrix recon example.com --deep

# Save results as JSON
beatrix recon example.com --deep -j -o recon.json
```

### Batch Scanning

```bash
# Create a targets file
echo "https://api.target1.com
https://api.target2.com
https://api.target3.com" > targets.txt

# Scan all for CORS
beatrix batch targets.txt -m cors -o ./reports
```

### GHOST — Autonomous AI Pentester

```bash
# Basic investigation
beatrix ghost https://api.example.com/users?id=1

# With a specific objective
beatrix ghost https://api.example.com -X POST -d '{"user":"admin"}' -o "Test for SQL injection"

# With auth
beatrix ghost https://example.com -H "Authorization: Bearer TOKEN" --max-turns 50
```

### HackerOne Integration

```bash
# List programs
beatrix h1 programs

# Search for a program
beatrix h1 programs -s "shopify"

# Check for duplicates before submitting
beatrix h1 dupecheck shopify cors misconfiguration

# Submit a report
beatrix h1 submit shopify -t "CORS Misconfiguration" -f report.md -i "Account takeover" -s high

# Dry run
beatrix h1 submit shopify -t "CORS" -f report.md -i "ATO" -s high --dry-run
```

### GitHub Secret Scanning

```bash
# Full org scan
beatrix github-recon acme-corp

# Quick scan (skip git history)
beatrix github-recon acme-corp --quick

# Specific repo with report
beatrix github-recon acme-corp --repo acme-corp/api-server -o report.md
```

### Validation

```bash
# Validate findings before submission
beatrix validate beatrix_report.json

# Validate with verbose output
beatrix validate scan_results.json -v
```

Accepts both envelope format (`{"findings": [...], "metadata": {...}}`) and bare lists (`[...]`).

### JSON Output Format

All `-o` / `--output` JSON exports use a standardized envelope:

```json
{
  "findings": [
    {
      "title": "CORS Misconfiguration",
      "severity": "high",
      "confidence": "confirmed",
      "url": "https://example.com/api",
      "scanner_module": "cors",
      "description": "...",
      "evidence": "...",
      "remediation": "..."
    }
  ],
  "metadata": {
    "tool": "beatrix",
    "version": "1.0.0",
    "target": "example.com",
    "total_findings": 1,
    "generated_at": "2026-02-23T12:00:00Z"
  }
}
```

---

## Configuration

Config file: `~/.beatrix/config.yaml`

```bash
# Show current config
beatrix config --show

# Set values
beatrix config --set scanning.rate_limit 50
beatrix config --set ai.enabled true
beatrix config --set output.dir ./my_results
```

### Available Config Keys

| Key | Default | Description |
|-----|---------|-------------|
| `scanning.threads` | 50 | Concurrent threads |
| `scanning.rate_limit` | 100 | Requests per second |
| `scanning.timeout` | 10 | HTTP timeout (seconds) |
| `ai.enabled` | false | Enable AI features |
| `ai.provider` | bedrock | AI provider (bedrock/anthropic) |
| `ai.model` | claude-haiku | Model name |
| `output.dir` | . | Default output directory |
| `output.verbose` | false | Verbose logging |

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | Anthropic API key (for GHOST) |
| `AWS_REGION` | AWS region for Bedrock |
| `GITHUB_TOKEN` | GitHub token for recon |
| `H1_USERNAME` | HackerOne username |
| `H1_API_TOKEN` | HackerOne API token |

---

## Getting Help

```bash
# Open the full interactive HTML manual (recommended)
beatrix manual

# Quick reference table
beatrix

# Detailed help for any command
beatrix help hunt
beatrix help strike
beatrix help ghost
beatrix help bounty-hunt

# Full module reference
beatrix arsenal

# List available stuff
beatrix list --modules
beatrix list --presets
```

---

## Architecture

```
beatrix/
├── cli/main.py              # CLI entry point — 20 commands via Click + Rich
├── core/
│   ├── engine.py            # BeatrixEngine — orchestrates everything, 29 modules
│   ├── kill_chain.py        # 7-phase kill chain executor
│   ├── external_tools.py    # 13 async subprocess tool runners
│   ├── types.py             # Finding, Severity, Confidence, ScanContext
│   ├── seclists_manager.py  # Dynamic wordlist engine (SecLists + PayloadsAllTheThings)
│   ├── oob_detector.py      # OOB callback manager (LocalPoCClient + interact.sh)
│   ├── poc_server.py        # Built-in PoC validation server (890 LOC, pure asyncio)
│   ├── correlation_engine.py # MITRE ATT&CK correlation
│   ├── findings_db.py       # SQLite findings storage (WAL mode)
│   ├── issue_consolidator.py # Finding deduplication
│   └── poc_chain_engine.py  # PoC generation + Metasploit integration
├── scanners/
│   ├── base.py              # BaseScanner ABC — rate limiting, httpx client
│   ├── crawler.py           # Target spider — foundation for all scanning
│   ├── injection.py         # SQLi, XSS, CMDi, LFI, SSTI (57K+ dynamic payloads, response_analyzer + WAF bypass)
│   ├── ssrf.py              # 44-payload SSRF scanner
│   ├── cors.py              # 6-technique CORS bypass scanner
│   ├── auth.py              # JWT, OAuth, 2FA, session attacks
│   ├── idor.py              # IDOR + BAC scanners
│   ├── nuclei.py            # Nuclei template engine wrapper
│   └── ...                  # 29 scanner modules total
├── validators/              # ImpactValidator + ReadinessGate
├── reporters/               # Markdown, JSON, HTML chain reports
├── recon/                   # ReconRunner — subfinder/amass/nmap integration
├── ai/                      # GHOST agent, Haiku integration
├── integrations/            # HackerOne API client
└── utils/                   # WAF bypass, VRT classifier, helpers, response_analyzer
```

---

## Legal Disclaimer

This tool is designed for **authorized security testing only**. Only use Beatrix against targets you have explicit permission to test. Unauthorized access to computer systems is illegal.

The operators of this tool are responsible for ensuring all applicable laws and regulations are followed.

---

*"You and I have unfinished business."*
