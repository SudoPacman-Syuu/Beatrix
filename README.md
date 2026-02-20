# ⚔️ BEATRIX CLI — The Black Mamba

> *"Revenge is a dish best served with a working PoC."*

A human-centric command-line bug bounty hunting framework. 38+ scanner modules, full OWASP Top 10 coverage, Kill Chain methodology, AI-assisted analysis, and HackerOne integration — all from your terminal.

Globally installable on any Linux system. Call it from anywhere, like `nmap`.

---

## Install (One Command)

```bash
git clone https://github.com/SudoPacman-Syuu/Beatrix.git && cd Beatrix && ./install.sh
```

That's it. The installer auto-detects your Python, picks the best install method, and puts `beatrix` on your PATH.

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

---

## Requirements

- **Python 3.11+** (the installer checks this for you)
- **Linux** (Debian, Ubuntu, Fedora, Arch, etc.)
- Optional external tools for extended features: `nuclei`, `httpx`, `subfinder`, `ffuf`, `katana`, `sqlmap`, `nmap`

### Verify installation

```bash
beatrix --version
beatrix list --modules
```

---

## Core Concepts

### The Kill Chain

Every `hunt` follows the Cyber Kill Chain methodology:

1. 🔍 **Reconnaissance** — Subdomain enum, port scan, service detection
2. ⚔️ **Weaponization** — Payload crafting, WAF fingerprinting
3. 📦 **Delivery** — Endpoint discovery, parameter fuzzing
4. 💥 **Exploitation** — Injection, auth bypass, IDOR, CORS, SSRF
5. 🔧 **Installation** — Persistence testing
6. 📡 **Command & Control** — Data exfiltration, OOB channels
7. 🎯 **Objectives** — Impact assessment, PoC generation

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

Run `beatrix arsenal` for the full table. Core modules:

| Module | Category | What It Tests |
|--------|----------|---------------|
| `cors` | A02 | Origin reflection, null origin, wildcard, credential leaks |
| `injection` | A05 | SQLi, XSS, command injection with WAF bypass |
| `headers` | A02 | CSP, HSTS, X-Frame-Options analysis |
| `redirect` | Redirect | Open redirect detection |
| `ssrf` | A10 | Cloud metadata extraction, internal service access |
| `takeover` | Takeover | Dangling CNAME → 30+ services |
| `idor` | A01 | ID manipulation, sequential/UUID/negative |
| `bac` | A01 | Method override, force browsing, privilege escalation |
| `auth` | A07 | JWT attacks, 2FA bypass, session management |
| `error_disclosure` | A02 | Stack traces, SQL errors, debug info |
| `js_analysis` | Recon | API routes, secrets from JS bundles |
| `endpoint_prober` | Recon | Admin panels, debug routes, hidden endpoints |

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
├── cli/main.py          # CLI entry point (this is what you interact with)
├── core/
│   ├── engine.py        # BeatrixEngine — orchestrates everything
│   ├── kill_chain.py    # 7-phase kill chain executor
│   └── types.py         # Finding, Severity, Target, ScanResult
├── scanners/
│   ├── base.py          # BaseScanner ABC (all scanners extend this)
│   ├── cors.py          # CORS misconfiguration
│   ├── injection.py     # SQLi, XSS, CMDi
│   ├── ssrf.py          # Server-Side Request Forgery
│   ├── idor.py          # Insecure Direct Object Reference
│   └── ...              # 38+ scanner modules
├── validators/          # ImpactValidator + ReadinessGate
├── reporters/           # Report generation (markdown, JSON)
├── recon/               # Reconnaissance tools
├── ai/                  # GHOST agent, Haiku integration
├── integrations/        # HackerOne API client
└── config/              # Default configurations
```

---

## Legal Disclaimer

This tool is designed for **authorized security testing only**. Only use Beatrix against targets you have explicit permission to test. Unauthorized access to computer systems is illegal.

The operators of this tool are responsible for ensuring all applicable laws and regulations are followed.

---

*"You and I have unfinished business."*
