# ⚔️ BEATRIX CLI — The Black Mamba

> *"Revenge is a dish best served with a working PoC."*

A command-line bug bounty hunting framework. 29 scanner modules, 13 external tool integrations, full OWASP Top 10 coverage, 7-phase Kill Chain methodology, AI-assisted analysis, and HackerOne integration — all from your terminal.

Globally installable on any Linux system. Call it from anywhere.

---
<img src="beatrix.gif" width="1920" alt="Demo GIF">

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

### Install Method Priority

The installer automatically selects the best method in this order:

1. **uv** (fastest, recommended) — auto-installed if missing
2. **venv** — Python built-in virtual environment at `~/.beatrix`
3. **pipx** — isolated app install
4. **pip --user** — user-level fallback

```bash
# Using make
git clone https://github.com/SudoPacman-Syuu/Beatrix.git && cd Beatrix
make install

# Using uv directly
uv tool install .

# Using pipx
pipx install .

# Dedicated venv + symlink to /usr/local/bin
make install-venv

# For development
make install-dev
```

Customize the venv location: `BEATRIX_VENV=~/my-venv ./install.sh`

### Uninstall

```bash
./uninstall.sh        # or: make uninstall
```

---

## Quick Start

```bash
beatrix                              # show all commands
beatrix hunt example.com             # scan a target
beatrix hunt -f targets.txt          # hunt all URLs from a file
beatrix strike api.com -m cors       # single module attack
beatrix help hunt                    # detailed command help
beatrix arsenal                      # full module reference
```

---

## The Death List — Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `hunt TARGET` | Full vulnerability scan | `beatrix hunt example.com` |
| `hunt -f FILE` | Hunt targets from file | `beatrix hunt -f targets.txt` |
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
| `browser [sub]` | Playwright browser scanning | `beatrix browser scan https://app.com` |
| `creds [sub]` | Credential validation | `beatrix creds validate jwt_secret TOKEN` |
| `origin-ip DOMAIN` | Origin IP behind CDN | `beatrix origin-ip example.com` |
| `inject TARGET` | Deep parameter injection | `beatrix inject https://api.com --deep` |
| `polyglot [sub]` | XSS polyglot generation | `beatrix polyglot generate` |
| `auth [sub]` | Auth & auto-login | `beatrix auth login example.com` |
| `auth browser TARGET` | Manual browser login | `beatrix auth browser example.com` |
| `auth sessions` | Manage saved sessions | `beatrix auth sessions --clear example.com` |
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

1. �️ **CDN Bypass** — Detects Cloudflare/Akamai/Fastly/CloudFront via IP range + header fingerprinting. Discovers origin IPs through 6+ techniques (DNS history, crt.sh SSL certs, MX records, subdomain correlation, misconfiguration checks, WHOIS). If origin found, all network scans target the real server instead of CDN edge. Optional API keys (SecurityTrails, Censys, Shodan) via environment variables.
2. 🔍 **Reconnaissance** — Subdomain enum (`subfinder`, `amass`), crawling (`katana`, `gospider`, `hakrawler`, `gau`), **full 65535-port TCP scan** (`nmap -sS -p-`) against origin IP when available, service fingerprinting, NSE vuln/discovery/auth scripts, UDP top-50 scan, **firewall fingerprinting + bypass testing** (`scapy`), **SSH deep audit** (`paramiko`), JS analysis, endpoint probing, tech fingerprinting (`whatweb`, `webanalyze`), **nuclei recon** (fast tech/panel/WAF detection), **nuclei network** (protocol checks on non-HTTP services)
2. ⚔️ **Weaponization** — Subdomain takeover, error disclosure, cache poisoning, prototype pollution
3. 📦 **Delivery** — CORS, open redirects, OAuth redirect, HTTP smuggling, WebSocket testing
4. 💥 **Exploitation** — Injection (SQLi/XSS/CMDi) with response_analyzer behavioral detection and WAF bypass fallback, SSRF, IDOR, BAC, auth bypass, SSTI, XXE, deserialization, GraphQL, mass assignment, business logic, ReDoS, payment, **nuclei exploit scan** (CVEs, workflows, authenticated, interactsh OOB), **nuclei headless** (DOM XSS, prototype pollution). SmartFuzzer runs ffuf-verified fuzzing on parameterized URLs. Confirmed findings are escalated to deep exploitation tools (`sqlmap`, `dalfox`, `commix`, `jwt_tool`)
5. 🔧 **Installation** — File upload bypass, polyglot uploads, path traversal
6. 📡 **Command & Control** — OOB callback correlation via built-in `PoCServer` (pure asyncio HTTP server, auto-binds free port) or external `interact.sh`. Blind SSRF/XXE/RCE confirmation from callbacks registered during Phase 4. `LocalPoCClient` provides offset-based dedup polling.
7. 🎯 **Objectives** — VRT classification (Bugcrowd VRT + CVSS 3.1), exploit chain generation via PoCChainEngine (correlates ≥2 findings), finding aggregation, deduplication, impact assessment

### Presets

| Preset | Description | Time |
|--------|-------------|------|
| `quick` | Surface scan, recon only | ~5 min |
| `standard` | Balanced scan (**default**) | ~15 min |
| `full` | Complete kill chain + full network recon | ~45–60 min |
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
| `origin_ip` | CDN detection (Cloudflare/Akamai/Fastly/CloudFront) + origin IP discovery via DNS history, SSL certs, MX records, subdomain correlation, misconfig checks |
| `crawl` | Depth-limited spider with soft-404 detection, form/param extraction |
| `endpoint_prober` | Probes 200+ common API/admin/debug paths |
| `js_analysis` | Extracts API routes, secrets, source maps from JS bundles |
| `headers` | CSP, HSTS, X-Frame-Options, security header analysis |
| `github_recon` | GitHub org secret scanning, git history analysis |
| `nmap_nse` | Full TCP 65535-port scan, service ID, NSE vuln/discovery/auth scripts, UDP top-50 |
| `ssh_auditor` | SSH server fingerprint, weak KEX/cipher/MAC, default credential brute-force |
| `packet_crafter` | Firewall fingerprint, source-port bypass, IP fragment bypass, TTL mapping |

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
| `nuclei` | Intelligent multi-phase scanner — recon, exploit, network, headless |

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
| `nmap` | Recon | Full TCP/UDP port scanning, service detection, NSE scripts |
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

## Network Testing (Full Preset)

The `--preset full` hunt runs a 4-phase adaptive network pipeline in the Reconnaissance phase. Each phase's output drives the next.

### Phase 0: CDN BYPASS (origin_ip_discovery)

Runs automatically before port scanning. Detects CDN/WAF and discovers origin IPs.

| Technique | Source | API Key? | Confidence |
|-----------|--------|----------|------------|
| DNS History | ViewDNS, DNSDumpster | No | 0.5–0.6 |
| SSL Certificate Search | crt.sh | No | 0.7 |
| MX Record Analysis | dig MX records | No | 0.8 |
| Subdomain Correlation | 40+ bypass subdomains | No | 0.7 |
| Misconfiguration Check | Header leaks, /server-status | No | 0.9 |
| Historical WHOIS | whois | No | 0.4 |
| SecurityTrails History | SecurityTrails API | `SECURITYTRAILS_API_KEY` | 0.85 |
| Censys Certificate Search | Censys API | `CENSYS_API_ID` + `CENSYS_API_SECRET` | 0.8 |
| Shodan Host Search | Shodan API | `SHODAN_API_KEY` | 0.75 |

Discovered origin IPs are validated (HTTP/HTTPS with Host header) and the highest-confidence validated IP replaces the CDN edge IP for all subsequent network scans.

### Phase 1: DISCOVER (nmap)

| Step | What | Timeout |
|------|------|---------|
| 1a | `nmap -sS -p- --min-rate 3000 -T4` — all 65535 TCP ports | 600s |
| 1b | Service/version fingerprint on open ports only | 300s |
| 1c | NSE `vuln and safe` scripts — CVEs, misconfigs | 600s |
| 1d | NSE `discovery and safe` scripts — http-enum, ssl-cert, banners | 600s |
| 1e | NSE `auth and safe` scripts — default creds, anonymous access | 600s |
| 1f | UDP top 50 — DNS, SNMP, NTP, SSDP | 120s |

### Phase 2: ANALYZE (scapy)

Only runs when Phase 1 finds filtered ports.

| Step | What |
|------|------|
| 2a | Firewall fingerprint — SYN/FIN/NULL/XMAS/ACK/Window probes |
| 2b | Source port bypass — SYN from ports 53/80/443/88/20 |
| 2c | IP fragmentation bypass — split TCP headers |
| 2d | TTL mapping — locate firewall hop position |

Each successful bypass generates a HIGH/CRITICAL finding.

### Phase 3: AUDIT (paramiko + NSE)

Service-specific deep audit based on Phase 1 discovery.

| Service | Tool | Checks |
|---------|------|--------|
| SSH | paramiko | Banner, KEX/cipher/MAC weakness, key strength, 20+ default creds |
| FTP | NSE | Anonymous access, bounce attack, vsftpd backdoor |
| SMTP | NSE | Open relay, user enum, NTLM info |
| MySQL/Postgres | NSE | Empty password, brute, version |
| Redis/MongoDB | NSE | Unauthenticated access (CRITICAL) |
| TLS | NSE | ssl-enum-ciphers, Heartbleed, POODLE, CCS injection |

### Context Flow

Network results are stored in `context["network"]` and consumed by downstream phases:

- **Phase 0 → Phase 1** — Origin IP replaces CDN edge for all nmap scans
- **Delivery (Phase 3)** — HTTP smuggling tested on ALL discovered HTTP ports + origin IP directly
- **Exploitation (Phase 4)** — Injection/SSRF/XSS on all HTTP ports + origin IP (CDN bypass)
- **C2 (Phase 6)** — Firewall profile informs exfiltration channel assessment

### CDN Bypass API Keys (Optional)

Set these environment variables to enable additional origin IP discovery techniques:

```bash
export SECURITYTRAILS_API_KEY=your_key_here    # SecurityTrails DNS history
export CENSYS_API_ID=your_id_here              # Censys certificate search
export CENSYS_API_SECRET=your_secret_here      # Censys API secret
export SHODAN_API_KEY=your_key_here            # Shodan host search
```

Without API keys, Beatrix uses 6 free techniques that work for most targets.

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

# Hunt all targets from a .txt file (one URL per line)
beatrix hunt -f targets.txt

# File-based hunt with full preset and reports
beatrix hunt -f targets.txt --preset full -o ./reports
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
# Create a targets file (one URL per line, # for comments)
echo "https://api.target1.com
https://api.target2.com
https://api.target3.com" > targets.txt

# Hunt all targets through the full kill chain
beatrix hunt -f targets.txt

# Hunt with specific preset and output
beatrix hunt -f targets.txt --preset full --ai -o ./reports

# Single-module batch scan (CORS only)
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

### Authenticated Scanning

Beatrix supports authenticated scanning through config files, CLI flags, environment variables, and **Burp Suite-style auto-login**. Auth flows automatically to all scanners — nuclei gets `-H` flags, IDOR gets user sessions, the crawler gets cookies.

#### Auto-Login (Burp Suite-style)

Store your username/email and password and Beatrix will automatically log in before scanning — just like Burp Suite's login macro. It probes common API and form login endpoints, tries multiple field-name combinations, and captures session tokens/cookies on success.

```bash
# Interactive login wizard (saves to ~/.beatrix/auth.yaml)
beatrix auth login example.com

# Or pass credentials via CLI flags
beatrix hunt target.com --login-user user@example.com --login-pass 'P@ssw0rd'
beatrix hunt target.com --login-user user@example.com --login-pass 'P@ssw0rd' --login-url https://target.com/api/auth/login

# Or via environment variables
export BEATRIX_LOGIN_USER="user@example.com"
export BEATRIX_LOGIN_PASS="P@ssw0rd"
export BEATRIX_LOGIN_URL="https://target.com/api/auth/login"  # optional
beatrix hunt target.com
```

The `auth login` wizard prompts for target, username/email, password (masked input), and optional login URL. Credentials are saved to `~/.beatrix/auth.yaml` and auto-loaded on subsequent scans.

**How it works:**
1. Collects cookies from the target's home page (CSRF tokens, etc.)
2. Probes 24 common API login endpoints with JSON payloads (`/api/auth/login`, `/api/v1/session`, `/oauth/token`, etc.)
3. Tries 12 traditional form login endpoints (`/login`, `/signin`, `/wp-login.php`, etc.)
4. Uses 10 field-name combinations per endpoint (`email`/`password`, `username`/`passwd`, `login`/`pass`, etc.)
5. Skips 404s quickly, stops on 401/403 (endpoint found, credentials wrong)
6. **Detects OTP/2FA challenges** — if the server responds with a verification code requirement (email OTP, SMS code, TOTP), Beatrix prompts you to enter the code interactively
7. On success, captured session cookies and auth tokens flow to all scanners
8. **Session is saved** to `~/.beatrix/sessions/` and reused for 24 hours (skip re-auth on repeat scans)

#### OTP / 2FA Handling

Many sites require OTP verification on every login. Beatrix detects OTP challenges automatically by scanning JSON responses for 2FA keywords (`requires_2fa`, `verification_required`, `otp`, etc.) and prompts you to enter the code sent to your email/phone.

If auto-login can't complete (WAF blocks, CAPTCHA, complex 2FA), use the **manual browser login**:

```bash
# Open a browser, log in manually, Beatrix captures your session
beatrix auth browser example.com

# In headless environments (e.g., codespaces), paste cookies from DevTools instead
beatrix auth browser example.com  # falls back to cookie-paste prompt

# Or pass cookies directly from your browser's DevTools
beatrix hunt example.com --cookie "session=abc123" --cookie "XSRF-TOKEN=xyz"
```

#### Session Persistence

Once authenticated (via auto-login, manual browser, or OTP flow), sessions are saved to `~/.beatrix/sessions/<domain>.json` and automatically reused for 24 hours.

```bash
# List all saved sessions
beatrix auth sessions

# Clear a specific session
beatrix auth sessions --clear example.com

# Clear all sessions
beatrix auth sessions --clear-all

# Force fresh login (ignore saved session)
beatrix hunt example.com --fresh-login

# Use manual browser login for this hunt
beatrix hunt example.com --manual-login
```

#### Static Credentials (Manual)

```bash
# Generate a sample config file
beatrix auth init

# Edit ~/.beatrix/auth.yaml with your credentials, then scan — auth is auto-loaded
beatrix hunt target.com

# Or use CLI flags directly
beatrix hunt target.com --token "Bearer eyJ..."
beatrix hunt target.com --cookie "session=abc123" --cookie "csrf=xyz"
beatrix hunt target.com --header "X-API-Key: key123"
beatrix hunt target.com --auth-user admin --auth-pass password

# View current auth state
beatrix auth show
beatrix auth show -t example.com

# Edit auth config in your default editor
beatrix auth config
```

Auth config supports per-target credentials and IDOR dual-session testing (see `~/.beatrix/auth.yaml`).

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
| `SECURITYTRAILS_API_KEY` | SecurityTrails DNS history (CDN bypass) |
| `CENSYS_API_ID` | Censys certificate search (CDN bypass) |
| `CENSYS_API_SECRET` | Censys API secret (CDN bypass) |
| `SHODAN_API_KEY` | Shodan host search (CDN bypass) |

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
├── cli/main.py              # CLI entry point — 25 commands via Click + Rich
├── core/
│   ├── engine.py            # BeatrixEngine — orchestrates everything, 29 modules
│   ├── kill_chain.py        # 7-phase kill chain executor + 3-phase network pipeline
│   ├── nmap_scanner.py      # Full TCP/UDP scanning, NSE vuln/discovery/auth scripts
│   ├── packet_crafter.py    # Scapy firewall fingerprint, source-port/fragment bypass, TTL map
│   ├── ssh_auditor.py       # SSH fingerprint, weak crypto, default credential brute-force
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
│   ├── origin_ip_discovery.py # CDN bypass — Cloudflare/Akamai/Fastly origin IP discovery (916 LOC)
│   ├── injection.py         # SQLi, XSS, CMDi, LFI, SSTI (57K+ dynamic payloads, response_analyzer + WAF bypass)
│   ├── ssrf.py              # 44-payload SSRF scanner
│   ├── cors.py              # 6-technique CORS bypass scanner
│   ├── auth.py              # JWT, OAuth, 2FA, session attacks
│   ├── idor.py              # IDOR + BAC scanners
│   ├── nuclei.py            # Nuclei v3 — multi-phase, authenticated, intelligent templates
│   └── ...                  # 30 scanner modules total
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
