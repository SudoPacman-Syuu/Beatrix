# BEATRIX Architecture

**Version:** 1.0.0  
**Last Updated:** February 24, 2026

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              BEATRIX CLI                                    │
│            beatrix hunt [-f file] / strike / ghost / recon / batch          │
│                         (Click + Rich terminal UI)                          │
└─────────────────────────────────────────┬───────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CORE ENGINE (engine.py)                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Kill Chain   │  │ 29 Scanner   │  │  External    │  │  Issue       │     │
│  │ Executor     │  │ Modules      │  │  Toolkit     │  │ Consolidator │     │
│  │ (7 phases)   │  │ (BaseScanner)│  │ (13 tools)   │  │ (dedup)      │     │
│  └──────┬───────┘  └──────────────┘  └──────────────┘  └──────────────┘     │
│         │                                                                   │
│         ▼                                                                   │
│  Phase 1: _handle_recon ──────────────→ crawl, endpoint_prober, js_analysis │
│  Phase 2: _handle_weaponization ──────→ takeover, error_disclosure, cache   │
│  Phase 3: _handle_delivery ───────────→ cors, redirect, smuggling, websocket│
│         ├── PoCServer starts ─────────→ auto-binds free port, detects IP    │
│  Phase 4: _handle_exploitation ───────→ injection, ssrf, idor, auth, nuclei │
│           ├── deep exploit tools ─────→ sqlmap, dalfox, commix, jwt_tool    │
│           ├── SmartFuzzer ────────────→ ffuf-verified fuzzing on param URLs │
│           └── scanners use PoCServer ─→ OOB callbacks, CORS/clickjack PoCs  │
│  Phase 5: _handle_installation ───────→ file_upload                         │
│  Phase 6: _handle_c2 ────────────────→ OOB callback polling + correlation   │
│           └── LocalPoCClient | interact.sh (auto-selected)                  │
│  Phase 7: _handle_actions ────────────→ VRT classification, PoC chain gen,  │
│                                         aggregation (findings in state)     │
└─────────────────────────────────────────┬───────────────────────────────────┘
                                          │
              ┌───────────────┬───────────┼───────────┬─────────────────┐
              ▼               ▼           ▼           ▼                 ▼
┌──────────────────┐ ┌──────────────┐ ┌────────────────┐ ┌───────────────────┐
│ FINDINGS PIPELINE│ │ EXTERNAL     │ │  PoC SERVER    │ │ REPORTING         │
├──────────────────┤ │ TOOLS        │ │  (poc_server)  │ ├───────────────────┤
│ Finding dataclass│ ├──────────────┤ ├────────────────┤ │ Markdown / JSON   │
│ → Consolidator   │ │ 13 async     │ │ Pure asyncio   │ │ HTML chain reports│
│ → FindingsDB     │ │ subprocess   │ │ HTTP server    │ │ MITRE ATT&CK map  │
│ → ImpactValidator│ │ runners with │ │ OOB callbacks  │ │ HackerOne submit  │
│ → ReadinessGate  │ │ timeouts     │ │ CORS/click PoC │ │                   │
└──────────────────┘ └──────────────┘ │ exfil collect  │ └───────────────────┘
                                      └────────────────┘
```

---

## Kill Chain Phase → Module Mapping

Every `beatrix hunt` invocation runs through these phases. Each phase handler
calls `_run_scanner()` or `_run_scanner_on_urls()` with the exact engine
module key shown below.

| Phase | Handler | Engine Module Keys |
|-------|---------|-------------------|
| 1. Reconnaissance | `_handle_recon` | `crawl`, `endpoint_prober`, `js_analysis`, `headers`, `github_recon` + external: subfinder, amass, nmap, katana, gospider, hakrawler, gau, whatweb, webanalyze, dirsearch |
| 2. Weaponization | `_handle_weaponization` | `takeover`, `error_disclosure`, `cache_poisoning`, `prototype_pollution` |
| 3. Delivery | `_handle_delivery` | `cors`, `redirect`, `oauth_redirect`, `http_smuggling`, `websocket` |
| 4. Exploitation | `_handle_exploitation` | `injection` (+ response_analyzer + WAF bypass), `ssti`, `ssrf`, `mass_assignment`, `redos`, `xxe`, `deserialization`, `idor`, `bac`, `auth`, `graphql`, `business_logic`, `payment`, `nuclei` + SmartFuzzer (ffuf verification) + external: sqlmap, dalfox, commix, jwt_tool |
| 5. Installation | `_handle_installation` | `file_upload` |
| 6. C2 | `_handle_c2` | OOB detector polling — `LocalPoCClient` (built-in) or `InteractshClient` (external). PoCServer callbacks are polled with dedup tracking. |
| 7. Actions | `_handle_actions` | VRT classification (Bugcrowd VRT + CVSS 3.1) → PoCChainEngine (exploit chain generation from correlated findings) → aggregation via `KillChainState.all_findings` |

---

## MITRE ATT&CK Tactics (Web Focus)

| Tactic ID | Name | BEATRIX Coverage |
|-----------|------|------------------|
| TA0043 | Reconnaissance | Subdomain enum, port scan, crawling, JS analysis, tech fingerprint |
| TA0001 | Initial Access | Auth bypass, injection, CORS, open redirect |
| TA0006 | Credential Access | JWT attacks, session hijack, credential spray, GitHub secrets |
| TA0003 | Persistence | File upload, cookie manipulation |
| TA0004 | Privilege Escalation | IDOR, BAC, mass assignment, role confusion |
| TA0009 | Collection | GraphQL introspection, API scraping, error disclosure |
| TA0010 | Exfiltration | SSRF, XXE, OOB callbacks, CORS abuse |

---

## PoC Validation Server (`poc_server.py`)

Beatrix includes a **built-in PoC validation server** — a pure `asyncio` HTTP server that eliminates the dependency on external collaborator services (interact.sh) for OOB callback detection and automated PoC generation.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        PoCServer (890 LOC)                      │
│  Pure asyncio.start_server — no external dependencies           │
├─────────────────────────────────────────────────────────────────┤
│  Routes:                                                        │
│    /cb/{uid}        OOB callback endpoint (GET/POST)            │
│    /poc/{id}        Serve generated PoC pages                   │
│    /collect/{id}    Exfiltration data collection                │
│    /clickjack       Clickjacking PoC generator                  │
│    /enumerate       URL enumeration via browser redirect        │
│    /enumerate/results  Enumeration results collection           │
│    /health          Health check                                │
├─────────────────────────────────────────────────────────────────┤
│  Features:                                                      │
│    • Auto-binds free port (port=0)                              │
│    • Auto-detects local IP (UDP probe to 8.8.8.8)               │
│    • CORS PoC generation (XHR + credential leak)                │
│    • Clickjacking PoC (iframe overlay)                          │
│    • URL enumeration via browser history/timing                 │
│    • Data exfiltration collection endpoint                      │
│    • JS-safe string escaping for template contexts              │
│    • Full callback logging with timestamps + source IP          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  LocalPoCClient (oob_detector.py)               │
│  Async context manager wrapping PoCServer + OOBDetector         │
├─────────────────────────────────────────────────────────────────┤
│  • Drop-in replacement for InteractshClient                     │
│  • create_payload(vuln_type) → OOBPayload with callback URL     │
│  • poll() → List[OOBInteraction] (with dedup tracking)          │
│  • Auto-start/stop lifecycle via async with                     │
│  • Offset-based dedup: only returns NEW callbacks per poll      │
└─────────────────────────────────────────────────────────────────┘
```

### Kill Chain Integration

| Phase | Integration Point |
|-------|-------------------|
| Before Phase 3 | `PoCServer` started, injected into `ctx.extra["poc_server"]` |
| Phase 3-4 | Scanners (CORS, SSRF, XXE, deserialization, CSS exfiltrator) use `poc_server` for OOB callbacks and PoC generation |
| Phase 6 | `LocalPoCClient.poll()` retrieves new callbacks, creates CRITICAL findings |
| Finally | `PoCServer.stop()` called in cleanup |

### Scanner Integrations

| Scanner | How It Uses PoCServer |
|---------|----------------------|
| `cors.py` | `register_cors_poc()` — generates browser-ready CORS exploitation PoC pages |
| `ssrf.py` | `register_oob_payload()` + `oob_url()` — OOB callback URLs for blind SSRF |
| `xxe.py` | `register_oob_payload()` + `oob_url()` — direct callback URLs (avoids broken subdomain-on-IP patterns) |
| `deserialization.py` | `base_url` netloc as collaborator domain for ysoserial payloads |
| `css_exfiltrator.py` | `base_url` netloc as callback domain for CSS exfil collection |

---

## OWASP Top 10:2021 Coverage

| OWASP | Scanner Modules |
|-------|----------------|
| A01 Broken Access Control | `idor`, `bac`, `mass_assignment`, `endpoint_prober` |
| A02 Cryptographic Failures | `cors`, `headers`, `graphql` |
| A03 Injection | `injection` (57K+ payloads), `ssti`, `xxe`, `deserialization` + sqlmap/dalfox/commix |
| A04 Insecure Design | `payment`, `business_logic`, `file_upload` |
| A05 Security Misconfiguration | `error_disclosure`, `cache_poisoning`, `js_analysis` |
| A06 Vulnerable Components | `nuclei` (12,600+ CVE templates) |
| A07 Auth Failures | `auth` + jwt_tool |
| A08 Software Integrity | `prototype_pollution`, `deserialization` |
| A09 Logging Failures | (covered via error_disclosure probing) |
| A10 SSRF | `ssrf` + OOB detector |

---

## Directory Structure

```
beatrix/
├── __init__.py                    # v1.0.0
├── cli/
│   └── main.py                    # 20 CLI commands (Click + Rich)
├── core/
│   ├── engine.py                  # BeatrixEngine — 29 module registry, presets
│   ├── kill_chain.py              # KillChainExecutor — 7-phase state machine
│   ├── external_tools.py          # 13 async tool runners (ExternalToolkit)
│   ├── types.py                   # Finding, Severity, Confidence, ScanContext
│   ├── oob_detector.py            # OOB callback manager (InteractshClient + LocalPoCClient)
│   ├── poc_server.py              # Built-in PoC validation HTTP server (890 LOC)
│   ├── correlation_engine.py      # MITRE ATT&CK event correlation
│   ├── findings_db.py             # SQLite WAL-mode findings storage
│   ├── issue_consolidator.py      # Multi-dimensional finding dedup
│   ├── poc_chain_engine.py        # PoC generation + Metasploit search (wired into Phase 7)
│   ├── smart_fuzzer.py            # Intelligent fuzzing engine (wired into Phase 4)
│   ├── response_analyzer.py       # HTTP response analysis (wired into injection.py)
│   ├── privilege_graph.py         # Authorization graph analysis
│   ├── methodology.py             # OWASP/MITRE framework alignment
│   ├── nmap_scanner.py            # Nmap async wrapper
│   ├── subfinder.py               # Subfinder async wrapper
│   ├── ffuf_engine.py             # ffuf async integration
│   ├── parallel_haiku.py          # Concurrent AI workers
│   ├── ssh_auditor.py             # SSH configuration auditing
│   ├── auto_register.py           # Scanner auto-discovery
│   ├── seclists_manager.py        # Dynamic wordlist engine (SecLists + PATT, 57K+ payloads)
│   ├── scan_check_types.py        # Scan check type definitions
│   └── packet_crafter.py          # Custom packet construction
├── scanners/
│   ├── base.py                    # BaseScanner ABC — rate limiter, httpx client
│   ├── crawler.py                 # Target spider — soft-404, forms, params, tech
│   ├── injection.py               # SQLi, XSS, CMDi, LFI, SSTI (57K+ dynamic payloads via SecLists + PATT, response_analyzer behavioral detection, WAF bypass fallback)
│   ├── ssrf.py                    # 44-payload SSRF scanner
│   ├── cors.py                    # 6-technique CORS bypass
│   ├── auth.py                    # JWT, OAuth, 2FA, Keycloak, session
│   ├── idor.py                    # IDOR + BAC (merged module)
│   ├── ssti.py                    # Template injection (Jinja2, Twig, etc.)
│   ├── xxe.py                     # XML external entity
│   ├── deserialization.py         # Java/PHP/Python/.NET deser
│   ├── graphql.py                 # Introspection, batching, injection
│   ├── mass_assignment.py         # Hidden field binding
│   ├── business_logic.py          # Race conditions, boundary testing
│   ├── redirect.py                # Open redirect + OAuth redirect
│   ├── http_smuggling.py          # CL.TE / TE.CL / TE.TE desync
│   ├── websocket.py               # Origin, CSWSH, message injection
│   ├── takeover.py                # Subdomain takeover (30+ services)
│   ├── error_disclosure.py        # Stack traces, DB errors, framework leaks
│   ├── cache_poisoning.py         # Unkeyed headers, fat GET, param cloaking
│   ├── prototype_pollution.py     # Server-side + client-side PP
│   ├── headers.py                 # Security header analysis
│   ├── endpoint_prober.py         # 200+ path probe with soft-404 detection
│   ├── js_bundle.py               # JS secrets, source maps, API routes
│   ├── github_recon.py            # GitHub org scanning
│   ├── nuclei.py                  # Nuclei template engine wrapper
│   ├── file_upload.py             # Extension bypass, polyglot, path traversal
│   ├── payment.py                 # Checkout flow manipulation
│   ├── redos.py                   # Regex DoS detection
│   ├── browser_scanner.py         # Playwright-based DOM XSS
│   ├── credential_validator.py    # Credential validation
│   ├── css_exfiltrator.py         # CSS injection data exfil
│   ├── mobile_interceptor.py      # ADB + mitmproxy traffic capture
│   ├── polyglot_generator.py      # Multi-context payload generation
│   └── power_injector.py          # Advanced insertion point testing
├── ai/
│   ├── ghost.py                   # GHOST autonomous pentester (10 tools)
│   ├── assistant.py               # AIAssistant, HaikuGrunt, Bedrock/Anthropic
│   └── tasks.py                   # TaskRouter, model selection
├── hunters/
│   ├── rapid.py                   # RapidHunter (multi-domain sweep)
│   └── haiku.py                   # HaikuHunter (AI-assisted)
├── recon/
│   └── __init__.py                # ReconRunner — tool orchestration
├── integrations/
│   └── hackerone.py               # HackerOne API client
├── reporters/
│   └── chain_reporting.py         # HTML chain report, MITRE heatmap
├── validators/                    # ImpactValidator + ReadinessGate
└── utils/
    ├── helpers.py                 # Shared utilities
    ├── advanced_waf_bypass.py     # WAF evasion techniques
    ├── vrt_classifier.py          # Bugcrowd VRT classification
    └── response_validator.py      # HTTP response validation
```

---

## Data Flow

```
1. USER INPUT
   beatrix hunt example.com --preset full
                │
                ▼
2. CLI (cli/main.py)
   Parses args → creates BeatrixEngine → selects preset → calls engine.hunt()
                │
                ▼
3. ENGINE (core/engine.py)
   Loads 29 scanner modules → creates KillChainExecutor → executor.execute()
                │
                ▼
4. KILL CHAIN (core/kill_chain.py)
   Phase 1: _handle_recon
     → crawl target (crawler.py) → context["discovered_urls"], context["forms"]
     → external tools: subfinder, amass, nmap, katana, gospider
     → endpoint_prober, js_analysis, headers, github_recon
                │
   Phase 2-3: _handle_weaponization, _handle_delivery
     → takeover, error_disclosure, cache_poisoning, prototype_pollution
     → cors, redirect, oauth_redirect, http_smuggling, websocket
                │
   Phase 4: _handle_exploitation
     → OOB detector initialized for blind vuln confirmation
     → injection (+ response_analyzer behavioral detection + WAF bypass fallback), ssrf, idor, bac, auth, ssti, xxe, deserialization, ...
     → SmartFuzzer: ffuf-verified fuzzing on parameterized URLs
     → Confirmed findings → sqlmap, dalfox, commix, jwt_tool (deep exploit)
                │
   Phase 5-6: _handle_installation, _handle_c2
     → file_upload scanner
     → OOB detector polled for callbacks → findings from blind vulns
                │
   Phase 7: _handle_actions
     → VRT classification (Bugcrowd VRT + CVSS 3.1) on all findings
     → PoCChainEngine: correlation → exploit chain generation (≥2 findings)
     → Aggregation
                │
                ▼
5. FINDING PIPELINE
   KillChainState.all_findings → VRTClassifier (CVSS 3.1) → PoCChainEngine
     → IssueConsolidator (dedup) → ImpactValidator
     → FindingsDB (SQLite) → ReportGenerator (markdown/JSON/HTML + VRT enrichment)
                │
                ▼
6. OUTPUT
   Rich terminal display + optional file reports + HackerOne submission
```

---

## Dynamic Wordlist Engine (`seclists_manager.py`)

The `SecListsManager` provides 57,000+ unique injection payloads fetched on-demand from GitHub:

- **90 raw GitHub URLs**: 27 from SecLists + 63 from PayloadsAllTheThings
- **11 payload categories**: `sqli`, `xss`, `cmdi`, `ssti`, `lfi`, `ssrf`, `nosqli`, `ldap`, `xxe`, `redirect`, `crlf`
- **Disk + memory cache**: `~/.cache/beatrix/wordlists/` with 7-day TTL
- **Fallback payloads**: Built-in per-category fallbacks when offline
- **Singleton pattern**: `get_manager()` returns shared instance

### Consumers

| Module | How It Uses SecListsManager |
|--------|-----------------------------|
| `InjectionScanner` (`scanners/injection.py`) | `_augment_with_seclists()` — augments built-in payloads with all matching category wordlists |
| `FFufEngine` (`core/ffuf_engine.py`) | `get_wordlist()` — fetches specific wordlist files for exhaustive fuzzing modes |

### Payload Breakdown

| Source | Entries | Raw Payloads |
|--------|---------|-------------|
| SecLists | 27 | ~32,700 |
| PayloadsAllTheThings | 63 | ~37,100 |
| **Combined (deduplicated)** | **90** | **~57,000** |

---

## External Tool Integration

All 13 external tools are managed via `ExternalToolkit` (a lazy singleton on the
`KillChainExecutor`). Each tool runner:

- Uses `asyncio.create_subprocess_exec` for non-blocking execution
- Has configurable timeout (default 120s)
- Captures both stdout AND stderr (stderr logged on non-zero exit)
- Returns structured Python dicts/lists, not raw strings
- Gracefully degrades when binary is not installed (`available` property)

| Runner Class | Binary | Used By |
|-------------|--------|---------|
| `SubfinderRunner` | `subfinder` | _handle_recon |
| `AmassRunner` | `amass` | _handle_recon |
| `NmapRunner` | `nmap` | _handle_recon |
| `KatanaRunner` | `katana` | _handle_recon |
| `GospiderRunner` | `gospider` | _handle_recon |
| `HakrawlerRunner` | `hakrawler` | _handle_recon |
| `GauRunner` | `gau` | _handle_recon |
| `WhatwebRunner` | `whatweb` | _handle_recon, crawler |
| `WebanalyzeRunner` | `webanalyze` | _handle_recon, crawler |
| `DirsearchRunner` | `dirsearch` | _handle_recon |
| `SqlmapRunner` | `sqlmap` | _handle_exploitation |
| `DalfoxRunner` | `dalfox` | _handle_exploitation |
| `CommixRunner` | `commix` | _handle_exploitation |
| `JwtToolRunner` | `jwt_tool` | _handle_exploitation |
| `MetasploitRunner` | `msfconsole` | poc_chain_engine |

---

## Technology Stack

| Component | Technology | Reason |
|-----------|------------|--------|
| Language | Python 3.11+ | Async, rich ecosystem, AI libs |
| Async | asyncio + httpx | High-performance HTTP |
| CLI | Click + Rich | Best Python CLI framework |
| Database | SQLite (WAL) | Zero-config, portable, concurrent reads |
| Config | YAML | Human-readable |
| Go tools | nuclei, httpx, ffuf, subfinder, katana, etc. | Performance-critical scanning |
| AI | Claude API (Bedrock/Anthropic) | GHOST agent, Haiku-assisted hunting |
