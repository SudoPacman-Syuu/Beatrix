# BEATRIX Project Status

**Version:** 1.0.0
**Last Updated:** March 6, 2026
**Current Phase:** Stable — Nuclei integration fully fixed (16 issues), injection/JS bundle/auth scanner false positives fixed, origin IP pipeline hardened with ASN validation
**Framework LOC:** ~73,800 (112 Python files total, ~66,300 in inner package)

---

## Quick Reference

| Component | Lines | Files | Status | Notes |
|-----------|-------|-------|--------|-------|
| Core Engine | 22,349 | 27 | ✅ Working | Engine, kill chain, types, methodology, external tools, fuzzer, OOB, correlation, **seclists_manager (dynamic wordlists)**, **poc_server (PoC validation HTTP server)**, **auth_config**, **auto_login**, **finding_enricher** |
| Scanner Modules | 29,496 | 40 | ✅ Working | 32 registered BaseScanner modules + 8 standalone modules + support |
| CLI Framework | 4,644 | 3 | ✅ Working | 26 commands via Click + Rich |
| AI Integration | 1,893 | 4 | ✅ Working | GHOST agent, HaikuGrunt, Bedrock/Anthropic |
| Recon Module | 472 | 1 | ✅ Working | Subdomain enum, tech detect, JS analysis |
| Hunters | 474 | 3 | ✅ Working | RapidHunter, HaikuHunter |
| Integrations | 683 | 2 | ✅ Working | HackerOne API client |
| Validators | 1,277 | 3 | ✅ Working | ImpactValidator, ReadinessGate |
| Reporters | 1,294 | 2 | ✅ Working | Chain reporting, HTML output, VRT enrichment (Bugcrowd VRT + CVSS 3.1) |
| Utils | 3,716 | 6 | ✅ Working | WAF bypass, VRT classifier, helpers, response validator |

---

## CLI Commands (26 total)

```
beatrix hunt          # Full hunt with kill chain (single target or -f file)
beatrix probe         # Quick target alive check
beatrix strike        # Single scanner module attack
beatrix recon         # Subdomain/tech/JS/endpoint recon
beatrix ghost         # GHOST autonomous pentesting agent
beatrix rapid         # Multi-target sweep (takeover, debug, CORS)
beatrix haiku-hunt    # AI-assisted hunting via Bedrock
beatrix bounty-hunt   # [DEPRECATED] → use `beatrix hunt --preset full`
beatrix validate      # Validate findings from JSON
beatrix github-recon  # GitHub org/user secret scanning
beatrix h1            # HackerOne operations (programs/dupecheck/submit)
beatrix mobile        # Mobile app traffic interception
beatrix browser       # Playwright-based browser scanning (DOM XSS, WAF evasion)
beatrix creds         # Credential validation (JWT, API keys, AWS, GitHub, Stripe)
beatrix origin-ip     # Origin IP discovery behind CDN/WAF
beatrix inject        # Deep parameter injection (SQLi, XSS, SSTI, CMDi)
beatrix polyglot      # XSS polyglot generation, mXSS, DOM clobbering payloads
beatrix batch         # Batch scan from file
beatrix config        # Configuration management
beatrix list          # List available modules/presets
beatrix arsenal       # Display all scanner modules + categories
beatrix manual        # Open interactive HTML manual
beatrix setup         # Interactive setup wizard
beatrix auth          # Auth credential management (init, config, login, show, browser, idor, sessions)
beatrix findings      # Findings management (show, hunts, export, diff, delete, summary)
beatrix help          # Display help information
```

---

## External Tool Integration (13 Runners)

| Tool Runner | Binary | Kill Chain Phase | Purpose |
|------------|--------|-----------------|---------|
| `run_subfinder` | subfinder | 1 Recon | Subdomain enumeration |
| `run_nmap` | nmap | 1 Recon | Port/service scanning |
| `run_whatweb` | whatweb | 1 Recon | Technology fingerprinting |
| `run_webanalyze` | webanalyze | 1 Recon | Tech detection (Wappalyzer replacement) |
| `run_ffuf` | ffuf | 2 Weaponization | Directory/endpoint fuzzing |
| `run_nuclei` | nuclei | 3 Delivery | CVE template scanning |
| `run_sqlmap` | sqlmap | 4 Exploitation | SQL injection exploitation |
| `run_dalfox` | dalfox | 4 Exploitation | XSS exploitation |
| `run_commix` | commix | 4 Exploitation | Command injection exploitation |
| `run_jwt_tool` | jwt_tool | 4 Exploitation | JWT attack toolkit |
| `run_metasploit` | msfconsole | PoC Chain | Exploit search, module suggestions |

All runners live in `beatrix/core/external_tools.py` (1,144 LOC). `ExternalToolkit` is a lazy singleton on `KillChainExecutor` — instantiated once per hunt via `self.toolkit` property.

---

## Kill Chain (7 Phases)

| Phase | Name | Scanner Keys | External Tools |
|-------|------|-------------|----------------|
| 1 | Reconnaissance | `crawl`, `endpoint_prober`, `js_analysis`, `headers`, `github_recon` | subfinder, amass, nmap, katana, gospider, hakrawler, gau, whatweb, webanalyze, dirsearch |
| 2 | Weaponization | `takeover`, `error_disclosure`, `cache_poisoning`, `prototype_pollution` | — |
| 3 | Delivery | `cors`, `redirect`, `oauth_redirect`, `http_smuggling`, `websocket` | — |
| 4 | Exploitation | `injection`, `ssrf`, `idor`, `bac`, `auth`, `ssti`, `xxe`, `deserialization`, `graphql`, `mass_assignment`, `business_logic`, `redos`, `payment`, `nuclei` + SmartFuzzer (ffuf) | sqlmap, dalfox, commix, jwt_tool |
| 5 | Installation | `file_upload` | — |
| 6 | Command & Control | LocalPoCClient / InteractshClient OOB polling | — |
| 7 | Objectives | VRT classification (Bugcrowd VRT + CVSS 3.1), PoCChainEngine (exploit chain generation), IssueConsolidator dedup + impact assessment | — |

---

## Architecture

```
beatrix/                       # Inner framework package
├── __init__.py                # v1.0.0
├── core/                      # Engine + orchestration (22.3K LOC, 27 files)
│   ├── engine.py              # BeatrixEngine orchestrator
│   ├── types.py               # Finding, Severity, Confidence, Target, ScanContext
│   ├── kill_chain.py          # 7-phase kill chain executor (2,642 LOC)
│   ├── external_tools.py      # 13 async subprocess tool runners (1,179 LOC)
│   ├── methodology.py         # MITRE ATT&CK / OWASP alignment
│   ├── correlation_engine.py  # Cross-finding correlation
│   ├── oob_detector.py        # OOB callback monitor (InteractshClient + LocalPoCClient)
│   ├── poc_server.py          # Built-in PoC validation HTTP server (890 LOC)
│   ├── smart_fuzzer.py        # Intelligent fuzzing engine
│   ├── poc_chain_engine.py    # PoC chain generation
│   ├── parallel_haiku.py      # Concurrent AI workers
│   ├── ffuf_engine.py         # ffuf integration engine
│   ├── nmap_scanner.py        # nmap integration engine
│   ├── subfinder.py           # subfinder integration engine
│   ├── ssh_auditor.py         # SSH configuration auditor
│   ├── packet_crafter.py      # Custom packet crafting
│   ├── privilege_graph.py     # Privilege escalation graph
│   ├── findings_db.py         # Findings persistence
│   ├── issue_consolidator.py  # Deduplication + consolidation
│   ├── response_analyzer.py   # HTTP response analysis
│   ├── seclists_manager.py    # Dynamic wordlist engine (SecLists + PATT, 57K+ payloads)
│   ├── scan_check_types.py    # Scan check type definitions
│   ├── auth_config.py         # Auth credential management (YAML, CLI, env vars) (848 LOC)
│   ├── auto_login.py          # Automated login engine (endpoint discovery, session capture) (2,231 LOC)
│   ├── auto_register.py       # Account auto-registration for authenticated testing
│   └── finding_enricher.py    # Deterministic finding enrichment (poc_curl, impact, CWE) (542 LOC)
├── scanners/                  # Scanner modules (29.5K LOC, 40 files)
│   ├── base.py                # BaseScanner ABC, ScanContext
│   ├── injection.py           # SQLi, XSS, CMDi, LFI, SSTI (57K+ dynamic payloads, response_analyzer behavioral detection, WAF bypass fallback)
│   ├── ssrf.py                # SSRF (44 payloads, gopher/AWS/GCP/Azure)
│   ├── idor.py                # IDOR + method override
│   ├── auth.py                # Authentication bypass
│   ├── cors.py                # CORS misconfiguration
│   ├── ssti.py                # Server-side template injection
│   ├── xxe.py                 # XML external entity
│   ├── redirect.py            # Open redirect + OAuth redirect
│   ├── headers.py             # Security header analysis
│   ├── error_disclosure.py    # Error/info leak detection
│   ├── http_smuggling.py      # HTTP request smuggling
│   ├── deserialization.py     # Insecure deserialization
│   ├── mass_assignment.py     # Mass assignment
│   ├── prototype_pollution.py # JS prototype pollution
│   ├── cache_poisoning.py     # Web cache poisoning
│   ├── file_upload.py         # File upload bypass
│   ├── graphql.py             # GraphQL introspection + injection
│   ├── websocket.py           # WebSocket security
│   ├── redos.py               # Regular expression DoS
│   ├── takeover.py            # Subdomain takeover
│   ├── nuclei.py              # Nuclei CVE template scanner
│   ├── endpoint_prober.py     # Endpoint discovery
│   ├── js_bundle.py           # JavaScript bundle analysis
│   ├── payment_scanner.py     # Payment flow testing
│   ├── business_logic.py      # Business logic flaws
│   ├── idor_auth.py           # Authenticated IDOR testing
│   ├── browser_scanner.py     # Browser-based scanning (Playwright)
│   ├── crawler.py             # Target crawling
│   ├── credential_validator.py # Credential validation
│   ├── css_exfiltrator.py     # CSS injection exfiltration
│   ├── jwt_analyzer.py        # JWT analysis module
│   ├── mobile_interceptor.py  # Mobile traffic interception
│   ├── origin_ip_discovery.py # Origin IP behind CDN
│   ├── polyglot_generator.py  # XSS polyglot + DOM clobbering
│   ├── power_injector.py      # Deep parameter injection
│   ├── insertion.py           # Insertion point detection
│   ├── param_miner.py         # Hidden parameter discovery
│   ├── sequencer.py           # Token randomness analysis
│   ├── backslash_scanner.py   # Backslash-powered path normalization attacks
│   └── github_recon.py        # GitHub secret scanning
├── ai/                        # AI layer (1.9K LOC, 4 files)
│   ├── assistant.py           # AIAssistant, HaikuGrunt, Bedrock/Anthropic
│   ├── ghost.py               # GHOST autonomous pentesting agent (10 tools)
│   └── tasks.py               # TaskRouter, model selection
├── cli/                       # Click CLI (4,644 LOC, 3 files)
│   ├── main.py                # 26 commands
│   └── __main__.py            # python -m beatrix.cli entry point
├── recon/                     # Recon module (472 LOC)
│   └── __init__.py            # ReconRunner, ReconResult
├── hunters/                   # Hunting workflows (474 LOC, 3 files)
│   ├── rapid.py               # RapidHunter (multi-domain sweep)
│   └── haiku.py               # HaikuHunter (AI-assisted)
├── integrations/              # External services (683 LOC, 2 files)
│   └── hackerone.py           # HackerOneClient, H1ReportDraft
├── validators/                # Finding validation (1.3K LOC, 3 files)
│   ├── impact_validator.py    # ImpactValidator
│   └── readiness_gate.py      # ReadinessGate
├── reporters/                 # Output generation (1.2K LOC, 2 files)
│   └── chain_reporting.py     # Attack chain HTML reports
└── utils/                     # Shared utilities (3.7K LOC, 6 files)
    ├── helpers.py             # HTTP helpers, encoding, parsing
    ├── advanced_waf_bypass.py # WAF evasion techniques
    ├── vrt_classifier.py      # Bugcrowd VRT classification
    └── response_validator.py  # Response validation utilities
```

---

## GHOST Agent

Ported from Java `AIAgentV2.java` (1,215 lines) → Python `ghost.py` (~700 lines).

**10 Tools:**
| Tool | Purpose |
|------|---------|
| `send_http_request` | Send arbitrary HTTP requests |
| `inject_payload` | Inject into specific parameters |
| `fuzz_parameter` | Fuzz with anomaly detection |
| `time_based_test` | Timing-based blind injection |
| `compare_responses` | Diff two stored responses |
| `search_response` | Literal + regex search |
| `extract_from_response` | URLs, emails, tokens, custom patterns |
| `encode_payload` | URL, base64, HTML, unicode, hex encoding |
| `record_finding` | Log a confirmed vulnerability |
| `conclude_investigation` | Generate investigation summary |

**Architecture:** Autonomous tool-call loop with `<tool_call>` XML parsing, response caching (cross-tool reference), max 50 iterations, configurable AI backend (Anthropic or Bedrock).

---

## Next Steps

- [x] Fix nuclei integration (16 issues — all fixed, see `nuclei-audit.md`)
- [x] Fix injection scanner false positives (behavioral detection, XSS reflection)
- [x] Fix JS bundle scanner framework noise (SvelteKit/React internals)
- [x] Fix auth scanner rate-limit on non-existent endpoints
- [x] Fix install.sh (httpx shim, root config, nuclei templates, chromium deps)
- [x] Fix subfinder `-nW` flag
- [ ] Move `bounty_hunter.py` into `beatrix/hunters/bounty.py` (proper framework module)
- [ ] Add unit tests for GHOST agent
- [ ] Add unit tests for scanner modules
- [ ] Integration test: full kill chain on a test target
- [ ] GHOST: add Bedrock Sonnet support for complex investigations
- [ ] Auto-login: handle OTP/2FA flows that require email verification codes
- [ ] Auto-login: detect false-positive auth (Cloudflare-only cookies vs real session)