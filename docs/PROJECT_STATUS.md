# BEATRIX Project Status

**Codename:** The Omega Project
**Version:** 1.0.0 "The Bride"
**Last Updated:** February 23, 2026
**Current Phase:** Stable — Full audit complete
**Framework LOC:** ~55,355 (88 Python files across inner package)

---

## Quick Reference

| Component | Lines | Files | Status | Notes |
|-----------|-------|-------|--------|-------|
| Core Engine | 16,150 | 21 | ✅ Working | Engine, kill chain, types, methodology, external tools, fuzzer, OOB, correlation, **seclists_manager (dynamic wordlists)** |
| Scanner Modules | 27,431 | 39 | ✅ Working | 27 BaseScanner + 2 BaseModule subclasses + support modules |
| CLI Framework | 2,993 | 2 | ✅ Working | 20 commands via Click + Rich |
| AI Integration | 1,828 | 4 | ✅ Working | GHOST agent, HaikuGrunt, Bedrock/Anthropic |
| Recon Module | 472 | 1 | ✅ Working | Subdomain enum, tech detect, JS analysis |
| Hunters | 474 | 3 | ✅ Working | RapidHunter, HaikuHunter |
| Integrations | 683 | 2 | ✅ Working | HackerOne API client |
| Validators | 1,277 | 3 | ✅ Working | ImpactValidator, ReadinessGate |
| Reporters | 1,216 | 2 | ✅ Working | Chain reporting, HTML output |
| Utils | 3,696 | 6 | ✅ Working | WAF bypass, VRT classifier, helpers, response validator |

---

## CLI Commands (20 total)

```
beatrix hunt          # Full hunt with kill chain
beatrix probe         # Quick target alive check
beatrix strike        # Single scanner module attack
beatrix recon         # Subdomain/tech/JS/endpoint recon
beatrix ghost         # GHOST autonomous pentesting agent
beatrix rapid         # Multi-target sweep (takeover, debug, CORS)
beatrix haiku-hunt    # AI-assisted hunting via Bedrock
beatrix bounty-hunt   # Full OWASP Top 10 hunt
beatrix validate      # Validate findings from JSON
beatrix github-recon  # GitHub org/user secret scanning
beatrix h1            # HackerOne operations (programs/dupecheck/submit)
beatrix mobile        # Mobile app traffic interception
beatrix batch         # Batch scan from file
beatrix config        # Configuration management
beatrix list          # List available modules/presets
beatrix arsenal       # Display all scanner modules + categories
beatrix manual        # Open interactive HTML manual
beatrix chain-report  # Generate attack chain HTML report
beatrix oob-check     # Check OOB interaction logs
beatrix version       # Display version info
```

---

## External Tool Integration (13 Runners)

| Tool Runner | Binary | Kill Chain Phase | Purpose |
|------------|--------|-----------------|---------|
| `run_subfinder` | subfinder | 1 Recon | Subdomain enumeration |
| `run_nmap` | nmap | 1 Recon | Port/service scanning |
| `run_whatweb` | whatweb | 1 Recon | Technology fingerprinting |
| `run_webanalyze` | webanalyze | 1 Recon | Tech detection (Wappalyzer replacement) |
| `run_wafw00f` | wafw00f | 1 Recon | WAF detection |
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

| Phase | Name | Key Modules | External Tools |
|-------|------|-------------|----------------|
| 1 | Reconnaissance | EndpointProber, JSBundleAnalyzer, SubdomainTakeoverScanner | subfinder, nmap, whatweb, webanalyze, wafw00f |
| 2 | Weaponization | HeaderSecurityScanner, ErrorDisclosureScanner | ffuf |
| 3 | Delivery | NucleiScanner, CORSScanner, CachePoisoningScanner | nuclei |
| 4 | Exploitation | InjectionScanner, SSRFScanner, IDORScanner, AuthScanner, SSTIScanner, XXEScanner, + 8 more | sqlmap, dalfox, commix, jwt_tool |
| 5 | Installation | FileUploadScanner | — |
| 6 | Command & Control | InteractshClient OOB polling | — |
| 7 | Objectives | IssueConsolidator dedup + impact assessment | — |

---

## Architecture

```
beatrix/                       # Inner framework package
├── __init__.py                # v1.0.0 "The Bride"
├── multi_scanner.py           # Concurrent scanner orchestration
├── core/                      # Engine + orchestration (15.3K LOC, 20 files)
│   ├── engine.py              # BeatrixEngine orchestrator
│   ├── types.py               # Finding, Severity, Confidence, Target, ScanContext
│   ├── kill_chain.py          # 7-phase kill chain executor (1,226 LOC)
│   ├── external_tools.py      # 13 async subprocess tool runners (1,144 LOC)
│   ├── methodology.py         # MITRE ATT&CK / OWASP alignment
│   ├── correlation_engine.py  # Cross-finding correlation
│   ├── oob_detector.py        # Out-of-band callback monitor
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
│   └── scan_check_types.py    # Scan check type definitions
├── scanners/                  # Scanner modules (27.4K LOC, 39 files)
│   ├── base.py                # BaseScanner ABC, ScanContext
│   ├── injection.py           # SQLi, XSS, CMDi, LFI, SSTI (57K+ dynamic payloads)
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
│   ├── reconx_compat.py       # ReconX compatibility layer
│   └── github_recon.py        # GitHub secret scanning
├── ai/                        # AI layer (1.8K LOC, 4 files)
│   ├── assistant.py           # AIAssistant, HaikuGrunt, Bedrock/Anthropic
│   ├── ghost.py               # GHOST autonomous pentesting agent (10 tools)
│   └── tasks.py               # TaskRouter, model selection
├── cli/                       # Click CLI (3K LOC, 2 files)
│   └── main.py                # 20 commands
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

## Session Log

### Session 1 — February 5, 2026

**Focus:** Project initialization & initial framework build

- Created project structure and documentation
- Ported core engine, types, kill chain from ReconX
- Ported scanner modules (CORS, injection, IDOR, auth, SSRF, etc.)
- Built CLI framework with Click/Rich
- Integrated AI layer (HaikuGrunt, Bedrock backend)
- Built validators, reporters, utilities

### Session 2 — February 6, 2026

**Focus:** GHOST port, codebase consolidation, framework cleanup

- Ported GHOST autonomous agent from Java to Python (700 LOC, all 10 tools)
- Wired `beatrix ghost` CLI command
- Created `beatrix/recon/` module (consolidated from standalone `recon.py`)
- Created `beatrix/integrations/` package (moved HackerOne client into framework)
- Created `beatrix/hunters/` module (consolidated `rapid_hunter.py` + `haiku_hunter.py`)
- Fixed `sys.path` hacks, renamed shadowing `ScanResult` → `MultiScanResult`
- Verified all framework imports pass, all CLI commands register

### Session 3 — February 6, 2026

**Focus:** Installer fix, tool wiring, first bug audit

- Fixed installer bash crash (`((found++))` → `found=$((found + 1))`)
- Replaced dead wappalyzer with webanalyze throughout
- Created `beatrix/core/external_tools.py` — 13 async subprocess tool runners (1,144 LOC)
- Wired 12 previously cosmetic-only tools into actual scanner code
- First comprehensive audit: found and fixed 19 bugs across the codebase
- **Commits:** `1f29431`, `0bb9882`, `ce3a1a4`

### Session 4 — February 6, 2026

**Focus:** Integration depth audit + pipeline audit

- Deep integration audit: found and fixed 13 integration problems (output discarded, features never called, missing request context, multi-instantiation)
- End-to-end pipeline audit: found and fixed 7 pipeline bugs
  - CRITICAL: `_handle_exploitation` referenced undefined `toolkit` variable, silently preventing sqlmap/dalfox/commix/jwt_tool from ever running
  - `_run_scanner_on_urls` had no timeout, silent exception swallowing
  - OOB detector initialized too late, `_handle_actions` reading empty context
  - SSRF bypassing rate limiter, `KillChainPhase.modules` listing fictional module names
- **Commits:** `d31c8bb`, `124be1a`

### Session 5 — February 7, 2026

**Focus:** Final re-audit, remaining bug fixes, documentation rewrite

**Bugs fixed:**
- `install.sh`: `check_optional_tools` listed "wappalyzer" instead of "webanalyze" — tool always shown as missing
- `kill_chain.py` Phase 6 (`_handle_c2`): OOB detector initialized but never polled — now actually polls for callbacks and creates CRITICAL findings from confirmed interactions
- `cli/main.py`: `batch` command called `asyncio.run()` in a loop destroying/recreating event loops — now uses single `asyncio.run()` wrapping async function
- `chain_reporting.py`: Bare fallback import `from correlation_engine import ...` — replaced with proper `raise ImportError` with context

**Warnings fixed:**
- `ExternalToolkit` instantiated multiple times per hunt — now lazy singleton property on `KillChainExecutor` (`self.toolkit`)
- `external_tools.py` stderr sent to `DEVNULL` — now captured via `asyncio.subprocess.PIPE`, logged on non-zero exit

**Documentation:**
- README.md: Complete rewrite — accurate module counts, per-phase module tables, external tool integration table
- ARCHITECTURE.md: Complete rewrite from scratch — old version had fictional paths
- PROJECT_STATUS.md: Complete rewrite with accurate stats
- Manual (index.html): Updated module counts, tool references, kill chain descriptions

---

## Scanner Coverage (OWASP Top 10:2021)

| OWASP | Scanner | Status |
|-------|---------|--------|
| A01 Broken Access Control | IDORScanner, AuthScanner, MassAssignmentScanner, EndpointProber | ✅ |
| A02 Cryptographic Failures | CORSScanner, HeaderSecurityScanner, GraphQLScanner | ✅ |
| A03 Injection | InjectionScanner (57K+ dynamic payloads), SSTIScanner, XXEScanner, DeserializationScanner, PowerInjector | ✅ |
| A04 Insecure Design | PaymentScanner, BusinessLogicScanner, FileUploadScanner | ✅ |
| A05 Security Misconfiguration | ErrorDisclosureScanner, JSBundleAnalyzer, CachePoisoningScanner | ✅ |
| A06 Vulnerable Components | NucleiScanner (12,600+ CVE templates) | ✅ |
| A07 Auth Failures | AuthScanner, CredentialValidator | ✅ |
| A08 Software Integrity | PrototypePollutionScanner, DeserializationScanner | ✅ |
| A09 Logging Failures | (covered via error_disclosure probing) | ✅ |
| A10 SSRF | SSRFScanner (44 payloads, cloud metadata, gopher) | ✅ |
| — Subdomain Takeover | SubdomainTakeoverScanner | ✅ |
| — Open Redirect | OpenRedirectScanner, OAuthRedirectScanner | ✅ |
| — HTTP Smuggling | HTTPSmugglingScanner | ✅ |
| — ReDoS | ReDoSScanner | ✅ |
| — WebSocket | WebSocketScanner | ✅ |
| — CSS Injection | CSSExfiltrator | ✅ |

---

## Source Materials

| Source | Purpose | Size |
|--------|---------|------|
| ReconX v1.3 | Reference (older) | ~34K LOC |
| ReconX v1.4 | Primary port source | ~44K LOC |
| GHOST/BurpSweet | AI agent source | ~5.6K LOC Java |
| Burp decompiled | Scanning patterns reference | ~18K Java files |

---

## Next Steps

- [ ] Move `bounty_hunter.py` into `beatrix/hunters/bounty.py` (proper framework module)
- [ ] Move `hunt.py` pipeline into a CLI command (`beatrix full-hunt`)
- [ ] Add unit tests for GHOST agent
- [ ] Add unit tests for scanner modules
- [ ] Integration test: full kill chain on a test target
- [ ] GHOST: add Bedrock Sonnet support for complex investigations
- [ ] Explore Agent Bridge for multi-Claude coordination during hunts
- [x] Dynamic wordlist engine (SecLists + PayloadsAllTheThings)
- [x] Standardize JSON output format (envelope with metadata)
- [x] Fix `validate` command crash on bare-list JSON
- [x] Harden installer (extended extras, dependency verification)

---

### Session 6 — February 23, 2026

**Focus:** Dynamic wordlist engine, PayloadsAllTheThings integration, JSON output standardization

**New module — `seclists_manager.py` (851 LOC):**
- `SecListsManager` class: dynamic wordlist fetcher with disk + memory cache (7-day TTL)
- 90 GitHub raw URLs in `DIRECT_URL_CATALOG`: 27 from SecLists, 63 from PayloadsAllTheThings
- 11 payload categories: `sqli`, `xss`, `cmdi`, `ssti`, `lfi`, `ssrf`, `nosqli`, `ldap`, `xxe`, `redirect`, `crlf`
- Fallback payloads for offline operation
- Singleton pattern via `get_manager()`
- All 90 URLs verified returning HTTP 200, 57,045 unique payloads after dedup

**injection.py — Dynamic payload augmentation:**
- Added `_init_seclists()`, `_augment_with_seclists()`, `_load_builtin_payloads()` methods
- InjectionScanner now augments built-in payloads with SecListsManager for all 5 attack categories
- Validated: 56,481 total payloads loaded (cmdi: 8,776, path: 35,933, sqli: 1,419, ssti: 55, xss: 10,298)

**FFufEngine — Now functional:**
- `HAS_SECLISTS = True` since `seclists_manager.py` now exists
- Exhaustive payload loaders working: XSS (6,350), SQLi (389), LFI (1,760), RCE (8,262)

**JSON output standardization:**
- All `-o` flag paths now produce `{"findings": [...], "metadata": {...}}` envelope
- `_export_json()` in main.py — updated with envelope + metadata
- `reporter.export_json()` in reporters/__init__.py — updated with envelope + metadata
- `findings export --fmt json` — updated with envelope + filter metadata
- `validate` command — now handles both envelope and bare-list JSON inputs

**install.sh hardening:**
- All install methods now try `.[extended]` extras first, fallback to base
- Added `CORE_PYTHON_DEPS` array (28 packages) with import verification
- Added `verify_python_deps()` and `repair_python_deps()` functions

**Commits:** `b24db94`

---

*"Those of you lucky enough to have your lives, take them with you. However, leave the limbs you've lost. They belong to me now."*