# BEATRIX — Scanner Component Map

**Last Updated:** March 10, 2026

Quick reference for Beatrix's scanning architecture: kill chain phases, registered modules, external tools, core types, and data flow.

---

## Kill Chain Phases & Registered Modules

Scans execute phases in order. Each phase dispatches its registered scanner modules.

| Phase | Name | Scanner Keys | Module Count |
|-------|------|-------------|:------------:|
| **1** | Reconnaissance | `crawl` (scope-aware, error capture), `endpoint_prober`, `js_analysis`, `headers` (per-endpoint), `github_recon` + `recon_helpers` (14 functions) | 5 + helpers |
| **2** | Weaponization | `takeover`, `error_disclosure`, `cache_poisoning`, `prototype_pollution` | 4 |
| **3** | Delivery | `cors`, `redirect`, `oauth_redirect`, `http_smuggling`, `websocket` | 5 |
| **4** | Exploitation | `injection`, `ssrf`, `idor`, `bac`, `auth`, `ssti`, `xxe`, `deserialization`, `graphql`, `mass_assignment`, `business_logic`, `redos`, `payment`, `nuclei` | 14 |
| **5** | Installation | `file_upload` | 1 |
| **6** | Command & Control | *(inline: OOB detector, PoC server, token enumerator)* | 0 |
| **7** | Actions on Objectives | *(inline: credential validation, Metasploit RC gen, VRT classification, PoC chain engine)* | 0 |

**Total registered modules:** 32

---

## Engine Module Registry

String key → class instance, all wired in `core/engine.py`:

| Key | Class | File |
|-----|-------|------|
| `crawl` | `TargetCrawler` | `scanners/crawler.py` |
| `endpoint_prober` | `EndpointProber` | `scanners/endpoint_prober.py` |
| `js_analysis` | `JSBundleAnalyzer` | `scanners/js_bundle.py` |
| `headers` | `HeaderSecurityScanner` | `scanners/headers.py` |
| `github_recon` | `GitHubRecon` | `scanners/github_recon.py` |
| `takeover` | `SubdomainTakeoverScanner` | `scanners/takeover.py` |
| `error_disclosure` | `ErrorDisclosureScanner` | `scanners/error_disclosure.py` |
| `cache_poisoning` | `CachePoisoningScanner` | `scanners/cache_poisoning.py` |
| `prototype_pollution` | `PrototypePollutionScanner` | `scanners/prototype_pollution.py` |
| `cors` | `CORSScanner` | `scanners/cors.py` |
| `redirect` | `OpenRedirectScanner` | `scanners/redirect.py` |
| `oauth_redirect` | `OAuthRedirectScanner` | `scanners/redirect.py` |
| `http_smuggling` | `HTTPSmugglingScanner` | `scanners/http_smuggling.py` |
| `websocket` | `WebSocketScanner` | `scanners/websocket.py` |
| `injection` | `InjectionScanner` | `scanners/injection.py` |
| `ssrf` | `SSRFScanner` | `scanners/ssrf.py` |
| `idor` | `IDORScanner` | `scanners/idor.py` |
| `bac` | `BACScanner` | `scanners/idor.py` |
| `auth` | `AuthScanner` | `scanners/auth.py` |
| `ssti` | `SSTIScanner` | `scanners/ssti.py` |
| `xxe` | `XXEScanner` | `scanners/xxe.py` |
| `deserialization` | `DeserializationScanner` | `scanners/deserialization.py` |
| `graphql` | `GraphQLScanner` | `scanners/graphql.py` |
| `mass_assignment` | `MassAssignmentScanner` | `scanners/mass_assignment.py` |
| `business_logic` | `BusinessLogicScanner` | `scanners/business_logic.py` |
| `redos` | `ReDoSScanner` | `scanners/redos.py` |
| `payment` | `PaymentScanner` | `scanners/payment_scanner.py` |
| `nuclei` | `NucleiScanner` | `scanners/nuclei.py` (versioned tech Dict, WAF bypass: realistic UA, CDN-aware rate limiting, origin IP rewrite with TLS SNI) |
| `file_upload` | `FileUploadScanner` | `scanners/file_upload.py` |
| `backslash` | `BackslashPoweredScanner` | `scanners/backslash_scanner.py` |
| `param_miner` | `ParamMiner` | `scanners/param_miner.py` |
| `sequencer` | `SequencerScanner` | `scanners/sequencer.py` |

---

## Presets

| Preset | Phases | Modules |
|--------|--------|---------|
| `quick` | 1, 3 | 6 |
| `stealth` | 1 | 5 |
| `recon` | 1, 2 | 9 |
| `standard` | 1–4 | 21 |
| `injection` | 1, 3, 4 | 12 |
| `api` | 1, 3, 4 | 15 |
| `web` | 1–5 | 32 |
| `full` | 1–7 | all 32 |

---

## Scan Execution Flow

```
beatrix hunt <target> --preset <p>
  └─ BeatrixEngine.hunt()
       ├─ Resolve preset → phases + module list
       ├─ KillChainExecutor.execute()
       │    ├─ Start PoC server (OOB callbacks, CORS PoC, token enum)
       │    ├─ Session validator calibration (if auth configured)
       │    └─ For each phase (in order):
       │         ├─ Between-phase session health check (re-auth if expired)
       │         ├─ _execute_phase() → phase handler
       │         │    └─ _run_scanner() per module key
       │         │         ├─ async with scanner → creates httpx client
       │         │         ├─ scanner.apply_auth(auth_creds)
       │         │         ├─ asyncio.wait_for(scanner.scan(ctx), timeout)
       │         │         └─ Stamps scanner_module on findings
       │         └─ Merge context into KillChainState
       ├─ IssueConsolidator.deduplicate()
       ├─ FindingEnricher (poc_curl, impact, CWE, repro steps)
       └─ Optional AI enrichment via HaikuGrunt (OWASP, remediation)
```

### Per-Scanner Timeouts

| Module | Timeout |
|--------|---------|
| Default | 600s |
| `nuclei` | 3,600s |
| `nmap_nse` | 1,800s |
| `ssh_auditor`, `packet_crafter` | 900s |
| `origin_ip_discovery` | 300s |

---

## Base Scanner Interface

All scanners extend `BaseScanner` (`scanners/base.py`):

| Item | Description |
|------|-------------|
| `scan(context) → AsyncIterator[Finding]` | **Abstract** — must implement |
| `passive_scan(context)` | Optional override for passive analysis |
| `active_scan(context, insertion_point)` | Optional override for active injection |
| `apply_auth(auth_creds)` | Injects headers + cookies into httpx client |
| `reapply_auth(auth_creds)` | Re-injects after mid-scan re-authentication |
| `session_appears_dead` | True after ≥3 consecutive 401s |
| `request(method, url, **kw)` | Rate-limited HTTP with 429 retry (3×) and 401 tracking |
| `create_finding(...)` | Pre-stamps `scanner_module`, `owasp_category`, `mitre_technique`, `found_at` |

`ScanContext` dataclass: `url`, `base_url`, `request`, `response`, `parameters`, `headers`, `cookies`, `insertion_points`, `extra`, `timestamp`. Factory: `ScanContext.from_url(url)`.

---

## Technology Fingerprint Pipeline

`context["technologies"]` is a `Dict[str, str]` (name → version) built from 5 sources during Phase 1:

| Source | Where | What it contributes |
|--------|-------|---------------------|
| Crawler `_fingerprint_tech()` | `crawler.py` | Server/X-Powered-By headers (raw values, e.g., `"nginx/1.20.1"`) |
| Nmap service scan | `kill_chain.py` (after enriched_ports) | Service product + version from port fingerprinting |
| WhatWeb | `kill_chain.py` (Step 4) | Technology name + version dict |
| Webanalyze | `kill_chain.py` (Step 4) | Technology name + version dict |
| Header scanner findings | `kill_chain.py` (after concurrent_results) | Server/X-Powered-By extracted from findings |

All sources merge via `_merge_technologies()` which:
- Parses versions from compound strings (`"nginx/1.20.1"` → name `"nginx"`, version `"1.20.1"`)
- Normalizes names via `_TECH_ALIASES` (`"httpd"` → `"apache"`, `"node.js"` → `"node"`, etc.)
- Never overwrites a known version with a blank

The final dict is passed to `NucleiScanner.set_technologies()` which stores it as `Dict[str, str]` for tag-based template selection.

---

## Core Type System (`core/types.py`)

### Enums

| Enum | Values |
|------|--------|
| `Severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `Confidence` | `CERTAIN`, `FIRM`, `TENTATIVE`, `WEAK` |
| `InsertionPointType` | `URL_PARAM`, `BODY_PARAM`, `COOKIE`, `HEADER`, `JSON_VALUE`, `XML_VALUE`, `URL_PATH`, `URL_PATH_FOLDER`, `ENTIRE_BODY`, `MULTIPART` |
| `MitreTactic` | 13 tactics (TA0043 → TA0040) |
| `OwaspCategory` | A01–A10 (OWASP Top 10 2021) |
| `TargetStatus` | `PENDING`, `RECON`, `SCANNING`, `EXPLOITING`, `COMPLETE`, `PAUSED`, `ERROR` |

### Key Dataclasses

| Class | Key Fields |
|-------|-----------|
| `Finding` | `id`, `title`, `severity`, `confidence`, `url`, `parameter`, `payload`, `request`, `response`, `evidence`, `description`, `impact`, `remediation`, `poc_curl`, `poc_python`, `scanner_module`, `owasp_category`, `cwe_id`, `mitre_technique` |
| `InsertionPoint` | `name`, `value`, `type`, `original_request`, `position` |
| `Target` | `id`, `domain`, `scope`, `exclude`, `status`, `priority`, `program`, `platform` |
| `ScanResult` | `target`, `module`, `findings`, `errors`, `requests_sent`, `endpoints_tested` |
| `HttpRequest` / `HttpResponse` | Standard HTTP envelope fields |

---

## Scan Check Registry (`core/scan_check_types.py`)

| Type | Interface | Dispatch |
|------|-----------|----------|
| `PassiveScanCheck` | `do_passive_check(url, status, headers, body)` | Per-host or per-request |
| `ActiveScanCheck` | `do_active_check(url, insertion_point, send_request)` | Per-insertion-point |

`ScanCheckRegistry` manages registration, enable/disable, and stats (`findings_produced`, `requests_sent`, `errors`).

---

## External Tool Runners

### In `core/external_tools.py` (13 runners)

**Recon (8):**

| Class | Binary | Method |
|-------|--------|--------|
| `KatanaRunner` | `katana` | `crawl()` |
| `AmassRunner` | `amass` | `enumerate()` |
| `GospiderRunner` | `gospider` | `spider()` |
| `HakrawlerRunner` | `hakrawler` | `crawl()` |
| `GauRunner` | `gau` | `fetch_urls()` |
| `WhatwebRunner` | `whatweb` | `fingerprint()` → version-preserving merge via `_merge_technologies()` |
| `WebanalyzeRunner` | `webanalyze` | `fingerprint()` → version-preserving merge via `_merge_technologies()` |
| `DirsearchRunner` | `dirsearch` | `scan()` |

**Exploitation (3):**

| Class | Binary | Method |
|-------|--------|--------|
| `SqlmapRunner` | `sqlmap` | `exploit()` |
| `DalfoxRunner` | `dalfox` | `scan()` |
| `CommixRunner` | `commix` | `exploit()` |

**Auth (1):**

| Class | Binary | Methods |
|-------|--------|---------|
| `JwtToolRunner` | `jwt_tool` | `analyze()`, `tamper()` |

**Post-Exploitation (1):**

| Class | Binary | Methods |
|-------|--------|---------|
| `MetasploitRunner` | `msfconsole` | `generate_resource_file()`, `generate_exploit_rc()`, `search_modules()` |

### In separate core modules

| Class | File | Binary |
|-------|------|--------|
| `SubfinderRunner` | `core/subfinder.py` | `subfinder` |
| `NmapScanner` | `core/nmap_scanner.py` | `nmap` |
| `FfufEngine` | `core/ffuf_engine.py` | `ffuf` |

### In `core/recon_helpers.py` (14 functions, ~700 LOC)

MITRE ATT&CK TA0043 reconnaissance helpers called from kill chain Phase 1:

| Function | Purpose | MITRE |
|----------|---------|-------|
| `parse_robots_txt` | robots.txt paths + sitemaps | T1594 |
| `parse_sitemap` | sitemap.xml URL extraction | T1594 |
| `extract_html_intel` | Hidden inputs, IP/secret comments | T1594 |
| `deduplicate_parameterized_urls` | GAU URL dedup | T1593 |
| `extract_ssl_sans` | TLS certificate SANs | T1596.003 |
| `dns_recon` | A/MX/NS/TXT/CNAME + SPF/DMARC | T1590.002 |
| `discover_source_maps` | .map file exposure + secrets | T1592.004 |
| `probe_internal_hosts` | JS-discovered host liveness | T1590.004 |
| `check_known_cves` | Offline CVE lookup (16 products) | T1596.005 |
| `check_favicon_hash` | mmh3 favicon fingerprint | T1592.002 |
| `whois_asn_lookup` | ASN/org via Team Cymru DNS | T1596.002 |
| `probe_subdomain_liveness` | HTTP probe + tech merge | T1595.001 |
| `get_tech_probe_paths` | 60 paths for 15 technologies | T1592.002 |
| `github_domain_search` | GitHub Code Search API | T1593.003 |

---

## CDN Gate — Network Scan Skip Logic

When `origin_ip_discovery.py` detects a CDN but cannot find the origin IP, network Phases 1-3 are **skipped**:

| Phase | What | Skipped When CDN + No Origin |
|-------|------|:----------------------------:|
| Phase 1 | nmap full TCP, service fingerprint, NSE, UDP | ✅ Skipped |
| Phase 2 | scapy firewall fingerprint, bypass testing | ✅ Skipped |
| Phase 3 | SSH audit, service NSE, TLS audit | ✅ Skipped |
| Nuclei network | Protocol-specific non-HTTP checks | ✅ Naturally empty |
| HTTP scanners | All web application scanners | ❌ Run normally through CDN |

Gate variable: `cdn_no_origin` in `kill_chain.py` — computed after Phase 0 CDN detection.

---

## Unregistered Scanner Modules (commented-out imports)

These files exist in `scanners/` but are **not** imported or registered in the engine:

| File | Class | Purpose |
|------|-------|---------|
| `credential_validator.py` | `CredentialValidator` | Leaked credential validation |
| `mobile_interceptor.py` | `MobileInterceptor` | Android traffic interception |
| `power_injector.py` | `PowerInjector` | Advanced SQLi/XSS/CMDi |
| `browser_scanner.py` | `BrowserScanner` | Playwright-based scanning |
| `polyglot_generator.py` | `PolyglotGenerator` | XSS polyglot payloads |
| `css_exfiltrator.py` | `CSSExfiltrator` | CSS injection + data exfil |
| `idor_auth.py` | `AuthenticatedIDORScanner` | Multi-role AI-driven IDOR |
| `jwt_analyzer.py` | `JWTAnalyzer` | JWT deep analysis |

---

## Auth Pipeline

```
auth.yaml (user home)
  └─ AuthConfigLoader._resolve_config_path()  ← handles sudo
       └─ AuthConfigLoader.load() → AuthCredentials
            ├─ main user: headers, cookies, login creds
            ├─ idor.user1: login creds, headers, cookies
            └─ idor.user2: login creds, headers, cookies

CLI (hunt/strike)
  ├─ perform_auto_login(main_user) → session cookies/tokens
  ├─ perform_auto_login(idor_user1) → session cookies/tokens
  └─ perform_auto_login(idor_user2) → session cookies/tokens

Engine
  ├─ scanner.apply_auth(auth_creds) → injects into httpx client
  ├─ Between-phase session health check → re-auth if expired
  └─ IDORScanner: cross-account testing with user1 + user2 sessions
```

---

## Scan Output Directory (`core/scan_output.py`)

Every hunt creates a `{target}-scan-{DD}-{Mon}-{YYYY}_{HH}-{MM}-{SS}` directory
in the current working directory containing all tool outputs:

```
CLI → ScanOutputManager(target) → BeatrixEngine → KillChainExecutor
  ├─ ExternalToolkit.set_output_manager() → all 13 tool runners auto-capture stdout
  ├─ _run_scanner() → writes scanner results JSON after each module
  ├─ _execute_phase() → writes context snapshots after each phase
  └─ hunt() → writes final findings JSON + summary text
```

Phase subdirectories: `recon/`, `weaponization/`, `delivery/`, `exploitation/`,
`installation/`, `c2/`, `actions/`, `findings/`. All files named `{tool}_{target}.{ext}`.
