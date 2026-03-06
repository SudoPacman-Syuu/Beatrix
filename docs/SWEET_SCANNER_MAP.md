# BEATRIX — Scanner Component Map

**Last Updated:** March 5, 2026

Quick reference for Beatrix's scanning architecture: kill chain phases, registered modules, external tools, core types, and data flow.

---

## Kill Chain Phases & Registered Modules

Scans execute phases in order. Each phase dispatches its registered scanner modules.

| Phase | Name | Scanner Keys | Module Count |
|-------|------|-------------|:------------:|
| **1** | Reconnaissance | `crawl`, `endpoint_prober`, `js_analysis`, `headers`, `github_recon` | 5 |
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
| `nuclei` | `NucleiScanner` | `scanners/nuclei.py` (WAF bypass: realistic UA, CDN-aware rate limiting, origin IP rewrite with TLS SNI) |
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
| `WhatwebRunner` | `whatweb` | `fingerprint()` |
| `WebanalyzeRunner` | `webanalyze` | `fingerprint()` |
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
