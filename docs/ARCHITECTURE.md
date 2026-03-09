# BEATRIX Architecture

**Version:** 1.0.4  
**Last Updated:** March 10, 2026

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
│  │ Kill Chain   │  │ 32 Scanner   │  │  External    │  │  Issue       │     │
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

        ┌───────────────────────────────────────────────────────────────────┐
        │                  SCAN OUTPUT MANAGER (scan_output.py)             │
        │  Creates per-scan directory: {target}-scan-{DD}-{Mon}-{YYYY}_…   │
        │  Captures: raw tool stdout, scanner results, context snapshots,  │
        │  findings JSON, and summary. All files named after target.       │
        │  Organized into phase subdirs: recon/ weaponization/ delivery/   │
        │  exploitation/ installation/ c2/ actions/ findings/              │
        └───────────────────────────────────────────────────────────────────┘
```

---

## Kill Chain Phase → Module Mapping

Every `beatrix hunt` invocation runs through these phases. Each phase handler
calls `_run_scanner()` or `_run_scanner_on_urls()` with the exact engine
module key shown below.

| Phase | Handler | Engine Module Keys |
|-------|---------|-------------------|
| 1. Reconnaissance | `_handle_recon` | `crawl` (scope-aware, error capture), `endpoint_prober`, `js_analysis`, `headers` (per-endpoint), `github_recon` + external: subfinder, amass, nmap, katana, gospider, hakrawler, gau, whatweb, webanalyze, dirsearch + `recon_helpers`: robots/sitemap, HTML intel, SSL SAN, DNS recon, source maps, CVE lookup, favicon hash, subdomain liveness, WHOIS/ASN, GitHub domain search, internal host probe |
| 2. Weaponization | `_handle_weaponization` | `takeover`, `error_disclosure`, `cache_poisoning`, `prototype_pollution` |
| 3. Delivery | `_handle_delivery` | `cors`, `redirect`, `oauth_redirect`, `http_smuggling`, `websocket` |
| 4. Exploitation | `_handle_exploitation` | `injection` (+ response_analyzer + WAF bypass + baseline XSS filter), `ssti`, `ssrf`, `mass_assignment`, `redos`, `xxe`, `deserialization`, `idor`, `bac`, `auth`, `graphql`, `business_logic`, `payment`, `nuclei` (WAF bypass: realistic UA, CDN-aware rate limiting, additive origin IP scan with TLS SNI, FTL error detection, stats parsing) + SmartFuzzer (ffuf verification) + external: sqlmap, dalfox, commix, jwt_tool |
| 5. Installation | `_handle_installation` | `file_upload` |
| 6. C2 | `_handle_c2` | OOB detector polling — `LocalPoCClient` (built-in) or `InteractshClient` (external). PoCServer callbacks are polled with dedup tracking. |
| 7. Actions | `_handle_actions` | VRT classification (Bugcrowd VRT + CVSS 3.1) → PoCChainEngine (exploit chain generation from correlated findings) → aggregation via `KillChainState.all_findings` |

---

## MITRE ATT&CK Tactics (Web Focus)

| Tactic ID | Name | BEATRIX Coverage |
|-----------|------|------------------|
| TA0043 | Reconnaissance | 13-step recon pipeline — see Recon Advancement section below |
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
| A06 Vulnerable Components | `nuclei` (18,000+ templates — official + 3 external repos, WAF bypass, ASN-validated origin IP, FTL error detection), version-aware tech fingerprint pipeline |
| A07 Auth Failures | `auth` + jwt_tool |
| A08 Software Integrity | `prototype_pollution`, `deserialization` |
| A09 Logging Failures | (covered via error_disclosure probing) |
| A10 SSRF | `ssrf` + OOB detector |

---

## Technology Fingerprint Pipeline

Beatrix builds a **version-aware technology fingerprint** (`context["technologies"]`: `Dict[str, str]`)
from multiple sources throughout Phase 1. Version data is preserved end-to-end and fed to
nuclei for intelligent template selection.

### Data Sources → Merge Pipeline

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    TECHNOLOGY FINGERPRINT PIPELINE                           │
│  context["technologies"]: Dict[str, str]  (name → version)                  │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. Crawler _fingerprint_tech()                                              │
│     Server: nginx/1.20.1  →  technologies: ["nginx/1.20.1"]                 │
│     X-Powered-By: Express →  technologies: ["Express"]                      │
│                        │                                                     │
│                        ▼                                                     │
│  2. Kill chain normalization (_merge_technologies)                            │
│     List → Dict with parsed versions:                                        │
│       ["nginx/1.20.1", "PHP"] → {"nginx": "1.20.1", "php": ""}              │
│     Alias table normalizes names:                                            │
│       "httpd" → "apache", "node.js" → "node", etc.                          │
│                        │                                                     │
│                        ▼                                                     │
│  3. Nmap service scan merge                                                  │
│     product: "OpenSSH", version: "8.7" → {"openssh": "8.7"}                 │
│     Merged into tech dict without overwriting existing versions              │
│                        │                                                     │
│                        ▼                                                     │
│  4. WhatWeb + Webanalyze merge (_merge_technologies)                         │
│     {"nginx": "1.20.1", "PHP": "7.4.3"} → merged with version preservation  │
│                        │                                                     │
│                        ▼                                                     │
│  5. Header scanner feedback                                                  │
│     Extracts Server/X-Powered-By from header scanner findings               │
│     Merges back into tech dict via _merge_technologies()                     │
│                        │                                                     │
│                        ▼                                                     │
│  6. Tech fingerprint logged                                                  │
│     "Tech fingerprint: versioned: nginx 1.20.1, php 7.4.3; unversioned: …" │
│                        │                                                     │
│                        ▼                                                     │
│  7. Nuclei set_technologies(Dict[str, str])                                  │
│     Stores as _detected_technologies: Dict[str, str]                         │
│     Keys drive TECH_TAG_MAP matching for tag selection                        │
│     Versions preserved for future template filtering                         │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Helper Functions (kill_chain.py module-level)

| Function | Purpose |
|----------|---------|
| `_parse_tech_version(s)` | Parses `"nginx/1.20.1"` → `("nginx", "1.20.1")`. Handles slash and space separators. |
| `_merge_technologies(target, source)` | Merges dict or list into target dict. Parses versions, normalizes names via `_TECH_ALIASES`, never overwrites a known version with blank. |
| `_TECH_ALIASES` | Normalization table: `httpd→apache`, `node.js→node`, `mariadb→mysql`, etc. |

### Version Preservation Guarantees

- **Crawler**: Raw `Server` header value passed through (e.g., `"nginx/1.20.1"`)
- **Kill chain normalization**: `_merge_technologies()` parses versions from strings
- **Nmap merge**: Service `product`/`version` from port scan merged into tech dict
- **WhatWeb/Webanalyze**: Version-preserving merge via `_merge_technologies()`

---

## Recon Advancement — MITRE ATT&CK TA0043 Coverage

Phase 1 (`_handle_recon`) implements a 13-step recon pipeline aligned to
MITRE ATT&CK TA0043 Reconnaissance (excluding social engineering: T1598, T1591).

### Recon Steps (kill_chain.py)

| Step | Description | MITRE Technique | Module |
|------|-------------|-----------------|--------|
| 0 | Subdomain enum (subfinder + amass) | T1596.003 | subfinder, amass |
| 1 | Crawl target (scope-aware, error capture) | T1594 | crawler.py |
| 1b | robots.txt + sitemap.xml parsing | T1594 | recon_helpers |
| 1c | HTML comment + hidden input extraction | T1594 | recon_helpers |
| 2 | Network recon pipeline (nmap 3-phase) | T1595.001, T1595.002 | nmap_scanner |
| 2b | Crawl non-standard HTTP ports | T1595.001 | crawler.py |
| 3 | External crawlers (katana, gau, etc.) | T1593.002 | external_tools |
| 3a-i | GAU URL parameter deduplication | T1593 | recon_helpers |
| 3a-ii | SSL SAN extraction | T1596.003 | recon_helpers |
| 3a-iii | DNS record analysis (MX/NS/TXT/SPF/DMARC) | T1590.002, T1596.001 | recon_helpers |
| 4 | Tech fingerprinting (whatweb + webanalyze) | T1592.002 | external_tools |
| 4b | Tech-driven endpoint probing | T1592.002, T1595.002 | recon_helpers |
| 4c | CVE lookup for detected tech versions | T1596.005 | recon_helpers |
| 4d | Favicon hash fingerprinting | T1592.002 | recon_helpers |
| 5 | Dirsearch directory brute-force | T1595.003 | external_tools |
| 6–9 | Concurrent scanners (endpoint, JS, headers, GitHub) | T1594, T1593.003 | scanners |
| — | Per-endpoint header analysis | T1592.002 | headers.py |
| 7 | JS endpoint extraction + backfeed | T1594 | js_bundle.py |
| 8 | Source map discovery | T1592.004, T1594 | recon_helpers |
| 9 | Auth-protected endpoint extraction | T1589 | kill_chain |
| 10 | Internal host probing | T1590.004 | recon_helpers |
| 11 | Subdomain liveness scanning | T1595.001 | recon_helpers |
| 12 | GitHub domain-wide code search | T1593.003 | recon_helpers |
| 13 | WHOIS / ASN lookup | T1596.002 | recon_helpers |

### Helper Module: `core/recon_helpers.py` (~700 LOC)

| Function | MITRE Technique | Purpose |
|----------|-----------------|---------|
| `parse_robots_txt` | T1594 | Extract paths, Disallow entries, sitemaps |
| `parse_sitemap` | T1594 | Parse sitemap.xml / sitemapindex |
| `extract_html_intel` | T1594 | Hidden inputs, IP comments, secrets, meta generators |
| `deduplicate_parameterized_urls` | T1593 | (netloc, path, param_names) dedup |
| `extract_ssl_sans` | T1596.003 | TLS certificate Subject Alternative Names |
| `dns_recon` | T1590.002 | A/AAAA/MX/TXT/NS/CNAME + SPF/DMARC |
| `discover_source_maps` | T1592.004 | Probe .map files for source code exposure |
| `probe_internal_hosts` | T1590.004 | DNS + HTTP liveness for JS-discovered hosts |
| `check_known_cves` | T1596.005 | Offline CVE lookup for 16 common technologies |
| `check_favicon_hash` | T1592.002 | mmh3 hash → known product (13 signatures) |
| `whois_asn_lookup` | T1596.002 | Team Cymru DNS for ASN/org/IP ranges |
| `probe_subdomain_liveness` | T1595.001 | HTTP probe with tech fingerprint extraction |
| `get_tech_probe_paths` | T1592.002 | 60 tech-specific probe paths (15 technologies) |
| `github_domain_search` | T1593.003 | GitHub Code Search API for target references |

### Downstream Wiring

- **Auth-protected endpoints** → Phase 4 `auth` + `bac` scanners
- **Source map API endpoints** → `discovered_urls` for injection testing
- **Alive subdomains** → `discovered_urls` for all subsequent phases
- **Error responses** → `context["error_responses"]` for error_disclosure targeting
- **Parameter registry** → `context["param_registry"]` for unified injection testing
- **Recon findings** → `FindingEnricher.enrich_batch()` for CWE/PoC enrichment
- **Correlation engine** → Phase 7 `EventCorrelationEngine` already wired

### Scope-Aware Crawling

The crawler accepts `scope` patterns (e.g. `["*.example.com", "example.com"]`).
When set via `kill_chain.py`, links to in-scope subdomains are followed during
crawling — expanding attack surface discovery beyond same-origin links.

---

## CDN Gate — Network Scan Intelligence

When a CDN (Cloudflare, Akamai, Fastly, CloudFront, Sucuri, Incapsula) is detected via `origin_ip_discovery.py` and **no origin IP** can be discovered, the network pipeline's Phases 1–3 are **skipped entirely**:

| Scenario | Phase 0 (CDN detect) | Phases 1–3 (nmap/scapy/SSH) | HTTP scanners |
|----------|---------------------|------------------------------|---------------|
| No CDN detected | — | **Run** against domain | Run |
| CDN detected + origin IP found | Resolves origin | **Run** against origin IP | Run through CDN |
| CDN detected + **no origin IP** | ⚠️ Warning logged | **SKIPPED** (CDN gate) | Run through CDN |
| Target is raw IP | Skipped | **Run** against IP | Run |

### Why

Scanning a CDN edge with a 65,535-port nmap sweep + NSE scripts + packet crafting + SSH audit produces data about Cloudflare's infrastructure, not the target's. The time wasted is significant (10+ minutes) and the results are misleading.

### What Gets Skipped

- **Phase 1**: Full TCP SYN scan (65,535 ports), service fingerprinting, NSE vuln/discovery/auth scripts, UDP top-50
- **Phase 2**: Scapy firewall fingerprinting, source port bypass, fragment bypass, TTL mapping
- **Phase 3**: SSH audit (paramiko), service-specific NSE scripts, TLS audit
- **Nuclei network scan**: No non-HTTP services discovered → naturally empty

### What Still Runs

All HTTP-layer scanners (injection, XSS, CORS, SSRF, SSTI, etc.) operate through the CDN and test the actual web application. External crawlers (katana, gospider, gau) also run normally.

### Implementation

The gate is a single boolean `cdn_no_origin` computed after Phase 0:

```python
cdn_no_origin = (
    bool(context["network"].get("cdn_detected"))
    and scan_target == domain
    and not target_is_ip
)
```

Each phase checks `cdn_no_origin` and emits an info-level skip message explaining why it was skipped.

---

## Scan Output Manager (`scan_output.py`)

Every `beatrix hunt` automatically creates an **organized output directory** in the
current working directory. The directory captures raw tool output, scanner results,
phase context snapshots, and final findings — all as separate, human-readable files.

### Directory Naming Convention

```
{sanitized_target}-scan-{DD}-{Mon}-{YYYY}_{HH}-{MM}-{SS}
```

Example: `example.com-scan-09-Mar-2026_17-53-48`

- Scheme (`https://`) and path are stripped from the target
- Ports appear as `example.com_8080`
- Timestamp uses local time at scan start

### Output Directory Structure

```
example.com-scan-09-Mar-2026_17-53-48/
├── scan_info.txt               # Scan metadata (target, times, duration)
├── recon/                      # Phase 1 outputs
│   ├── subdomains_example.com.json      # Subfinder + Amass subdomains
│   ├── crawl_example.com.json           # Crawler results (pages, URLs, forms, tech)
│   ├── robots_sitemap_example.com.json  # robots.txt paths + sitemap URLs
│   ├── html_extraction_example.com.json # Hidden params, IPs in comments, secrets
│   ├── network_recon_example.com.json   # Nmap ports, services, firewall, SSH, CDN
│   ├── ssl_sans_example.com.json        # SSL certificate SANs + wildcards
│   ├── dns_recon_example.com.json       # DNS records (A, MX, NS, TXT, SPF, DMARC)
│   ├── technologies_example.com.json    # Merged tech fingerprint snapshot
│   ├── whois_asn_example.com.json       # WHOIS / ASN infrastructure data
│   ├── param_registry_example.com.json  # Unified parameter registry
│   ├── attack_surface_example.com.json  # Final attack surface (URLs, JS, forms)
│   ├── katana_example.com.txt           # Raw katana crawl output
│   ├── gau_example.com.txt              # Raw GAU historical URLs
│   ├── amass_example.com.txt            # Raw amass subdomain output
│   ├── nmap_example.com.txt             # Raw nmap scan output
│   ├── whatweb_example.com.json         # Raw WhatWeb fingerprint data
│   ├── endpoint_prober_example.com.json # Endpoint prober results
│   ├── headers_example.com.json         # Header analysis results
│   ├── js_analysis_example.com.json     # JS bundle analysis results
│   └── phase_1_Reconnaissance_example.com.json  # Phase context snapshot
├── weaponization/              # Phase 2 outputs
├── delivery/                   # Phase 3 outputs (CORS, redirect, etc.)
├── exploitation/               # Phase 4 outputs (SQLi, XSS, etc.)
│   ├── sqlmap_example.com.txt  # Raw sqlmap output
│   ├── dalfox_example.com.txt  # Raw dalfox output
│   └── injection_example.com.json  # Injection scanner results
├── installation/               # Phase 5 outputs
├── c2/                         # Phase 6 outputs
├── actions/                    # Phase 7 outputs
└── findings/                   # Final aggregated results
    ├── all_findings_example.com.json  # Full findings JSON
    └── findings_summary_example.com.txt  # Human-readable summary
```

### Data Flow

```
CLI (_hunt_single_target)
  └─ creates ScanOutputManager(target)
       └─ passed to BeatrixEngine(output_manager=...)
            └─ passed to KillChainExecutor(output_manager=...)
                 ├─ toolkit.set_output_manager() → all 13 ExternalTool runners
                 │    └─ ExternalTool._run() auto-captures raw stdout
                 ├─ _run_scanner() writes scanner results after each module
                 │    (always writes, even with 0 findings)
                 ├─ _handle_recon() writes 11 context snapshots:
                 │    subdomains, crawl, robots_sitemap, html_extraction,
                 │    network_recon, ssl_sans, dns_recon, technologies,
                 │    whois_asn, param_registry, attack_surface
                 └─ _execute_phase() writes context snapshots after each phase
```

- **ExternalTool._run()**: Automatically writes raw stdout to the matching phase
  subdirectory when `output_manager` is set. Each tool has a `DEFAULT_PHASE`
  class attribute (1=recon, 4=exploitation, 5=post-exploitation).
- **Scanner results**: Written as JSON after each scanner completes — **always**,
  even with zero findings (provides audit trail of what was tested).
- **Recon context snapshots**: 11 `write_context_snapshot()` calls throughout
  `_handle_recon` capture every recon data source: subdomains, crawl data,
  robots/sitemap, HTML extraction, network recon, SSL SANs, DNS records,
  technologies, WHOIS/ASN, parameter registry, and final attack surface.
- **Phase context snapshots**: Written after each phase completes.
- **Findings**: Written by `BeatrixEngine.hunt()` after dedup + enrichment.
- All output saving is **best-effort** — exceptions are silently caught so scan
  execution is never interrupted by I/O errors.
- **Header scanner**: Server/X-Powered-By values extracted from findings and merged
- **Nuclei**: `_detected_technologies` is now `Dict[str, str]`, preserving versions

---

## Directory Structure

```
beatrix/
├── __init__.py                    # v1.0.0
├── cli/
│   └── main.py                    # 26 CLI commands (Click + Rich)
├── core/
│   ├── engine.py                  # BeatrixEngine — 32 module registry, presets
│   ├── kill_chain.py              # KillChainExecutor — 7-phase state machine, version-aware tech pipeline
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
│   ├── auto_register.py           # Account auto-registration for authenticated testing
│   ├── seclists_manager.py        # Dynamic wordlist engine (SecLists + PATT, 57K+ payloads)
│   ├── scan_check_types.py        # Scan check type definitions
│   ├── packet_crafter.py          # Custom packet construction
│   ├── auth_config.py             # Auth credential management (YAML, CLI, env vars)
│   ├── auto_login.py              # Automated login engine (endpoint discovery, session capture)
│   ├── finding_enricher.py        # Deterministic finding enrichment (poc_curl, impact, CWE)
│   └── scan_output.py             # ScanOutputManager — per-scan organized output directory
├── scanners/
│   ├── base.py                    # BaseScanner ABC — rate limiter, httpx client
│   ├── crawler.py                 # Target spider — soft-404, forms, params, version-preserving tech fingerprint
│   ├── injection.py               # SQLi, XSS, CMDi, LFI, SSTI (57K+ dynamic payloads via SecLists + PATT, response_analyzer behavioral detection, baseline-filtered XSS reflection, WAF bypass fallback)
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
│   ├── nuclei.py                  # Nuclei template engine wrapper (versioned tech Dict, WAF bypass, origin IP additive scan, CDN-aware rate limiting, FTL error detection, stats parsing, timeout caps)
│   ├── file_upload.py             # Extension bypass, polyglot, path traversal
│   ├── payment_scanner.py          # Checkout flow manipulation
│   ├── redos.py                   # Regex DoS detection
│   ├── browser_scanner.py         # Playwright-based DOM XSS
│   ├── credential_validator.py    # Credential validation
│   ├── css_exfiltrator.py         # CSS injection data exfil
│   ├── mobile_interceptor.py      # ADB + mitmproxy traffic capture
│   ├── polyglot_generator.py      # Multi-context payload generation
│   ├── power_injector.py          # Advanced insertion point testing
│   ├── insertion.py               # Insertion point discovery
│   ├── origin_ip_discovery.py     # CDN bypass, origin IP fingerprinting, ASN validation (Team Cymru DNS)
│   ├── param_miner.py             # Hidden parameter discovery
│   ├── sequencer.py               # Token randomness analysis
│   └── backslash_scanner.py       # Backslash-powered path normalization attacks
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
    ├── helpers.py                 # Shared utilities, is_ip_address() (used by 6 modules for IP target detection)
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
   (26 Click commands: hunt, strike, ghost, recon, probe, browser, creds, inject, etc.)
                │
                ▼
3. ENGINE (core/engine.py)
   Loads 29 scanner modules → creates KillChainExecutor → executor.execute()
                │
                ▼
4. KILL CHAIN (core/kill_chain.py)
   IP Detection: is_ip_address(target) → sets context["is_ip"]
     → If IP: skips subfinder, amass, crt.sh, origin-IP discovery, GitHub recon
     → All HTTP-based scanners run normally on IP targets
   Phase 1: _handle_recon
     → crawl target (crawler.py) → context["discovered_urls"], context["forms"]
     → _fingerprint_tech() captures versioned Server/X-Powered-By headers
     → _merge_technologies() normalizes via alias table, preserves versions
     → external tools: subfinder, amass, nmap, katana, gospider
     → nmap service products/versions merged into context["technologies"]
     → WhatWeb/Webanalyze merged via _merge_technologies() (version-preserving)
     → header scanner findings extracted back into context["technologies"]
     → tech fingerprint logged (versioned + unversioned summary)
     → endpoint_prober, js_analysis, headers, github_recon
     → **CDN Gate**: If CDN detected (Cloudflare/Akamai/Fastly/etc.) and no origin
       IP found, network Phases 1-3 (nmap, packet_crafter, ssh_auditor) are skipped
       entirely — scanning a CDN edge only enumerates CDN infrastructure, not the
       target's. HTTP-layer scanners still test through the CDN normally.
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
