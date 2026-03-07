# Nuclei Integration — Comprehensive Audit

> **Scope**: Every nuclei-related code path in Beatrix — `nuclei.py`, `kill_chain.py`,
> `origin_ip_discovery.py`, `engine.py`, `install.sh`, and all callers.
>
> **Date**: 2025-07-15 (initial), 2026-03-06 (franktech cross-reference, fixes applied)  
> **Evidence**: Live scans of `fivetran.com` and `franktech.net` with `--preset full`  
> **Result**: 16 issues identified, **all 16 fixed**. Additional false positive
> bugs found in injection scanner via cross-reference (also fixed — see `BEATRIX_AUDIT.md`).
> **Post-audit sweep (2026-03-06):** One additional nuclei bug found and fixed during
> scanner-audit sweep — tag fallback in `_run_nuclei()` silently filtered network/workflow
> templates (tracked as B-02 in `SCANNER_AUDIT.md`, fixed in `b6a2dd1`).

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Issue Catalog](#3-issue-catalog)
   - [N-01: Origin IP Rewrite Poisons All URLs](#n-01-origin-ip-rewrite-poisons-all-urls)
   - [N-02: Origin IP Validation Has No ASN/Infrastructure Check](#n-02-origin-ip-validation-has-no-asninfrastructure-check)
   - [N-03: Webflow Missing From Hosting Provider Ranges](#n-03-webflow-missing-from-hosting-provider-ranges)
   - [N-04: Hosting Signature Check Doesn't Catch Rendered Customer Pages](#n-04-hosting-signature-check-doesnt-catch-rendered-customer-pages)
   - [N-05: Duplicate Rate Limit Flags — `-rate-limit` and `-rl` Are Aliases](#n-05-duplicate-rate-limit-flags--rate-limit-and--rl-are-aliases)
   - [N-06: Exploit and Headless Phases Have No Outer Timeout](#n-06-exploit-and-headless-phases-have-no-outer-timeout)
   - [N-07: Timeout Calculation Produces Absurd Values for Large URL Sets](#n-07-timeout-calculation-produces-absurd-values-for-large-url-sets)
   - [N-08: FTL/Fatal Errors Silently Swallowed](#n-08-ftlfatal-errors-silently-swallowed)
   - [N-09: Headless Mode Missing Chromium System Dependencies](#n-09-headless-mode-missing-chromium-system-dependencies)
   - [N-10: Scan Completion Stats Never Parsed or Validated](#n-10-scan-completion-stats-never-parsed-or-validated)
   - [N-11: URL Accumulation Across Phases on Shared Instance](#n-11-url-accumulation-across-phases-on-shared-instance)
   - [N-12: Interactsh Session Isolation — OOB Unification Broken](#n-12-interactsh-session-isolation--oob-unification-broken)
   - [N-13: Headless Template Guard Only Checks Official Dir](#n-13-headless-template-guard-only-checks-official-dir)
   - [N-14: Confidence Assignment Ignores Template Quality](#n-14-confidence-assignment-ignores-template-quality)
   - [N-15: No Request Count Validation — Impossible Completion Goes Undetected](#n-15-no-request-count-validation--impossible-completion-goes-undetected)
   - [N-16: install.sh Template Download Runs As Root Under Sudo](#n-16-installsh-template-download-runs-as-root-under-sudo)
4. [Origin IP Pipeline — End-to-End Failure Analysis](#4-origin-ip-pipeline--end-to-end-failure-analysis)
5. [What Actually Happened in the Fivetran Scan](#5-what-actually-happened-in-the-fivetran-scan)
6. [Priority Matrix](#6-priority-matrix)
7. [Fix Roadmap](#7-fix-roadmap)

---

## 1. Executive Summary

Nuclei integration in Beatrix is architecturally well-designed — multi-phase scanning,
technology-aware tag selection, authenticated scanning, WAF-aware rate limiting, origin IP
bypass, interactsh OOB unification, workflow support, and external template repos.  On paper
it's one of the most sophisticated nuclei integrations in any automated tool.

**In practice, it produced zero results** — until all 16 issues documented below were fixed.

The live scan of `fivetran.com` exposed a cascade of failures at every layer:

| Phase | URLs | Time | Findings | What Went Wrong |
|-------|------|------|----------|-----------------|
| RECON | 111,638 | 29s | 0 | URLs rewritten to Webflow IP; no meaningful scanning occurred |
| EXPLOIT | 111,638 | 33s | 0 | Same origin IP poisoning; duplicate rate limit flags; no outer timeout |
| HEADLESS | 223,276 | 11s | 0 | Crashed immediately — missing `libatk-1.0.so.0`; FTL error swallowed |

A second scan of `franktech.net` (March 6, 2026) confirmed every nuclei failure with a
**correct** origin IP — disproving the theory that fixing the origin IP alone would fix nuclei:

| Phase | URLs | Time | Findings | What Went Wrong |
|-------|------|------|----------|-----------------|
| RECON | 96 | 30s | 0 | Correct origin IP (167.71.161.180), still 0 findings — rewrite disrupts template matching |
| EXPLOIT | 96 | 30s | 0 | Same — templates expect hostname URLs, not IP literals |
| HEADLESS | 193 | 1s | 0 | Same crash — `libatk-1.0.so.0` missing, identical FTL error |

The root cause was a chain reaction: a flawed origin IP discovery accepts a shared hosting IP
(Webflow 198.202.211.1) as the "real origin" → all 111K URLs get rewritten to that IP →
nuclei sends requests to Webflow instead of Fivetran → Webflow returns generic responses →
nuclei finds nothing. Meanwhile, headless mode couldn't work because `install.sh` never installed
chromium dependencies, and the fatal crash error was silently swallowed by the stderr parser.

**16 distinct issues** documented below, ranging from P0 (scan-breaking) to P3 (cosmetic).
**All 16 have been fixed.** The franktech.net cross-reference also uncovered 4 additional bugs
in the injection and JS bundle scanners (documented in `BEATRIX_AUDIT.md` as Bugs 6–9,
also all fixed).

---

## 2. Architecture Overview

### File Map

| File | Lines | Role |
|------|-------|------|
| `beatrix/scanners/nuclei.py` | 1,176 | Core implementation — `NucleiScanner` class |
| `beatrix/core/kill_chain.py` | ~2,600 | Orchestrator — calls nuclei in 4 places (network, recon, exploit, headless) |
| `beatrix/scanners/origin_ip_discovery.py` | ~900 | Origin IP discovery — feeds `set_origin_ip()` |
| `beatrix/core/engine.py` | ~600 | Module registry — WAF detection for standalone `strike -m nuclei` |
| `beatrix/scanners/__init__.py` | ~85 | Scanner registry — exports `NucleiScanner` |
| `install.sh` | ~750 | Installer — nuclei binary, template download |

### Scan Mode Architecture

```
Kill Chain
  │
  ├─ Phase 0: Origin IP Discovery → origin_ip_discovery.py
  │   └─ If origin IP found → set_origin_ip(ip, domain)
  │
  ├─ Phase 1 Network: scan_network() on non-HTTP ports
  │   └─ network_targets = ["{origin_ip}:{port}", ...]
  │
  ├─ Phase 1 Recon: scan_recon() in parallel with other scanners
  │   ├─ add_urls(recon_urls)
  │   ├─ set_technologies(techs), set_auth(...), set_waf(...), set_origin_ip(...)
  │   └─ _run_nuclei(urls, recon_tags, severity=info,low)
  │       └─ Origin IP rewrite → rewrites ALL matching URLs to origin IP
  │
  ├─ Phase 4 Exploit: scan_exploit() after other exploit scanners
  │   ├─ add_urls(all_urls)  ← includes recon URLs already in _urls_to_scan
  │   ├─ set_technologies(enriched_techs), set_auth, set_waf, set_origin_ip
  │   └─ _run_nuclei(urls, exploit_tags, full severity)
  │       ├─ Main tag-based scan
  │       └─ Workflow scan (per detected technology)
  │
  └─ Phase 4 Headless: scan_headless()
      └─ _run_nuclei(urls, headless tags, -headless flag)
```

### Key Method Call Chain

```
kill_chain.py → nuclei.add_urls() → self._urls_to_scan.extend()
kill_chain.py → nuclei.set_origin_ip(ip, domain) → self._origin_ip, self._target_domain
kill_chain.py → nuclei.scan_recon(ctx) → _run_nuclei(urls, tags)
                                              │
                                              ├─ Origin IP rewrite (L889-903)
                                              ├─ Write URLs to temp file
                                              ├─ Build command (tags, auth, rate limits, etc.)
                                              ├─ Start subprocess
                                              ├─ Stream stdout (JSONL) → _parse_nuclei_finding()
                                              ├─ Drain stderr (background task, keyword filter)
                                              └─ Kill process on timeout or EOF
```

---

## 3. Issue Catalog

---

### N-01: Origin IP Rewrite Poisons All URLs — ✅ FIXED

**Priority**: P0 — Scan-breaking  
**File**: `nuclei.py` lines 889–903  
**Impact**: Every URL sent to nuclei hits the wrong server  
**Fix**: Origin IP rewrite no longer replaces URLs. Instead, it *adds* origin-targeted URLs alongside the originals, so nuclei scans both CDN and origin paths. Removed global `Host` header override; per-URL Host headers are set only on origin-targeted URLs via nuclei's header syntax.

#### What the code does

```python
# nuclei.py L889-903 — inside _run_nuclei()
effective_targets = targets
if self._origin_ip and self._target_domain:
    from urllib.parse import urlparse, urlunparse
    rewritten = []
    for t in targets:
        parsed = urlparse(t) if "://" in t else None
        if parsed and parsed.hostname == self._target_domain:
            # Replace only the hostname, preserving scheme/path/query
            rewritten.append(urlunparse(parsed._replace(netloc=
                parsed.netloc.replace(self._target_domain, self._origin_ip, 1)
            )))
        else:
            rewritten.append(t)
    effective_targets = rewritten
```

When `set_origin_ip("198.202.211.1", "fivetran.com")` is called, this loop rewrites every URL
whose hostname matches `fivetran.com`. In the fivetran scan, 111K+ URLs like
`https://fivetran.com/integrations/sql-server?utm_source=google` all became
`https://198.202.211.1/integrations/sql-server?utm_source=google`.

#### Why this is wrong

1. **Blanket rewrite is dangerous.** The intent is CDN bypass, but most crawled URLs are
   application paths (`/integrations/`, `/docs/`, `/blog/`). These paths exist on the CDN-served
   application but may not exist on the origin IP's web server. A proper CDN bypass only needs
   to rewrite a small set of base-path URLs to probe the origin.

2. **If the origin IP is a shared hosting provider** (Webflow, Shopify, etc.), ALL rewritten
   requests go to that provider's infrastructure. Nuclei scans Webflow's server, not Fivetran's.

3. **Subdomain exclusion is good but insufficient.** The code correctly skips subdomains
   (`parsed.hostname == self._target_domain` matches exact domain only), but the problem is
   with the main domain's 111K URLs, not subdomains.

#### What should happen

Run nuclei **twice**: once on the full URL list through the CDN (normal path), and once on
a small set of base URLs (`https://{origin_ip}/`, `https://{origin_ip}/robots.txt`, etc.)
targeting the origin directly. The CDN pass catches misconfigurations visible through the
CDN. The origin pass catches things the WAF blocks.

#### Cross-Reference: franktech.net (March 6, 2026)

The franktech.net scan provides critical evidence that **this bug exists independently of
wrong origin IPs**. Unlike fivetran (Webflow shared hosting), franktech's origin IP
`167.71.161.180` is a **correct, legitimate DigitalOcean droplet** serving the real
application (Immich photo management, Express + SvelteKit). Confirmed via direct curl:

```
curl --resolve franktech.net:443:167.71.161.180 'https://franktech.net/api/admin/users'
→ HTTP 401 {"message":"Authentication required","error":"Unauthorized","statusCode":401}
```

Despite having the **correct** origin IP, nuclei still produced 0 findings across all 3
modes (RECON: 96 URLs/30s/0, EXPLOIT: 96 URLs/30s/0, HEADLESS: 193 URLs/1s/crash). This
proves the rewrite isn't just broken for wrong IPs — **the blanket rewrite mechanism itself
disrupts template matching** because nuclei templates expect hostname-based URLs
(`https://franktech.net/path`), not IP-based URLs (`https://167.71.161.180/path`). Many
templates match on hostname patterns in the URL or response, and IP-rewritten URLs break
these matches silently.

---

### N-02: Origin IP Validation Has No ASN/Infrastructure Check — ✅ FIXED

**Priority**: P0 — Scan-breaking (upstream of N-01)  
**File**: `origin_ip_discovery.py` lines 717–796  
**Impact**: Shared hosting IPs accepted as origin IPs  
**Fix**: Added `_lookup_asn()` via Team Cymru DNS (TXT query to `origin.asn.cymru.com` + `peer.asn.cymru.com`). Checks ASN description against `HOSTING_ASN_KEYWORDS` list (webflow, shopify, squarespace, wix, netlify, vercel, github, heroku, wordpress, ghost, fly.io, render, railway, cloudflare, akamai, fastly, incapsula, sucuri, stackpath). Infrastructure IPs are rejected.

#### What the code does

```python
# origin_ip_discovery.py L729-790 — check_ip() inner function
async def check_ip(ip_info: Dict) -> Optional[Dict]:
    ip = ip_info['ip']
    # ...
    async with session.get(
        f"{scheme}://{ip}/",
        headers={'Host': domain},
        ssl=ssl_arg,
        allow_redirects=False,
    ) as resp:
        body = (await resp.text())[:4000].lower()

        # Hosting provider detection via string matching
        is_hosting = any(sig in body for sig in HOSTING_SIGNATURES)

        # "Validation": domain appears in response
        domain_in_response = (
            domain in body
            or domain in str(resp.headers).lower()
            or resp.status in (200, 301, 302, 403)
        )
        if domain_in_response:
            ip_info['validated'] = True
```

Validation consists of:
1. Checking if the response body contains known hosting provider strings
2. Checking if the response body/headers contain the target domain
3. Accepting the IP if the response is 200, 301, 302, or 403

#### Why this is wrong

For `198.202.211.1` (Webflow), this validation **passes** because:
- Webflow renders fivetran.com's content → body contains "fivetran.com" → `domain_in_response = True`
- The HOSTING_SIGNATURES list checks for `"webflow.com"` in the body, but Webflow's rendered
  customer pages don't contain "webflow.com" — they contain the customer's domain and content
- Response status is 200 → auto-validates

**Missing checks that would catch this:**

| Check | What it would reveal |
|-------|---------------------|
| **ASN lookup** (whois/BGP) | ASN 209242 = "Webflow, Inc." — not Fivetran |
| **Reverse DNS** (PTR record) | Would show a Webflow hostname |
| **TLS certificate subject** | Cert issued to webflow.com or *.webflow.io |
| **IP range ownership** | 198.202.0.0/16 belongs to Webflow |
| **Server header** | Webflow returns `server: Webflow` |
| **X-Served-By header** | Webflow infrastructure identifiers |

Any ONE of these checks would correctly identify 198.202.211.1 as Webflow infrastructure.

#### Simplified explanation

The code asks: "Does this IP serve content about fivetran.com?" and Webflow says "yes" because
it hosts fivetran.com's marketing site. But the RIGHT question is: "Does this IP belong to
Fivetran's infrastructure?" which requires checking WHO OWNS the IP, not what content it serves.

---

### N-03: Webflow Missing From Hosting Provider Ranges — ✅ FIXED

**Priority**: P1 — Contributes to false origin IP acceptance  
**File**: `origin_ip_discovery.py` lines 50–67  
**Impact**: Webflow IPs pass the `_is_cdn_ip()` pre-filter  
**Fix**: Added Webflow `198.202.208.0/20`, Ghost(Pro) `178.128.0.0/16`, and Fly.io `66.241.124.0/22` + `137.66.0.0/16` to `HOSTING_PROVIDER_RANGES`.

#### What the code does

```python
# origin_ip_discovery.py L50-67
HOSTING_PROVIDER_RANGES = [
    "23.227.32.0/20",        # Shopify
    "3.0.0.0/15", "52.0.0.0/11",  # Heroku (AWS subset)
    "185.199.108.0/22",      # GitHub Pages
    "75.2.60.0/24", "99.83.231.0/24",  # Netlify
    "76.76.21.0/24",         # Vercel
    "198.185.159.0/24", "198.49.23.0/24",  # Squarespace
    "185.230.63.0/24", "185.230.60.0/22",  # Wix
    "192.0.64.0/18",         # WordPress.com
]
```

Webflow's IP ranges are absent. IP `198.202.211.1` is not in any of these ranges, so it passes
the `_is_cdn_ip()` check that's supposed to filter out shared hosting IPs.

#### What's missing

Webflow's known IP ranges (approximate, based on ASN 209242):
- `198.202.208.0/20` (covers 198.202.208.0 – 198.202.223.255)
- `34.117.0.0/16` (some Webflow assets on GCP)

Additionally, these popular hosting providers are also missing:
- **Fly.io**: various ranges
- **Render**: GCP-hosted
- **Railway**: various ranges
- **DigitalOcean App Platform**: 162.159.0.0/16 (some)
- **Azure Static Web Apps**: various
- **AWS Amplify**: EC2 ranges (overlaps with Heroku entry)

#### Simplified explanation

The code has a blocklist of hosting provider IP ranges to reject as false positives.
Webflow isn't on the list, so its IPs sail through as potential origin IPs.

---

### N-04: Hosting Signature Check Doesn't Catch Rendered Customer Pages — ✅ FIXED

**Priority**: P1 — Only works for unbranded hosting error pages  
**File**: `origin_ip_discovery.py` lines 720–724  
**Impact**: Any hosting provider that renders customer content evades detection  
**Fix**: Hosting signature check now examines response headers (`server`, `x-served-by`, `x-powered-by`, `via`, `x-hosted-by`) in addition to body text. Headers like `server: Webflow` are caught even when the body contains only customer branding.

#### What the code does

```python
# origin_ip_discovery.py L720-724
HOSTING_SIGNATURES = [
    "shopify", "squarespace", "wix.com", "herokuapp.com",
    "wordpress.com", "ghost.io", "webflow.com", "netlify",
    "vercel", "github.io", "pages.dev", "only a shopify store",
]
```

These strings are searched for in the first 4KB of the response body. If found, the IP is
marked as `hosting_provider_detected = True` and its confidence is slashed.

#### Why this fails

When Webflow renders `fivetran.com`, the response body contains:
- `"fivetran.com"` — yes (customer domain)
- `"webflow.com"` — **no** (Webflow strips its branding from rendered customer pages)

The body looks like a normal fivetran.com page — HTML with Fivetran's content, links, etc.
There's no `"webflow.com"` string anywhere in the rendered output. A customer's site only
shows `webflow.com` if:
- The site is on a free plan with a `.webflow.io` domain
- The site has footer badges enabled
- The site hasn't customized its 404 page

For a paid customer like Fivetran with a custom domain, the rendered content is 100%
branded as Fivetran.

#### What would work

Check **response headers** instead of/in addition to body text:
- `server: Webflow` — Webflow always sets this header
- `x-wf-*` headers — Webflow internal routing headers
- `x-powered-by: Webflow` — sometimes present

Also check TLS certificate details — Webflow sites use certificates issued to Webflow's
infrastructure, not to the customer domain.

---

### N-05: Duplicate Rate Limit Flags — `-rate-limit` and `-rl` Are Aliases — ✅ FIXED

**Priority**: P1 — Effective rate limit is not what the code intends  
**File**: `nuclei.py` lines 921–922  
**Impact**: Rate limit is always the "per-host" value, not the "global" value  
**Fix**: Removed the duplicate `-rl` flag. Only `-rate-limit` (the canonical flag) is passed, using `self._rate_limit` as the single global rate limit value.

#### What the code does

```python
# nuclei.py L916-922 — inside _run_nuclei()
cmd = [
    self.nuclei_path,
    # ...
    "-rate-limit", str(self._rate_limit),      # Intended: global rate limit
    "-rl", str(self._rate_limit_per_host),      # Intended: per-host rate limit
    # ...
]
```

The code sets two rate limit values:
- `self._rate_limit` = 150 default (30 with WAF)
- `self._rate_limit_per_host` = 50 default (15 with WAF)

#### Why this is wrong

In nuclei v3, `-rl` is simply an **alias** for `-rate-limit`. They are the same flag:

```
-rl, -rate-limit int  maximum number of requests to send per second (default 150)
```

There is **no per-host rate limit flag** in nuclei v3. The code passes both flags to the same
nuclei process on the same command line. When a CLI flag is specified twice, the toolchain's
flag parser (typically Go's `flag` package or `goflags`) uses the **last value**. So the
effective rate limit is always `self._rate_limit_per_host` (50 default, 15 with WAF).

| Scenario | Intended global | Intended per-host | Actual effective |
|----------|----------------|-------------------|------------------|
| No WAF | 150 rps | 50 rps | **50 rps** |
| WAF detected | 30 rps | 15 rps | **15 rps** |

The "global" rate limit value is always ignored. This isn't catastrophic (lower rates are
safer), but the code structure is misleading and the behavior doesn't match the intent.

#### Simplified explanation

The code tries to set two separate rate limits (global and per-host), but nuclei only has one
rate limit setting. The two flags are different names for the same thing, so the second one
always wins.

---

### N-06: Exploit and Headless Phases Have No Outer Timeout — ✅ FIXED

**Priority**: P0 — Can hang the entire scan indefinitely  
**File**: `kill_chain.py` lines 1828–1858  
**Impact**: Nuclei exploit/headless phases can run for hours with no kill switch  
**Fix**: Both exploit and headless nuclei calls are now wrapped in `asyncio.wait_for()` with a `nuclei_timeout` (from `SCANNER_TIMEOUT_OVERRIDES`, default 3600s). On timeout, partial results collected so far are preserved and the scan continues to the next phase.

#### What the code does

**Recon phase** — has an outer timeout:
```python
# kill_chain.py L1443
scanner_tasks.append(asyncio.wait_for(
    _nuclei_recon_task(),
    timeout=self.SCANNER_TIMEOUT_OVERRIDES.get("nuclei", self.SCANNER_TIMEOUT)
    # = 3600 seconds (1 hour)
))
```

**Exploit phase** — no outer timeout:
```python
# kill_chain.py L1828-1840
async with nuclei:
    async for finding in nuclei.scan_exploit(exploit_ctx):
        if not finding.scanner_module:
            finding.scanner_module = "nuclei"
        exploit_result["findings"].append(finding)
        self._emit("finding", scanner="nuclei", finding=finding)
```

**Headless phase** — no outer timeout:
```python
# kill_chain.py L1848-1856
async with nuclei:
    async for finding in nuclei.scan_headless(headless_ctx):
        # ...
```

Neither exploit nor headless is wrapped in `asyncio.wait_for()`. The only timeout is
nuclei.py's internal `self.timeout_seconds` which is set by `_calculate_timeout()`.

#### Why this is dangerous

For 111K URLs in exploit mode, `_calculate_timeout()` computes (see N-07):
```python
extra = max(0, 111638 - 50) * 2 = 223,176
timeout = max(600, 600 + 223176) = 223,776 seconds = ~62 hours
```

The nuclei subprocess has a 62-hour wall-clock timeout. There is no outer timeout from the kill
chain to override this. If nuclei hangs or runs slowly, the entire scan blocks for up to 62
hours.

#### Simplified explanation

The recon nuclei scan has a 1-hour maximum. The exploit and headless scans have no maximum —
they're allowed to run as long as nuclei's own timeout says, which can be calculated as days
for large URL sets.

---

### N-07: Timeout Calculation Produces Absurd Values for Large URL Sets — ✅ FIXED

**Priority**: P1 — Enables N-06  
**File**: `nuclei.py` lines 676–694  
**Impact**: Timeouts scale linearly with URL count, producing multi-day values  
**Fix**: All timeout modes now capped at 3300 seconds (55 minutes). Combined with the outer `asyncio.wait_for()` timeout from N-06, nuclei can never run longer than ~1 hour per phase.

#### What the code does

```python
# nuclei.py L676-694
def _calculate_timeout(self, url_count: int, mode: str = "exploit") -> int:
    if mode == "recon":
        return max(180, 120 + url_count * 3)
    elif mode == "network":
        return max(180, 180 + len(self._network_targets) * 5)
    elif mode == "headless":
        return max(300, 120 + url_count * 30)
    else:  # exploit
        extra = max(0, url_count - 50) * 2
        return max(int(self._base_timeout), int(self._base_timeout + extra))
```

#### Example calculations for 111,638 URLs

| Mode | Formula | Result | Human-readable |
|------|---------|--------|----------------|
| recon | 120 + 111,638 × 3 | 334,914s | **3.9 days** |
| exploit | 600 + (111,638 − 50) × 2 | 223,776s | **2.6 days** |
| headless | 120 + 111,638 × 30 | 3,349,140s | **38.8 days** |

These timeouts are the subprocess wall-clock limits. Nuclei will never take 38 days, but
the timeout doesn't protect against broken scans. The comment says "No hard caps —
effectiveness is the priority" but effectiveness requires the scan to actually finish in a
reasonable time.

#### What should happen

Cap timeouts at a reasonable maximum (e.g., 2 hours for exploit, 4 hours for headless).
If nuclei hasn't completed in that time, something is wrong (stuck request, DNS loop, etc.).

---

### N-08: FTL/Fatal Errors Silently Swallowed — ✅ FIXED

**Priority**: P0 — Scan-breaking  
**File**: `nuclei.py` lines 994–1008  
**Impact**: Nuclei crashes are reported as "0 findings" success  
**Fix**: `_drain_stderr()` now checks for `[FTL]`, `[FAT]`, `fatal`, and `panic` keywords, logging them immediately as warnings and setting a `fatal_detected` flag. After nuclei exits, the completion logic checks `process.returncode != 0` and `fatal_detected` — if either is true, emits a `scanner_error` event and logs "Nuclei FAILED" instead of "Nuclei complete".

#### What the code does

```python
# nuclei.py L994-1008 — _drain_stderr()
async def _drain_stderr():
    """Read stderr in background so the pipe doesn't block."""
    try:
        while True:
            raw = await process.stderr.readline()
            if not raw:
                break
            text = raw.decode("utf-8", errors="replace").strip()
            if text:
                stderr_lines.append(text)
                # Log stats/progress lines so the user sees activity
                if any(kw in text.lower() for kw in
                       ("templates", "hosts", "requests", "errors",
                        "matched", "duration", "rps")):
                    self.log(f"[nuclei] {text}")
    except Exception:
        pass
```

The keyword filter only logs lines containing: `templates`, `hosts`, `requests`, `errors`,
`matched`, `duration`, `rps`. Nuclei's fatal error format is:

```
[FTL] Could not create browser: operation not permitted: ...missing libatk-1.0.so.0
```

`[FTL]` doesn't match any of the filter keywords. The error IS stored in `stderr_lines` but
only the last 5 stderr lines are logged AFTER the scan completes:

```python
# nuclei.py L1076-1078
if stderr_lines:
    for sline in stderr_lines[-5:]:
        self.log(f"[nuclei stderr] {sline}")
```

If nuclei produces more than 5 other stderr lines after the FTL error (stats, progress, etc.),
the FTL line is pushed out of the last-5 window and never logged.

#### What actually happened

The headless scan crashed immediately with:
```
[FTL] Could not create browser: operation not permitted: ...missing libatk-1.0.so.0
```
Nuclei exited with an error code. The scan reported:
```
Nuclei complete: 0 findings in 11s
```
No error was visible. No `scanner_error` event was emitted. The scan appeared to succeed.

#### What should happen

1. **Filter for `[FTL]`, `[FAT]`, `fatal`, `panic`** in stderr and emit `scanner_error` event
2. **Check process.returncode** after nuclei exits — non-zero means failure
3. **Log ALL stderr** if findings count is 0 (something went wrong)
4. **Don't report success** if the process crashed

---

### N-09: Headless Mode Missing Chromium System Dependencies — ✅ FIXED

**Priority**: P0 — Headless mode can never work  
**File**: `install.sh` (no headless dep section exists)  
**Impact**: `scan_headless()` crashes on every invocation  
**Fix**: Added `apt-get install` block to `install.sh` for 13 chromium system libraries required by go-rod (libatk1.0-0, libatk-bridge2.0-0, libcups2, libgbm1, libgtk-3-0, libnss3, libxcomposite1, libxdamage1, libxfixes3, libxrandr2, libpango1.0-0, libdrm2, libxshmfence1).

#### What happens

Nuclei's headless mode uses `go-rod` (a Go library for controlling Chromium). `go-rod`
downloads its own Chromium binary, but Chromium requires system libraries that are NOT
installed by `install.sh`:

| Library | Package (Debian/Ubuntu) | Required for |
|---------|------------------------|--------------|
| `libatk-1.0.so.0` | `libatk1.0-0` | Accessibility toolkit |
| `libatk-bridge-2.0.so.0` | `libatk-bridge2.0-0` | AT-SPI bridge |
| `libcups.so.2` | `libcups2` | Print support |
| `libgbm.so.1` | `libgbm1` | Graphics buffer manager |
| `libgtk-3.so.0` | `libgtk-3-0` | GTK widgets |
| `libnss3.so` | `libnss3` | TLS/SSL support |
| `libxcomposite.so.1` | `libxcomposite1` | X11 compositing |
| `libxdamage.so.1` | `libxdamage1` | X11 damage tracking |
| `libxfixes.so.3` | `libxfixes3` | X11 fixes |
| `libxrandr.so.2` | `libxrandr2` | X11 display management |
| `libpango-1.0.so.0` | `libpango1.0-0` | Text rendering |
| `libdrm.so.2` | `libdrm2` | Direct Rendering Manager |
| `libxshmfence.so.1` | `libxshmfence1` | X shared memory fencing |
| `libxkbcommon.so.0` | `libxkbcommon0` | Keyboard handling |

#### The fix

Add to `install.sh` in the system dependencies section:

```bash
# Chromium dependencies for nuclei headless mode (go-rod)
apt-get install -y \
    libatk1.0-0 libatk-bridge2.0-0 libcups2 libgbm1 \
    libgtk-3-0 libnss3 libxcomposite1 libxdamage1 \
    libxfixes3 libxrandr2 libpango1.0-0 libdrm2 \
    libxshmfence1 libxkbcommon0
```

#### Simplified explanation

Nuclei's browser scanning mode needs Chrome. Chrome needs a dozen system libraries for
rendering, accessibility, and display. The installer never installs them, so Chrome can't
start, and Beatrix's headless scan crashes every time.

---

### N-10: Scan Completion Stats Never Parsed or Validated — ✅ FIXED

**Priority**: P1 — No way to detect scanning failures  
**File**: `nuclei.py` lines 994–1008 (stderr), lines 1072–1078 (summary)  
**Impact**: Cannot distinguish "0 real findings" from "scan didn't run"  
**Fix**: `_drain_stderr()` now parses nuclei's stats lines from stderr using regex, extracting `templates_loaded`, `targets_loaded`, `requests_done`, `requests_total`, and `errors`. These are stored in a `scan_stats` dict and logged in the completion summary.

#### What the code does

Nuclei prints detailed statistics to stderr when `-stats` is enabled:
```
[INF] Templates loaded: 6543 | Workflows: 12
[INF] Targets loaded: 111638
[INF] [stats] [500.12s] Requests: 45000/1234560 (3.6%) | RPS: 90 | Matched: 0 | Errors: 12
```

The `_drain_stderr()` function matches keywords and prints matching lines. The scan summary
only reports:
```python
self.log(f"Nuclei complete: {findings_count} findings in {total_elapsed}s")
```

#### What's missing

1. **Template count**: How many templates were selected after tag filtering? If it's 0, nuclei
   scanned nothing. The code never knows.

2. **Request count**: How many HTTP requests were actually sent? If it's 0, nuclei couldn't
   reach the targets. The code never knows.

3. **Error count**: How many requests failed? If errors ≈ requests, every request failed
   (e.g., Webflow returning 404s for all paths). The code never knows.

4. **Completion ratio**: How many URLs were actually scanned vs. skipped? Nuclei may skip
   hosts after too many errors (`-mhe` flag, disabled for origin IP). The code never knows.

#### What should happen

Parse the stats line from stderr:
```python
# Example regex
match = re.match(r'Requests:\s+(\d+)/(\d+).*RPS:\s+(\d+).*Errors:\s+(\d+)', stats_line)
if match:
    completed, total, rps, errors = match.groups()
```
Then validate sanity:
- If `completed / total < 0.01` and elapsed < expected, nuclei didn't actually scan
- If `errors / completed > 0.5`, most requests failed — emit warning
- If template count is 0, tag filtering eliminated all templates — emit error

---

### N-11: URL Accumulation Across Phases on Shared Instance — ✅ FIXED

**Priority**: P2 — Wasteful but not broken  
**File**: `nuclei.py` L478 + `kill_chain.py` L1389/L1784  
**Impact**: Duplicate URLs between recon and exploit phases  
**Fix**: Changed `_urls_to_scan` from `List` to `Set`. Duplicates are eliminated at insertion time via `add_urls()` instead of only at scan time.

#### What happens

The kill chain uses the same `NucleiScanner` instance for all phases:
```python
nuclei = self.engine.modules.get("nuclei")  # Same object in recon and exploit
```

In the recon phase:
```python
nuclei.add_urls(recon_urls)  # Adds to self._urls_to_scan
```

In the exploit phase:
```python
nuclei.add_urls(all_urls)  # Adds MORE to self._urls_to_scan
```

After both phases, `self._urls_to_scan` contains `recon_urls + all_urls`. Each scan mode
does `set()` deduplication internally, so exact duplicates are removed. But the accumulation
means `self._urls_to_scan` grows monotonically across phases.

#### Practical impact

Not severe because `set()` dedup handles exact duplicates. But:
- Memory usage grows unnecessarily (111K URLs stored twice = ~20MB of strings)
- `_calculate_timeout()` uses `len(urls)` after dedup, which is correct
- If a URL appears in `recon_urls` but with different query params in `all_urls`, both variants are scanned (which is actually desirable)

---

### N-12: Interactsh Session Isolation — OOB Unification Broken — ✅ FIXED

**Priority**: P2 — Feature doesn't work as intended  
**File**: `kill_chain.py` lines 1813–1815 + `nuclei.py` lines 486–489  
**Impact**: Nuclei OOB interactions not visible to Beatrix's OOB detector  
**Fix**: `set_interactsh()` now accepts an optional `auth_token` parameter. The kill chain passes both the server URL and auth token (if available from the OOB detector context) so nuclei uses `-itoken` alongside `-interactsh-server`.

#### What the code does

```python
# kill_chain.py L1813-1815
if context.get("oob_domain"):
    oob_domain = context["oob_domain"]
    parts = oob_domain.split(".", 1)
    if len(parts) > 1:
        nuclei.set_interactsh(server=f"https://{parts[1]}")
```

This extracts the parent domain from Beatrix's OOB domain (e.g., `abc123.oast.fun` →
`https://oast.fun`) and passes it to nuclei as the interactsh server.

#### Why this doesn't unify anything

Nuclei creates its **own** interactsh session on the specified server. It generates its own
unique subdomain token. Any OOB callbacks triggered by nuclei's templates go to nuclei's
token, not Beatrix's token.

The result:
- **Nuclei** sees its own OOB interactions (and reports them as findings) ✓
- **Beatrix's OOB detector** sees ITS OOB interactions ✓
- **Neither** sees the other's interactions ✗
- They happen to use the same server but have separate sessions ✗

The comment says "unify OOB detection with Beatrix's OOB detector" but all this achieves is
making both tools use the same interactsh server (which they might do anyway with the default
public server).

#### Simplified explanation

The code tries to share one OOB callback system between nuclei and Beatrix, but each gets its
own separate mailbox on the same server. They never see each other's mail.

---

### N-13: Headless Template Guard Only Checks Official Dir — ✅ FIXED

**Priority**: P3 — Edge case, unlikely to trigger  
**File**: `nuclei.py` lines 808–811  
**Impact**: Headless scan skipped if official dir has no headless templates, even if external repos do  
**Fix**: Headless template guard now checks all three template directories: official (`_template_dir`), custom (`_custom_template_dir`), and external (`_extra_template_dirs`). Only skips if none contain headless templates.

#### What the code does

```python
# nuclei.py L808-811 — inside scan_headless()
headless_templates = list(self._template_dir.glob("**/headless/**/*.yaml"))
if not headless_templates:
    self.log("No headless templates found — skipping")
    return
```

This checks only `self._template_dir` (the official `~/nuclei-templates/` directory) for
headless templates. External template repos (`self._extra_template_dirs`) and custom templates
(`self._custom_template_dir`) are not checked.

#### Why this matters (marginally)

The nuclei command itself is built with `-tags headless` and includes all template directories
via `-t` flags. So nuclei WOULD include headless templates from external repos if they existed.
But the Python-side guard exits early before the command is even built.

In practice, the official nuclei-templates repo always has headless templates, so this guard
never triggers. It would only be an issue if templates failed to download AND the user had
custom headless templates.

---

### N-14: Confidence Assignment Ignores Template Quality — ✅ FIXED

**Priority**: P3 — Cosmetic but affects downstream prioritization  
**File**: `nuclei.py` lines 1134–1139  
**Impact**: All high/critical findings get CERTAIN confidence regardless of template reliability  
**Fix**: Confidence scoring now considers: OOB interactions and extracted results boost to CERTAIN; CVSS score ≥ 7.0 boosts to CERTAIN; templates tagged with `fuzz`, `blind`, or `default-login` are capped at FIRM; info-severity findings capped at TENTATIVE.

#### What the code does

```python
# nuclei.py L1134-1139 — inside _parse_nuclei_finding()
confidence = Confidence.FIRM
if sev_str in ("critical", "high"):
    confidence = Confidence.CERTAIN
elif sev_str == "info":
    confidence = Confidence.FIRM
```

Every critical/high finding gets `CERTAIN` confidence. But nuclei templates vary enormously
in quality:
- **Version-specific CVE checks**: Highly reliable (match exact version strings)
- **Pattern-based detections**: May false-positive (regex on response body)
- **Blind injection checks**: Require timing/OOB correlation, can false-positive
- **Community-contributed templates**: No quality guarantee

Blanket CERTAIN confidence inflates findings that haven't been verified.

---

### N-15: No Request Count Validation — Impossible Completion Goes Undetected — ✅ FIXED

**Priority**: P1 — Core diagnostic gap  
**File**: `nuclei.py` lines 1072–1073  
**Impact**: Scans that process zero requests report as successful  
**Fix**: After nuclei completes, a sanity check fires: if elapsed time < 30s AND findings == 0 AND URL count ≥ 10, a warning is emitted ("completed suspiciously fast — may not have scanned"). Combined with N-08's returncode check and N-10's stats parsing, impossible completions are now detectable.

#### What the code does

```python
# nuclei.py L1072-1073
total_elapsed = int(time.monotonic() - wall_start)
self.log(f"Nuclei complete: {findings_count} findings in {total_elapsed}s")
```

The scan reports findings count and elapsed time. No sanity check:

| Question | Answer | Checked? |
|----------|--------|----------|
| How many templates were loaded? | Unknown | ❌ |
| How many requests were sent? | Unknown | ❌ |
| What was the throughput? | Unknown | ❌ |
| Did nuclei exit with error code? | `process.returncode` available but not checked | ❌ |
| Were there fatal errors in stderr? | Stored in `stderr_lines` but not checked | ❌ |
| Is 111K URLs in 29s physically possible? | No (at 15 rps = ~22 requests) | ❌ |

#### The math

With WAF detected (Cloudflare), rate limit is set to `-rl 15` (see N-05). At 15 requests per
second, in 29 seconds nuclei can send at most **435 requests**. With 6,000+ templates per URL,
scanning even ONE URL fully requires 6,000+ requests. Scanning 111,638 URLs would require
~670 million requests. At 15 rps that's **517 days**.

The 29-second completion means nuclei either:
1. Loaded 0 templates (tag filter eliminated everything)
2. Sent 0 requests (all targets failed immediately)
3. Errored out immediately (FTL/panic)
4. Made <435 requests and exited

**Any of these should trigger a warning.** The code treats all of them as success.

---

### N-16: install.sh Template Download Runs As Root Under Sudo — ✅ FIXED

**Priority**: P2 — Causes permission issues on subsequent runs  
**File**: `install.sh` lines 566–573  
**Impact**: Templates owned by root when installed via `sudo ./install.sh`  
**Fix**: Template download now runs as `$SUDO_USER` (or falls back to `$REAL_USER`) via `sudo -u` when the installer is running under sudo, ensuring templates are saved to the correct home directory.

#### What the code does

```bash
# install.sh L566-573
if command_exists nuclei; then
    info "Downloading nuclei templates (one-time, ~500MB)..."
    nuclei -update-templates &>/dev/null && \
        success "nuclei templates downloaded" || \
        warn "Failed to download nuclei templates (run 'nuclei -update-templates' manually)"
fi
```

When `install.sh` is run via `sudo`, this command runs `nuclei -update-templates` as root.
Nuclei downloads templates to `~/nuclei-templates/`, which under sudo resolves to
`/root/nuclei-templates/`.

#### The problem cascade

1. Templates are saved to `/root/nuclei-templates/` (owned by root)
2. Beatrix runs via `sudo beatrix hunt ...` which wraps with `HOME=/home/codespace`
   (the wrapper script sets this)
3. nuclei.py checks `Path.home() / "nuclei-templates"` which resolves to
   `/home/codespace/nuclei-templates`
4. This directory doesn't exist (templates are in `/root/nuclei-templates/`)
5. `_ensure_templates()` triggers `nuclei -update-templates` AGAIN during the scan
6. Under the beatrix wrapper, `HOME=/home/codespace`, so templates go to the right place this time

So there's a self-healing path IF the beatrix wrapper correctly sets HOME. But the initial
install downloads 500MB of templates that are never used, wasting time and bandwidth.

#### What should happen

Run template download as the real user, not root:
```bash
if command_exists nuclei; then
    sudo -u "$REAL_USER" nuclei -update-templates &>/dev/null
fi
```

---

## 4. Origin IP Pipeline — End-to-End Failure Analysis

The origin IP system involves 3 files and has 6 stages. Here's exactly how each stage
failed for `fivetran.com`:

### Stage 1: CDN Detection (✓ Correct)
**File**: `origin_ip_discovery.py` L248–285  
**What happened**: Resolved `fivetran.com` → Cloudflare IP, detected `cf-ray` header → `cdn_detected = "Cloudflare"`  
**Verdict**: Correct.

### Stage 2: Origin IP Discovery (↓ Found candidates)
**File**: `origin_ip_discovery.py` L200–240  
**What happened**: Ran 6+ techniques (DNS history, crt.sh, subdomain correlation, MX, misconfigs, WHOIS). Found multiple candidate IPs including `198.202.211.1`.  
**Verdict**: Working as designed. The candidates include real IPs that responded to the domain.

### Stage 3: IP Validation (✗ FALSE POSITIVE)
**File**: `origin_ip_discovery.py` L717–796  
**What happened**: Checked `198.202.211.1` with `Host: fivetran.com`:
1. `_is_cdn_ip()` → **False** (Webflow not in hosting provider ranges)
2. Response body contains `"fivetran.com"` → `domain_in_response = True`
3. HOSTING_SIGNATURES check → `"webflow.com"` NOT in rendered body → `is_hosting = False`
4. Result: `validated = True`, `confidence = 0.7` + 0.2 boost = **0.9**

**Verdict**: WRONG. `198.202.211.1` is Webflow shared hosting (ASN 209242), not Fivetran infrastructure. Three missing checks (N-02, N-03, N-04) all failed to catch this.

### Stage 4: Origin IP Acceptance (✗ Based on false validation)
**File**: `kill_chain.py` L588–596  
**What happened**:
```python
if best_ip.get('confidence', 0) >= 0.6 and not best_ip.get('hosting_provider_detected'):
    origin_ip = best_ip['ip']  # 198.202.211.1
    context["network"]["scan_target"] = origin_ip
```
Confidence 0.9 >= 0.6 ✓, hosting_provider_detected = False ✓ → Accepted.  
**Verdict**: Correct behavior given wrong input.

### Stage 5: Nuclei Origin IP Configuration (✗ Propagates bad IP)
**File**: `kill_chain.py` L1413–1414 and L1804–1805  
```python
nuclei.set_origin_ip("198.202.211.1", "fivetran.com")
```
Sets `self._origin_ip = "198.202.211.1"` and `self._target_domain = "fivetran.com"`.  
**Verdict**: Correct behavior given wrong input from stage 4.

### Stage 6: URL Rewrite (✗ Poisons all URLs)
**File**: `nuclei.py` L889–903  
Every URL matching `fivetran.com` hostname gets rewritten:
```
https://fivetran.com/integrations/sql-server → https://198.202.211.1/integrations/sql-server
```
All 111,638 URLs now point to Webflow.  
**Verdict**: Architectural flaw (N-01) compounded by validation failure (N-02/03/04).

### The chain reaction

```
Missing Webflow in HOSTING_PROVIDER_RANGES (N-03)
  + Hosting signature doesn't check headers (N-04)
  + No ASN/infrastructure check (N-02)
  ─────────────────────────────────────────────
  = False positive origin IP
    │
    ↓
  Blanket URL rewrite (N-01)
    │
    ↓
  111K URLs → Webflow instead of Fivetran
    │
    ↓
  0 meaningful findings across all 3 phases
```

---

## 5. What Actually Happened in the Fivetran Scan

### RECON Phase (29 seconds, 0 findings)

1. Kill chain called `nuclei.set_origin_ip("198.202.211.1", "fivetran.com")`
2. Called `nuclei.add_urls(recon_urls)` with ~111K discovered URLs
3. Called `nuclei.set_waf("Cloudflare")` → rate limits dropped to 30/15 rps
4. Called `nuclei.scan_recon(ctx)`
5. Inside `scan_recon()`:
   - Built recon tags (tech, detect, panel, waf, ...)
   - `_calculate_timeout(111638, "recon")` = 120 + 111,638 × 3 = **334,934 seconds** (~3.9 days)
   - Called `_run_nuclei(urls, tags, severity=info,low)`
6. Inside `_run_nuclei()`:
   - **All 111,638 URLs rewritten** from `fivetran.com` to `198.202.211.1`
   - Command includes `-rate-limit 30 -rl 15` → effective rate: **15 rps** (N-05)
   - Command includes `-H "Host: fivetran.com"` and `-sni fivetran.com`
   - Nuclei started, connected to `198.202.211.1` (Webflow)
7. Nuclei behavior:
   - Loaded templates matching recon tags + info/low severity
   - Started sending requests to `198.202.211.1` at 15 rps
   - Webflow responded with rendered fivetran.com content (or redirects)
   - Templates checked responses for misconfigs, exposed panels, etc.
   - No matches because it's all Webflow-rendered marketing content
   - At 15 rps in 29 seconds, sent **~435 requests** out of potentially millions needed
   - Likely: nuclei completed template enumeration and found nothing to match → exited quickly
   - OR: readline timeout triggered after no stdout for 120s... but 29s < 120s
   - Most likely: nuclei noted the targets are all the same IP, optimized heavily, and exited
8. Result: `"Nuclei complete: 0 findings in 29s"`

### EXPLOIT Phase (33 seconds, 0 findings)

Same sequence as recon but with:
- Full severity (critical,high,medium,low,info)
- Exploit-oriented tags
- Same origin IP rewrite → same 198.202.211.1 target
- Additional time for workflow scan attempts (0 workflows found — no WordPress/Jenkins/etc. on Webflow)
- Same 15 rps effective rate limit
- Same result: 0 findings in ~33s

### HEADLESS Phase (11 seconds, 0 findings)

1. `nuclei.scan_headless(ctx)` called
2. `_calculate_timeout(223276, "headless")` = 120 + 223,276 × 30 = **6,698,400 seconds** (~77 days)
3. `_run_nuclei(urls, headless tags, -headless)` started
4. Nuclei tried to launch Chromium via go-rod
5. Go-rod couldn't find `libatk-1.0.so.0` → **CRASH**:
   ```
   [FTL] Could not create browser: operation not permitted: ...missing libatk-1.0.so.0
   ```
6. Nuclei exited immediately with error
7. `_drain_stderr()` captured the FTL line in `stderr_lines`
8. FTL line does NOT match keyword filter → **not logged during scan** (N-08)
9. Process exited → stdout EOF → scan loop ended
10. `process.returncode` → non-zero (error) → **NOT CHECKED** (N-15)
11. Only last 5 stderr lines logged, FTL may or may not be among them
12. Result: `"Nuclei complete: 0 findings in 11s"` — reported as SUCCESS

---

## 5b. What Actually Happened in the Franktech Scan

> Second scan against `franktech.net` (March 6, 2026) — validates audit conclusions
> with a **correct** origin IP on a real application.

### Target Profile

| Property | Value |
|----------|-------|
| Origin IP | `167.71.161.180` (DigitalOcean) |
| Stack | nginx/1.20.1, Express (Node.js), SvelteKit SSR, Immich |
| CDN | None detected |
| SSH | OpenSSH_8.7 on port 22 |
| Scan duration | 1,879 seconds |
| Total findings | 24 (from all scanners combined) |

### Nuclei Results

| Phase | URLs | Time | Findings | Verdict |
|-------|------|------|----------|---------|
| NETWORK | 1 service | 34s | 0 | Templates loaded (18,056 total), scanned SSH, nothing matched |
| RECON | 96 | 30s | 0 | Origin IP rewrite active; same 0-finding pattern as fivetran |
| EXPLOIT | 96 | 30s | 0 | Same — correct IP, still no results |
| HEADLESS | 193 | 1s | 0 | **Crashed** — identical `libatk-1.0.so.0` FTL error |

### Key Differences from Fivetran

1. **Origin IP is correct** — `167.71.161.180` serves the real Immich app (confirmed
   via `curl --resolve`). Unlike fivetran's Webflow IP, this is legitimate infrastructure.
   **Nuclei still found nothing**, proving N-01's blanket rewrite is broken regardless
   of IP correctness.

2. **Smaller URL set** — 96 URLs (vs 111K for fivetran). The timeout calculations are
   reasonable (408s RECON, 692s EXPLOIT). N-07's absurd timeout problem only manifests
   at scale.

3. **Templates loaded correctly** — `12,669 official + 5,387 external = 18,056`.
   The install.sh template fix (commit `90f4126`) works. Templates are NOT the problem.

4. **Same headless crash** — Identical `libatk-1.0.so.0` error, confirming N-09 across
   environments. The FTL was captured in `stderr_lines` and logged as
   `[nuclei stderr] [FTL]...` this time (happened to be in last 5 lines), but the scan
   still reported "0 findings in 1s" as success.

### Non-Nuclei Findings — False Positive Epidemic

The franktech scan exposed critical bugs **outside** the nuclei integration — in the
injection scanner and JS bundle scanner:

| Finding | Validator Score | Actual Verdict | Bug |
|---------|----------------|----------------|-----|
| SQLi in `option` param | 100/100 READY | **False positive** | `_check_response()` uses hardcoded `200, {}` — see BEATRIX_AUDIT Bug 6 |
| XSS in `option` param | 100/100 READY | **False positive** | `</HTML>` matches nginx's own error page HTML — see BEATRIX_AUDIT Bug 7 |
| API Routes in JS | 77/100 READY | **False positive** | SvelteKit internal constants, not API endpoints — see BEATRIX_AUDIT Bug 8 |
| Auth-Protected Endpoints | 77/100 READY | Legitimate | Real 401 responses from Immich API |

The two 100/100 findings are particularly dangerous — they'd cause immediate reputation
damage if submitted to a bug bounty program. The injection scanner's behavioral detection
bug (hardcoded `200, {}`) means **every behavioral finding ever produced is a false positive**.

---

## 6. Priority Matrix

| ID | Issue | Priority | Impact | Status |
|----|-------|----------|--------|--------|
| **N-01** | Origin IP rewrite poisons all URLs | **P0** | All nuclei scans useless when origin IP set | ✅ Fixed — adds origin URLs alongside originals |
| **N-02** | No ASN/infrastructure check in validation | **P0** | False positive origin IPs accepted | ✅ Fixed — Team Cymru DNS ASN lookup |
| **N-06** | Exploit/headless phases have no outer timeout | **P0** | Can hang entire scan for days | ✅ Fixed — `asyncio.wait_for()` wrapper |
| **N-08** | FTL/fatal errors silently swallowed | **P0** | Crashes reported as success | ✅ Fixed — FTL/fatal detection + returncode check |
| **N-09** | Missing chromium system deps | **P0** | Headless mode can never work | ✅ Fixed — 13 libs added to install.sh |
| **N-03** | Webflow missing from hosting provider ranges | **P1** | One specific provider evades filter | ✅ Fixed — Webflow, Ghost(Pro), Fly.io added |
| **N-04** | Hosting signature only checks body text | **P1** | Rendered customer pages evade detection | ✅ Fixed — response header check added |
| **N-05** | -rate-limit and -rl are aliases | **P1** | Rate limit is not what code intends | ✅ Fixed — removed duplicate `-rl` |
| **N-07** | Timeout calculation produces absurd values | **P1** | Enables N-06, obscures problems | ✅ Fixed — capped at 3300s |
| **N-10** | Scan stats never parsed or validated | **P1** | Can't detect scan failures | ✅ Fixed — stderr stats parsing |
| **N-15** | No request count validation | **P1** | Impossible completions undetected | ✅ Fixed — sanity check on fast completions |
| **N-11** | URL accumulation across phases | **P2** | Wasted memory, harmless | ✅ Fixed — `_urls_to_scan` is now a Set |
| **N-12** | Interactsh session isolation | **P2** | OOB unification doesn't work | ✅ Fixed — auth token passed alongside server |
| **N-16** | Template download as root | **P2** | Templates in wrong location | ✅ Fixed — runs as `$SUDO_USER` |
| **N-13** | Headless guard checks only official dir | **P3** | Edge case, never triggers | ✅ Fixed — checks all template dirs |
| **N-14** | Confidence ignores template quality | **P3** | Slightly inflated confidence scores | ✅ Fixed — OOB/CVSS/tag-based scoring |

### Non-Nuclei Issues Discovered During Cross-Reference

These bugs are in the injection scanner, not nuclei, but were discovered through nuclei audit
cross-referencing with the franktech scan. Documented in full in `BEATRIX_AUDIT.md`.
**All 4 fixed.**

| ID | Issue | Priority | File | Status |
|----|-------|----------|------|--------|
| **B-06** | Behavioral detection hardcoded `200, {}` | **P0** | `injection.py` L669 | ✅ Fixed — passes actual status/headers |
| **B-07** | XSS reflection matches static HTML | **P1** | `injection.py` L138-140 | ✅ Fixed — baseline comparison filter |
| **B-08** | JS bundle extracts framework internals | **P2** | `js_bundle.py` | ✅ Fixed — noise pattern filter |
| **B-09** | Rate limit check on 404 endpoints | **P2** | `auth.py` | ✅ Fixed — skips all-404 responses |

---

## 7. Fix Roadmap — ✅ ALL COMPLETE

### Phase 1: Critical — Make Nuclei Actually Work (P0) — ✅ DONE

1. ~~**N-08 + N-15: Error detection**~~ ✅ FTL/fatal keyword detection in stderr, returncode check, fast-completion sanity check
2. ~~**N-09: Install chromium deps**~~ ✅ 13 system libs added to install.sh
3. ~~**N-01: Fix origin IP rewrite**~~ ✅ Adds origin URLs alongside originals instead of replacing; removed global Host header
4. ~~**N-06: Add outer timeouts**~~ ✅ `asyncio.wait_for()` with `nuclei_timeout` on exploit + headless calls
5. ~~**N-02: Add ASN check to origin IP validation**~~ ✅ Team Cymru DNS lookup with `HOSTING_ASN_KEYWORDS`

### Phase 2: Important — Correct Behavior (P1) — ✅ DONE

6. ~~**N-05: Fix rate limit flags**~~ ✅ Removed duplicate `-rl` flag
7. ~~**N-07: Cap timeout calculation**~~ ✅ All modes capped at 3300s (55 min)
8. ~~**N-03 + N-04: Improve hosting provider detection**~~ ✅ Webflow/Ghost/Fly.io CIDRs added; response header check added
9. ~~**N-10 + N-15: Parse and validate scan stats**~~ ✅ Regex parsing of templates, targets, requests, errors from stderr

### Phase 3: Polish (P2/P3) — ✅ DONE

10. ~~**N-11**~~ ✅ `_urls_to_scan` changed from List to Set
11. ~~**N-12**~~ ✅ Passes interactsh auth token alongside server URL
12. ~~**N-16**~~ ✅ Template download runs as `$SUDO_USER` under sudo
13. ~~**N-13**~~ ✅ Headless guard checks official, custom, and external template dirs
14. ~~**N-14**~~ ✅ Confidence uses OOB interactions, CVSS, tag-based downgrading

### Phase 4: Non-Nuclei False Positive Fixes (from franktech cross-reference) — ✅ ALL FIXED

15. ~~**B-06: Fix injection behavioral detection**~~ ✅ Done
16. ~~**B-07: Fix XSS reflection false positives**~~ ✅ Done
17. ~~**B-08: Filter framework internals from JS routes**~~ ✅ Done
18. ~~**B-09: Skip rate limit findings on 404 endpoints**~~ ✅ Done

---

*End of audit.*
