# Beatrix Scanner Audit — Post-Fix Deep Dive

**Date:** 2025-07-17 (initial), 2026-03-06 (Tier 1 fixes + critical fixes + nuclei sweep + HIGH sweep)  
**Scope:** Systematic codebase audit inspired by the franktech.net scan results  
**Status:** 14 items fixed (commits `6f9861b`, `ae433d5`, `9fccdff`, `b6a2dd1`, plus HIGH sweep); 33 remaining  
**Complements:** `BEATRIX_AUDIT.md` (bugs 1–9), `nuclei-audit.md` (N-01 through N-16)

---

## Executive Summary

After fixing the original 25 issues (Bugs 1–9 + N-01 through N-16), a new franktech.net scan ran cleanly — zero false positives, correct origin-IP rejection, nuclei error reporting working. However, the scan exposed deeper structural issues across the scanner framework:

- **No circuit breakers anywhere.** Every scanner fires its full payload battery regardless of connection failures.
- **No stale URL filtering.** GAU returns historical URLs on dead hosts; they waste minutes of DNS timeouts across 14+ scanner passes.
- **Injection scanner loads 56K+ payloads** from SecLists with no cap, then tests them sequentially at 1 req/s.
- **Nuclei killed during template loading** — the readline idle timeout counts only stdout, but template compilation writes to stderr.
- **Finding pipeline has dedup holes** — dynamic descriptions, cross-scanner duplicates, and payload variants all bypass consolidation.

47 individual issues identified, organized by system area.

---

## Priority Matrix

| Priority | Count | Resolved | Description |
|----------|------:|:--------:|-------------|
| **CRITICAL** | 3 | 2 (1 mitigated) | ~~Nuclei timeout race~~, injection payload explosion (mitigated), ~~stale URL pipeline~~ |
| **HIGH** | 9 | 9 | ~~SSRF false-positive patterns~~, ~~finding misclassification~~, ~~circuit breaker~~, ~~cache dedup~~, ~~dedup failures~~, ~~nuclei tag fallback~~, ~~error_disclosure dedup~~, ~~host failure tracking~~, ~~file_upload cap~~ |
| **MEDIUM** | 21 | 1 | Sequential execution, timeout config, transport error propagation, ~~payload prioritization~~, broad pattern matching |
| **LOW** | 15 | 1 | Logging noise, minor dedup gaps, ~~duplicate probe headers~~, cosmetic issues |

---

## A. Kill Chain & URL Pipeline

### A-01: No URL Liveness Gate (CRITICAL) — ✅ FIXED

**Files:** `kill_chain.py` L1180–1265, `external_tools.py` L352–381  
**Fix:** Added `_filter_dead_host_urls()` method to kill chain. After URL discovery merge (external crawlers + GAU), extracts unique hostnames and runs async DNS resolution (3s timeout per host, all hosts in parallel). URLs on unresolvable hosts are stripped from both `discovered_urls` and `urls_with_params`. Dead hosts stored in `context["_dead_hosts"]` for downstream scanners.  
**Observed:** franktech.net scan — GAU returned ~30 URLs on `www.franktech.net` which doesn't resolve via DNS. These dead URLs were passed to 14 scanner phases.

**Pipeline gap:**
1. GAU fetches historical URLs — filters only static extensions (`.png`, `.jpg`, etc.), no DNS check
2. URLs merged into `discovered_urls` at L1264 — no host validation
3. `_run_scanner_on_urls()` at L340 iterates blindly — no pre-flight check
4. `ScanContext.from_url()` at `base.py` L60 is parse-only — no network contact

**Impact:** ~18–30 minutes of cumulative DNS timeouts across all phases. Each scanner gets a fresh `httpx.AsyncClient`, so DNS failure caching doesn't persist across scanners.

**Scanners affected:** All 12 `_run_scanner_on_urls` invocations + 2 Nuclei bulk passes = 14 passes over the same dead URLs.

### A-02: error_disclosure Base-URL Duplication (HIGH) — ✅ FIXED

**Files:** `kill_chain.py` `_handle_weaponization()`  
**Fix:** Replaced `list(set(discovered))[:20]` with per-netloc deduplication. Now extracts unique hosts via `urlparse().netloc.lower()` and keeps at most 1 URL per host, capped at 20 total. If no URLs pass filtering, falls back to the target URL.
**Observed:** franktech.net scan — "Error disclosure scan on http://www.franktech.net:80" logged ~18 times.

~~**Root cause:** Kill chain does `list(set(discovered))[:20]` — deduplicates by full URL string. But the scanner's `PROBE_PATHS` loop uses only `context.base_url` (scheme://netloc). Twenty URLs like `http://host/path1?a=1`, `http://host/path2?b=2` all produce identical probe requests on the same origin.~~

~~**Waste:** 20 URLs × 38 probe paths = 760 requests, of which ~720 are identical (same origin + same probe path). Only `_fuzz_existing_paths()` (5 requests per URL using the full path) produces unique work.~~

### A-03: redirect Scanner Has No URL Cap (MEDIUM) — ✅ FIXED

**File:** `kill_chain.py` L1567–1569  
**Observed:** franktech.net scan — redirect scanner received 51 URLs.

The redirect scanner receives `urls_with_params` with **no cap**. Every other scanner has a cap (injection: 50, error_disclosure: 20, prototype_pollution: 15). On crawl-heavy targets, this list can be arbitrarily large.

### A-04: injection_targets Built Without Host Grouping (MEDIUM) — ✅ FIXED

**File:** `kill_chain.py` L1686–1702

```python
injection_targets = list(dict.fromkeys(urls_with_params + api_endpoints + extra_http_urls))
```

Dedup is by exact URL string. No grouping by host, no prioritization by parameter count, no filtering of URLs on dead hosts. A target with 50 URLs on 3 hosts could have 40 URLs on one host and 5 each on the other two — the scanner spends most time on the dominant host with no diversity guarantee.

### A-05: No Host-Level Failure Tracking in `_run_scanner_on_urls` (HIGH) — ✅ FIXED

**File:** `kill_chain.py` `_run_scanner_on_urls()`  
**Fix:** Added per-host consecutive failure tracking inside the URL loop. Extracts host via `urlparse().netloc.lower()` for each URL. On exception, increments `host_fail_count[host]`. After 3 consecutive failures on the same host, skips all remaining URLs for that host and emits a warning event. Also checks `context["_dead_hosts"]` (populated by A-01's DNS gate) to skip known-dead hosts immediately. Successful scans reset the counter for that host.

Works in concert with C-01's circuit breaker: `BaseScanner.request()` tracks per-host transport errors and raises `CircuitBreakerOpen` after 5 failures — which propagates to this handler's `except Exception` block and increments the kill-chain-level counter.

~~When URL 1 on `host-x.com` fails with a connection error, the `except Exception: continue` skips to URL 2 — which may also be on `host-x.com`. No mechanism exists to mark a host as dead and skip remaining URLs on that host.~~

### A-06: Weaponization/Delivery Phases Are Fully Sequential (MEDIUM) — ✅ FIXED

**File:** `kill_chain.py` L1529–1610

Weaponization runs `takeover` → `error_disclosure` → `cache_poisoning` → `prototype_pollution` sequentially. Delivery runs `cors` → `redirect` → `oauth_redirect` → `http_smuggling` → `websocket` sequentially. These scanners are independent and could safely run in parallel (within rate limits). The exploitation phase runs 19+ scanners sequentially for the same reason.

Only the recon phase uses `asyncio.gather` for parallel dispatch (5 scanners).

### A-07: Scanner Errors Not Aggregated in Final Report (LOW) — ✅ FIXED

**File:** `kill_chain.py` L120, `cli/main.py` L1386–1388

Individual scanner errors are emitted as real-time events and displayed inline in the scrolling log (truncated to 50 lines). They are **not** added to `PhaseResult.errors` and there is no post-scan error summary. Errors scroll off screen and are effectively invisible in the final output.

---

## B. Nuclei Timeout Race Condition

### B-01: Readline Idle Timeout Kills Nuclei During Template Loading (CRITICAL) — ✅ FIXED

**File:** `nuclei.py` L1006  
**Fix:** Replaced stdout-only idle timer with a shared `last_activity` timestamp. Both `_drain_stderr()` (via `nonlocal last_activity`) and the stdout loop reset the timestamp on each line received. Stdout loop changed from blocking `readline_timeout`-length waits to 10s poll intervals, checking `idle_seconds = time.monotonic() - last_activity` after each timeout. Nuclei is only killed when BOTH stdout AND stderr have been silent for 120s. This prevents template-compilation-phase kills since nuclei writes progress to stderr during compilation.

Additionally cleaned up dead `_rate_limit_per_host` attribute (set but never used after `-rl` flag removal in N-05) and updated docstring.

~~The `readline_timeout = 120` monitors only stdout. Nuclei runs with `-jsonl -silent`, producing zero stdout during template compilation. Template loading progress is written to stderr, which is drained by `_drain_stderr()` — but stderr activity does **not** reset the stdout idle timer.~~

~~**Sequence:**~~
~~1. Nuclei starts with 12,600+ templates~~
~~2. Template compilation begins — writes progress to stderr~~
~~3. stdout is silent during compilation (no `-jsonl` output yet)~~
~~4. After 120 seconds of stdout silence → `process.kill()` fires~~
~~5. Nuclei dies with exit -15, templates=0, targets=0~~

~~This is the root cause of the `templates=0 / targets=0 / exit -15` observed in every nuclei phase of the franktech scan.~~

### B-02: Tag Fallback Silently Filters Network/Workflow Templates (HIGH) — ✅ FIXED (b6a2dd1)

**File:** `nuclei.py` L894–895 (now removed)  
**Fix:** Removed the `if not tags: tags = self._build_exploit_tags()` fallback in `_run_nuclei()`. Callers that want tag filtering pass tags explicitly; callers that want no filter pass `tags=""` and limit scope via `cmd_extra` (`-t dir`, `-w workflow`, `-headless`).

**Root cause:** `_run_nuclei()` converted empty `tags` to the full 40+ exploit tag set. Three callers pass `tags=""`:
- `scan_network()` — passes `-t network/` to run ALL network templates. The injected `-tags` silently skipped templates lacking exploit tags (e.g. templates tagged only `redis-check` or `ftp-anon`).
- `scan_exploit()` workflows — passes `-w workflow.yaml`. Tags don't affect nuclei workflows, but injected dead flags.
- `scan_headless()` — passes `-headless -tags headless`. The injected exploit tags widened scope but headless-specific `-tags headless` in `cmd_extra` was appended after, and nuclei uses last-wins for `-tags`, so this was functionally harmless.

**Impact:** Network scan phase missed templates that don't carry common exploit tags — potentially significant for protocol-level checks (Redis, MongoDB, FTP, SMTP).

---

## C. Circuit Breaker Absence (Systemic)

### C-01: BaseScanner Has No Circuit Breaker (HIGH) — ✅ FIXED

**File:** `base.py` `BaseScanner.request()`  
**Fix:** Added circuit breaker to `BaseScanner.request()`. Tracks consecutive transport errors per host using `_cb_host_failures` dict. Catches `httpx.ConnectError`, `httpx.ConnectTimeout`, `httpx.ReadTimeout`, `httpx.WriteTimeout`, `httpx.PoolTimeout`, and `httpx.RemoteProtocolError`. After `_CB_THRESHOLD` (5) consecutive transport failures on the same host, raises `CircuitBreakerOpen` (new exception, subclass of `Exception`). Successful responses reset the counter. The circuit breaker check runs BEFORE the request — once tripped, subsequent requests to the same host fail immediately with no network I/O.

New `CircuitBreakerOpen` exception class defined at module level. Scanners with `except Exception: continue` naturally skip the breaker exception and move to the next payload/URL.

~~`BaseScanner.request()` handles only:~~
~~- **HTTP 429** — retry with exponential backoff (up to 3 retries)~~
~~- **HTTP 401** — session expiry tracking~~

~~It does **not** catch or track:~~
~~- `httpx.ConnectError` (DNS failure, connection refused)~~
~~- `httpx.TimeoutException` (read/write timeout)~~
~~- `httpx.RemoteProtocolError` (protocol violations)~~

~~These transport errors propagate to the caller. Most scanners catch them with bare `except Exception: continue` and move to the next payload, never tracking consecutive failures.~~

### C-02: No Scanner Has a Circuit Breaker — ✅ FIXED (via C-01)

**Fix:** The circuit breaker is implemented in `BaseScanner.request()` — inherited by all 20+ scanners. No per-scanner changes needed.

~~**Affected scanners (all 11 audited):**~~

| Scanner | Catch Pattern | Line | Continues After Failure? |
|---------|--------------|------|-------------------------|
| ssrf | `except Exception: pass` | L332 | Yes — silently |
| cors | `except Exception` | L153, L203 | Yes — logs each |
| http_smuggling | no explicit catch | — | Propagates to per-URL handler |
| redirect | `except Exception` | L236 | Yes — logs each |
| deserialization | `except Exception: continue` | L365 | Yes |
| mass_assignment | `except Exception` | L417 | Yes — logs each |
| xxe | `except Exception: continue` | L425 | Yes |
| idor | `except Exception: continue` | L632 | Yes |
| prototype_pollution | `except Exception: continue` | L267 | Yes |
| file_upload | implicit | — | Yes |
| cache_poisoning | `except Exception: continue` | L339 | Yes |

~~**Impact for SSTI specifically:** `ssti.py` fires 31 requests per URL (8 templates × 2 params + 5 headers × 3 payloads) on DNS-unresolvable hosts. Zero pre-flight DNS check, zero early exit after first failure.~~

All scanners now inherit circuit breaker protection — after 5 consecutive transport errors on a host, `CircuitBreakerOpen` is raised and caught by each scanner's existing `except Exception` handler.

---

## D. Injection Scanner Efficiency

### D-01: Unbounded SecLists Payload Loading (CRITICAL) — ✅ FIXED

**File:** `injection.py` L105–149, `seclists_manager.py` L651–762

`_augment_with_seclists()` loads payloads from 16 SQLi sources, 20 XSS sources, 3 CMDi sources, 1 SSTI source, and 17 LFI/Path sources. Payloads are deduplicated but **never capped**. The `injection.py` L139 append has no `[:N]` limit.

**Result:** 56,000+ payloads loaded (SecLists XSS alone has ~10K entries, SQLi ~15K, LFI ~10K).

With 50 URLs × 3 params × 56K payloads = 8.4 million potential requests. At 1 req/s sequential, this would take ~97 days. The 600s timeout kills it after testing a tiny fraction.

**Partial mitigation (6f9861b):** Payloads are now stable-sorted by detection priority (D-03 ✅) — error-based first, time-based last. Combined with the per-category `break` on first finding, the 600s timeout now covers the highest-signal portion of the payload space. A hard cap was considered but rejected to preserve fuzzing coverage — the sort ensures the timeout budget is spent on payloads most likely to produce results.

### D-02: Fully Sequential Execution (MEDIUM) — ✅ FIXED

**File:** `injection.py` L434, L466

Both the URL loop and the payload loop are strictly sequential — one `await self.request()` at a time. The `BaseScanner.semaphore` (capacity 10) exists but is never used for parallel dispatch; it's acquired and released around each single request.

### D-03: No Payload Prioritization (MEDIUM) — ✅ FIXED (6f9861b)

**File:** `injection.py` L99–126  
**Fix:** Added `_DETECTION_PRIORITY = {"error": 0, "reflect": 1, "behavior": 2, "time": 3}` and stable-sorted each payload category after loading. Error-based payloads (instant pattern match) run first, then reflection checks, then behavioral comparisons, then time-based (5s+ each) last. Stable sort preserves builtins-before-SecLists order within each detection type.

~~Built-in payloads (27 total, hand-crafted) are tested first, then SecLists payloads in file-order. There is:~~
- ~~No severity-based sorting~~
- No adaptive deprioritization after repeated negatives *(still open)*
- ~~No "fast-first" strategy — time-based payloads (5+ seconds each) are intermixed with instant error-based ones~~

### D-04: Redundant Baselines Per Insertion Point (LOW) — ✅ FIXED

**File:** `injection.py` L452–454

Behavioral and time-based baselines are fetched once per insertion point, not once per URL. A URL with 3 parameters generates 6 baseline requests (3 behavioral + 3 time-based) instead of the optimal 2.

### D-05: No Early Termination Across Parameters (LOW) — ✅ FIXED

**File:** `injection.py` L480

After finding SQLi on parameter `id`, the scanner still tests all payloads across all categories on parameters `page`, `sort`, etc. Finding SQLi on one param doesn't reduce the work on remaining params.

### D-06: 600s Timeout Inadequate (MEDIUM) — ✅ FIXED

**File:** `kill_chain.py` L255

The injection scanner gets the default `SCANNER_TIMEOUT = 600` with no override. Given the payload volume and sequential execution, 600s covers <0.01% of the payload space. The timeout should either be increased or (better) the payload count should be capped.

---

## E. Scanner-Specific Issues

### E-01: SSRF Param Patterns Too Broad (HIGH) — ✅ FIXED (ae433d5)

**File:** `ssrf.py` L76–91  
**Fix:** Replaced bare substring patterns with plain word list + custom word-boundary lookaround `(?<![a-zA-Z0-9])word(?![a-zA-Z0-9])`. Uses non-alphanumeric boundary (not `\b`) so underscores, hyphens, and dots act as separators — `redirect_url` matches `url`, `proxy-host` matches `host/proxy`, but `total` does not match `to` and `validate` does not match `val`. (Initial fix in `6f9861b` used `\b` which treats `_` as a word character, breaking compound param matching. Corrected in `ae433d5`.)

~~`SSRF_PARAM_PATTERNS` uses `re.search` with patterns like `r'to'`, `r'val'`, `r'open'`, `r'data'`. These match substrings: `total`, `validate`, `opened`, `dataset` all trigger false-positive candidate detection.~~

### E-02: IDOR Scanner Fires Write Methods Blindly (MEDIUM) — ✅ FIXED

**File:** `idor.py` L610

Sends PUT/PATCH/DELETE with empty JSON `{}` body to every candidate URL without first checking if the endpoint supports those methods. Generates 405 response spam and could inadvertently modify data on poorly-protected endpoints.

### E-03: IDOR Uses Raw Finding() Constructor (LOW) — ✅ FIXED

**File:** `idor.py` L667–714

Uses `Finding(...)` directly instead of `self.create_finding()`, bypassing scanner metadata injection (`scanner_module`, `owasp_category`, `found_at`). Makes findings inconsistent with output from other scanners.

### E-04: XXE XML Acceptance Probe Too Permissive (MEDIUM) — ✅ FIXED

**File:** `xxe.py` L427–436

`_probe_xml_acceptance` treats any status code that isn't 415/406/403 as "accepts XML." A 500 or 404 response triggers the full XXE payload battery — wasting time on endpoints that don't actually process XML.

### E-05: file_upload Defaults to PHP Target Tech (MEDIUM) — ✅ FIXED

**File:** `file_upload.py` L202

`target_tech` defaults to `"php"`, generating PHP-specific payloads (`.php.jpg`, `<?php` shells) even on non-PHP targets. The scanner has no tech detection to auto-select the right payload set.

### E-06: file_upload Unbounded Test List (HIGH) — ✅ FIXED

**File:** `file_upload.py` `scan()`  
**Fix:** Reordered test generation by impact priority (extension bypass first, then traversal, polyglot, XSS, content-type last) and added `_MAX_UPLOAD_TESTS = 25` cap. The cap trims the tail of the priority-ordered list, keeping the highest-value tests.

~~`_generate_extension_tests()` produces ~30+ tests (double-ext: 10, case: 3, null: 1, alt: 10+, trailing: 4), plus content-type tests (5), polyglot (2), XSS (3), and traversal (7). Total ~60+ tests with no cap.~~

Total uncapped: 46 tests. After cap: 25 (extension:25 out of 29 kept, covers all double-ext + case + null + most alt extensions).

### E-07: HTTP Smuggling Hardcoded Timing Threshold (MEDIUM) — ✅ FIXED

**File:** `http_smuggling.py` L192–194

`TIMEOUT_THRESHOLD = 5.0s` and `BASELINE_TOLERANCE = 2.0s` are class constants, not configurable. On slow networks or high-latency targets, normal response times could exceed these thresholds, causing false positives.

### E-08: Prototype Pollution Passive Patterns Too Broad (MEDIUM) — ✅ FIXED

**File:** `prototype_pollution.py` L389–400

Passive scan matches `Object.assign(` or `JSON.parse` in response bodies. Nearly every modern web application includes these patterns in bundled JavaScript, generating noise.

### E-09: Cache Poisoning Duplicate Probe Header (LOW) — ✅ FIXED (6f9861b)

**File:** `cache_poisoning.py` L98–125  
**Fix:** Removed duplicate `X-Original-URL` and `X-Rewrite-URL` entries. Both headers now appear exactly once (in the "Host overrides" section). Added comment noting the intentional single listing.

~~`X-Original-URL` appears twice in `PROBE_HEADERS`, causing the same header to be tested twice.~~

### E-10: CORS Evil Domain Not Configurable (LOW) — ✅ FIXED

**File:** `cors.py` L47

`EVIL_DOMAIN = "evil.com"` is hardcoded. If a target's WAF blocks requests from `evil.com` specifically, all CORS tests fail. Should be configurable per scan.

---

## F. Response Analysis & Finding Pipeline

### F-01: Finding Enricher Misclassifies Unknown Injection Types (HIGH) — ✅ FIXED (6f9861b)

**File:** `finding_enricher.py` L372–376  
**Fix:** Changed fallback from `return "sqli"` to `return "injection"`. Since `"injection"` has no entry in `IMPACT_TEMPLATES`, it falls through to `_generic_impact()` (severity-based generic text) and generic reproduction steps — both produce valid, non-inflated output.

~~`_detect_vuln_type()` falls back to `return "sqli"` when `module == "injection"` but no subtype keyword matches. Any unrecognized injection finding gets SQLi's CWE, impact template, and reproduction steps — inflating severity and misclassifying the vulnerability.~~

### F-02: Impact Template Fallback Walks Upward (MEDIUM) — ✅ FIXED

**File:** `finding_enricher.py` L308–313

If a LOW-severity finding has no impact template at its level but a CRITICAL template exists, it gets the critical-level impact text. This inflates the perceived impact of low-severity findings.

### F-03: PoC Curl Command Omits Payload (LOW) — ✅ FIXED

**File:** `finding_enricher.py` L426–428

`_enrich_poc_curl()` builds a curl command against the clean URL without the actual injection payload. The PoC is therefore not reproducible — it hits the unmodified endpoint.

### F-04: Parameter Extraction Picks Arbitrary First Param (LOW) — ✅ FIXED

**File:** `finding_enricher.py` L247–254

Last-resort parameter extraction via URL query string picks `next(iter(qs))` — the arbitrary first query parameter. For multi-param URLs, this can assign the wrong parameter name.

### F-05: Issue Consolidator Defeated by Dynamic Descriptions (HIGH) — ✅ FIXED

**File:** `issue_consolidator.py` `_decide()` + `_normalize_description()`  
**Fix:** Added `_normalize_description()` method that strips dynamic content before comparing descriptions. Uses regex patterns to remove: ISO-8601/epoch timestamps, UUIDs, HTTP status codes, IPv4 addresses, hex hashes (32+ chars), response/upload excerpts, and base64-like tokens (20+ chars). After stripping, collapses whitespace. The `_decide()` method now normalizes both descriptions before the diff check — only genuinely different descriptions trigger `KEEP_BOTH`.

~~`_decide()` returns `KEEP_BOTH` when descriptions differ by more than 20 chars. Scanners that append timestamps, request IDs, or dynamic content to descriptions produce unique descriptions for the same bug — defeating dedup.~~

### F-06: Cross-Scanner Duplicates Not Merged (MEDIUM) — ✅ FIXED

**File:** `issue_consolidator.py` L89–90

Fingerprint includes `module` (scanner_module). If `injection` and `smart_fuzzer` both find SQLi on the same URL/param, they get different fingerprints and appear as separate findings.

### F-07: Multiple Payloads Create Duplicate Reports (MEDIUM) — ✅ FIXED

**File:** `issue_consolidator.py` L155–158

`KEEP_BOTH` for differing payloads with same severity. Three different SQLi payloads confirming the same vulnerability on the same parameter produce three separate findings. Only the first confirmed payload is needed.

### F-08: Variant Fingerprint Prevents Cascading Dedup (LOW) — ✅ FIXED

**File:** `issue_consolidator.py` L127–131

`KEEP_BOTH` generates `new_fp = fp + f"_{len(self._findings)}"`. This synthetic fingerprint means later duplicates of the variant finding never match it, so dedup is completely bypassed for all subsequent occurrences.

### F-09: Title Normalization Missing Many Vuln Types (LOW) — ✅ FIXED

**File:** `issue_consolidator.py` L75

`_normalize_title()` doesn't cover: deserialization, file upload, cache poisoning, mass assignment, prototype pollution, http smuggling. These fall through to the slugified title, making dedup fragile for those types.

### F-10: Response Analyzer Uses MD5 for Body Hashing (MEDIUM) — ✅ FIXED

**File:** `response_analyzer.py` L178–179

`hashlib.md5()` is used for body fingerprinting. MD5 is collision-prone; for the security scanner, SHA-256 would be both more correct and only marginally slower.

### F-11: Blind Indicator Requires min_attrs=2 (LOW) — ✅ FIXED

**File:** `response_analyzer.py` L404–410

`is_blind_indicator()` requires at least 2 attribute changes by default. A single meaningful change (e.g., status 200→500) is ignored even when it's a strong blind-injection signal.

---

## G. BaseScanner Infrastructure

### G-01: BaseScanner.log() Uses print() Instead of Logger (LOW) — ✅ FIXED

**File:** `base.py` L339

`log()` calls `print()` directly despite `logger = logging.getLogger(...)` being defined at L15. This bypasses log levels, handlers, and formatting.

### G-02: No Cross-Scanner Rate Limiting (LOW) — ✅ FIXED

**File:** `base.py` L107

The `asyncio.Semaphore(rate_limit)` is per-scanner-instance. When the kill chain runs scanners sequentially this isn't a problem, but the parallel recon batch (5 scanners) shares no global rate limit.

### G-03: Per-Request Timeout Not Configurable Per Scanner (LOW) — ✅ FIXED

**File:** `base.py` L122

`self.timeout = self.config.get("timeout", 10)` — all scanners use 10s unless the config overrides it. Time-based injection detection uses 5s delays, meaning the 10s timeout barely accommodates one round-trip with the injected delay. No scanner customizes this.

---

## Summary Table

| ID | Area | Severity | One-Line Description |
|----|------|----------|---------------------|
| A-01 | Kill Chain | **CRITICAL** | ~~No URL liveness gate — dead hosts waste 18–30 min of DNS timeouts~~ ✅ Fixed — async DNS gate filters dead hosts |
| A-02 | Kill Chain | **HIGH** | ~~error_disclosure scans same origin 20× due to query-string-only URL differentiation~~ ✅ Fixed — per-netloc dedup |
| A-03 | Kill Chain | **MEDIUM** | ~~redirect scanner receives URLs with no cap~~ ✅ Fixed — capped at 30 |
| A-04 | Kill Chain | **MEDIUM** | ~~injection_targets not grouped by host~~ ✅ Fixed — round-robin host grouping |
| A-05 | Kill Chain | **HIGH** | ~~No host-level failure tracking in `_run_scanner_on_urls`~~ ✅ Fixed — per-host consecutive failure tracking (threshold=3) |
| A-06 | Kill Chain | **MEDIUM** | ~~Weaponization/Delivery phases fully sequential~~ ✅ Fixed — asyncio.gather parallel dispatch |
| A-07 | Kill Chain | **LOW** | ~~Scanner errors not aggregated in final report~~ ✅ Fixed — error table in hunt results |
| B-01 | Nuclei | **CRITICAL** | ~~readline_timeout kills nuclei during template loading (stdout-only idle timer)~~ ✅ Fixed — shared last_activity timer |
| B-02 | Nuclei | **HIGH** | ~~Tag fallback silently filtered network/workflow templates~~ ✅ Fixed — removed fallback (`b6a2dd1`) |
| C-01 | BaseScanner | **HIGH** | ~~No circuit breaker for transport errors~~ ✅ Fixed — per-host circuit breaker (threshold=5, raises `CircuitBreakerOpen`) |
| C-02 | All Scanners | **HIGH** | ~~Zero scanners implement connection-failure tracking~~ ✅ Fixed via C-01 — all scanners inherit circuit breaker |
| D-01 | Injection | **CRITICAL** | ~~SecLists payloads loaded without cap (56K+)~~ ✅ Fixed — 100/category cap (configurable via `seclists_cap`) |
| D-02 | Injection | **MEDIUM** | ~~Fully sequential — 1 req at a time~~ ✅ Fixed — asyncio.gather batching (5/batch, time-based sequential) |
| D-03 | Injection | **MEDIUM** | ~~No payload prioritization~~ ✅ Fixed — sorted by detection priority |
| D-04 | Injection | **LOW** | ~~Redundant baselines per insertion point~~ ✅ Fixed — baseline per URL, not per IP |
| D-05 | Injection | **LOW** | ~~No early termination across parameters~~ ✅ Fixed — `_found_categories` cross-param skip |
| D-06 | Injection | **MEDIUM** | ~~600s timeout covers <0.01% of payload space~~ ✅ Fixed — injection timeout increased to 1200s |
| E-01 | SSRF | **HIGH** | ~~Param patterns match substrings~~ ✅ Fixed — custom word boundaries |
| E-02 | IDOR | **MEDIUM** | ~~Fires PUT/PATCH/DELETE blindly without OPTIONS check~~ ✅ Fixed — OPTIONS preflight filters unsupported methods |
| E-03 | IDOR | **LOW** | ~~Uses raw `Finding()` bypassing `create_finding()`~~ ✅ Fixed — converted to `create_finding()` |
| E-04 | XXE | **MEDIUM** | ~~XML acceptance probe treats 500/404 as acceptance~~ ✅ Fixed — reject 500/404/501/502/503 |
| E-05 | file_upload | **MEDIUM** | ~~Defaults to PHP payloads regardless of target tech~~ ✅ Fixed — auto-detection from response headers |
| E-06 | file_upload | **HIGH** | ~~~60+ tests with no cap~~ ✅ Fixed — capped at 25, priority-ordered |
| E-07 | HTTP Smuggling | **MEDIUM** | ~~Hardcoded timing threshold (5.0s)~~ ✅ Fixed — configurable via `timeout_threshold`/`baseline_tolerance` |
| E-08 | Prototype Pollution | **MEDIUM** | ~~Passive patterns match common JS builtins~~ ✅ Fixed — removed Object.assign, tightened JSON.parse |
| E-09 | Cache Poisoning | **LOW** | ~~Duplicate `X-Original-URL`~~ ✅ Fixed — deduped |
| E-10 | CORS | **LOW** | ~~Evil domain not configurable~~ ✅ Fixed — `config.get("evil_domain")` override |
| F-01 | Finding Enricher | **HIGH** | ~~Misclassifies unknown injection types as SQLi~~ ✅ Fixed — returns "injection" |
| F-02 | Finding Enricher | **MEDIUM** | ~~Impact template fallback walks severity upward~~ ✅ Fixed — walks downward from finding's severity |
| F-03 | Finding Enricher | **LOW** | ~~PoC curl omits actual payload~~ ✅ Fixed — injects payload into URL (GET) or `-d` body (POST) |
| F-04 | Finding Enricher | **LOW** | ~~Parameter extraction picks arbitrary first param~~ ✅ Fixed — `_SKIP_PARAMS` skips utility params |
| F-05 | Issue Consolidator | **HIGH** | ~~Dynamic descriptions defeat dedup~~ ✅ Fixed — `_normalize_description()` strips dynamic content before comparison |
| F-06 | Issue Consolidator | **MEDIUM** | ~~Cross-scanner duplicates not merged~~ ✅ Fixed — removed `module` from injection-class fingerprints |
| F-07 | Issue Consolidator | **MEDIUM** | ~~Multiple payloads for same vuln create duplicate reports~~ ✅ Fixed — removed KEEP_BOTH for different-payload duplicates |
| F-08 | Issue Consolidator | **LOW** | ~~Variant fingerprint prevents cascading dedup~~ ✅ Fixed — `_variant_groups` dict for cascading dedup |
| F-09 | Issue Consolidator | **LOW** | ~~Title normalization missing many vuln types~~ ✅ Fixed — 29 patterns (was 18), reordered oauth |
| F-10 | Response Analyzer | **MEDIUM** | ~~MD5 used for body hashing~~ ✅ Fixed — SHA-256 |
| F-11 | Response Analyzer | **LOW** | ~~Blind indicator requires min 2 attribute changes~~ ✅ Fixed — default min_attrs=1 |
| G-01 | BaseScanner | **LOW** | ~~`log()` uses `print()` not `logger`~~ ✅ Fixed — uses `logging.getLogger` |
| G-02 | BaseScanner | **LOW** | ~~No cross-scanner rate limiting~~ ✅ Fixed — global semaphore (limit 20) |
| G-03 | BaseScanner | **LOW** | ~~Per-request timeout not configurable per scanner~~ ✅ Fixed — `DEFAULT_TIMEOUT` class constant, config override |

---

## Recommended Fix Order

### Tier 1 — Immediate (eliminates wasted scan time)
1. ~~**A-01** — Add DNS liveness gate after URL discovery, before scanner dispatch~~ ✅ Done
2. ~~**B-01** — Reset nuclei idle timer on stderr activity (or wait for first stdout line)~~ ✅ Done
3. ~~**D-01** — Cap SecLists payloads per category (e.g., `[:100]`)~~ ✅ Done — 100/category hard cap (configurable via `seclists_cap`)
4. ~~**C-01 + C-02** — Add circuit breaker to `BaseScanner.request()` (bail after 5 consecutive `ConnectError`/`TimeoutException` on same host)~~ ✅ Done — per-host circuit breaker with `CircuitBreakerOpen` exception

### Tier 2 — High value (reduces false positives and duplicates)
5. ~~**E-01** — Fix SSRF param patterns with word boundaries~~ ✅ Done (ae433d5)
6. ~~**F-01** — Remove SQLi fallback in `_detect_vuln_type()`~~ ✅ Done (6f9861b)
7. ~~**F-05** — Strip dynamic content from descriptions before dedup comparison~~ ✅ Done — `_normalize_description()` strips timestamps/IPs/UUIDs/hashes
8. ~~**A-02** — Deduplicate error_disclosure URLs by base_url (scheme://netloc)~~ ✅ Done — per-netloc dedup
9. ~~**E-06** — Cap file_upload tests at ~20~~ ✅ Done — capped at 25, priority-ordered

### Tier 3 — Optimization (improves scan speed)
10. ~~**D-02** — Add `asyncio.gather` batching for injection payloads~~ ✅ Done — batch size 5, time-based sequential
11. ~~**A-06** — Parallelize weaponization/delivery scanner dispatch~~ ✅ Done — `asyncio.gather` parallel dispatch
12. ~~**A-05** — Track failed hosts in `_run_scanner_on_urls`, skip remaining URLs on dead hosts~~ ✅ Done — per-host failure tracking (threshold=3)
13. ~~**D-03** — Sort payloads by priority (error-based first, time-based last)~~ ✅ Done (6f9861b)

### Tier 4 — Polish
14. Fix remaining MEDIUM/LOW items as encountered

### Additional fixes applied (not in original audit)
15. ✅ **Injection baseline reset** — `_baseline_body`/`_baseline_status`/`_baseline_headers` reset at top of `_test_insertion_point()` to prevent stale data leaking across insertion points (6f9861b)
16. ✅ **Nuclei rate sanity check** — `effective_rate` in sanity check was referencing removed `_rate_limit_per_host`; corrected to `self._rate_limit or 150` (6f9861b)
17. ~~✅ **E-09** — Cache poisoning duplicate headers~~ (6f9861b)
18. ✅ **A-01** — DNS liveness gate for dead host filtering
19. ✅ **B-01** — Nuclei idle timer shared across stdout+stderr + dead code cleanup (`_rate_limit_per_host` removed, docstring updated)
20. ✅ **B-02** — Removed tag fallback in `_run_nuclei()` that silently filtered network/workflow templates (`b6a2dd1`)
21. ✅ **C-01 + C-02** — Circuit breaker in `BaseScanner.request()` — per-host transport error tracking, `CircuitBreakerOpen` after 5 failures
22. ✅ **A-02** — error_disclosure URL dedup by netloc instead of full URL string
23. ✅ **A-05** — Host-level failure tracking in `_run_scanner_on_urls()` — skip remaining URLs after 3 consecutive failures per host
24. ✅ **E-06** — file_upload test cap at 25, priority-ordered (extension > traversal > polyglot > XSS > content-type)
25. ✅ **F-05** — `_normalize_description()` strips dynamic content (timestamps, IPs, UUIDs, hashes, response excerpts) before dedup comparison
