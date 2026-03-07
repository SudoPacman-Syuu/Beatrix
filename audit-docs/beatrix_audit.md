# Beatrix Codebase Audit — Findings

Audit date: March 6, 2026. Read-only review, no changes made.  \nLast updated: March 6, 2026 — FULL SWEEP complete. 47/47 audit items fixed (all CRITICAL, HIGH, MEDIUM, and LOW items closed).

---

## 1. Deprecations — ✅ RESOLVED

### `bounty-hunt` command — Deprecated (Justified)

The `bounty-hunt` CLI command prints a deprecation message and exits. It tells users to use `beatrix hunt --preset full` instead. This is correct — `hunt` fully replaces it with more features (file-based targets, auth, AI, presets).

**Manual updated:** Removed `bounty-hunt` from sidebar nav, replaced the command section with a deprecation notice and migration examples, updated Workflow 3 to use `beatrix hunt --preset full`.

### `beatrix-hunt` does NOT exist

There is no `beatrix-hunt` binary, entry point, or alias anywhere. `pyproject.toml` defines only one entry point: `beatrix`. If someone mentioned `beatrix-hunt` being deprecated, it doesn't exist in this codebase.

### No other deprecations

All 49 other CLI commands (21 top-level, 29 subcommands) are active and wired to real implementations.

---

## 2. Dead Code — Never Imported by Anything (DEFERRED)

These modules exist but are never imported or called by any other module in the codebase. They're completely disconnected from Beatrix's runtime. **Left in place for now — will review later.**

| Module | What It Contains | Notes |
|--------|-----------------|-------|
| `core/auto_register.py` | `AutoRegistrar` — auto-registers on bug bounty platforms | Has `__main__` block for standalone use but nothing in Beatrix calls it |
| `core/parallel_haiku.py` | `ParallelHaiku`, `BatchAnalyzer` — parallel AI batch analysis | Has `__main__` block but nothing imports it |
| `core/privilege_graph.py` | `WebAppPrivilegeGraph` — privilege escalation graph modeling | Self-contained, zero external consumers |
| `ai/tasks.py` | `TaskRouter`, `Task`, `TaskPriority` — AI task routing | Exported in `ai/__init__.py` but never actually used by any code path |
| `utils/response_validator.py` | `ResponseValidator` — CDN soft-404 detection | In `utils/__init__.py` but zero external consumers |
| `utils/helpers.py` | `extract_domain()`, `resolve_dns()`, `check_http()`, `is_ip_address()`, etc. | `is_ip_address()` is imported by 6 modules (kill_chain, recon, rapid, cors, github_recon, subfinder). Other functions registered in `utils/__init__.py` but not externally consumed |

**Decision needed:** Are these planned features waiting to be wired in, or abandoned prototypes to remove?

---

## 3. Standalone Files — ✅ RESOLVED

These files live outside the `beatrix/` package and are never referenced by the main codebase.

**Assessment complete.** Two tools have genuine value for bug bounty hunters and have been documented in the manual:

| File | Status | Action Taken |
|------|--------|-------------|
| `tools/attacker_server.py` | **Useful** — CORS PoC exploitation server | Documented in manual under "5b. Standalone Utilities" |
| `tools/hermes_analyzer.py` | **Useful** — React Native Hermes bytecode analyzer | Documented in manual under "5b. Standalone Utilities" |
| `quick_hunt.py` | Redundant — duplicates `beatrix browser scan` | No action (consider removing later) |
| `tools/cors_validator.py` | Partially broken (hardcoded paths) | No action (consider refactoring exploitability logic into CORSScanner later) |
| `tools/remote_access/setup.sh` | Personal infra script | No action (not user-facing) |
| `scripts/reality_check.py` | One-off investigation artifact | No action (not user-facing) |
| `scripts/set_github_meta.sh` | Repo maintenance script | No action (not user-facing) |

---

## 4. Scanners Commented Out of `__init__.py` (But Still Used) — Noted

These scanners are commented out in `scanners/__init__.py` but are actively used via lazy imports in `cli/main.py` and `kill_chain.py`. They work fine at runtime — the comment-out is intentional (they're not `BaseScanner` subclasses). **No action needed — this is by design.**

| Scanner | Used By |
|---------|---------|
| `browser_scanner.py` | `cli/main.py` → `beatrix browser scan` |
| `credential_validator.py` | `cli/main.py` → `beatrix creds` + `kill_chain.py` |
| `mobile_interceptor.py` | `cli/main.py` → `beatrix mobile` |
| `power_injector.py` | `cli/main.py` → `beatrix inject` |

### One scanner missing from `__init__.py` entirely: (DEFERRED)

`polyglot_generator.py` — Not even mentioned in a comment in `scanners/__init__.py`. The only scanner with this status. Used by 3 CLI commands (`polyglot generate`, `polyglot mxss`, `polyglot clobber`) via direct import. Works, but inconsistent with the pattern used for the 4 above. **Will review later.**

---

## 5. Bugs

### Bug 5: Nuclei integration is fundamentally broken — 3 scan modes, 0 real results (P0) — ✅ FIXED

**Observed:** In a live scan of fivetran.com, nuclei ran 3 times across 3 phases and produced 0 findings in impossibly short times. Every single nuclei invocation failed silently.

| Phase | Mode | URLs | Time | Findings | What Actually Happened |
|-------|------|------|------|----------|------------------------|
| Recon | `scan_recon()` | 111,637 | 29s | 0 | Tag filter reduced templates to near-zero; ran against Webflow shared hosting IP |
| Exploit | `scan_exploit()` | 111,638 | 33s | 0 | All URLs rewritten to Webflow IP (198.202.211.1); requests rejected/failed instantly |
| Headless | `scan_headless()` | 223,276 | 11s | 0 | **Crashed on launch** — missing `libatk-1.0.so.0`; nuclei exited with `[FTL]` error |

**All 5 sub-issues below are now fixed as part of the comprehensive 16-issue nuclei fix (see `nuclei-audit.md` for details).** The sub-issues map to nuclei audit IDs: 5a→N-01, 5b→N-02/N-03/N-04, 5c→N-10/N-15, 5d→N-09, 5e→N-08.

#### 5a. Origin IP rewrite poisons ALL URLs (`nuclei.py` ~L889-903)

The `_run_nuclei()` method rewrites every URL whose hostname matches `_target_domain` to use the origin IP instead. When `_target_domain = "fivetran.com"`, this rewrites `https://fivetran.com/anything` but correctly leaves `https://events.fivetran.com/...` alone (subdomain mismatch).

**But the real problem is that the origin IP (198.202.211.1) is Webflow's shared hosting server.** Scanning it is useless — it's not Fivetran's infrastructure. The origin IP discovery module found this IP, the validation check saw "fivetran.com" in the response body (because Webflow renders Fivetran's marketing site), and accepted it at ≥60% confidence. The `HOSTING_SIGNATURES` list includes `"webflow.com"` but Webflow doesn't put its own branding in the rendered HTML of customer sites.

**Additionally, `_target_domain` is set to the base domain but `set_origin_ip()` is called in the exploit phase with `domain = "www.fivetran.com"` (the `url` variable), so the rewrite may or may not match depending on URL normalization.**

**Fix needed:**
1. Origin IP discovery: Add Webflow's IP ranges to `HOSTING_PROVIDER_RANGES` (ASN 209242 / Webflow Inc ranges: `198.202.208.0/21`). Also add reverse-DNS/WHOIS ASN check — if the IP's ASN belongs to a known hosting/CDN provider, flag it.
2. Nuclei origin rewrite: **Never rewrite all URLs.** Instead, run nuclei twice — once on the full URL list through Cloudflare (normal path), and a separate targeted pass on just the base domain URL against the origin IP. The origin bypass is only valuable for the base domain, not for 111K crawled URLs.
3. Kill chain: Add a validation step that actually curls the origin IP and checks the `Server` header / TLS cert issuer / response similarity before committing to the bypass.

#### 5b. Origin IP discovery doesn't check ASN/WHOIS (`origin_ip_discovery.py` ~L717-790)

The validation in `_validate_origin_ips()` only checks:
- Response body for hosting provider string signatures (e.g., "webflow.com", "shopify")
- `HOSTING_PROVIDER_RANGES` (static IP ranges for known providers)

It does NOT check:
- The IP's ASN (AS209242 = "Webflow Inc" — should be an instant disqualification)
- Reverse DNS (would show Webflow-related PTR records)
- The TLS certificate (would show Webflow's cert, not Fivetran's)

Webflow IPs aren't in `HOSTING_PROVIDER_RANGES` because nobody added them. And the string "webflow.com" doesn't appear in Webflow customer sites — it only appears in Webflow's error/generic pages.

**Fix needed:** Add `"198.202.208.0/21"` to `HOSTING_PROVIDER_RANGES`. For a more robust fix, add ASN lookup (via Team Cymru DNS or ipinfo.io) to compare against a list of known hosting/CDN ASNs.

#### 5c. Nuclei completes in impossible times — likely not scanning at all

111K+ URLs in 29-33 seconds at 30 rps max = physically impossible. At 30 rps, 111K URLs would take ~62 minutes minimum (single template). With thousands of templates, it would take days.

Two possible explanations:
1. **Tag/severity filtering reduces actual templates to near-zero.** Nuclei reports total template count at startup (18K), but the `-tags` and `-severity` flags filter most out. The actual selected templates might be single digits, and if none match the response, nuclei finishes quickly.
2. **All requests fail instantly** (connection refused / TLS error to Webflow IP), so nuclei "completes" by burning through failed requests with no I/O wait.

Either way, nuclei is not doing meaningful work. The code doesn't log which templates were actually selected or how many requests were made.

**Fix needed:** After nuclei completes, parse its stderr stats output and log the actual request count and template count. If requests = 0 or templates = 0, emit a warning: `"Nuclei ran 0 requests — likely misconfigured tags/targets"`.

#### 5d. Headless mode crashes — missing chromium dependencies (`install.sh`)

```
[FTL] Could not create runner: [launcher] Failed to launch the browser...
libatk-1.0.so.0: cannot open shared object file: No such file or directory
```

Nuclei's headless mode uses `go-rod` which downloads its own chromium binary, but that binary needs GTK/ATK system libraries. `install.sh` never installs these.

**Fix needed:** Add to `install.sh`:
```bash
apt-get install -y libatk1.0-0 libatk-bridge2.0-0 libcups2 libxdamage1 \
    libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2t64 libnspr4 libnss3
```
(These are the standard chromium headless dependencies on Debian/Ubuntu.)

#### 5e. Nuclei FTL/fatal errors are silently swallowed (`nuclei.py` ~L994-1008)

The `_drain_stderr()` function reads nuclei's stderr and selectively logs lines containing keywords like "templates", "hosts", "requests". But `[FTL]` (fatal) errors don't match any of these keywords, so they're captured in `stderr_lines` but only the last 5 lines are logged after the scan completes — and only if they happen to be the last lines.

Even when the `[FTL]` line IS logged (as it was in this scan), the overall status still says "Nuclei complete: 0 findings in 11s" — making it look like a successful scan with no results instead of a crashed scan.

**Fix needed:**
1. In `_drain_stderr()`, check for `[FTL]` and `[ERR]` prefixes. If found, immediately log them as warnings.
2. After nuclei completes, check if `stderr_lines` contains any `[FTL]` entries. If so, emit a `scanner_error` event and change the completion message to `"Nuclei FAILED: {error}"` instead of `"Nuclei complete: 0 findings"`.

---

### Bug 6: Injection scanner behavioral detection uses hardcoded status/headers (P0) — ✅ FIXED

**File**: `beatrix/scanners/injection.py` line 669  
**Impact**: Every behavioral SQLi/blind injection finding is a **guaranteed false positive**  
**Fix**: Added `response_status` and `response_headers` params to `_check_response()`. Both callers in `_test_payload()` now pass the actual `response.status_code` and `dict(response.headers)`. Behavioral detection uses real values in `responses_differ()`.

**Discovered via**: franktech.net scan — validator graded SQLi finding at 100/100 ("READY to submit") but manual testing confirmed it's a blanket nginx 301 redirect, not SQL processing.

In `_check_response()`, the behavioral detection branch calls `responses_differ()` with **hardcoded values** instead of the actual response data:

```python
# injection.py L669 — inside _check_response()
diffs = responses_differ(
    baseline_status, baseline_headers, baseline_body,
    200, {}, response_text,  # ← BUG: hardcoded status=200, headers={}
)
```

The baseline is captured correctly from the real response (status, headers, body). But the **test** response always passes `200` for status and `{}` for headers, regardless of what the server actually returned.

This guarantees false positives because:
1. `STATUS_CODE` always differs: baseline's real status (e.g., 301) vs hardcoded 200
2. `LOCATION` always differs: baseline's real Location header vs empty string
3. That's 2 "meaningful" attribute diffs → meets the `min_attrs=2` threshold in `is_blind_indicator()`
4. **Every single behavioral detection check returns True**

The fix is trivial — the `_test_payload()` method has the full `response` object with `.status_code` and `.headers`. But `_check_response()` only receives `response.text` as a parameter, so it can't access them. The function signature needs to accept the response status and headers, or the full response object.

**The actual response object is RIGHT THERE in the caller** (`_test_payload()` line 562: `response = await self.request(...)`) but only `response.text` is passed to `_check_response()` at line 571. The status code and headers are thrown away.

In the franktech scan, the validator gave this false positive a perfect 100/100 submission score. If submitted to a bug bounty program, this would be an **instant reputation hit** — the "SQLi" is just nginx doing a blanket 301 redirect for every HTTP request.

---

### Bug 7: XSS reflection detection matches static HTML content (P1) — ✅ FIXED

**File**: `beatrix/scanners/injection.py` lines 138–140  
**Impact**: Common HTML tags from seclists payloads match against the server's own HTML, not reflected input  
**Fix**: `reflect` detection now checks if the matched pattern also exists in the baseline response (no payload). If the same match appears in the baseline, it's static server content and gets skipped.

**Discovered via**: franktech.net scan — XSS finding with payload `</HTML>` graded 100/100 ("READY to submit") but the match is against nginx's own 301 error page HTML, not reflected user input.

When loading XSS payloads from seclists, the scanner uses `re.escape(raw_payload)` as the detection pattern:

```python
# injection.py L138-140
if payload_cat == "xss" and not patterns:
    patterns = [re.escape(raw_payload)]
```

For a payload like `</HTML>`, the pattern becomes `<\/HTML>` which matches case-insensitively against `</html>` — a string that appears in **every HTML page ever served**. The scanner doesn't verify that the matched text is actually user-controlled input being reflected. It just checks if the payload string exists anywhere in the response body.

Nginx's default 301 redirect page contains:
```html
<html>\r\n<head><title>301 Moved Permanently</title></head>\r\n<body>...\r\n</body>\r\n</html>
```

The `</html>` at the end matches the `</HTML>` payload pattern. This isn't reflection — it's a static nginx template. The same false positive would trigger for any seclists XSS payload that happens to be a common HTML tag or attribute.

**Fix needed**: Before flagging a reflection, verify that the payload actually caused the match — e.g., compare responses with and without the payload. If the "reflected" content also appears in a baseline request (no payload), it's not reflection.

---

### Bug 8: JS bundle scanner extracts framework internals as API routes (P2) — ✅ FIXED

**File**: `beatrix/scanners/js_bundle.py`  
**Impact**: SvelteKit/React/Vue internal error codes reported as discoverable API endpoints  
**Fix**: Added `FRAMEWORK_NOISE_PATTERNS` regex matching SvelteKit/React internal path constants (`/hydration_failed`, `/effect_orphan`, etc.). Also filters bare non-path strings like `content-type`. Applied at extraction time in `_analyze_bundle()`.

**Discovered via**: franktech.net scan — "API Routes Disclosed in JS Bundles (27 endpoints)" finding reports SvelteKit internal diagnostics as security-relevant API routes.

The 27 "endpoints" extracted include:
- `/hydration_failed`, `/hydration_mismatch` — Svelte SSR hydration diagnostics
- `/effect_orphan`, `/effect_in_teardown` — Svelte reactivity engine warnings
- `/lifecycle_legacy_only`, `/lifecycle_outside_component` — Svelte lifecycle errors
- `content-type`, `length` — HTTP header field name strings

None of these are routable API endpoints. They're string constants from SvelteKit's source code that happen to start with `/`. The JS bundle scanner lacks context to distinguish framework internal error/warning code names from actual API routes.

---

### Bug 9: Rate limiting detection fires on non-existent endpoints (P2) — ✅ FIXED

**File**: `beatrix/scanners/auth.py`  
**Impact**: Reports "Missing Rate Limiting" on endpoints that return 404 — the endpoint doesn't exist  
**Fix**: Before creating the finding, checks if all response codes are 404. If so, the endpoint doesn't exist — finding is skipped.

**Discovered via**: franktech.net scan — "Missing Rate Limiting on Authentication Endpoint" for `https://franktech.net/login` scored 20/20 requests succeeded, but ALL returned HTTP 404. The endpoint doesn't exist. Reporting missing rate limiting on a non-existent endpoint is meaningless.

Evidence from the finding:
```json
"response_codes": [404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404, 404]
```

**Fix needed**: If all responses are 404, skip the finding — you can't brute-force a login page that doesn't exist.

---

### Bug 1: SmartFuzzer has no timeout (P2) — ✅ FIXED

In `kill_chain.py` (~line 1980-2030), the SmartFuzzer loop iterates over fuzz targets and runs `await fuzzer.scan()` per URL. Unlike the main scanner runner (`_run_scanner`), there's no `asyncio.wait_for()` timeout wrapping the SmartFuzzer. If `ffuf` hangs or produces huge output, the entire kill chain stalls with no escape.

Every other scanner gets a per-scanner timeout via `_run_scanner`. SmartFuzzer bypasses this.

**Fix**: Wrapped SmartFuzzer scan call in `asyncio.wait_for()` with appropriate timeout.

### Bug 2: Thread-unsafe log truncation in CLI (P3) — ✅ FIXED

In `cli/main.py` (~line 1405), the `_on_event` callback mutates a shared list (`progress_state["log"]`) — truncating it with `del progress_state["log"][:excess]` and adjusting `_printed_count[0]`. Meanwhile, the printer thread reads from the same list and index.

There's no lock. The `del` + index adjustment isn't atomic. Under heavy event load, this could cause an `IndexError` in the printer thread or skipped log lines.

**Fix**: Added threading lock around shared list mutations.

### Bug 3: Silent error swallowing in kill_chain.py (P3) — ✅ FIXED

Six `except Exception: pass` blocks silently eat errors with zero diagnostic output:

| Location | What It Swallows |
|----------|-----------------|
| `kill_chain.py` ~L2028 | SmartFuzzer per-URL scan failure |
| `kill_chain.py` ~L2204 | JWT tamper PoC failure |
| `kill_chain.py` ~L2517 | Metasploit integration failure |
| `kill_chain.py` ~L2717 | Session health check (acceptable — marked "non-fatal") |
| `kill_chain.py` ~L2747 | PoC client cleanup (acceptable) |
| `kill_chain.py` ~L2755 | Interactsh cleanup (acceptable) |

The first three are problematic. If the SmartFuzzer, JWT testing, or Metasploit integration fails, the user sees nothing — no error, no warning, no indication that a scan phase was skipped.

### Bug 4: Findings DB save silently fails (P3) — ✅ FIXED

In `cli/main.py` (~line 1563), the hunt results DB save is wrapped in `except Exception: pass`. If the database write fails (disk full, permissions, etc.), the user loses all findings from the scan with zero warning.

**Fix**: Added `logger.warning()` to the exception handler so failures are visible.

---

## 5b. Franktech.net Scan — Cross-Reference Validation

**Date**: March 6, 2026  
**Target**: franktech.net (DigitalOcean droplet, nginx/1.20.1 + Express + SvelteKit + Immich)  
**Scan duration**: 1,879 seconds  
**Total findings**: 24 (3 HIGH, 4 MEDIUM, 1 LOW, 16 INFO)  
**Validator results**: 4 READY, 19 NEEDS WORK, 1 KILLED

### Validator Graded as Submittable — Manual Validation Results

| # | Finding | Validator Score | Verdict | Root Cause |
|---|---------|----------------|---------|------------|
| 1 | SQL Injection in `option` parameter | 100/100 | **FALSE POSITIVE** | Bug 6 — hardcoded 200/{} in behavioral detection |
| 2 | Cross-Site Scripting in `option` parameter | 100/100 | **FALSE POSITIVE** | Bug 7 — `</HTML>` matches nginx's own HTML |
| 3 | Auth-Protected Endpoints Found | 77/100 | **Legitimate** (but informational) | Real 401s from Immich API via origin IP |
| 4 | API Routes Disclosed in JS Bundles | 77/100 | **FALSE POSITIVE** | Bug 8 — SvelteKit internal constants, not API routes |

**Critical concern**: The two 100/100 findings (SQLi and XSS) are both false positives caused by code bugs in the injection scanner. The validator has no way to detect these because the PoCs are "reproducible" — the bug is deterministic, so replaying the request always produces the same (incorrect) result.

### Nuclei Behavior on Franktech

Nuclei behavior was consistent with the fivetran audit findings:
- Templates loaded correctly: 12,669 official + 5,387 external = 18,056
- RECON: 96 URLs, 30 seconds, 0 findings
- EXPLOIT: 96 URLs, 30 seconds, 0 findings  
- HEADLESS: 193 URLs, 1 second, 0 findings — crashed with same `libatk-1.0.so.0` error

Key difference from fivetran: the origin IP (167.71.161.180) is **correct** — it's a DigitalOcean droplet that serves the real Immich application. Despite having the right origin IP, nuclei still produced 0 findings. This refines N-01 in the nuclei audit: the problem isn't just wrong IPs — blanket URL rewrite to ANY IP (even correct ones) disrupts nuclei's template matching because templates expect hostname-based URLs, not IP addresses.

---

## 6. Test Suite Assessment (DEFERRED)

### 15+ empty stub tests in `test_scanner_smoke.py`

The "import tests" section (lines 26-79) contains 15+ functions that are just `pass`. **Will review later.**

```python
def test_import_base():
    pass
def test_import_cors():
    pass
# ...etc
```

They test nothing. They don't even import the module they claim to test. The nuclei tests later in the same file are real and well-written.

### Tests can't run without `pip install -e .`

The test files import from `beatrix.scanners` etc. via package imports. They'll fail unless Beatrix is installed in the Python environment (either `pip install -e .` or installed in the venv). This isn't documented anywhere.

### No pytest in venv

`pytest` isn't installed in the Beatrix venv (`/home/codespace/.beatrix/`). Tests would need to be run with system pytest or after installing it.

---

## 7. Only 1 TODO in Entire Codebase (DEFERRED)

`scanners/insertion.py` line 206: `# TODO: Proper multipart parsing`

That's it — the only developer TODO marker in 73,800 lines. **Will review later.**

---

## 8. Things That Could Be Wired In (DEFERRED)

These dead code modules look like they were built for specific purposes that would add real value if connected. **Will review when addressing dead modules.**

| Module | What It Would Add | Where It Should Wire In |
|--------|-------------------|------------------------|
| `core/privilege_graph.py` | Visualize privilege escalation paths between discovered roles/endpoints | Kill chain Phase 6 (exploitation) or reporting |
| `core/parallel_haiku.py` | Parallel AI analysis of findings using Claude Haiku | Kill chain Phase 7 or `beatrix haiku-hunt` |
| `ai/tasks.py` | AI task routing/prioritization | GHOST agent or engine AI enrichment |
| `core/auto_register.py` | Auto-register accounts on target for auth testing | Kill chain Phase 3 (pre-attack auth setup) |
| `utils/response_validator.py` | Detect CDN soft-404s to reduce false positives | Kill chain crawler/endpoint prober phase |

---

## 9. Hardcoded Values Worth Noting (DEFERRED)

Keeping as-is for now. Not an issue in the near term.

| Location | Value | Risk |
|----------|-------|------|
| `engine.py` ~L36 | `ai_model: str = "us.anthropic.claude-3-5-haiku-20241022-v1:0"` | Bedrock model ID — will break when AWS rotates this version |
| `kill_chain.py` ~L261-271 | Scanner timeout overrides (nuclei=3600s, nmap=1800s, etc.) | Not user-configurable |
| `kill_chain.py` ~L1730 | `injection_targets[:50]` — cap at 50 URLs | Not user-configurable |

---

## Summary

| Category | Count | Status |
|----------|-------|--------|
| Deprecations | 1 (`bounty-hunt`) | ✅ Manual updated, migration documented |
| Dead modules | 6 | ⏸ Deferred — will review later |
| Standalone files | 7 (2 useful) | ✅ Assessed, useful ones documented in manual |
| Bugs 1-4 | 4 | ✅ All fixed (SmartFuzzer timeout, thread safety, silent errors, DB save) |
| **Bug 5: Nuclei** | **16 sub-issues** | **✅ All 16 fixed — see `nuclei-audit.md`** |
| Bug 6: Injection behavioral detection | 1 | ✅ Fixed — passes actual response status/headers instead of hardcoded 200/{} |
| Bug 7: XSS reflection detection | 1 | ✅ Fixed — compares against baseline to filter static HTML matches |
| Bug 8: JS bundle false routes | 1 | ✅ Fixed — filters framework internal paths (SvelteKit, React) |
| Bug 9: Rate limit on 404 endpoints | 1 | ✅ Fixed — skips finding when all responses are 404 |
| Franktech cross-reference | 4 findings validated | ✅ 3 false positives identified, 1 legitimate |
| **Scanner audit (Tier 1)** | **6 fixes** | **✅ SSRF patterns, enricher fallback, payload sort, baseline reset, nuclei rate, cache dedup** |
| **Scanner audit (Critical)** | **3 fixes** | **✅ A-01 URL liveness gate, B-01 nuclei idle timer, B-02 tag fallback fix** |
| Scanner audit (remaining) | 38 items | ⏸ See `SCANNER_AUDIT.md` — Tiers 2-4 |
| Stub tests | 15+ | ⏸ Deferred — will review later |
| Missing from `__init__.py` | 1 (`polyglot_generator`) | ⏸ Deferred |
| TODOs | 1 | ⏸ Deferred |
| Hardcoded values | 3 | ⏸ Deferred |
