# BEATRIX — Sweet Scanner Component Map

**Purpose:** Quick reference for the scanning architecture patterns used in Beatrix

---

## Scanner Components

### Core Interfaces

| Interface | Purpose | BEATRIX Equivalent |
|-----------|---------|-------------------|
| Scanner | Main scanner API | `core/engine.py` |
| Audit | Audit/scan session | `core/kill_chain.py` |
| AuditResult | Scan results | `core/types.py` (Finding) |

### Scan Checks

| Interface | Purpose | BEATRIX Module |
|-----------|---------|----------------|
| ActiveScanCheck | Active scanning logic | `core/scan_check_types.py` |
| PassiveScanCheck | Passive analysis | `core/scan_check_types.py` |
| ScanCheckType | Check type enum | `core/scan_check_types.py` |

### Audit Issues

| Interface | Purpose | BEATRIX Equivalent |
|-----------|---------|-------------------|
| AuditIssue | Single finding | `core/types.py` (Finding dataclass) |
| AuditIssueDefinition | Issue metadata | Config / finding fields |
| AuditIssueSeverity | Severity levels | `core/types.py` (Severity enum) |
| AuditIssueConfidence | Confidence levels | `core/types.py` (Confidence enum) |

### Insertion Points

| Interface | Purpose | Notes |
|-----------|---------|-------|
| AuditInsertionPoint | Where to inject | URL param, header, body, etc. |
| AuditInsertionPointProvider | Custom insertion points | For complex params |
| AuditInsertionPointType | Type enum | PARAM_URL, PARAM_BODY, HEADER, etc. |

---

## Key Scanner Architecture Patterns

### 1. Active Scanner Logic

**What the Scanner Does:**
1. Identifies insertion points (URL params, body params, headers, cookies)
2. For each insertion point, runs relevant checks
3. Injects payloads, analyzes responses
4. Reports findings with evidence

**Python Implementation:**
```python
class ActiveScanner:
    def scan(self, request: HttpRequest) -> List[Finding]:
        findings = []
        insertion_points = self.find_insertion_points(request)
        
        for point in insertion_points:
            for check in self.get_relevant_checks(point):
                result = check.run(request, point)
                if result:
                    findings.append(result)
        
        return findings
```

### 2. Insertion Point Detection

**Types Supported:**
- `PARAM_URL` — URL query parameters
- `PARAM_BODY` — POST body parameters
- `PARAM_COOKIE` — Cookie values
- `PARAM_HEADER` — Header values (Host, Referer, etc.)
- `PARAM_JSON` — JSON body values
- `PARAM_XML` — XML body values
- `ENTIRE_BODY` — Full body replacement
- `URL_PATH` — Path segments
- `URL_PATH_FOLDER` — Directory traversal points

### 3. Check Categories

**Scanner Categories:**
- SQL Injection (error-based, time-based, boolean-based)
- XSS (reflected, stored indicators)
- Command Injection (OS command execution)
- Path Traversal (file read/write)
- XML Injection (XXE, XPath)
- LDAP Injection
- Header Injection (CRLF)
- Open Redirect
- SSRF
- File Upload
- Deserialization

### 4. Response Analysis

**Key Detection Methods:**
- Error message matching (SQL errors, stack traces)
- Reflection detection (payload in response)
- Time-based detection (response delay)
- Out-of-band detection (OOB callbacks via interact.sh)
- Content comparison (baseline vs payload)

---

## Priority Implementation Order

1. **HTTP Client** — Async requests with full control
2. **Insertion Point Detection** — Find where to inject
3. **SQL Injection** — Most common high-severity
4. **XSS** — Common, easy wins
5. **Command Injection** — Critical severity
6. **Path Traversal** — File read primitives
7. **SSRF** — Internal network access
8. **Other checks** — As needed

---

## Notes

1. The scanner is pattern matching + timing + response comparison
2. The value is in the **payload libraries** and **detection heuristics**
3. Beatrix combines open-source scanning patterns + AI analysis for superior results
4. Dynamic wordlists (57K+ payloads from SecLists + PayloadsAllTheThings) power the injection engine
