# BEATRIX - Burp Scanner Component Map

**Purpose:** Quick reference for porting Burp scanner capabilities to Python

---

## Burp Montoya API - Scanner Components

Located in: `decompiled software/sources/burp/api/montoya/scanner/`

### Core Interfaces

| Interface | Purpose | BEATRIX Equivalent |
|-----------|---------|-------------------|
| `Scanner.java` | Main scanner API | `core/scanner_engine.py` |
| `Audit.java` | Audit/scan session | `core/audit_session.py` |
| `AuditResult.java` | Scan results | `core/findings.py` |

### Scan Checks

| Interface | Purpose | BEATRIX Module |
|-----------|---------|----------------|
| `ActiveScanCheck.java` | Active scanning logic | `modules/scanner/active.py` |
| `PassiveScanCheck.java` | Passive analysis | `modules/scanner/passive.py` |
| `ScanCheckType.java` | Check type enum | `core/types.py` |

### Audit Issues

| Interface | Purpose | BEATRIX Equivalent |
|-----------|---------|-------------------|
| `AuditIssue.java` | Single finding | `core/finding.py` |
| `AuditIssueDefinition.java` | Issue metadata | `config/issues.yaml` |
| `AuditIssueSeverity.java` | Severity levels | `core/types.py` |
| `AuditIssueConfidence.java` | Confidence levels | `core/types.py` |

### Insertion Points

| Interface | Purpose | Notes |
|-----------|---------|-------|
| `AuditInsertionPoint.java` | Where to inject | URL param, header, body, etc. |
| `AuditInsertionPointProvider.java` | Custom insertion points | For complex params |
| `AuditInsertionPointType.java` | Type enum | PARAM_URL, PARAM_BODY, HEADER, etc. |

### BChecks (Burp's Custom Checks)

| Interface | Purpose | Notes |
|-----------|---------|-------|
| `BChecks.java` | BCheck management | Custom scan checks |
| `BCheckImportResult.java` | Import results | For loading external checks |

---

## Key Scanner Logic Locations (Obfuscated)

The actual scanner implementation is obfuscated. Key patterns to look for:

```java
// Pattern: Payload injection
// Look for classes that use IScannerInsertionPoint
grep -r "InsertionPoint" sources/burp/

// Pattern: Issue reporting
// Look for AuditIssue creation
grep -r "AuditIssue\|IScanIssue" sources/burp/

// Pattern: HTTP requests
// Look for HttpRequestResponse handling
grep -r "HttpRequestResponse\|makeHttpRequest" sources/burp/
```

---

## What We Actually Need to Port

### 1. Active Scanner Logic

**What Burp Does:**
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

**Types to Support:**
- `PARAM_URL` - URL query parameters
- `PARAM_BODY` - POST body parameters
- `PARAM_COOKIE` - Cookie values
- `PARAM_HEADER` - Header values (Host, Referer, etc.)
- `PARAM_JSON` - JSON body values
- `PARAM_XML` - XML body values
- `ENTIRE_BODY` - Full body replacement
- `URL_PATH` - Path segments
- `URL_PATH_FOLDER` - Directory traversal points

### 3. Check Categories

**From Burp's Scanner:**
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
- Out-of-band detection (collaborator callbacks)
- Content comparison (baseline vs payload)

---

## Priority Porting Order

1. **HTTP Client** - Async requests with full control
2. **Insertion Point Detection** - Find where to inject
3. **SQL Injection** - Most common high-severity
4. **XSS** - Common, easy wins
5. **Command Injection** - Critical severity
6. **Path Traversal** - File read primitives
7. **SSRF** - Internal network access
8. **Other checks** - As needed

---

## ReconX Already Has

From `modules/injection_scanner.py` (96KB):
- SQL injection detection
- XSS detection
- Command injection
- SSTI detection
- Basic response analysis

**We can use this as starting point**, then enhance with Burp's more sophisticated detection patterns.

---

## Notes

1. Burp's scanner is sophisticated but not magic - it's pattern matching + timing + response comparison
2. The value is in the **payload libraries** and **detection heuristics**
3. We don't need to reverse-engineer obfuscated code - we understand the concepts
4. ReconX + Burp patterns + AI analysis = better than either alone
