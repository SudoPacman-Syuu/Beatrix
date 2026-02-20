# BEATRIX Architecture

**Version:** 0.1.0  
**Last Updated:** February 5, 2026

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              BEATRIX CLI                                     │
│                         beatrix hunt / strike / report                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CORE ENGINE                                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ Kill Chain  │  │ Methodology │  │  Scheduler  │  │   Session   │        │
│  │   Engine    │  │   Engine    │  │   (Async)   │  │   Manager   │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
┌───────────────────────┐ ┌───────────────────────┐ ┌───────────────────────┐
│   RECONNAISSANCE      │ │   WEAPONIZATION       │ │   EXPLOITATION        │
│   (Phase 1-2)         │ │   (Phase 3-4)         │ │   (Phase 5-7)         │
├───────────────────────┤ ├───────────────────────┤ ├───────────────────────┤
│ • Subdomain enum      │ │ • Payload generation  │ │ • Active scanning     │
│ • Port scanning       │ │ • PoC crafting        │ │ • Injection testing   │
│ • Service detection   │ │ • Attack planning     │ │ • Auth bypass         │
│ • JS analysis         │ │ • WAF fingerprinting  │ │ • Privilege escalation│
│ • API discovery       │ │                       │ │ • Data exfiltration   │
└───────────────────────┘ └───────────────────────┘ └───────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         INTEGRATIONS LAYER                                   │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐  │
│  │ nuclei  │ │  httpx  │ │  ffuf   │ │ katana  │ │ sqlmap  │ │ Claude  │  │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          REPORTING ENGINE                                    │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │ Finding Storage │  │ PoC Generator   │  │ Report Formatter│             │
│  │   (SQLite)      │  │                 │  │ (HackerOne/BC)  │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Framework Alignment

### Cyber Kill Chain Mapping

| Phase | Kill Chain | BEATRIX Module | Description |
|-------|------------|----------------|-------------|
| 1 | Reconnaissance | `recon/` | Target discovery, subdomain enum, port scan |
| 2 | Weaponization | `payload/` | Payload crafting, PoC generation |
| 3 | Delivery | `scanner/` | Request delivery, injection points |
| 4 | Exploitation | `exploit/` | Vulnerability exploitation |
| 5 | Installation | `persist/` | Persistence mechanisms (if applicable) |
| 6 | Command & Control | `exfil/` | Data extraction, callback testing |
| 7 | Actions on Objectives | `report/` | Evidence collection, report generation |

### MITRE ATT&CK Tactics (Web Focus)

| Tactic ID | Name | BEATRIX Coverage |
|-----------|------|------------------|
| TA0043 | Reconnaissance | Subdomain, port, service, JS analysis |
| TA0001 | Initial Access | Auth bypass, injection, misconfig |
| TA0006 | Credential Access | JWT attack, session hijack, cred spray |
| TA0003 | Persistence | Cookie manipulation, token theft |
| TA0004 | Privilege Escalation | IDOR, BAC, role confusion |
| TA0009 | Collection | Data extraction, API scraping |
| TA0010 | Exfiltration | CORS abuse, SSRF, OOB channels |

### OWASP Testing Guide Mapping

| OWASP Category | BEATRIX Module |
|----------------|----------------|
| WSTG-INFO | `modules/recon/` |
| WSTG-CONF | `modules/config/` |
| WSTG-IDNT | `modules/identity/` |
| WSTG-ATHN | `modules/auth/` |
| WSTG-ATHZ | `modules/authz/` (BAC, IDOR) |
| WSTG-SESS | `modules/session/` |
| WSTG-INPV | `modules/injection/` |
| WSTG-ERRH | `modules/errors/` |
| WSTG-CRYP | `modules/crypto/` |
| WSTG-BUSV | `modules/logic/` |
| WSTG-CLNT | `modules/client/` |
| WSTG-APIT | `modules/api/` |

---

## Component Details

### 1. Core Engine (`core/`)

```
core/
├── __init__.py
├── engine.py           # Main orchestration
├── kill_chain.py       # Kill chain state machine
├── methodology.py      # Framework alignment (from ReconX)
├── scheduler.py        # Async task scheduling
├── session.py          # Target/finding persistence
├── config.py           # Configuration management
└── ai_agent.py         # Claude integration (GHOST port)
```

### 2. Modules (`modules/`)

```
modules/
├── __init__.py
├── recon/              # Reconnaissance
│   ├── subdomain.py
│   ├── portscan.py
│   ├── probe.py
│   └── js_analysis.py
├── scanner/            # Active scanning (Burp port)
│   ├── active_scanner.py
│   ├── passive_analyzer.py
│   ├── crawler.py
│   └── intruder.py
├── injection/          # Injection testing
│   ├── sqli.py
│   ├── xss.py
│   ├── cmdi.py
│   ├── ssti.py
│   └── xxe.py
├── auth/               # Authentication attacks
│   ├── bypass.py
│   ├── bruteforce.py
│   └── jwt.py
├── authz/              # Authorization attacks
│   ├── idor.py
│   ├── bac.py
│   └── privilege_graph.py
├── api/                # API testing
│   ├── rest.py
│   ├── graphql.py
│   └── grpc.py
└── misc/               # Other
    ├── cors.py
    ├── ssrf.py
    ├── csrf.py
    └── sensitive_data.py
```

### 3. Integrations (`integrations/`)

```
integrations/
├── __init__.py
├── nuclei.py           # Nuclei wrapper
├── httpx.py            # httpx wrapper
├── ffuf.py             # ffuf wrapper
├── katana.py           # Katana wrapper
├── sqlmap.py           # sqlmap wrapper
├── claude.py           # Claude API (Haiku/Sonnet/Opus)
└── burp_import.py      # Import Burp scan results
```

### 4. CLI (`cli/`)

```
cli/
├── __init__.py
├── main.py             # Entry point
├── commands/
│   ├── hunt.py         # beatrix hunt
│   ├── strike.py       # beatrix strike
│   ├── add.py          # beatrix add
│   ├── list.py         # beatrix list
│   ├── report.py       # beatrix report
│   └── config.py       # beatrix config
└── output.py           # Pretty terminal output
```

---

## Data Flow

```
1. USER INPUT
   beatrix hunt example.com --preset full --ai haiku
                │
                ▼
2. TARGET QUEUE (Death List)
   SQLite: targets.db
   - domain, scope, status, priority
                │
                ▼
3. RECONNAISSANCE PHASE
   subfinder → httpx → katana → js_analysis
   Output: discovered assets, endpoints, parameters
                │
                ▼
4. ANALYSIS PHASE (Optional AI)
   Claude Haiku analyzes findings
   Prioritizes likely vulnerabilities
                │
                ▼
5. EXPLOITATION PHASE
   injection_scanner → auth_bypass → idor → bac
   Each finding validated, false positives eliminated
                │
                ▼
6. POC GENERATION
   Working curl/Python PoC for each confirmed vuln
                │
                ▼
7. REPORTING
   findings.db → markdown/HTML report
   Bug bounty submission format
```

---

## Technology Stack

| Component | Technology | Reason |
|-----------|------------|--------|
| Language | Python 3.11+ | ReconX compat, async, AI libs |
| Async | asyncio + httpx | High-performance HTTP |
| CLI | Click | Best Python CLI framework |
| Database | SQLite | Zero-config, portable |
| Config | YAML | Human-readable |
| Performance tools | Go binaries | httpx, ffuf, nuclei |
| AI | Claude API | Haiku (cheap), Sonnet (balanced) |

---

## Configuration

```yaml
# beatrix.yaml
target:
  scope: ["*.example.com"]
  exclude: ["admin.example.com"]
  
scanning:
  threads: 50
  rate_limit: 100  # requests/second
  timeout: 10
  
ai:
  enabled: true
  provider: bedrock  # or anthropic
  model: us.anthropic.claude-3-5-haiku-20241022-v1:0
  api_key_env: BEATRIX_API_KEY
  
reporting:
  format: hackerone
  auto_submit: false
  
tools:
  nuclei: /usr/bin/nuclei
  httpx: /usr/bin/httpx
  ffuf: /usr/bin/ffuf
```

---

## Next Steps

See [PROJECT_STATUS.md](PROJECT_STATUS.md) for implementation roadmap.
