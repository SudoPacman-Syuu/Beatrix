#!/usr/bin/env python3
"""
Hermes v96 Bytecode Analyzer for BEATRIX

Since hbctool doesn't support v96 and hermes-dec doesn't exist,
we parse the bytecode format directly to extract security-relevant data.

Hermes bytecode format (v96):
- Magic: 0xc61fbc03
- Header with string table offset, function table offset, etc.
- String storage (identifiers, string literals)
- Function headers (name, params, bytecode offset)
- Regex table
- Debug info

For pentesting, we care about:
- All string literals (URLs, API keys, secrets, config)
- Function names (reveals app structure, auth flow, crypto logic)
- Regex patterns (input validation bypass clues)
"""

import json
import re
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

# ============================================================================
# HERMES HEADER PARSER
# ============================================================================

HERMES_MAGIC = 0x03BC1FC6  # Little-endian magic bytes

@dataclass
class HermesHeader:
    magic: int
    version: int
    sha1: bytes  # 20 bytes
    file_length: int
    global_code_index: int
    function_count: int
    string_kind_count: int
    identifier_count: int
    string_count: int
    overflow_string_count: int
    string_storage_size: int


def parse_header(data: bytes) -> Optional[HermesHeader]:
    """Parse the Hermes bytecode header."""
    if len(data) < 128:
        return None

    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != HERMES_MAGIC:
        print(f"Warning: unexpected magic 0x{magic:08x} (expected 0x{HERMES_MAGIC:08x})")

    version = struct.unpack_from('<I', data, 4)[0]
    sha1 = data[8:28]
    file_length = struct.unpack_from('<I', data, 28)[0]
    global_code_index = struct.unpack_from('<I', data, 32)[0]
    function_count = struct.unpack_from('<I', data, 36)[0]
    string_kind_count = struct.unpack_from('<I', data, 40)[0]
    identifier_count = struct.unpack_from('<I', data, 44)[0]
    string_count = struct.unpack_from('<I', data, 48)[0]
    overflow_string_count = struct.unpack_from('<I', data, 52)[0]
    string_storage_size = struct.unpack_from('<I', data, 56)[0]

    return HermesHeader(
        magic=magic,
        version=version,
        sha1=sha1,
        file_length=file_length,
        global_code_index=global_code_index,
        function_count=function_count,
        string_kind_count=string_kind_count,
        identifier_count=identifier_count,
        string_count=string_count,
        overflow_string_count=overflow_string_count,
        string_storage_size=string_storage_size,
    )


# ============================================================================
# STRING EXTRACTION (multiple strategies)
# ============================================================================

def extract_printable_strings(data: bytes, min_length: int = 6) -> List[str]:
    """Extract all printable ASCII strings from raw bytes."""
    strings = []
    current = []

    for byte in data:
        if 0x20 <= byte <= 0x7e:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append(''.join(current))
            current = []

    if len(current) >= min_length:
        strings.append(''.join(current))

    return strings


def extract_utf8_strings(data: bytes, min_length: int = 4) -> List[str]:
    """Extract UTF-8 encoded strings."""
    strings = []
    # Look for null-terminated UTF-8 strings
    parts = data.split(b'\x00')
    for part in parts:
        try:
            s = part.decode('utf-8', errors='strict')
            if len(s) >= min_length and any(c.isalpha() for c in s):
                # Filter out binary garbage
                if all(0x20 <= ord(c) <= 0x7e or c in '\t\n\r' for c in s):
                    strings.append(s)
        except (UnicodeDecodeError, ValueError):
            continue

    return strings


# ============================================================================
# SECURITY-RELEVANT PATTERN MATCHING
# ============================================================================

SECURITY_PATTERNS = {
    # URLs and Endpoints
    'urls': re.compile(r'https?://[^\s"\'<>\]\)]{8,}'),
    'api_paths': re.compile(r'(?:/api/|/v[0-9]+/|/graphql|/rest/|/webhook)[^\s"\'<>]{2,}'),
    'subdomains': re.compile(r'[a-z0-9][-a-z0-9]*\.(?:exodus\.io|exodus\.com|exodusmovement\.com)[^\s"\'<>]*'),

    # Crypto and Keys
    'api_keys': re.compile(r'(?:api[_-]?key|apikey|api_secret|client_secret)["\s:=]+["\']?([a-zA-Z0-9_\-]{16,})["\']?', re.I),
    'private_keys': re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
    'hex_keys': re.compile(r'(?:key|secret|token|password|passwd|pwd|seed|mnemonic)["\s:=]+["\']?([0-9a-fA-F]{32,})["\']?', re.I),
    'base64_secrets': re.compile(r'(?:key|secret|token|password)["\s:=]+["\']?([A-Za-z0-9+/]{32,}={0,2})["\']?', re.I),
    'jwt_tokens': re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+'),

    # Firebase
    'firebase_db': re.compile(r'[a-z0-9-]+\.firebaseio\.com'),
    'firebase_api': re.compile(r'AIza[0-9A-Za-z_-]{35}'),
    'firebase_project': re.compile(r'[a-z0-9-]+\.cloudfunctions\.net'),
    'firebase_storage': re.compile(r'[a-z0-9-]+\.appspot\.com'),

    # AWS
    'aws_access_key': re.compile(r'AKIA[0-9A-Z]{16}'),
    'aws_bucket': re.compile(r's3://[a-z0-9][a-z0-9.-]*|[a-z0-9.-]+\.s3\.amazonaws\.com'),

    # Google
    'google_api_key': re.compile(r'AIzaSy[A-Za-z0-9_-]{33}'),
    'google_oauth': re.compile(r'[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com'),

    # Crypto Wallet Specific
    'mnemonic_words': re.compile(r'(?:mnemonic|seed|bip39|recovery)[^"\']{0,30}(?:word|phrase|backup)', re.I),
    'derivation_path': re.compile(r"m/\d+['h]?/\d+['h]?/\d+['h]?(?:/\d+['h]?)*"),
    'encryption_algo': re.compile(r'(?:aes|chacha|xchacha|argon2|scrypt|pbkdf2|nacl|tweetnacl)[-_]?(?:256|128|gcm|cbc|ctr|poly1305)?', re.I),

    # Sensitive Functionality
    'auth_functions': re.compile(r'(?:login|signIn|signUp|register|authenticate|authorize|verifyToken|checkAuth|getSession|logout|resetPassword|forgotPassword|changePassword|validateOTP|verify2FA|verifyBiometric)', re.I),
    'crypto_functions': re.compile(r'(?:encrypt|decrypt|generateKey|deriveKey|signTransaction|broadcastTx|generateMnemonic|mnemonicToSeed|createWallet|exportPrivateKey|importWallet|backupSeed)', re.I),
    'storage_functions': re.compile(r'(?:localStorage|AsyncStorage|SecureStore|Keychain|getItem|setItem|removeItem|clearStorage)', re.I),

    # Internal/Debug
    'debug_flags': re.compile(r'(?:debug|staging|sandbox|test|dev)(?:Mode|Flag|Env|Environment|Server|API|URL)["\s:=]+(?:true|1|"[^"]*")', re.I),
    'internal_ips': re.compile(r'(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(?::\d+)?'),
    'localhost': re.compile(r'(?:localhost|127\.0\.0\.1)(?::\d+)?'),

    # Sardine / Payment
    'sardine': re.compile(r'(?:sardine|sardineai)[^"\']{0,50}(?:client|api|key|secret|token)', re.I),
    'payment_ids': re.compile(r'(?:client_id|clientId|merchant_id|merchantId)["\s:=]+["\']?([a-f0-9-]{36}|[a-zA-Z0-9_-]{16,})["\']?', re.I),

    # Sentry
    'sentry_dsn': re.compile(r'https://[a-f0-9]+@[a-z0-9.]+\.ingest\.(?:us\.)?sentry\.io/\d+'),
}


def categorize_strings(strings: List[str]) -> Dict[str, List[str]]:
    """Categorize extracted strings by security relevance."""
    categorized = defaultdict(list)

    for s in strings:
        for category, pattern in SECURITY_PATTERNS.items():
            matches = pattern.findall(s)
            if matches:
                for match in matches:
                    value = match if isinstance(match, str) else s
                    if value not in categorized[category]:
                        categorized[category].append(value)
            elif pattern.search(s):
                if s not in categorized[category]:
                    categorized[category].append(s)

    return dict(categorized)


def extract_domains(strings: List[str]) -> Set[str]:
    """Extract all domains (not just Exodus-related)."""
    domain_pattern = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:com|io|org|net|dev|app|xyz|ai|co|me|cc|us|uk|de|fr|jp|kr|cn|au|ca|in)\b', re.I)
    domains = set()
    for s in strings:
        for m in domain_pattern.finditer(s):
            d = m.group(0).lower()
            if len(d) > 5 and not d.startswith('.'):
                domains.add(d)
    return domains


# ============================================================================
# FUNCTION TABLE EXTRACTION
# ============================================================================

def extract_function_names(strings: List[str]) -> List[str]:
    """
    Extract likely function/method names from strings.
    Hermes stores function names as identifier strings.
    """
    fn_pattern = re.compile(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$')

    # Filter for likely function names (camelCase, PascalCase, snake_case)
    functions = []
    for s in strings:
        if 3 <= len(s) <= 80 and fn_pattern.match(s):
            # Heuristic: function names are usually camelCase or contain common patterns
            if (any(c.isupper() for c in s[1:]) or  # has uppercase after first char
                '_' in s or                            # snake_case
                s.startswith(('get', 'set', 'is', 'has', 'on', 'handle', 'create',
                             'update', 'delete', 'fetch', 'send', 'validate', 'check',
                             'parse', 'render', 'init', 'load', 'save', 'export',
                             'import', 'generate', 'verify', 'sign', 'encrypt', 'decrypt',
                             'derive', 'compute', 'calculate', 'process', 'format',
                             'broadcast', 'submit', 'connect', 'disconnect'))):
                functions.append(s)

    return sorted(set(functions))


# ============================================================================
# MAIN ANALYSIS
# ============================================================================

def analyze_bundle(filepath: str, output_dir: str = '/tmp/exodus_analysis'):
    """Full analysis of a Hermes bytecode bundle."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    print(f"[*] Loading {filepath}...")
    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"[*] File size: {len(data):,} bytes ({len(data)/1024/1024:.1f} MB)")

    # Parse header
    header = parse_header(data)
    if header:
        print("\n[*] Hermes Header:")
        print(f"    Version: {header.version}")
        print(f"    Function count: {header.function_count:,}")
        print(f"    String count: {header.string_count:,}")
        print(f"    Identifier count: {header.identifier_count:,}")
        print(f"    String storage: {header.string_storage_size:,} bytes")
        print(f"    SHA1: {header.sha1.hex()}")

    # Extract strings
    print("\n[*] Extracting strings...")
    ascii_strings = extract_printable_strings(data, min_length=4)
    utf8_strings = extract_utf8_strings(data, min_length=4)

    # Deduplicate
    all_strings = sorted(set(ascii_strings + utf8_strings))
    print(f"    ASCII strings: {len(ascii_strings):,}")
    print(f"    UTF-8 strings: {len(utf8_strings):,}")
    print(f"    Unique strings: {len(all_strings):,}")

    # Save all strings
    with open(f'{output_dir}/all_strings.txt', 'w') as f:
        for s in all_strings:
            f.write(s + '\n')

    # Categorize by security relevance
    print("\n[*] Categorizing security-relevant strings...")
    categorized = categorize_strings(all_strings)

    for cat, items in sorted(categorized.items()):
        print(f"    {cat}: {len(items)} findings")

    # Save categorized results
    with open(f'{output_dir}/security_findings.json', 'w') as f:
        json.dump(categorized, f, indent=2)

    # Extract domains
    print("\n[*] Extracting domains...")
    domains = extract_domains(all_strings)
    exodus_domains = sorted(d for d in domains if 'exodus' in d)
    other_domains = sorted(domains - set(exodus_domains))

    print(f"    Exodus domains: {len(exodus_domains)}")
    print(f"    Third-party domains: {len(other_domains)}")

    with open(f'{output_dir}/domains_exodus.txt', 'w') as f:
        for d in exodus_domains:
            f.write(d + '\n')

    with open(f'{output_dir}/domains_thirdparty.txt', 'w') as f:
        for d in other_domains:
            f.write(d + '\n')

    # Extract function names
    print("\n[*] Extracting function names...")
    functions = extract_function_names(all_strings)
    print(f"    Likely function names: {len(functions)}")

    # Filter security-relevant functions
    security_keywords = [
        'auth', 'login', 'sign', 'token', 'session', 'password', 'credential',
        'encrypt', 'decrypt', 'key', 'seed', 'mnemonic', 'wallet', 'backup',
        'private', 'secret', 'biometric', 'pin', 'otp', '2fa', 'totp',
        'derive', 'hash', 'hmac', 'pbkdf', 'scrypt', 'argon',
        'transaction', 'broadcast', 'transfer', 'swap', 'exchange',
        'store', 'storage', 'keychain', 'secure',
        'firebase', 'sentry', 'sardine', 'api',
        'admin', 'debug', 'test', 'sandbox', 'staging',
    ]

    sec_functions = [f for f in functions if any(kw in f.lower() for kw in security_keywords)]
    print(f"    Security-relevant functions: {len(sec_functions)}")

    with open(f'{output_dir}/functions_all.txt', 'w') as f:
        for fn in functions:
            f.write(fn + '\n')

    with open(f'{output_dir}/functions_security.txt', 'w') as f:
        for fn in sec_functions:
            f.write(fn + '\n')

    # Extract URLs
    print("\n[*] Extracting URLs...")
    url_pattern = re.compile(r'https?://[^\s"\'<>\]\)\\]{8,}')
    all_urls = sorted(set(m.group(0) for s in all_strings for m in url_pattern.finditer(s)))
    print(f"    URLs found: {len(all_urls)}")

    with open(f'{output_dir}/urls.txt', 'w') as f:
        for url in all_urls:
            f.write(url + '\n')

    # Extract derivation paths (crypto-specific)
    deriv_pattern = re.compile(r"m/\d+['h]?/\d+['h]?(?:/\d+['h]?)*")
    deriv_paths = sorted(set(m.group(0) for s in all_strings for m in deriv_pattern.finditer(s)))
    if deriv_paths:
        print(f"\n[*] Derivation paths found: {len(deriv_paths)}")
        for p in deriv_paths:
            print(f"    {p}")

    # Extract encryption-related strings
    print("\n[*] Encryption/crypto references...")
    crypto_pattern = re.compile(r'(?:aes|chacha|xchacha|argon2|scrypt|pbkdf2|nacl|tweetnacl|ed25519|secp256k1|curve25519|sha256|sha512|ripemd160|keccak|blake2|bip32|bip39|bip44|slip10|slip39)[-_]?(?:256|128|gcm|cbc|ctr|poly1305|id)?', re.I)
    crypto_refs = sorted(set(m.group(0) for s in all_strings for m in crypto_pattern.finditer(s)))
    print(f"    Crypto references: {len(crypto_refs)}")
    for c in crypto_refs[:30]:
        print(f"    {c}")

    with open(f'{output_dir}/crypto_references.txt', 'w') as f:
        for c in crypto_refs:
            f.write(c + '\n')

    # ================================================================
    # SUMMARY REPORT
    # ================================================================
    print(f"\n{'='*70}")
    print(f"ANALYSIS COMPLETE — Results in {output_dir}/")
    print(f"{'='*70}")
    print("\nFiles generated:")
    for p in sorted(Path(output_dir).iterdir()):
        sz = p.stat().st_size
        print(f"  {p.name:<35} {sz:>10,} bytes")

    # Print critical findings
    critical_cats = ['api_keys', 'hex_keys', 'base64_secrets', 'jwt_tokens',
                     'private_keys', 'aws_access_key', 'firebase_api', 'google_api_key',
                     'sentry_dsn', 'debug_flags', 'internal_ips', 'localhost',
                     'payment_ids', 'sardine']

    print(f"\n{'='*70}")
    print("CRITICAL SECURITY FINDINGS")
    print(f"{'='*70}")
    for cat in critical_cats:
        if cat in categorized and categorized[cat]:
            print(f"\n  [{cat.upper()}] ({len(categorized[cat])} found):")
            for item in categorized[cat][:10]:
                # Truncate long values
                display = item if len(item) < 120 else item[:117] + '...'
                print(f"    → {display}")
            if len(categorized[cat]) > 10:
                print(f"    ... and {len(categorized[cat]) - 10} more (see security_findings.json)")

    return categorized


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    bundle = sys.argv[1] if len(sys.argv) > 1 else '/tmp/exodus_decompiled/resources/assets/index.android.bundle'
    output = sys.argv[2] if len(sys.argv) > 2 else '/tmp/exodus_analysis'

    if not Path(bundle).exists():
        print(f"Error: {bundle} not found")
        sys.exit(1)

    analyze_bundle(bundle, output)
