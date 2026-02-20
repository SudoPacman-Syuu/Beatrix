"""
BEATRIX Response Analyzer

Ported from Burp Suite's ResponseVariationsAnalyzer + ResponseKeywordsAnalyzer.

Compares HTTP responses to detect subtle differences that indicate
blind injection, access control bypasses, or behavioral changes.

Uses 30 attribute types extracted from Burp's Montoya API AttributeType enum.
"""

import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set


class AttributeType(Enum):
    """
    Response attributes to compare (from Burp's Montoya API).

    Each attribute captures a different dimension of the response,
    enabling detection of subtle behavioral differences.
    """
    STATUS_CODE = auto()
    CONTENT_LENGTH = auto()
    CONTENT_TYPE = auto()
    ETAG_HEADER = auto()
    LAST_MODIFIED_HEADER = auto()
    CONTENT_LOCATION = auto()
    LOCATION = auto()
    COOKIE_NAMES = auto()
    TAG_NAMES = auto()
    TAG_IDS = auto()
    DIV_IDS = auto()
    BODY_CONTENT = auto()
    LIMITED_BODY_CONTENT = auto()
    VISIBLE_TEXT = auto()
    WORD_COUNT = auto()
    VISIBLE_WORD_COUNT = auto()
    LINE_COUNT = auto()
    COMMENTS = auto()
    INITIAL_CONTENT = auto()
    CANONICAL_LINK = auto()
    PAGE_TITLE = auto()
    FIRST_HEADER_TAG = auto()
    HEADER_TAGS = auto()
    ANCHOR_LABELS = auto()
    INPUT_SUBMIT_LABELS = auto()
    BUTTON_SUBMIT_LABELS = auto()
    INPUT_IMAGE_LABELS = auto()
    CSS_CLASSES = auto()
    NON_HIDDEN_FORM_INPUT_TYPES = auto()
    OUTBOUND_EDGE_COUNT = auto()


@dataclass
class ResponseFingerprint:
    """Fingerprint of a single HTTP response across all attribute dimensions."""
    attributes: Dict[AttributeType, Any] = field(default_factory=dict)
    raw_status: int = 0
    raw_length: int = 0
    body_hash: str = ""


class _HTMLAttributeParser(HTMLParser):
    """Lightweight HTML parser that extracts attribute values for fingerprinting."""

    def __init__(self):
        super().__init__()
        self.tag_names: Set[str] = set()
        self.tag_ids: Set[str] = set()
        self.div_ids: Set[str] = set()
        self.css_classes: Set[str] = set()
        self.anchor_labels: List[str] = []
        self.header_tags: List[str] = []
        self.first_header_tag: Optional[str] = None
        self.input_submit_labels: List[str] = []
        self.button_submit_labels: List[str] = []
        self.input_image_labels: List[str] = []
        self.non_hidden_input_types: Set[str] = set()
        self.title: str = ""
        self.canonical_link: str = ""
        self.comments: List[str] = []
        self.visible_text_parts: List[str] = []
        self.outbound_edges: int = 0

        self._in_title = False
        self._in_a = False
        self._in_button_submit = False
        self._current_a_text = ""
        self._current_button_text = ""
        self._skip_content = False

    # -- parser callbacks --------------------------------------------------

    def handle_starttag(self, tag: str, attrs):
        tag_lower = tag.lower()
        self.tag_names.add(tag_lower)
        attr_dict = {k.lower(): v for k, v in attrs if k}

        tag_id = attr_dict.get("id", "")
        if tag_id:
            self.tag_ids.add(tag_id)
            if tag_lower == "div":
                self.div_ids.add(tag_id)

        for cls in (attr_dict.get("class") or "").split():
            if cls:
                self.css_classes.add(cls)

        if tag_lower == "title":
            self._in_title = True
        elif tag_lower in ("script", "style"):
            self._skip_content = True
        elif tag_lower == "a":
            self._in_a = True
            self._current_a_text = ""
            href = attr_dict.get("href", "")
            if href and href.startswith("http"):
                self.outbound_edges += 1
        elif tag_lower == "link" and attr_dict.get("rel") == "canonical":
            self.canonical_link = attr_dict.get("href") or ""
        elif tag_lower in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self.header_tags.append(tag_lower)
            if self.first_header_tag is None:
                self.first_header_tag = tag_lower
        elif tag_lower == "input":
            itype = (attr_dict.get("type") or "text").lower()
            if itype == "submit":
                label = attr_dict.get("value", "")
                if label:
                    self.input_submit_labels.append(label)
            elif itype == "image":
                label = attr_dict.get("alt", "") or attr_dict.get("value", "")
                if label:
                    self.input_image_labels.append(label)
            if itype != "hidden":
                self.non_hidden_input_types.add(itype)
        elif tag_lower == "button":
            btn_type = (attr_dict.get("type") or "").lower()
            if btn_type == "submit" or not btn_type:
                self._in_button_submit = True
                self._current_button_text = ""

    def handle_endtag(self, tag: str):
        tag_lower = tag.lower()
        if tag_lower == "title":
            self._in_title = False
        elif tag_lower in ("script", "style"):
            self._skip_content = False
        elif tag_lower == "a":
            self._in_a = False
            label = self._current_a_text.strip()
            if label:
                self.anchor_labels.append(label)
        elif tag_lower == "button":
            if self._in_button_submit:
                label = self._current_button_text.strip()
                if label:
                    self.button_submit_labels.append(label)
            self._in_button_submit = False

    def handle_data(self, data: str):
        if self._in_title:
            self.title += data
        if self._in_a:
            self._current_a_text += data
        if self._in_button_submit:
            self._current_button_text += data
        if not self._skip_content:
            stripped = data.strip()
            if stripped:
                self.visible_text_parts.append(stripped)

    def handle_comment(self, data: str):
        self.comments.append(data.strip())


def _extract_attributes(
    status_code: int,
    headers: Dict[str, str],
    body: str,
) -> ResponseFingerprint:
    """
    Extract all 30 Burp-style attribute dimensions from a response.
    """
    attrs: Dict[AttributeType, Any] = {}
    h = {k.lower(): v for k, v in headers.items()}

    # Direct header attributes
    attrs[AttributeType.STATUS_CODE] = status_code
    attrs[AttributeType.CONTENT_LENGTH] = len(body)
    attrs[AttributeType.CONTENT_TYPE] = h.get("content-type", "")
    attrs[AttributeType.ETAG_HEADER] = h.get("etag", "")
    attrs[AttributeType.LAST_MODIFIED_HEADER] = h.get("last-modified", "")
    attrs[AttributeType.CONTENT_LOCATION] = h.get("content-location", "")
    attrs[AttributeType.LOCATION] = h.get("location", "")

    # Cookie names from Set-Cookie headers
    cookie_names: Set[str] = set()
    for key, val in headers.items():
        if key.lower() == "set-cookie":
            name = val.split("=", 1)[0].strip()
            if name:
                cookie_names.add(name)
    attrs[AttributeType.COOKIE_NAMES] = frozenset(cookie_names)

    # Body-level attributes
    attrs[AttributeType.BODY_CONTENT] = hashlib.md5(body.encode(errors="replace")).hexdigest()
    attrs[AttributeType.LIMITED_BODY_CONTENT] = hashlib.md5(body[:512].encode(errors="replace")).hexdigest()
    attrs[AttributeType.LINE_COUNT] = body.count("\n") + 1
    words = body.split()
    attrs[AttributeType.WORD_COUNT] = len(words)
    attrs[AttributeType.INITIAL_CONTENT] = body[:256]

    # HTML parsing
    parser = _HTMLAttributeParser()
    try:
        parser.feed(body)
    except Exception:
        pass

    attrs[AttributeType.TAG_NAMES] = frozenset(parser.tag_names)
    attrs[AttributeType.TAG_IDS] = frozenset(parser.tag_ids)
    attrs[AttributeType.DIV_IDS] = frozenset(parser.div_ids)
    attrs[AttributeType.CSS_CLASSES] = frozenset(parser.css_classes)
    attrs[AttributeType.PAGE_TITLE] = parser.title.strip()
    attrs[AttributeType.CANONICAL_LINK] = parser.canonical_link
    attrs[AttributeType.FIRST_HEADER_TAG] = parser.first_header_tag or ""
    attrs[AttributeType.HEADER_TAGS] = tuple(parser.header_tags)
    attrs[AttributeType.ANCHOR_LABELS] = tuple(parser.anchor_labels[:50])
    attrs[AttributeType.INPUT_SUBMIT_LABELS] = tuple(parser.input_submit_labels)
    attrs[AttributeType.BUTTON_SUBMIT_LABELS] = tuple(parser.button_submit_labels)
    attrs[AttributeType.INPUT_IMAGE_LABELS] = tuple(parser.input_image_labels)
    attrs[AttributeType.NON_HIDDEN_FORM_INPUT_TYPES] = frozenset(parser.non_hidden_input_types)
    attrs[AttributeType.COMMENTS] = tuple(parser.comments[:20])
    visible = " ".join(parser.visible_text_parts)
    attrs[AttributeType.VISIBLE_TEXT] = hashlib.md5(visible.encode(errors="replace")).hexdigest()
    attrs[AttributeType.VISIBLE_WORD_COUNT] = len(visible.split())
    attrs[AttributeType.OUTBOUND_EDGE_COUNT] = parser.outbound_edges

    return ResponseFingerprint(
        attributes=attrs,
        raw_status=status_code,
        raw_length=len(body),
        body_hash=attrs[AttributeType.BODY_CONTENT],
    )


class ResponseVariationsAnalyzer:
    """
    Tracks which response attributes vary and which stay constant
    across multiple responses.

    Usage (mirrors Burp's interface):
        analyzer = ResponseVariationsAnalyzer()
        analyzer.update(200, headers1, body1)
        analyzer.update(200, headers2, body2)

        varying   = analyzer.variant_attributes()
        stable    = analyzer.invariant_attributes()
    """

    def __init__(self):
        self._fingerprints: List[ResponseFingerprint] = []
        self._variant: Set[AttributeType] = set()
        self._invariant: Set[AttributeType] = set()
        self._first_values: Dict[AttributeType, Any] = {}
        self._frozen = False

    def update(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
    ) -> ResponseFingerprint:
        """Feed a new response; returns its fingerprint."""
        fp = _extract_attributes(status_code, headers, body)
        self._fingerprints.append(fp)

        if len(self._fingerprints) == 1:
            self._first_values = dict(fp.attributes)
            self._invariant = set(AttributeType)
        else:
            newly_variant: Set[AttributeType] = set()
            for attr in self._invariant:
                if fp.attributes.get(attr) != self._first_values.get(attr):
                    newly_variant.add(attr)
            self._invariant -= newly_variant
            self._variant |= newly_variant

        return fp

    def variant_attributes(self) -> Set[AttributeType]:
        """Attributes that changed across observed responses."""
        return set(self._variant)

    def invariant_attributes(self) -> Set[AttributeType]:
        """Attributes that stayed the same across all observed responses."""
        return set(self._invariant)

    @property
    def sample_count(self) -> int:
        return len(self._fingerprints)


class ResponseKeywordsAnalyzer:
    """
    Tracks which keywords appear/disappear across responses.

    Usage:
        analyzer = ResponseKeywordsAnalyzer(["error", "success", "denied"])
        analyzer.update(body1)
        analyzer.update(body2)
        varying   = analyzer.variant_keywords()
        stable    = analyzer.invariant_keywords()
    """

    def __init__(self, keywords: List[str]):
        self._keywords = keywords
        self._first_hits: Optional[Set[str]] = None
        self._variant: Set[str] = set()
        self._invariant: Set[str] = set()
        self._count = 0

    def update(self, body: str) -> Dict[str, int]:
        """Feed a response body; returns keyword counts."""
        body_lower = body.lower()
        counts: Dict[str, int] = {}
        present: Set[str] = set()
        for kw in self._keywords:
            c = body_lower.count(kw.lower())
            counts[kw] = c
            if c > 0:
                present.add(kw)

        self._count += 1
        if self._first_hits is None:
            self._first_hits = present
            self._invariant = set(self._keywords)
        else:
            newly_variant: Set[str] = set()
            for kw in self._invariant:
                was_present = kw in self._first_hits
                is_present = kw in present
                if was_present != is_present:
                    newly_variant.add(kw)
            self._invariant -= newly_variant
            self._variant |= newly_variant

        return counts

    def variant_keywords(self) -> Set[str]:
        return set(self._variant)

    def invariant_keywords(self) -> Set[str]:
        return set(self._invariant)


# =============================================================================
# HIGH-LEVEL COMPARISON HELPERS
# =============================================================================

def responses_differ(
    baseline_status: int,
    baseline_headers: Dict[str, str],
    baseline_body: str,
    test_status: int,
    test_headers: Dict[str, str],
    test_body: str,
    *,
    ignore_attrs: Optional[Set[AttributeType]] = None,
) -> Dict[AttributeType, tuple]:
    """
    Compare two responses and return which attributes differ.

    Returns dict of {AttributeType: (baseline_value, test_value)} for diffs.
    Useful for blind injection detection, access control testing, etc.
    """
    ignore = ignore_attrs or set()
    fp1 = _extract_attributes(baseline_status, baseline_headers, baseline_body)
    fp2 = _extract_attributes(test_status, test_headers, test_body)

    diffs: Dict[AttributeType, tuple] = {}
    for attr in AttributeType:
        if attr in ignore:
            continue
        v1 = fp1.attributes.get(attr)
        v2 = fp2.attributes.get(attr)
        if v1 != v2:
            diffs[attr] = (v1, v2)
    return diffs


def is_blind_indicator(
    diffs: Dict[AttributeType, tuple],
    *,
    min_attrs: int = 2,
) -> bool:
    """
    Heuristic: do the response differences suggest a blind injection worked?

    Ignores noisy attributes (content-length, word count alone).
    Requires at least `min_attrs` meaningful attributes to differ.
    """
    NOISY = {
        AttributeType.CONTENT_LENGTH,
        AttributeType.WORD_COUNT,
        AttributeType.LINE_COUNT,
        AttributeType.ETAG_HEADER,
        AttributeType.LAST_MODIFIED_HEADER,
    }
    meaningful = {k for k in diffs if k not in NOISY}
    return len(meaningful) >= min_attrs
