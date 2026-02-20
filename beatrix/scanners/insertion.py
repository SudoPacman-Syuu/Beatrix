"""
BEATRIX Insertion Point Detector

Identifies injection points in HTTP requests where payloads can be inserted.

This is the foundation for all injection testing (SQLi, XSS, SSTI, etc).

Based on Burp's insertion point concept:
- URL parameters
- Body parameters (form, JSON, XML)
- Headers
- Cookies
- Path segments
- File names

Reference: Burp's IScannerInsertionPoint interface
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from beatrix.core.types import InsertionPoint, InsertionPointType


class BodyFormat(Enum):
    """Detected body format"""
    NONE = auto()
    FORM_URLENCODED = auto()
    JSON = auto()
    XML = auto()
    MULTIPART = auto()
    RAW = auto()


@dataclass
class ParsedRequest:
    """Fully parsed HTTP request with all components"""
    method: str
    url: str
    path: str
    query_string: str
    headers: Dict[str, str]
    cookies: Dict[str, str]
    body: bytes
    body_format: BodyFormat

    # Parsed components
    url_params: Dict[str, str] = field(default_factory=dict)
    body_params: Dict[str, Any] = field(default_factory=dict)
    path_segments: List[str] = field(default_factory=list)
    json_paths: List[Tuple[str, Any]] = field(default_factory=list)


class InsertionPointDetector:
    """
    Detects and creates insertion points from HTTP requests.

    An insertion point represents a location where attack payloads
    can be inserted. Each insertion point knows how to:
    - Build a modified request with the payload
    - Identify what type of injection it's suitable for
    """

    # Headers that are generally safe/useful to test
    TESTABLE_HEADERS = [
        "user-agent",
        "referer",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-real-ip",
        "x-custom-ip-authorization",
        "x-originating-ip",
        "x-client-ip",
        "host",
        "origin",
        "accept-language",
    ]

    # Headers to never modify
    SKIP_HEADERS = [
        "content-length",
        "connection",
        "accept-encoding",
        "transfer-encoding",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.test_headers = self.config.get("test_headers", self.TESTABLE_HEADERS)

    def detect(self, request: ParsedRequest) -> List[InsertionPoint]:
        """
        Detect all insertion points in a request.

        Returns a list of InsertionPoint objects that can be used
        for injection testing.
        """
        points = []

        # 1. URL Parameters
        points.extend(self._detect_url_params(request))

        # 2. Body Parameters
        points.extend(self._detect_body_params(request))

        # 3. Headers
        points.extend(self._detect_headers(request))

        # 4. Cookies
        points.extend(self._detect_cookies(request))

        # 5. Path Segments
        points.extend(self._detect_path_segments(request))

        # 6. JSON Nested Values
        if request.body_format == BodyFormat.JSON:
            points.extend(self._detect_json_paths(request))

        return points

    def parse_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: bytes = b"",
    ) -> ParsedRequest:
        """
        Parse a raw HTTP request into components.
        """
        parsed_url = urlparse(url)

        # Parse query parameters
        url_params = {}
        if parsed_url.query:
            for k, v in parse_qs(parsed_url.query).items():
                url_params[k] = v[0] if v else ""

        # Parse cookies
        cookies = {}
        cookie_header = headers.get("cookie", headers.get("Cookie", ""))
        if cookie_header:
            for part in cookie_header.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    cookies[k] = v

        # Detect body format
        content_type = headers.get("content-type", headers.get("Content-Type", ""))
        body_format, body_params = self._parse_body(body, content_type)

        # Parse path segments
        path_segments = [s for s in parsed_url.path.split("/") if s]

        return ParsedRequest(
            method=method,
            url=url,
            path=parsed_url.path,
            query_string=parsed_url.query,
            headers=headers,
            cookies=cookies,
            body=body,
            body_format=body_format,
            url_params=url_params,
            body_params=body_params,
            path_segments=path_segments,
        )

    def _parse_body(
        self,
        body: bytes,
        content_type: str
    ) -> Tuple[BodyFormat, Dict[str, Any]]:
        """Parse request body based on content type"""

        if not body:
            return BodyFormat.NONE, {}

        ct_lower = content_type.lower()

        # JSON
        if "application/json" in ct_lower:
            try:
                data = json.loads(body.decode("utf-8"))
                return BodyFormat.JSON, data if isinstance(data, dict) else {"_root": data}
            except Exception:
                return BodyFormat.RAW, {}

        # Form URL encoded
        if "application/x-www-form-urlencoded" in ct_lower:
            params = {}
            for k, v in parse_qs(body.decode("utf-8")).items():
                params[k] = v[0] if v else ""
            return BodyFormat.FORM_URLENCODED, params

        # XML
        if "application/xml" in ct_lower or "text/xml" in ct_lower:
            return BodyFormat.XML, {"_raw": body.decode("utf-8", errors="ignore")}

        # Multipart
        if "multipart/form-data" in ct_lower:
            # TODO: Proper multipart parsing
            return BodyFormat.MULTIPART, {}

        return BodyFormat.RAW, {}

    def _detect_url_params(self, request: ParsedRequest) -> List[InsertionPoint]:
        """Detect insertion points in URL parameters"""
        points = []

        for name, value in request.url_params.items():
            points.append(InsertionPoint(
                name=name,
                value=value,
                type=InsertionPointType.URL_PARAM,
                original_request=None,  # Will be set by caller
                position=(0, 0),  # Will be calculated
            ))

        return points

    def _detect_body_params(self, request: ParsedRequest) -> List[InsertionPoint]:
        """Detect insertion points in body parameters"""
        points = []

        if request.body_format == BodyFormat.FORM_URLENCODED:
            for name, value in request.body_params.items():
                points.append(InsertionPoint(
                    name=name,
                    value=str(value),
                    type=InsertionPointType.BODY_PARAM,
                    original_request=None,
                    position=(0, 0),
                ))

        elif request.body_format == BodyFormat.JSON:
            # Flatten JSON for simple params
            for name, value in request.body_params.items():
                if isinstance(value, (str, int, float, bool)):
                    points.append(InsertionPoint(
                        name=name,
                        value=str(value),
                        type=InsertionPointType.BODY_PARAM,
                        original_request=None,
                        position=(0, 0),
                    ))

        return points

    def _detect_headers(self, request: ParsedRequest) -> List[InsertionPoint]:
        """Detect insertion points in headers"""
        points = []

        for name, value in request.headers.items():
            name_lower = name.lower()

            # Skip certain headers
            if name_lower in self.SKIP_HEADERS:
                continue

            # Only test configured headers
            if name_lower in self.test_headers:
                points.append(InsertionPoint(
                    name=name,
                    value=value,
                    type=InsertionPointType.HEADER,
                    original_request=None,
                    position=(0, 0),
                ))

        return points

    def _detect_cookies(self, request: ParsedRequest) -> List[InsertionPoint]:
        """Detect insertion points in cookies"""
        points = []

        for name, value in request.cookies.items():
            points.append(InsertionPoint(
                name=name,
                value=value,
                type=InsertionPointType.COOKIE,
                original_request=None,
                position=(0, 0),
            ))

        return points

    def _detect_path_segments(self, request: ParsedRequest) -> List[InsertionPoint]:
        """Detect insertion points in URL path segments"""
        points = []

        for i, segment in enumerate(request.path_segments):
            # Look for segments that might be IDs or values
            if self._looks_like_value(segment):
                points.append(InsertionPoint(
                    name=f"path[{i}]",
                    value=segment,
                    type=InsertionPointType.URL_PATH,
                    original_request=None,
                    position=(i, i),
                ))

        return points

    def _detect_json_paths(self, request: ParsedRequest) -> List[InsertionPoint]:
        """Detect insertion points in nested JSON"""
        points = []

        def walk_json(obj: Any, path: str = ""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    new_path = f"{path}.{k}" if path else k
                    walk_json(v, new_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    walk_json(item, f"{path}[{i}]")
            else:
                # Leaf value
                points.append(InsertionPoint(
                    name=path,
                    value=str(obj),
                    type=InsertionPointType.JSON_VALUE,
                    original_request=None,
                    position=(0, 0),
                ))

        walk_json(request.body_params)
        return points

    def _looks_like_value(self, segment: str) -> bool:
        """
        Heuristic to determine if a path segment looks like a value
        that should be tested (IDs, filenames, etc.)
        """
        # Numeric IDs
        if segment.isdigit():
            return True

        # UUIDs
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        if re.match(uuid_pattern, segment, re.IGNORECASE):
            return True

        # Hex strings (likely IDs)
        if re.match(r'^[0-9a-f]{8,}$', segment, re.IGNORECASE):
            return True

        # Has file extension
        if "." in segment and len(segment.split(".")[-1]) <= 4:
            return True

        # Base64-ish
        if re.match(r'^[A-Za-z0-9+/=]{10,}$', segment):
            return True

        return False

    # =========================================================================
    # REQUEST BUILDING
    # =========================================================================

    def build_request_with_payload(
        self,
        request: ParsedRequest,
        insertion_point: InsertionPoint,
        payload: str,
    ) -> Tuple[str, Dict[str, str], bytes]:
        """
        Build a modified request with the payload inserted.

        Returns (url, headers, body) tuple.
        """
        url = request.url
        headers = dict(request.headers)
        body = request.body

        if insertion_point.type == InsertionPointType.URL_PARAM:
            url = self._inject_url_param(request, insertion_point.name, payload)

        elif insertion_point.type == InsertionPointType.BODY_PARAM:
            body = self._inject_body_param(request, insertion_point.name, payload)

        elif insertion_point.type == InsertionPointType.HEADER:
            headers[insertion_point.name] = payload

        elif insertion_point.type == InsertionPointType.COOKIE:
            headers["Cookie"] = self._inject_cookie(request, insertion_point.name, payload)

        elif insertion_point.type == InsertionPointType.URL_PATH:
            url = self._inject_path_segment(request, insertion_point.position[0], payload)

        elif insertion_point.type == InsertionPointType.JSON_VALUE:
            body = self._inject_json_value(request, insertion_point.name, payload)

        return url, headers, body

    def _inject_url_param(self, request: ParsedRequest, name: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(request.url)
        params = dict(request.url_params)
        params[name] = payload
        new_query = urlencode(params)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))

    def _inject_body_param(self, request: ParsedRequest, name: str, payload: str) -> bytes:
        """Inject payload into body parameter"""
        if request.body_format == BodyFormat.FORM_URLENCODED:
            params = dict(request.body_params)
            params[name] = payload
            return urlencode(params).encode()

        elif request.body_format == BodyFormat.JSON:
            data = dict(request.body_params)
            data[name] = payload
            return json.dumps(data).encode()

        return request.body

    def _inject_cookie(self, request: ParsedRequest, name: str, payload: str) -> str:
        """Inject payload into cookie"""
        cookies = dict(request.cookies)
        cookies[name] = payload
        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    def _inject_path_segment(self, request: ParsedRequest, index: int, payload: str) -> str:
        """Inject payload into path segment"""
        parsed = urlparse(request.url)
        segments = list(request.path_segments)
        if 0 <= index < len(segments):
            segments[index] = payload
        new_path = "/" + "/".join(segments)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            new_path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        ))

    def _inject_json_value(self, request: ParsedRequest, path: str, payload: str) -> bytes:
        """Inject payload into nested JSON path"""
        data = json.loads(request.body.decode())

        # Navigate to the path and set value
        parts = re.split(r'\.|\[|\]', path)
        parts = [p for p in parts if p]

        obj = data
        for i, part in enumerate(parts[:-1]):
            if part.isdigit():
                obj = obj[int(part)]
            else:
                obj = obj[part]

        final_key = parts[-1]
        if final_key.isdigit():
            obj[int(final_key)] = payload
        else:
            obj[final_key] = payload

        return json.dumps(data).encode()
