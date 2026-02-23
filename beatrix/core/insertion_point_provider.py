"""
BEATRIX Insertion Point Provider

Ported from Sweet Scanner's AuditInsertionPointProvider + AuditInsertionPointType.

Systematically extracts every injectable location from an HTTP request:
URL params, body params, cookies, headers, JSON values, XML values,
path segments, multipart fields, and entire-body replacement.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from beatrix.core.types import InsertionPoint, InsertionPointType


@dataclass
class RichInsertionPoint(InsertionPoint):
    """
    Extended insertion point with request-rebuilding capability.

    Given a payload, can reconstruct the full modified request.
    Mirrors Sweet Scanner's buildHttpRequestWithPayload().
    """
    # Context for rebuilding
    _method: str = "GET"
    _url: str = ""
    _headers: Dict[str, str] = field(default_factory=dict)
    _body: str = ""
    _cookies: Dict[str, str] = field(default_factory=dict)
    _param_key: str = ""  # For params: which key
    _json_path: str = ""  # For JSON: dot-notation path

    def build_request_with_payload(self, payload: str) -> Dict[str, Any]:
        """
        Reconstruct the full HTTP request with the payload injected
        at this insertion point.

        Returns dict with method, url, headers, body, cookies.
        """
        method = self._method
        url = self._url
        headers = dict(self._headers)
        body = self._body
        cookies = dict(self._cookies)

        if self.type == InsertionPointType.URL_PARAM:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[self._param_key] = [payload]
            new_query = urlencode(params, doseq=True)
            url = urlunparse(parsed._replace(query=new_query))

        elif self.type == InsertionPointType.BODY_PARAM:
            params = parse_qs(body, keep_blank_values=True)
            params[self._param_key] = [payload]
            body = urlencode(params, doseq=True)

        elif self.type == InsertionPointType.COOKIE:
            cookies[self._param_key] = payload

        elif self.type == InsertionPointType.HEADER:
            headers[self._param_key] = payload

        elif self.type == InsertionPointType.JSON_VALUE:
            try:
                data = json.loads(body)
                _set_json_path(data, self._json_path, payload)
                body = json.dumps(data)
            except (json.JSONDecodeError, KeyError):
                pass

        elif self.type == InsertionPointType.URL_PATH:
            parsed = urlparse(url)
            segments = parsed.path.split("/")
            idx = int(self._param_key) if self._param_key.isdigit() else -1
            if 0 <= idx < len(segments):
                segments[idx] = payload
            url = urlunparse(parsed._replace(path="/".join(segments)))

        elif self.type == InsertionPointType.URL_PATH_FOLDER:
            parsed = urlparse(url)
            segments = parsed.path.rstrip("/").split("/")
            idx = int(self._param_key) if self._param_key.isdigit() else -1
            if 0 <= idx < len(segments):
                segments[idx] = payload
            url = urlunparse(parsed._replace(path="/".join(segments)))

        elif self.type == InsertionPointType.ENTIRE_BODY:
            body = payload

        elif self.type == InsertionPointType.XML_VALUE:
            # Simple regex replacement for the named element
            pattern = re.compile(
                rf"(<{re.escape(self._param_key)}[^>]*>)(.*?)(</{re.escape(self._param_key)}>)",
                re.DOTALL,
            )
            body = pattern.sub(rf"\g<1>{payload}\g<3>", body, count=1)

        elif self.type == InsertionPointType.MULTIPART:
            # Replace value in the named multipart field
            pattern = re.compile(
                rf'(name="{re.escape(self._param_key)}"[^\r\n]*\r?\n\r?\n)(.*?)(\r?\n--)',
                re.DOTALL,
            )
            body = pattern.sub(rf"\g<1>{payload}\g<3>", body, count=1)

        return {
            "method": method,
            "url": url,
            "headers": headers,
            "body": body,
            "cookies": cookies,
        }


def _set_json_path(obj: Any, path: str, value: Any):
    """Set a value in a nested dict/list via dot-notation path."""
    keys = path.split(".")
    for key in keys[:-1]:
        if isinstance(obj, list) and key.isdigit():
            obj = obj[int(key)]
        elif isinstance(obj, dict):
            obj = obj[key]
        else:
            return
    last = keys[-1]
    if isinstance(obj, list) and last.isdigit():
        obj[int(last)] = value
    elif isinstance(obj, dict):
        obj[last] = value


def _walk_json(obj: Any, prefix: str = "") -> List[Tuple[str, str]]:
    """Walk a JSON object and return (dotpath, value) pairs for all leaves."""
    results: List[Tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                results.extend(_walk_json(v, p))
            else:
                results.append((p, str(v) if v is not None else ""))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            p = f"{prefix}.{i}" if prefix else str(i)
            if isinstance(v, (dict, list)):
                results.extend(_walk_json(v, p))
            else:
                results.append((p, str(v) if v is not None else ""))
    return results


def _parse_xml_params(body: str) -> List[Tuple[str, str]]:
    """Extract element-name/value pairs from XML body (simple regex)."""
    results: List[Tuple[str, str]] = []
    for m in re.finditer(r"<(\w+)([^>]*)>(.*?)</\1>", body, re.DOTALL):
        tag, _, value = m.groups()
        if not re.search(r"<\w+", value):  # leaf element
            results.append((tag, value.strip()))
    return results


def extract_insertion_points(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: str = "",
    cookies: Dict[str, str] | None = None,
) -> List[RichInsertionPoint]:
    """
    Extract ALL insertion points from an HTTP request.

    Mirrors Sweet Scanner's provideInsertionPoints().

    Returns a list of RichInsertionPoint objects, each capable of
    rebuilding the full request with a payload injected.
    """
    cookies = cookies or {}
    points: List[RichInsertionPoint] = []

    def _pt(
        name: str, value: str,
        type: InsertionPointType,
        _param_key: str,
        _json_path: str = "",
    ) -> RichInsertionPoint:
        return RichInsertionPoint(
            name=name, value=value, type=type,
            _method=method, _url=url, _headers=headers,
            _body=body, _cookies=cookies,
            _param_key=_param_key, _json_path=_json_path,
        )

    # 1. URL query parameters
    parsed = urlparse(url)
    if parsed.query:
        for key, vals in parse_qs(parsed.query, keep_blank_values=True).items():
            val = vals[0] if vals else ""
            points.append(_pt(
                name=key, value=val,
                type=InsertionPointType.URL_PARAM,
                _param_key=key,
            ))

    # 2. URL path segments (non-empty, skip first empty)
    segments = parsed.path.split("/")
    for i, seg in enumerate(segments):
        if not seg:
            continue
        # Filename-like segments
        if "." in seg or i == len(segments) - 1:
            points.append(_pt(
                name=f"path_segment_{i}", value=seg,
                type=InsertionPointType.URL_PATH,
                _param_key=str(i),
            ))
        else:
            points.append(_pt(
                name=f"path_folder_{i}", value=seg,
                type=InsertionPointType.URL_PATH_FOLDER,
                _param_key=str(i),
            ))

    # 3. Cookies
    for key, val in cookies.items():
        points.append(_pt(
            name=key, value=val,
            type=InsertionPointType.COOKIE,
            _param_key=key,
        ))

    # 4. Interesting headers (don't inject into all headers blindly)
    INJECTABLE_HEADERS = {
        "x-forwarded-for", "x-real-ip", "x-forwarded-host",
        "x-original-url", "x-rewrite-url", "referer", "origin",
        "x-custom-ip-authorization", "x-originating-ip",
        "x-remote-ip", "x-client-ip", "x-host",
        "true-client-ip", "cluster-client-ip",
        "x-forwarded-port", "x-forwarded-scheme",
        "accept-language", "user-agent",
    }
    for key, val in headers.items():
        if key.lower() in INJECTABLE_HEADERS:
            points.append(_pt(
                name=key, value=val,
                type=InsertionPointType.HEADER,
                _param_key=key,
            ))

    # 5. Body parameters (based on content type)
    content_type = headers.get("Content-Type", headers.get("content-type", "")).lower()

    if "application/x-www-form-urlencoded" in content_type and body:
        for key, vals in parse_qs(body, keep_blank_values=True).items():
            val = vals[0] if vals else ""
            points.append(_pt(
                name=key, value=val,
                type=InsertionPointType.BODY_PARAM,
                _param_key=key,
            ))

    elif "application/json" in content_type and body:
        try:
            data = json.loads(body)
            for path, val in _walk_json(data):
                points.append(_pt(
                    name=path, value=val,
                    type=InsertionPointType.JSON_VALUE,
                    _param_key=path, _json_path=path,
                ))
        except json.JSONDecodeError:
            pass

    elif ("text/xml" in content_type or "application/xml" in content_type) and body:
        for tag, val in _parse_xml_params(body):
            points.append(_pt(
                name=tag, value=val,
                type=InsertionPointType.XML_VALUE,
                _param_key=tag,
            ))

    elif "multipart/form-data" in content_type and body:
        for m in re.finditer(
            r'name="([^"]+)"[^\r\n]*\r?\n\r?\n(.*?)(?=\r?\n--)',
            body, re.DOTALL,
        ):
            key, val = m.groups()
            points.append(_pt(
                name=key, value=val.strip(),
                type=InsertionPointType.MULTIPART,
                _param_key=key,
            ))

    # 6. Entire body (always available for POST/PUT/PATCH)
    if method.upper() in ("POST", "PUT", "PATCH") and body:
        points.append(_pt(
            name="entire_body", value=body[:100],
            type=InsertionPointType.ENTIRE_BODY,
            _param_key="",
        ))

    return points
