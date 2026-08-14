"""
Beatrix Suite — the central dashboard (`beatrix-suite`).

One local server, one port, one browser tab. A Burp-Suite-style top tab bar
switches between tools *inside the page* (client-side show/hide) instead of the
old "one server + one port + one new tab per tool" pattern.

Layout:
  * Left rail  — Projects: numbered workspaces the user switches between (each
                 sections off its own scan data / scope). "+" creates a project;
                 right-click a project -> Delete.
  * Top tabs   — Tools within the active project:
      - Auth   — the existing auth GUI, rendered inline in a same-origin
                 ``<iframe>`` (its ``/api/*`` calls are mounted on this server).
      - Ghost  — a target/objective form that launches a GHOST v2 investigation
                 in a background thread and streams its events inline.

Everything is stdlib ``http.server`` — no web-framework dependency, same toolkit
as the two GUIs it unifies. Only one ``webbrowser.open`` ever fires, at launch.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import itertools
import json
import os
import re
import shutil
import socket
import ssl
import threading
import time
import webbrowser
import zlib
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, parse_qsl, urlparse

# Reuse the auth GUI wholesale: its self-contained page + the exact backend
# functions the standalone `beatrix auth gui` uses, so saved data is identical.
from beatrix.cli.auth_gui import (
    _PAGE as _AUTH_PAGE,
    _build_and_save,
    _clear_auth,
    _get_model_settings,
    _list_auth,
    _list_keys,
    _list_openrouter_models,
    _save_keys,
    _save_model_settings,
)
# Reuse the ghost dashboard's thread-safe event ring buffer.
from beatrix.cli.ghost_web import _Broker

DEFAULT_PORT = 8790
DEFAULT_STATE_DIR = Path.home() / ".beatrix" / "suite"

# Auth route -> backend fn, mirroring auth_gui._Handler exactly.
_AUTH_GET = {
    "/api/list": _list_auth,
    "/api/keys": _list_keys,
    "/api/model": _get_model_settings,
    "/api/models": _list_openrouter_models,
}
_AUTH_POST = {
    "/api/save": _build_and_save,
    "/api/clear": _clear_auth,
    "/api/keys": _save_keys,
    "/api/model": _save_model_settings,
}


# ── Hunt module/preset catalog ───────────────────────────────────────────────
# Plain-language descriptions for the control panel's hover tooltips. Reuses
# the CLI's own MODULE_REFERENCE (same table `beatrix arsenal` prints) so
# descriptions never drift; a few modules that exist on BeatrixEngine but
# predate/postdate that table get a short fallback description here instead.
_MODULE_FALLBACK_DESC = {
    "param_miner": {
        "name": "Param Miner", "category": "Reconnaissance",
        "description": "Finds hidden, unlinked request parameters by diffing responses "
                        "against a large wordlist — surfaces debug flags, cache keys, "
                        "and undocumented API parameters.",
    },
    "sequencer": {
        "name": "Token Sequencer", "category": "A07: Authentication Failures",
        "description": "Statistically analyzes session tokens, password-reset codes, and "
                        "CSRF tokens for low entropy or predictable patterns.",
    },
    "backslash": {
        "name": "Backslash-Powered Scanner", "category": "A03: Injection",
        "description": "Probes how each parameter's input is actually processed before "
                        "attacking it — cuts false positives versus blindly spraying payloads.",
    },
    "dom_xss": {
        "name": "DOM XSS Scanner", "category": "A03: Injection",
        "description": "Drives a real browser (Playwright) to find client-side / "
                        "DOM-based XSS that a payload sent straight to the server would never trigger.",
    },
}

_catalog_cache: Dict[str, Any] = {}


def _build_hunt_catalog() -> Dict[str, Any]:
    """Build the module + preset catalog once, from the real engine.

    Modules are restricted to whatever ``BeatrixEngine`` actually loaded, so
    the panel can never offer a module that doesn't exist or isn't installed
    (e.g. ``dom_xss`` when Playwright is missing), and each is enriched with
    the plain-language description used for the control panel's hover tooltips.
    """
    if _catalog_cache:
        return _catalog_cache

    from beatrix.cli.main import MODULE_REFERENCE
    from beatrix.core.engine import BeatrixEngine

    engine = BeatrixEngine()
    modules = []
    for key in sorted(engine.modules):
        info = MODULE_REFERENCE.get(key) or _MODULE_FALLBACK_DESC.get(key) or {
            "name": key.replace("_", " ").title(), "category": "Other",
            "description": "No description available yet.",
        }
        modules.append({"key": key, "name": info["name"],
                        "category": info["category"], "description": info["description"]})
    # Sort by category (then name) so same-category modules are adjacent —
    # the control panel groups consecutive same-category entries under one
    # header, so alphabetical-by-key order would print a near-duplicate
    # header per module instead of grouping them.
    modules.sort(key=lambda m: (m["category"], m["name"]))

    presets = []
    for key, cfg in BeatrixEngine.PRESETS.items():
        preset_modules = cfg["modules"] or sorted(engine.modules)  # [] means "all modules"
        presets.append({
            "key": key, "name": cfg["name"], "description": cfg["description"],
            "modules": [m for m in preset_modules if m in engine.modules],
        })

    _catalog_cache["modules"] = modules
    _catalog_cache["presets"] = presets
    return _catalog_cache


def _hunt_event_to_line(event: str, data: dict) -> Optional[Dict[str, str]]:
    """Convert one kill-chain progress event into a terminal line for the Hunt
    broker. Mirrors the CLI hunt command's own event renderer (``main.py``'s
    ``_on_event``) so the browser terminal reads like the real CLI output —
    just without Rich markup, since the frontend colors lines by ``type``
    instead (same pattern as the Ghost pane's event tags).
    """
    if event == "phase_start":
        return {"type": "phase",
                "text": f"{data.get('phase', '')} — {data.get('description', '')}"}
    if event == "phase_done":
        dur = data.get("duration", 0)
        n = data.get("findings", 0)
        return {"type": "phase_done",
                "text": f"✓ {data.get('phase', '')} complete — {n} finding{'s' if n != 1 else ''} ({dur:.1f}s)"}
    if event == "crawl_start":
        return {"type": "info", "text": "Crawling target..."}
    if event == "crawl_done":
        return {"type": "info", "text": (
            f"Crawl complete — {data.get('pages', 0)} pages, {data.get('urls', 0)} URLs, "
            f"{data.get('params_urls', 0)} with params, {data.get('js_files', 0)} JS files"
        )}
    if event == "crawl_error":
        return {"type": "scanner_error", "text": f"✗ Crawl error: {data.get('error', '')}"}
    if event == "scanner_start":
        return {"type": "scanner_start", "text": f"▸ {data.get('scanner', '')} → {data.get('target', '')}"}
    if event == "scanner_done":
        # Quiet on zero-finding completions (33 modules × "done, 0 findings"
        # would drown the transcript) — matches the CLI's own verbosity choice.
        n = data.get("findings", 0)
        if n > 0:
            return {"type": "scanner_done",
                    "text": f"{data.get('scanner', '')} found {n} issue{'s' if n != 1 else ''}"}
        return None
    if event == "scanner_error":
        return {"type": "scanner_error", "text": f"✗ {data.get('scanner', '')}: {data.get('error', '')}"}
    if event == "finding":
        f = data.get("finding")
        if not f:
            return None
        sev = getattr(getattr(f, "severity", None), "value", "info")
        title = getattr(f, "title", "Finding")
        parts = []
        if getattr(f, "url", None):
            parts.append(f"URL: {f.url}")
        if getattr(f, "parameter", None):
            parts.append(f"Param: {f.parameter}")
        evidence = getattr(f, "evidence", None)
        if evidence:
            parts.append(f"Evidence: {str(evidence)[:500]}")
        return {"type": "finding", "text": f"[{sev.upper()}] {title}", "detail": "\n".join(parts)}
    if event == "info":
        return {"type": "info", "text": f"ℹ {data.get('message', '')}"}
    return None


# ── Scope parsing/matching (Burp-style target scope) ─────────────────────────
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _parse_scope_entry(raw: str) -> Optional[str]:
    """Normalize one pasted scope line to a bare hostname/IP.

    Accepts a full URL (``https://example.com/path``), a bare domain
    (``example.com``), an already-wildcarded pattern (``*.example.com``), or a
    bare IP — with or without a trailing path/port. Returns ``None`` for
    blank/unparseable input.
    """
    raw = raw.strip()
    if not raw:
        return None
    if "://" in raw:
        host = urlparse(raw).hostname
        return host.lower() if host else None
    host = raw.split("/", 1)[0].split(":", 1)[0].strip()
    return host.lower() or None


def _is_ip_literal(host: str) -> bool:
    return bool(_IPV4_RE.match(host)) or ":" in host  # crude-but-sufficient IPv6 check


def _expand_for_crawler(hosts: List[str]) -> List[str]:
    """Turn plain hostnames into crawler-compatible scope patterns.

    ``TargetCrawler._hostname_in_scope`` only treats a pattern as covering
    subdomains when it's explicitly written ``*.host`` — a bare ``host`` is an
    exact match only there. ghost2's ``Scope.in_scope`` (used for the findings
    backstop and Ghost's tool gating below) already treats every allowed host
    as covering its own subdomains, so this expansion is crawler-specific.
    """
    patterns: List[str] = []
    for h in hosts:
        if h.startswith("*."):
            patterns.append(h)
            continue
        patterns.append(h)
        if not _is_ip_literal(h):
            patterns.append(f"*.{h}")
    return patterns


def _host_in_scope(url_or_host: str, hosts: List[str]) -> bool:
    """True if ``url_or_host`` matches one of ``hosts`` (or its subdomains).

    Delegates to ghost2's own ``Scope.in_scope`` so matching semantics are
    identical everywhere in the suite — the findings backstop filter here and
    the tool-level gating in ghost2's http_tools/scanner_tool/external_tool —
    instead of a second, possibly-drifting implementation.
    """
    from beatrix.ai.ghost2.core.session import Scope
    return Scope(target="", allowed_hosts=hosts).in_scope(url_or_host)


def _shutdown_loop(loop) -> None:
    """Cancel any tasks still pending on ``loop`` and close it.

    Mirrors what ``asyncio.run`` does on the way out. Needed because a
    stoppable run manages its own loop (instead of using ``asyncio.run``)
    so its task can be cancelled from another thread via
    ``loop.call_soon_threadsafe(task.cancel)`` when the user hits Stop.
    """
    import asyncio
    try:
        pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
        for t in pending:
            t.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
    except Exception:
        pass
    finally:
        asyncio.set_event_loop(None)
        loop.close()


def _parse_scope_text(raw: str) -> List[str]:
    """Split a pasted blob (newline/comma/whitespace-separated) into
    normalized, deduplicated hostnames, dropping anything unparseable."""
    parts = re.split(r"[\s,]+", raw or "")
    seen: List[str] = []
    for part in parts:
        host = _parse_scope_entry(part)
        if host and host not in seen:
            seen.append(host)
    return seen


# ── Projects ─────────────────────────────────────────────────────────────────
class _ProjectStore:
    """Persistent list of projects (workspaces) the dashboard switches between.

    v2: a project has two distinct numbers, and keeping them apart is the whole
    point:

    * ``id`` — identity. Monotonic, never reused, never shown. Everything on
      disk is keyed by it (``<state_dir>/projects/<id>/``, the issue store, the
      scope list) and in-flight runs poll by it, so reusing one would silently
      point a fresh project at a dead project's data.
    * ``label`` — the number on the tab. Allocated as the lowest positive
      integer no live project is currently using, so N tabs stay labeled within
      1..N instead of climbing forever as you create and delete.

    A label is only ever assigned at creation; deleting a project never
    renumbers the survivors (a tab's number changing under you while you work
    is worse than a gap). The freed number is handed to the next new project.

    Projects are persisted to ``<state_dir>/projects.json`` and render in
    creation order, so a gap-filling tab appears at the end of the rail rather
    than jumping into the middle. At least one project always exists — deleting
    the last one re-seeds a fresh one.
    """

    def __init__(self, state_dir: Path):
        self.root = Path(state_dir)
        self.file = self.root / "projects.json"
        self._lock = threading.Lock()
        self.root.mkdir(parents=True, exist_ok=True)
        self._data = self._read()
        if not self._data["projects"]:
            self._create_locked()
            self._write()

    # ── persistence ──────────────────────────────────────────────────────
    def _read(self) -> Dict[str, Any]:
        try:
            d = json.loads(self.file.read_text())
            d.setdefault("projects", [])
            d.setdefault("active", None)
            d.setdefault("next_id", 1)
            self._migrate_labels(d)
            return d
        except Exception:
            return {"projects": [], "active": None, "next_id": 1}

    @staticmethod
    def _migrate_labels(d: Dict[str, Any]) -> None:
        """Backfill `label` on records written before labels existed.

        Those were always named "Project {id}", so the id is the number the user
        already has on screen — reuse it rather than renumbering, which would
        move tabs the user is mid-way through working in. Labels only have to be
        unique, not contiguous: a store that opens as {1, 7} stays {1, 7} and
        lets 2..6 fill in as new projects are created.
        """
        taken = set()
        for p in d["projects"]:
            label = p.get("label")
            if not isinstance(label, int) or label < 1 or label in taken:
                # Prefer the number already showing in the old name, then the id.
                m = re.match(r"^Project (\d+)$", str(p.get("name", "")))
                label = int(m.group(1)) if m else p.get("id")
            if not isinstance(label, int) or label < 1 or label in taken:
                label = max(taken, default=0) + 1
            p["label"] = label
            p.setdefault("name", "Project %d" % label)
            taken.add(label)

    def _write(self) -> None:
        try:
            self.file.write_text(json.dumps(self._data, indent=2))
        except Exception:
            pass

    def _proj_dir(self, pid: int) -> Path:
        return self.root / "projects" / str(pid)

    def workspace_dir(self, pid: Any) -> Path:
        """Public accessor: the on-disk directory a project's scan output
        lives under, so tools (e.g. Hunt) can root their output there and
        keep projects' data separated."""
        d = self._proj_dir(pid)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _next_label_locked(self) -> int:
        """Lowest positive integer no live project is labeled with.

        Deleted projects give their number back, so the rail stays numbered
        within 1..N instead of climbing with `next_id`. Caller holds the lock.
        """
        taken = {p.get("label") for p in self._data["projects"]}
        label = 1
        while label in taken:
            label += 1
        return label

    def _create_locked(self) -> Dict[str, Any]:
        """Append a new project + make it active. Caller holds the lock."""
        pid = self._data["next_id"]
        self._data["next_id"] = pid + 1
        # id identifies (monotonic, keys the on-disk workspace); label is only
        # ever what the tab shows. See the class docstring for why they differ.
        label = self._next_label_locked()
        proj = {"id": pid, "label": label, "name": f"Project {label}",
                "created_at": time.time()}
        self._data["projects"].append(proj)
        self._data["active"] = pid
        try:
            self._proj_dir(pid).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return proj

    # ── API ──────────────────────────────────────────────────────────────
    def state(self) -> Dict[str, Any]:
        with self._lock:
            return {"projects": list(self._data["projects"]), "active": self._data["active"]}

    def new(self) -> Dict[str, Any]:
        with self._lock:
            self._create_locked()
            self._write()
            return {"ok": True, "projects": list(self._data["projects"]),
                    "active": self._data["active"]}

    def select(self, pid: Any) -> Dict[str, Any]:
        with self._lock:
            if any(p["id"] == pid for p in self._data["projects"]):
                self._data["active"] = pid
                self._write()
                return {"ok": True, "active": pid}
            return {"ok": False, "error": "no such project"}

    def delete(self, pid: Any) -> Dict[str, Any]:
        with self._lock:
            before = len(self._data["projects"])
            self._data["projects"] = [p for p in self._data["projects"] if p["id"] != pid]
            if len(self._data["projects"]) == before:
                return {"ok": False, "error": "no such project"}
            shutil.rmtree(self._proj_dir(pid), ignore_errors=True)
            # Keep at least one project, and keep `active` valid.
            if not self._data["projects"]:
                self._create_locked()
            elif self._data["active"] == pid:
                self._data["active"] = self._data["projects"][0]["id"]
            self._write()
            return {"ok": True, "projects": list(self._data["projects"]),
                    "active": self._data["active"]}

    # ── Scope (per project — separate from every other project's, like the
    # scan data in workspace_dir()) ───────────────────────────────────────
    def _find(self, pid: Any) -> Optional[Dict[str, Any]]:
        # str() comparison: `pid` may arrive as an int (POST JSON body) or a
        # str (parsed from a GET query string) — project ids are stored as int.
        for p in self._data["projects"]:
            if str(p["id"]) == str(pid):
                return p
        return None

    def get_scope(self, pid: Any) -> List[str]:
        with self._lock:
            p = self._find(pid)
            return list(p.get("scope", [])) if p else []

    def add_scope(self, pid: Any, entries: List[str]) -> Dict[str, Any]:
        with self._lock:
            p = self._find(pid)
            if p is None:
                return {"ok": False, "error": "no such project"}
            merged = set(p.get("scope", [])) | set(entries)
            p["scope"] = sorted(merged)
            self._write()
            return {"ok": True, "scope": p["scope"]}

    def remove_scope(self, pid: Any, entry: str) -> Dict[str, Any]:
        with self._lock:
            p = self._find(pid)
            if p is None:
                return {"ok": False, "error": "no such project"}
            p["scope"] = [s for s in p.get("scope", []) if s != entry]
            self._write()
            return {"ok": True, "scope": p["scope"]}

    def clear_scope(self, pid: Any) -> Dict[str, Any]:
        with self._lock:
            p = self._find(pid)
            if p is None:
                return {"ok": False, "error": "no such project"}
            p["scope"] = []
            self._write()
            return {"ok": True, "scope": []}


# ── Issues (Burp-style) ──────────────────────────────────────────────────────
# Every scanner "result"/finding — from a deterministic Hunt scan or a GHOST
# agent run — becomes a persistent, per-project *issue* the user can inspect,
# re-triage (severity), highlight, and delete, exactly like Burp's Issue
# activity. Severity has a fixed rank so the list can sort by it meaningfully.
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                   # "info-high" = high-signal info: not a vuln itself, but hands
                   # an attacker real recon that leads toward exploitation — an
                   # exact software version (→ CVE lookup) or a routable backend/
                   # origin IP (→ WAF-bypass). Ranked just above inert info.
                   "info-high": 4, "info": 5}
_VALID_SEVERITIES = set(_SEVERITY_ORDER)
# The palette offered in the right-click "Highlight" menu (Burp-style).
_HIGHLIGHT_COLORS = {"red", "orange", "yellow", "green", "blue", "purple", "gray", "none"}


def _stringify_evidence(ev: Any) -> str:
    """A Finding's ``evidence`` may be a str, dict, list, or anything — render
    it to a stable string for display without exploding on odd types."""
    if ev is None:
        return ""
    if isinstance(ev, str):
        return ev
    try:
        return json.dumps(ev, indent=2, default=str)
    except Exception:
        return str(ev)


def _doc_links(finding: Any) -> List[str]:
    """Derive documentation links (Burp's "References"/classifications) from a
    finding's own references plus its CWE id, so every issue links out to real
    docs even when the scanner didn't supply a URL."""
    links: List[str] = []
    for r in (getattr(finding, "references", None) or []):
        if r and r not in links:
            links.append(str(r))
    cwe = getattr(finding, "cwe_id", None)
    if cwe is not None:
        m = re.search(r"\d+", str(cwe))
        if m:
            url = f"https://cwe.mitre.org/data/definitions/{m.group()}.html"
            if url not in links:
                links.append(url)
    return links


# HTTP header name = RFC 7230 token. Used to tell a real header line apart from
# body content that merely contains a colon (e.g. an XML DOCTYPE / ENTITY line).
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
                 "TRACE", "CONNECT"}


def _looks_like_http_request(text: str) -> bool:
    """True if ``text`` opens with a real request line (``METHOD target ...``).

    Some scanners store a *payload* in ``finding.request`` rather than a full
    request — the XXE scanner puts the raw XML there, for instance. Those must be
    wrapped in an HTTP envelope before they can be shown or sent as a request."""
    first = (text or "").lstrip().split("\n", 1)[0].strip()
    parts = first.split()
    return len(parts) >= 2 and parts[0].upper() in _HTTP_METHODS


def _guess_content_type(body: str) -> str:
    s = (body or "").lstrip()
    if s.startswith("<?xml") or (s.startswith("<") and ">" in s):
        return "application/xml"
    if s[:1] in ("{", "["):
        return "application/json"
    if re.match(r"^[^=&\s]+=[^=&]*(&[^=&\s]+=[^=&]*)*$", s.strip()):
        return "application/x-www-form-urlencoded"
    return "text/plain"


def _wrap_request_body(url: str, parsed: Any, body_text: str, poc_curl: str) -> str:
    """Wrap a bare payload/body in a valid HTTP request envelope.

    So a finding whose ``request`` is just an XML/JSON/form payload (no request
    line, no headers) still displays as — and, from the Repeater, *sends* as — a
    real request instead of blowing up the header parser."""
    method = _method_from_poc_curl(poc_curl) or "POST"   # a body implies a write
    host = parsed.netloc or ""
    path = parsed.path or "/"
    query = parsed.query
    target = path + (("?" + query) if query else "")
    body = (body_text or "").rstrip("\n")
    lines = ["%s %s HTTP/1.1" % (method, target)]
    if host:
        lines.append("Host: " + host)
    lines.append("Content-Type: " + _guess_content_type(body))
    lines.append("Content-Length: %d" % len(body.encode("utf-8")))
    lines.append("")
    lines.append(body)
    return "\n".join(lines) + "\n"


def _method_from_poc_curl(poc_curl: str) -> Optional[str]:
    """Best-effort HTTP method from a curl PoC: an explicit ``-X``, or a data /
    form flag implying POST. Returns None when nothing indicates a method."""
    if not poc_curl:
        return None
    m = re.search(r"-X\s*([A-Za-z]+)", poc_curl)
    if m:
        return m.group(1).upper()
    if re.search(r"(?:^|\s)(?:-d|--data(?:-raw|-binary|-urlencode)?|-F|--form)\b", poc_curl):
        return "POST"
    return None


def _reconstruct_request(url: str, parsed: Any, parameter: str, payload: str,
                         poc_curl: str) -> str:
    """Build a raw HTTP request from a finding's metadata when neither the
    scanner nor the agent captured the real one.

    This is NOT the exact bytes that went over the wire — it's the request the
    finding *describes*: the affected endpoint with the injected
    parameter/payload placed where it belongs (query for GET-like methods, body
    otherwise). It exists so the Request tab is always populated with something
    real and actionable per issue; callers mark it reconstructed so the UI can
    say so and no one mistakes it for a captured transaction.
    """
    method = _method_from_poc_curl(poc_curl) or "GET"
    host = parsed.netloc or ""
    path = parsed.path or "/"
    query = parsed.query
    body = ""
    if parameter:
        if method in ("GET", "HEAD", "DELETE", "OPTIONS"):
            # Put the payload on the query string. If the vulnerable parameter is
            # already there (typically with a benign value), REPLACE its value —
            # that's the injection — rather than dropping the payload or adding a
            # duplicate. Other params keep their order and values; the payload is
            # left un-encoded so the injection reads the way Burp would show it.
            pairs = parse_qsl(query, keep_blank_values=True)
            out, replaced = [], False
            for k, v in pairs:
                if k == parameter and not replaced:
                    out.append((k, payload or "")); replaced = True
                else:
                    out.append((k, v))
            if not replaced:
                out.append((parameter, payload or ""))
            query = "&".join("%s=%s" % (k, v) for k, v in out)
        else:
            body = "%s=%s" % (parameter, payload or "")
    target = path + (("?" + query) if query else "")
    lines = ["%s %s HTTP/1.1" % (method, target)]
    if host:
        lines.append("Host: " + host)
    if body:
        lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append("Content-Length: %d" % len(body.encode("utf-8")))
    lines.append("")
    lines.append(body)
    return "\n".join(lines).rstrip("\n") + "\n"


# Findings that are pure information disclosure. A scanner marking one of these
# "low" is a miscalibration — by any bug-bounty taxonomy they're INFO, not a
# vulnerability. We normalize so the Issues tab is honest. Deliberately
# conservative: this ONLY ever downgrades a `low` (never medium/high/critical),
# only on a clear disclosure signature, and never something that names a real
# secret/credential (a genuine one is already ranked medium+ by its scanner).
_INFO_DISCLOSURE_RE = re.compile(
    r"disclos"                               # disclosed / disclosure — the big one
    r"|\binternal (?:host|hostname|ip)"
    r"|storage keys?\b"
    r"|\bapi routes?\b"
    r"|websocket endpoints?\b"
    r"|source ?maps?\b"
    r"|software version|version (?:disclosure|leak|detected)"
    r"|banner grab"
    r"|debug(?:/dev)? flag",
    re.IGNORECASE,
)
_SENSITIVE_FINDING_RE = re.compile(
    r"secret|credential|password|private key|api[ _-]?key|access[ _-]?token|\bjwt\b|hardcoded",
    re.IGNORECASE,
)

# ── "info-high" signal detection ──
# A concrete software version (name immediately followed by X.Y[.Z]) — the exact
# thing you feed a CVE search. Requires two version components so "v2 api" etc.
# doesn't trip it.
_VERSION_RE = re.compile(
    r"\b(?:nginx|apache2?|httpd|(?:microsoft-)?iis|openssh|libssh|php|python|"
    r"node(?:\.?js)?|express|tomcat|jetty|jboss|wildfly|glassfish|django|flask|"
    r"rails|ruby|perl|openssl|jquery|angularjs|angular|react|vue|next\.?js|"
    r"wordpress|drupal|joomla|litespeed|caddy|lighttpd|haproxy|varnish|gunicorn|"
    r"uwsgi|kestrel|coyote|passenger|bootstrap|lodash|struts|spring|laravel|symfony)"
    r"[\s/_-]*v?\d+(?:\.\d+)+",
    re.IGNORECASE,
)
# A version number attached to the word "version" ("Server Version: 2.4.29").
_VERSION_GENERIC_RE = re.compile(r"\bversion\b[\s:/=]*v?\d+(?:\.\d+)+", re.IGNORECASE)
# Titles that indicate a version/fingerprint finding — gates the body-version
# scan so an unrelated low isn't promoted just because its remediation names one.
_VERSION_TITLE_RE = re.compile(
    r"\b(?:version|banner|fingerprint|x-powered-by|server header|software|"
    r"technolog|outdated|end[- ]of[- ]life|\beol\b)",
    re.IGNORECASE,
)
# Titles about IP/origin/backend disclosure.
_IP_DISCLOSURE_TITLE_RE = re.compile(
    r"\b(?:ip address|origin ip|origin server|real ip|backend|internal (?:host|ip)|"
    r"host(?:name)? disclos|ip disclos)",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _has_public_ip(text: str) -> bool:
    """True if the text contains a globally-routable IPv4 (a real backend/origin
    address), as opposed to a loopback/private one that isn't directly reachable."""
    import ipaddress
    for m in _IPV4_RE.finditer(text or ""):
        try:
            if ipaddress.ip_address(m.group()).is_global:
                return True
        except ValueError:
            continue
    return False


def _has_actionable_signal(title: str, text: str) -> bool:
    """A disclosure that hands an attacker directly-actionable recon: an exact
    software version (→ CVE) or a routable backend/origin IP (→ direct hit)."""
    if _VERSION_RE.search(title):
        return True
    if _VERSION_TITLE_RE.search(title) and (_VERSION_RE.search(text) or _VERSION_GENERIC_RE.search(text)):
        return True
    if _IP_DISCLOSURE_TITLE_RE.search(title) and _has_public_ip(text):
        return True
    return False


def _normalize_severity(title: str, severity: str, description: str = "") -> str:
    """Classify an informational finding into the right tier.

    Only ever acts on ``low``/``info`` findings (a real vuln at medium+ is never
    touched, and a secret/credential is never hidden):

    * high-signal recon (exact version → CVE, or a routable backend/origin IP)
      → ``info-high``;
    * inert information disclosure (loopback IPs, endpoint/route names, storage
      keys) → ``info``;
    * anything else is left exactly as the scanner set it.
    """
    if severity not in ("low", "info"):
        return severity
    title = title or ""
    if _SENSITIVE_FINDING_RE.search(title):
        return severity
    text = title + "\n" + (description or "")
    if _has_actionable_signal(title, text):
        return "info-high"
    if severity == "low" and _INFO_DISCLOSURE_RE.search(title):
        return "info"
    return severity


def _finding_to_issue(finding: Any, scanner: str, origin: str) -> Dict[str, Any]:
    """Serialize a ``beatrix.core.types.Finding`` into a plain-dict issue record
    (the on-disk + wire format). Tolerates partially-populated findings from any
    of the 33 scanners or the agent's ``record_finding``."""
    url = getattr(finding, "url", "") or ""
    parsed = urlparse(url)
    sev = getattr(getattr(finding, "severity", None), "value", None) or "info"
    conf = getattr(getattr(finding, "confidence", None), "value", None) or "tentative"
    module = (getattr(finding, "scanner_module", "") or scanner or "unknown")
    title = getattr(finding, "title", "") or "Untitled finding"
    parameter = getattr(finding, "parameter", None) or ""
    payload = getattr(finding, "payload", None) or ""
    poc_curl = getattr(finding, "poc_curl", None) or ""
    evidence = _stringify_evidence(getattr(finding, "evidence", None))

    # Request / response tabs must always show something real per issue. Prefer
    # the captured transaction; otherwise reconstruct the request from the
    # finding's metadata and fall back to the evidence snippet (usually the
    # response proof) for the response. Both fallbacks are flagged so the UI can
    # label them — a security tool must never pass off a reconstruction as the
    # exact bytes on the wire.
    raw_request = getattr(finding, "request", None) or ""
    raw_response = getattr(finding, "response", None) or ""
    if not raw_request.strip():
        # Nothing captured — reconstruct from url + param + payload.
        raw_request = _reconstruct_request(url, parsed, parameter, payload, poc_curl)
        request_synthesized = True
    elif _looks_like_http_request(raw_request):
        request_synthesized = False        # a real request the scanner captured
    else:
        # A payload/fragment stored in `request` (e.g. XXE's raw XML) — wrap it in
        # an HTTP envelope so it's valid to display and to send from the Repeater.
        raw_request = _wrap_request_body(url, parsed, raw_request, poc_curl)
        request_synthesized = True
    response_synthesized = not raw_response.strip()
    if response_synthesized and evidence.strip():
        raw_response = evidence
    else:
        response_synthesized = False   # captured response, or genuinely nothing to show

    return {
        "title": title,
        "severity": _normalize_severity(
            title, sev, (getattr(finding, "description", "") or "") + "\n" + evidence),
        "orig_severity": sev,          # the scanner's raw call, kept for audit
        "confidence": conf,
        "url": url,
        "host": parsed.netloc,
        "path": parsed.path or "/",
        "parameter": parameter,
        "module": module,
        "origin": origin,
        "payload": payload,
        "description": getattr(finding, "description", "") or "",
        "impact": getattr(finding, "impact", "") or "",
        "remediation": getattr(finding, "remediation", "") or "",
        "evidence": evidence,
        "request": raw_request,
        "response": raw_response,
        "request_synthesized": request_synthesized,
        "response_synthesized": response_synthesized,
        "references": _doc_links(finding),
        "cwe": ("" if getattr(finding, "cwe_id", None) is None else str(finding.cwe_id)),
        "owasp": getattr(finding, "owasp_category", None) or "",
        "poc_curl": poc_curl,
        "poc_python": getattr(finding, "poc_python", None) or "",
        "reproduction_steps": list(getattr(finding, "reproduction_steps", None) or []),
        "validated": bool(getattr(finding, "validated", False)),
    }


# Fields the list view needs — keep the /issues payload light (request/response
# bodies can be large); the full record is fetched per-issue via /issues/detail.
_ISSUE_SUMMARY_FIELDS = ("id", "title", "severity", "confidence", "host", "path",
                         "url", "module", "origin", "highlight", "validated",
                         "false_positive", "discovered_at")


class _IssueStore:
    """Per-project issue list, persisted to ``<project>/issues.json``.

    Disk-backed with no long-lived cache (issue volume is modest and ops are
    low-frequency), so it can't drift from a project that was deleted out from
    under it — a removed project's workspace dir (and its issues.json) is gone,
    and this simply reads an empty list. All read-modify-write ops hold one
    lock, so the scan thread adding findings and the HTTP thread editing/listing
    never corrupt the file.
    """

    def __init__(self, projects: "_ProjectStore"):
        self._projects = projects
        self._lock = threading.Lock()

    def _file(self, pid: Any) -> Path:
        return self._projects.workspace_dir(pid) / "issues.json"

    def _read(self, pid: Any) -> Dict[str, Any]:
        try:
            d = json.loads(self._file(pid).read_text())
            d.setdefault("issues", [])
            d.setdefault("next_id", 1)
            return d
        except Exception:
            return {"issues": [], "next_id": 1}

    def _write(self, pid: Any, data: Dict[str, Any]) -> None:
        try:
            self._file(pid).write_text(json.dumps(data, indent=2, default=str))
        except Exception:
            pass

    @staticmethod
    def _key(issue: Dict[str, Any]) -> str:
        # Issue identity (for dedup): a scanner re-emitting the same finding, or
        # the post-run completion sweep re-seeing a live-captured one, must NOT
        # create a second issue — and must NOT clobber a user's re-triage.
        return "␟".join((issue.get("title", ""), issue.get("url", ""),
                              issue.get("parameter", ""), issue.get("module", "")))

    def add_finding(self, pid: Any, finding: Any, scanner: str, origin: str) -> Optional[Dict[str, Any]]:
        """Add a finding as a new issue.

        Idempotent by ``_key`` so live capture + the completion sweep never
        double-count. On a duplicate we still refresh the *severity* when the
        scanner's (normalized) call has changed — e.g. a re-scan after a
        classifier fix corrects a stale ``low`` to ``info`` — but only if the
        user hasn't manually re-triaged it (``user_severity``), so a human
        decision is never clobbered. Returns the (new or refreshed) summary, or
        None when nothing changed."""
        issue = _finding_to_issue(finding, scanner, origin)
        key = self._key(issue)
        with self._lock:
            data = self._read(pid)
            for existing in data["issues"]:
                if existing.get("key") == key:
                    new_sev = issue["severity"]
                    if (not existing.get("user_severity")
                            and existing.get("severity") != new_sev):
                        existing["severity"] = new_sev
                        existing["orig_severity"] = issue.get("orig_severity")
                        self._write(pid, data)   # only writes when it actually changed
                        return {k: existing.get(k) for k in _ISSUE_SUMMARY_FIELDS}
                    return None
            issue["id"] = data["next_id"]
            issue["key"] = key
            issue["highlight"] = None
            issue["false_positive"] = False
            issue["discovered_at"] = time.time()
            data["next_id"] += 1
            data["issues"].append(issue)
            self._write(pid, data)
            return {k: issue.get(k) for k in _ISSUE_SUMMARY_FIELDS}

    def list(self, pid: Any) -> List[Dict[str, Any]]:
        with self._lock:
            data = self._read(pid)
        return [{k: i.get(k) for k in _ISSUE_SUMMARY_FIELDS} for i in data["issues"]]

    def count(self, pid: Any) -> int:
        # Powers the tab badge — a call to attention, so dismissed (false
        # positive) issues don't count toward it.
        with self._lock:
            return sum(1 for i in self._read(pid)["issues"] if not i.get("false_positive"))

    def get(self, pid: Any, issue_id: Any) -> Optional[Dict[str, Any]]:
        with self._lock:
            data = self._read(pid)
        for i in data["issues"]:
            if str(i.get("id")) == str(issue_id):
                return i
        return None

    def update(self, pid: Any, issue_id: Any, severity: Optional[str] = None,
               highlight: Optional[str] = None,
               false_positive: Optional[bool] = None) -> Dict[str, Any]:
        with self._lock:
            data = self._read(pid)
            for i in data["issues"]:
                if str(i.get("id")) == str(issue_id):
                    if severity is not None:
                        sev = severity.lower().strip()
                        if sev not in _VALID_SEVERITIES:
                            return {"ok": False, "error": f"invalid severity '{severity}'"}
                        i["severity"] = sev
                        i["user_severity"] = True   # manual re-triage — dedup must not overwrite it
                    if highlight is not None:
                        color = highlight.lower().strip()
                        if color not in _HIGHLIGHT_COLORS:
                            return {"ok": False, "error": f"invalid highlight '{highlight}'"}
                        i["highlight"] = None if color == "none" else color
                    if false_positive is not None:
                        i["false_positive"] = bool(false_positive)
                    self._write(pid, data)
                    return {"ok": True, "issue": {k: i.get(k) for k in _ISSUE_SUMMARY_FIELDS}}
            return {"ok": False, "error": "no such issue"}

    def delete(self, pid: Any, issue_id: Any) -> Dict[str, Any]:
        with self._lock:
            data = self._read(pid)
            before = len(data["issues"])
            data["issues"] = [i for i in data["issues"] if str(i.get("id")) != str(issue_id)]
            if len(data["issues"]) == before:
                return {"ok": False, "error": "no such issue"}
            self._write(pid, data)
            return {"ok": True}

    def clear(self, pid: Any) -> Dict[str, Any]:
        with self._lock:
            data = self._read(pid)
            data["issues"] = []
            self._write(pid, data)
        return {"ok": True}


# ── Shell page ───────────────────────────────────────────────────────────────
# Left project rail + top tab bar (Dashboard | Auth | Ghost); panes swap
# client-side. Theme-aware, inline CSS/JS, no external requests.
_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Beatrix Suite</title>
<style>
  :root { --bg:#0a0f0c; --panel:#0e150f; --border:#1e2b22; --fg:#d3ddd2; --muted:#6f8175;
    --accent:#35d07e; --red:#ff6b6b; --green:#57d98a; --yellow:#f5c451; --violet:#b98cff; --blue:#5aa9ff; }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f5f8f4; --panel:#ffffff; --border:#d7e0d5; --fg:#1c2620; --muted:#5f7167;
      --accent:#12864e; --red:#c0392b; --green:#1a7f47; --yellow:#9a7b12; --violet:#7a3ff2; --blue:#0969da; } }
  * { box-sizing:border-box; }
  html, body { height:100%; }
  /* Matrix rain sits BEHIND everything (negative z-index → below the static
     content, above the body background). Using -1 means the content needs no
     stacking-context of its own, so dropdowns/menus keep working normally; the
     transparent panes still let the rain glimmer through. */
  #mrain { position:fixed; inset:0; z-index:-1; pointer-events:none; opacity:.38; }
  #mrain.off { display:none; }
  body { margin:0; display:flex; flex-direction:column; background:var(--bg); color:var(--fg);
    font:14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  header { display:flex; align-items:center; gap:16px; padding:10px 18px;
    background:var(--panel); border-bottom:1px solid var(--border);
    box-shadow:0 1px 0 color-mix(in srgb, var(--accent) 22%, transparent); }
  .brand { display:flex; align-items:center; gap:3px; user-select:none; }
  .brand-name { font-weight:800; font-size:15px; letter-spacing:.22em; color:var(--yellow);
    text-shadow:0 0 14px color-mix(in srgb, var(--yellow) 42%, transparent); }
  header .proj-label { margin-left:auto; color:var(--muted); font-size:12px; }
  header .status { color:var(--muted); font-size:12px; }
  header .session-chip { color:var(--accent); font-size:12px; font-weight:600; }
  header .session-chip:empty { display:none; }
  /* Hamburger menu */
  .menu-wrap { position:relative; }
  .hamburger { font-size:17px; line-height:1; color:var(--fg); background:transparent;
    border:1px solid transparent; border-radius:7px; padding:4px 9px; cursor:pointer; }
  .hamburger:hover { background:var(--bg); border-color:var(--border); }
  .app-menu { position:absolute; left:0; top:calc(100% + 8px); z-index:70; width:260px; display:none;
    background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:6px;
    box-shadow:0 16px 40px rgba(0,0,0,.45); }
  .app-menu.open { display:block; }
  .menu-session { padding:8px 10px 10px; border-bottom:1px solid var(--border); margin-bottom:6px; }
  .menu-label { font-size:10px; letter-spacing:.07em; text-transform:uppercase; color:var(--muted); }
  .menu-session-name { font-size:13.5px; font-weight:700; color:var(--fg); margin-top:2px; }
  .menu-session-path { font-size:11px; color:var(--muted); word-break:break-all; margin-top:2px; }
  .menu-item { display:block; width:100%; text-align:left; font:inherit; font-size:13px; color:var(--fg);
    background:transparent; border:0; border-radius:6px; padding:8px 10px; cursor:pointer; }
  .menu-item:hover { background:var(--bg); }
  /* Session picker modal */
  .modal-overlay { position:fixed; inset:0; z-index:90; display:none; align-items:center;
    justify-content:center; background:rgba(0,0,0,.55); backdrop-filter:blur(2px); }
  .modal-overlay.open { display:flex; }
  .modal { width:min(620px, 92vw); max-height:86vh; overflow:auto; background:var(--panel);
    border:1px solid var(--border); border-radius:14px; padding:20px 22px;
    box-shadow:0 24px 60px rgba(0,0,0,.5); }
  .modal-head { display:flex; align-items:center; }
  .modal h2 { margin:0; font-size:18px; }
  .modal-cancel { margin-left:auto; font-size:15px; color:var(--muted); background:transparent;
    border:0; cursor:pointer; border-radius:6px; padding:2px 7px; }
  .modal-cancel:hover { color:var(--fg); background:var(--bg); }
  .modal-sub { color:var(--muted); font-size:12.5px; line-height:1.55; margin:8px 0 14px; }
  .session-tabs { display:flex; gap:4px; border-bottom:1px solid var(--border); margin-bottom:12px; }
  .session-tabs button { font:inherit; font-size:13px; color:var(--muted); background:transparent;
    border:0; border-bottom:2px solid transparent; padding:7px 12px; cursor:pointer; }
  .session-tabs button.active { color:var(--fg); border-bottom-color:var(--accent); }
  .recent-list { display:flex; flex-direction:column; gap:6px; min-height:80px; }
  .recent-item { display:flex; align-items:center; gap:12px; padding:10px 12px; border:1px solid var(--border);
    border-radius:9px; cursor:pointer; background:var(--bg); }
  .recent-item:hover { border-color:var(--accent); }
  .recent-item.missing { opacity:.5; cursor:default; }
  .recent-item .ri-name { font-weight:600; font-size:13.5px; }
  .recent-item .ri-path { font-size:11px; color:var(--muted); word-break:break-all; }
  .recent-item .ri-meta { margin-left:auto; font-size:11px; color:var(--muted); white-space:nowrap; }
  .recent-empty { color:var(--muted); font-size:12.5px; font-style:italic; padding:16px 4px; }
  .fs-bar { display:flex; align-items:center; gap:8px; margin-bottom:8px; }
  .fs-btn { font:inherit; font-size:13px; color:var(--fg); background:var(--bg); border:1px solid var(--border);
    border-radius:6px; padding:5px 9px; cursor:pointer; }
  .fs-btn:hover { border-color:var(--accent); }
  .fs-path-input { flex:1; min-width:120px; font-family:ui-monospace,Menlo,monospace; font-size:12px;
    color:var(--fg); background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:5px 8px; }
  .fs-path-input:focus { outline:none; border-color:var(--accent); }
  .fs-list { border:1px solid var(--border); border-radius:9px; max-height:260px; overflow:auto;
    background:var(--bg); margin-bottom:12px; }
  .fs-row { display:flex; align-items:center; gap:9px; padding:8px 12px; cursor:pointer; font-size:13px;
    border-bottom:1px solid var(--border); }
  .fs-row:last-child { border-bottom:0; }
  .fs-row:hover { background:var(--panel); }
  .fs-row .fs-ico { opacity:.8; }
  .fs-row .fs-badge { margin-left:auto; font-size:10px; color:var(--accent); border:1px solid var(--accent);
    border-radius:4px; padding:1px 5px; }
  .fs-empty { padding:14px 12px; color:var(--muted); font-size:12px; font-style:italic; }
  .fs-actions { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
  .fs-actions input { flex:1; min-width:160px; font:inherit; font-size:13px; color:var(--fg);
    background:var(--bg); border:1px solid var(--border); border-radius:7px; padding:7px 10px; }
  .fs-actions .btn2 { font:inherit; font-size:13px; color:var(--fg); background:var(--bg);
    border:1px solid var(--border); border-radius:7px; padding:7px 12px; cursor:pointer; }
  .fs-actions .btn2:hover { border-color:var(--accent); }
  .sess-msg { margin-top:10px; font-size:12px; color:var(--red); min-height:16px; }
  .dot { width:9px; height:9px; border-radius:50%; display:inline-block; margin-right:6px;
    background:var(--green); vertical-align:middle;
    box-shadow:0 0 7px color-mix(in srgb, var(--green) 75%, transparent);
    animation:dotpulse 2.4s ease-in-out infinite; }
  @keyframes dotpulse { 0%,100%{ opacity:1; } 50%{ opacity:.45; } }

  .body { flex:1; min-height:0; display:flex; }

  /* Left project rail */
  .projects { width:54px; flex-shrink:0; background:var(--panel); border-right:1px solid var(--border);
    display:flex; flex-direction:column; align-items:center; gap:6px; padding:8px 0; overflow-y:auto; }
  .proj { width:38px; height:38px; border-radius:8px; border:1px solid var(--border); background:var(--bg);
    color:var(--muted); font:inherit; font-weight:700; cursor:pointer; flex-shrink:0;
    display:flex; align-items:center; justify-content:center; }
  .proj:hover { color:var(--fg); border-color:var(--accent); }
  .proj.active { color:var(--fg); border-color:var(--accent); background:rgba(63,208,214,.12);
    box-shadow:inset 3px 0 0 var(--accent); }
  .proj.add { color:var(--muted); font-weight:400; font-size:20px; border-style:dashed; }
  .proj.add:hover { color:var(--accent); }

  .workspace { flex:1; min-width:0; display:flex; flex-direction:column; }
  nav { display:flex; gap:2px; padding:0 12px; background:var(--panel); border-bottom:1px solid var(--border); }
  nav button { font:inherit; font-size:13px; color:var(--muted); background:transparent; border:none;
    border-bottom:2px solid transparent; padding:9px 16px; cursor:pointer; }
  nav button:hover { color:var(--fg); }
  nav button.active { color:var(--fg); border-bottom-color:var(--accent); }
  main { flex:1; min-height:0; position:relative; }
  .pane { position:absolute; inset:0; display:none; overflow:auto; }
  .pane.active { display:block; }
  .pane.frame { overflow:hidden; }
  iframe { width:100%; height:100%; border:0; display:block; background:transparent; }
  /* The Hunt workstation is a control panel + terminal side by side, so it
     overrides the generic block layout while active (ID beats .pane.active). */
  #pane-dashboard.active { display:flex; flex-direction:row; overflow:hidden; }

  /* Right-click context menu for project tabs */
  .ctx { position:fixed; z-index:50; display:none; background:var(--panel); border:1px solid var(--border);
    border-radius:6px; padding:4px; min-width:130px; box-shadow:0 8px 24px rgba(0,0,0,.35); }
  .ctx button { display:block; width:100%; text-align:left; font:inherit; font-size:13px; color:var(--red);
    background:transparent; border:0; padding:6px 10px; border-radius:4px; cursor:pointer; }
  .ctx button:hover { background:var(--bg); }

  .pad { padding:20px 24px; }
  h2 { font-size:16px; margin:0 0 8px; }
  p.sub { color:var(--muted); margin:0 0 18px; }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:flex-end; margin-bottom:12px; }
  label { display:block; font-size:12px; color:var(--muted); margin-bottom:4px; }
  input[type=text] { font:inherit; color:var(--fg); background:var(--bg); border:1px solid var(--border);
    border-radius:6px; padding:7px 10px; min-width:280px; }
  button.run { font:inherit; color:#08131a; background:var(--accent); border:0; border-radius:6px;
    padding:8px 16px; cursor:pointer; font-weight:600; }
  button.run:disabled { opacity:.5; cursor:default; }
  button.stop { font:inherit; color:#fff; background:var(--red); border:0; border-radius:6px;
    padding:8px 16px; cursor:pointer; font-weight:600; }
  button.stop:disabled { opacity:.4; cursor:default; }
  .ghost-toolbar { display:flex; align-items:center; gap:16px; margin:10px 0 4px;
    color:var(--muted); font-size:12px; }
  .ghost-toolbar b { color:var(--fg); }
  .ghost-toolbar .autoscroll-toggle { cursor:pointer; }
  .ghost-toolbar .autoscroll-toggle:hover { color:var(--fg); }
  .ghost-toolbar .btn { margin-left:auto; font:inherit; font-size:12px; color:var(--fg); background:var(--bg);
    border:1px solid var(--border); border-radius:6px; padding:5px 11px; cursor:pointer; }
  .ghost-toolbar .btn:hover { border-color:var(--accent); color:var(--accent); }
  #ghost-log { margin-top:6px; border-top:1px solid var(--border); padding-top:12px; }
  .ev { padding:2px 0; white-space:pre-wrap; word-break:break-word; }
  .ev .ts { color:var(--muted); margin-right:8px; font-size:12px; }
  .ev .tag { font-weight:700; margin-right:8px; }
  .ev.tool_start .tag { color:var(--yellow); } .ev.tool_end .tag { color:var(--blue); }
  .ev.agent_start .tag { color:var(--accent); } .ev.agent_end .tag { color:var(--muted); }
  .ev.reasoning .tag, .ev.thinking .tag { color:var(--violet); }
  .ev.finding .tag { color:var(--red); } .ev.verdict .tag { color:var(--green); }
  .ev.phase .tag { color:var(--accent); } .ev.phase_done .tag { color:var(--green); }
  .ev.scanner_start .tag { color:var(--yellow); } .ev.scanner_done .tag { color:var(--blue); }
  .ev.scanner_error .tag { color:var(--red); } .ev.info .tag { color:var(--muted); }
  .ev .detail { display:block; color:var(--muted); margin:2px 0 2px 84px; padding:6px 9px;
    background:var(--panel); border:1px solid var(--border); border-radius:6px; max-height:220px; overflow:auto; }
  .card { border:1px solid var(--border); border-radius:8px; background:var(--panel); padding:16px 18px; max-width:640px; }

  /* ── Hunt workstation: control panel (left) + terminal (right) ── */
  .hunt-controls { width:340px; flex-shrink:0; overflow-y:auto; border-right:1px solid var(--border);
    padding:16px; display:flex; flex-direction:column; min-height:0; }
  .hunt-controls label { display:block; font-size:12px; color:var(--muted); margin:12px 0 4px; }
  .hunt-controls label:first-of-type { margin-top:0; }
  .hunt-controls input[type=text] { width:100%; }
  .presets { display:flex; flex-wrap:wrap; gap:6px; }
  .preset-chip { font:inherit; font-size:11px; color:var(--muted); background:var(--bg);
    border:1px solid var(--border); border-radius:12px; padding:4px 10px; cursor:pointer; }
  .preset-chip:hover { border-color:var(--accent); color:var(--fg); }
  .preset-chip.active { background:var(--accent); color:#08131a; border-color:var(--accent); font-weight:600; }
  .mod-actions { display:flex; align-items:center; gap:10px; font-size:11px; color:var(--muted); margin:12px 0 6px; }
  .mod-actions a { color:var(--accent); text-decoration:none; cursor:pointer; }
  .mod-actions a:hover { text-decoration:underline; }
  .mod-actions .spacer { flex:1; }
  .modules { flex:1; min-height:80px; overflow-y:auto; border:1px solid var(--border); border-radius:6px; padding:4px 6px; }
  .mod-cat { font-size:10px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted);
    font-weight:700; padding:8px 4px 3px; }
  .mod-cat:first-child { padding-top:4px; }
  .mod-row { display:flex; align-items:center; gap:8px; padding:4px 6px; border-radius:4px; cursor:pointer; font-size:12.5px; }
  .mod-row:hover { background:var(--bg); }
  .mod-row input { flex-shrink:0; margin:0; }
  .mod-tooltip { position:fixed; z-index:60; display:none; max-width:280px; background:var(--panel);
    border:1px solid var(--border); border-radius:6px; padding:8px 10px; font-size:12px; color:var(--fg);
    line-height:1.45; box-shadow:0 8px 24px rgba(0,0,0,.35); pointer-events:none; }

  .hunt-terminal-wrap { flex:1; min-width:0; display:flex; flex-direction:column; padding:16px; min-height:0; }
  .term-chrome { flex:1; min-height:0; display:flex; flex-direction:column; background:#050607;
    border:1px solid var(--border); border-radius:8px; overflow:hidden; }
  .term-titlebar { display:flex; align-items:center; gap:6px; padding:8px 10px; background:#0d0f14;
    border-bottom:1px solid #1a1e28; flex-shrink:0; }
  .term-titlebar .dot { width:10px; height:10px; border-radius:50%; }
  .term-titlebar .dot.r { background:#ff5f57; }
  .term-titlebar .dot.y { background:#febc2e; }
  .term-titlebar .dot.g { background:#28c840; }
  .term-title { margin-left:8px; color:#6b7787; font-size:11.5px; }
  #hunt-log.terminal { flex:1; min-height:0; overflow-y:auto; padding:10px 14px; color:var(--fg); }

  /* ── Scope tab ── */
  .scope-list { border:1px solid var(--border); border-radius:6px; min-height:60px; max-height:340px; overflow-y:auto; }
  .scope-item { display:flex; align-items:center; gap:10px; padding:7px 12px; font-size:13px;
    border-bottom:1px solid var(--border); }
  .scope-item:last-child { border-bottom:none; }
  .scope-item .host { flex:1; }
  .scope-item button { font:inherit; font-size:12px; color:var(--muted); background:transparent;
    border:0; cursor:pointer; padding:2px 6px; border-radius:4px; }
  .scope-item button:hover { color:var(--red); background:var(--bg); }
  .scope-empty { padding:14px 12px; color:var(--muted); font-size:12.5px; }

  /* ── Issues tab (Burp-style) ── */
  nav button .badge { display:none; margin-left:6px; min-width:16px; padding:0 5px; border-radius:9px;
    background:var(--red); color:#fff; font-size:10.5px; font-weight:700; line-height:16px; text-align:center; }
  nav button .badge.show { display:inline-block; }
  #pane-issues.active { display:flex; flex-direction:column; overflow:hidden; }
  .iss-toolbar { display:flex; align-items:center; gap:14px; padding:8px 14px; border-bottom:1px solid var(--border);
    background:var(--panel); flex-shrink:0; font-size:12px; color:var(--muted); }
  .iss-toolbar b { color:var(--fg); }
  .iss-toolbar .spacer { flex:1; }
  .iss-toolbar select { font:inherit; font-size:12px; color:var(--fg); background:var(--bg);
    border:1px solid var(--border); border-radius:5px; padding:3px 6px; }
  .iss-toolbar a { color:var(--accent); cursor:pointer; }
  .iss-ghost-wrap { position:relative; }
  .iss-ghost-btn { font:inherit; font-size:12px; color:var(--fg); background:var(--bg);
    border:1px solid var(--border); border-radius:6px; padding:4px 9px; cursor:pointer; white-space:nowrap; }
  .iss-ghost-btn:hover { border-color:var(--accent); color:var(--accent); }
  .iss-ghost-menu { position:absolute; right:0; top:calc(100% + 6px); z-index:40; min-width:190px; display:none;
    background:var(--panel); border:1px solid var(--border); border-radius:9px; padding:6px;
    box-shadow:0 14px 34px rgba(0,0,0,.4); max-height:60vh; overflow:auto; }
  .iss-ghost-menu.open { display:block; }
  .ghost-menu-item { display:block; width:100%; text-align:left; font:inherit; font-size:12.5px; color:var(--fg);
    background:transparent; border:0; border-radius:5px; padding:6px 9px; cursor:pointer; white-space:nowrap; }
  .ghost-menu-item:hover { background:var(--bg); color:var(--accent); }
  .ghost-menu-sec { font-size:10px; letter-spacing:.06em; text-transform:uppercase; color:var(--muted);
    padding:8px 9px 3px; }
  .ghost-menu-empty { padding:8px 9px; color:var(--muted); font-style:italic; font-size:12px; }
  .iss-split { flex:1; min-height:0; display:flex; flex-direction:column; }
  .iss-list-wrap { flex:1 1 55%; min-height:80px; overflow:auto; }
  .iss-detail-wrap { flex:1 1 45%; min-height:120px; border-top:1px solid var(--border);
    display:flex; flex-direction:column; overflow:hidden; }

  /* ── Resizable split gutters: drag the bar to resize adjacent panes ── */
  .splitter { flex:0 0 7px; align-self:stretch; position:relative; z-index:6; background:var(--border); }
  .splitter-x { cursor:col-resize; }        /* side-by-side panes → vertical bar */
  .splitter-y { cursor:row-resize; }        /* stacked panes → horizontal bar */
  .splitter:hover, .splitter:focus-visible { background:var(--accent); outline:none; }
  .splitter::after { content:""; position:absolute; background:var(--muted); border-radius:3px; opacity:.55; }
  .splitter-x::after { top:calc(50% - 15px); left:calc(50% - 1.5px); width:3px; height:30px; }
  .splitter-y::after { left:calc(50% - 15px); top:calc(50% - 1.5px); height:3px; width:30px; }
  .splitter:hover::after, .splitter:focus-visible::after { background:#08131a; opacity:1; }
  table.iss { width:100%; border-collapse:collapse; font-size:12.5px; }
  table.iss thead th { position:sticky; top:0; background:var(--panel); text-align:left; padding:7px 10px;
    border-bottom:1px solid var(--border); cursor:pointer; user-select:none; white-space:nowrap; color:var(--muted); font-weight:600; }
  table.iss thead th:hover { color:var(--fg); }
  table.iss thead th .arrow { color:var(--accent); }
  table.iss tbody td { padding:6px 10px; border-bottom:1px solid var(--border); vertical-align:top; }
  table.iss tbody tr { cursor:pointer; }
  table.iss tbody tr:hover { background:var(--bg); }
  table.iss tbody tr.sel { background:rgba(63,208,214,.14); }
  table.iss tbody tr.hl-red { box-shadow:inset 3px 0 0 #ff5f57; }
  table.iss tbody tr.hl-orange { box-shadow:inset 3px 0 0 #ff9f43; }
  table.iss tbody tr.hl-yellow { box-shadow:inset 3px 0 0 #f7c948; }
  table.iss tbody tr.hl-green { box-shadow:inset 3px 0 0 #28c840; }
  table.iss tbody tr.hl-blue { box-shadow:inset 3px 0 0 #5aa9ff; }
  table.iss tbody tr.hl-purple { box-shadow:inset 3px 0 0 #b98cff; }
  table.iss tbody tr.hl-gray { box-shadow:inset 3px 0 0 #8a94a6; }
  /* False positives: dismissed, so they read as muted/struck but stay visible. */
  table.iss tbody tr.fp td { opacity:.5; }
  table.iss tbody tr.fp td:nth-child(2) { text-decoration:line-through; }
  table.iss tbody tr.fp .sev { filter:grayscale(1); }
  .fptag { display:inline-block; margin-left:7px; padding:0 6px; border-radius:4px; font-size:9px;
    font-weight:700; text-transform:uppercase; letter-spacing:.04em; vertical-align:middle;
    text-decoration:none; background:var(--border); color:var(--muted); }
  .sev { display:inline-block; padding:1px 7px; border-radius:4px; font-size:10.5px; font-weight:700;
    text-transform:uppercase; letter-spacing:.03em; color:#08131a; }
  .sev.critical { background:#ff5f57; color:#fff; } .sev.high { background:#ff9f43; }
  .sev.medium { background:#f7c948; } .sev.low { background:#5aa9ff; }
  .sev.info-high { background:#2dd4bf; color:#08131a; }   /* high-signal recon (versions, backend IPs) */
  .sev.info { background:#8a94a6; color:#fff; }
  .conf { color:var(--muted); font-size:11.5px; }
  .iss-empty { padding:24px; color:var(--muted); font-size:13px; text-align:center; }
  .iss-dtabs { display:flex; gap:2px; padding:6px 12px 0; border-bottom:1px solid var(--border); flex-shrink:0; }
  .iss-dtabs button { font:inherit; font-size:12px; color:var(--muted); background:transparent; border:none;
    border-bottom:2px solid transparent; padding:6px 12px; cursor:pointer; }
  .iss-dtabs button:hover { color:var(--fg); }
  .iss-dtabs button.active { color:var(--fg); border-bottom-color:var(--accent); }
  .iss-detail { flex:1; min-height:0; overflow:auto; padding:14px 18px; font-size:12.5px; }
  .iss-detail h3 { font-size:14px; margin:0 0 4px; }
  .iss-detail .kv { color:var(--muted); margin-bottom:12px; }
  .iss-detail .kv b { color:var(--fg); }
  .iss-detail section { margin-bottom:14px; }
  .iss-detail section > .lbl { font-weight:700; color:var(--accent); font-size:11px; text-transform:uppercase;
    letter-spacing:.04em; margin-bottom:4px; }
  .iss-detail pre { margin:0; padding:10px 12px; background:var(--panel); border:1px solid var(--border);
    border-radius:6px; overflow:auto; max-height:340px; white-space:pre-wrap; word-break:break-word; font-size:12px; }
  .iss-detail ul { margin:4px 0; padding-left:20px; }
  .iss-detail a { color:var(--blue); word-break:break-all; }
  .iss-detail .none { color:var(--muted); font-style:italic; }
  .iss-detail .synthnote { color:var(--yellow); font-size:11px; margin:0 0 7px;
    padding:5px 8px; background:var(--panel); border:1px solid var(--border); border-radius:5px; }
  .iss-detail .detail-actions { display:flex; justify-content:flex-end; margin:0 0 8px; }
  .iss-detail .detail-actions .btn { font:inherit; font-size:12px; color:var(--fg); background:var(--panel);
    border:1px solid var(--border); border-radius:6px; padding:5px 12px; cursor:pointer; }
  .iss-detail .detail-actions .btn:hover { border-color:var(--accent); color:var(--accent); }
  /* Issue right-click menu (severity / highlight / delete) */
  .iss-ctx { position:fixed; z-index:70; display:none; background:var(--panel); border:1px solid var(--border);
    border-radius:8px; padding:6px; min-width:190px; box-shadow:0 10px 30px rgba(0,0,0,.4); font-size:12.5px; }
  .iss-ctx .lbl { color:var(--muted); font-size:10.5px; text-transform:uppercase; letter-spacing:.04em; padding:5px 8px 3px; }
  .iss-ctx .opts { display:flex; flex-wrap:wrap; gap:4px; padding:0 6px 6px; }
  .iss-ctx .opts button { font:inherit; font-size:11px; padding:3px 8px; border-radius:4px; border:1px solid var(--border);
    background:var(--bg); color:var(--fg); cursor:pointer; }
  .iss-ctx .opts button:hover { border-color:var(--accent); }
  .iss-ctx .sw { display:inline-block; width:16px; height:16px; border-radius:4px; border:1px solid rgba(0,0,0,.3);
    cursor:pointer; }
  .iss-ctx .sw:hover { outline:2px solid var(--accent); }
  .iss-ctx hr { border:0; border-top:1px solid var(--border); margin:5px 4px; }
  .iss-ctx .fp { display:block; width:100%; text-align:left; font:inherit; font-size:12.5px; color:var(--fg);
    background:transparent; border:0; padding:6px 8px; border-radius:4px; cursor:pointer; }
  .iss-ctx .fp:hover { background:var(--bg); }
  .iss-ctx .del { display:block; width:100%; text-align:left; font:inherit; font-size:12.5px; color:var(--red);
    background:transparent; border:0; padding:6px 8px; border-radius:4px; cursor:pointer; }
  .iss-ctx .del:hover { background:var(--bg); }
  .iss-detail .fpbanner { color:var(--muted); font-size:11.5px; margin:0 0 12px; padding:6px 10px;
    background:var(--panel); border:1px solid var(--border); border-radius:6px; }

  /* ── Repeater ── */
  #pane-repeater.active { display:flex; flex-direction:column; overflow:hidden; }
  .rep-tabbar { flex-shrink:0; display:flex; align-items:flex-end; gap:2px; padding:8px 10px 0;
    background:var(--panel); border-bottom:1px solid var(--border); overflow-x:auto; }
  .rep-tab { font:inherit; font-size:12.5px; color:var(--muted); background:transparent;
    border:1px solid transparent; border-bottom:0; border-radius:6px 6px 0 0; padding:6px 10px;
    cursor:pointer; white-space:nowrap; display:flex; align-items:center; gap:6px; }
  .rep-tab:hover { color:var(--fg); }
  .rep-tab.active { color:var(--fg); background:var(--bg); border-color:var(--border); }
  .rep-tab .x { color:var(--muted); font-size:14px; line-height:1; padding:0 2px; border-radius:3px; }
  .rep-tab .x:hover { color:var(--red); background:var(--panel); }
  .rep-tab.add { color:var(--accent); font-size:15px; padding:6px 10px; }
  .rep-toolbar { flex-shrink:0; display:flex; align-items:center; gap:10px; padding:10px;
    background:var(--bg); border-bottom:1px solid var(--border); }
  #rep-target { flex:1; min-width:180px; font:inherit; font-size:13px; color:var(--fg);
    background:var(--panel); border:1px solid var(--border); border-radius:6px; padding:7px 10px; }
  .rep-hist { display:flex; align-items:center; gap:6px; font-size:12px; color:var(--muted); }
  .rep-hist button { font:inherit; font-size:15px; line-height:1; color:var(--fg); background:var(--panel);
    border:1px solid var(--border); border-radius:5px; width:26px; height:26px; cursor:pointer; }
  .rep-hist button:disabled { opacity:.4; cursor:default; }
  .rep-status { font-size:12.5px; color:var(--muted); white-space:nowrap; }
  .rep-status .ok { color:var(--green); } .rep-status .bad { color:var(--red); }
  .rep-status .dim { color:var(--muted); }
  .rep-split { flex:1; min-height:0; display:flex; gap:1px; background:var(--border); }
  .rep-col { flex:1; min-width:0; display:flex; flex-direction:column; background:var(--bg); }
  .rep-colhdr { flex-shrink:0; font-size:11px; letter-spacing:.06em; text-transform:uppercase;
    color:var(--muted); padding:7px 12px; background:var(--panel); border-bottom:1px solid var(--border); }
  /* Display tokens for HTTP syntax highlighting. They default to the app's
     theme colors (so they adapt to light/dark), and the settings menu overrides
     them per-user via inline vars on #pane-repeater. */
  #pane-repeater {
    --rep-font: ui-monospace, "SFMono-Regular", Menlo, Consolas, "Liberation Mono", monospace;
    --rep-font-size: 13px;
    --rep-line: 1.6;
    --tok-method: var(--violet);   --tok-path: var(--fg);        --tok-version: var(--muted);
    --tok-status-2xx: var(--green); --tok-status-3xx: var(--blue); --tok-status-err: var(--red);
    --tok-reason: var(--muted);
    --tok-hname: var(--accent);    --tok-hvalue: var(--fg);      --tok-hsep: var(--muted);
    --tok-json-key: var(--blue);   --tok-json-str: var(--green); --tok-json-num: var(--yellow);
    --tok-json-bool: var(--violet); --tok-json-punct: var(--muted);
    --tok-xml-tag: var(--blue);    --tok-xml-attr: var(--accent); --tok-xml-str: var(--green);
    --tok-xml-ent: var(--yellow);  --tok-comment: var(--muted);
    --tok-kw: var(--accent);
  }
  /* Shared type ramp for the request backdrop, the response, and the (invisible-
     text) textarea, so the caret lands exactly on the highlighted glyphs. */
  .rep-code, .rep-input {
    font-family: var(--rep-font); font-size: var(--rep-font-size); line-height: var(--rep-line);
    tab-size: 2; -moz-tab-size: 2; }
  .rep-editwrap { position:relative; flex:1; min-height:0; }
  .rep-hl, .rep-input {
    position:absolute; inset:0; margin:0; border:0; padding:12px 14px; box-sizing:border-box;
    white-space:pre; overflow:auto; }
  /* The textarea stays on top (z-index:1) and receives all editing, so the
     backdrop keeps pointer-events:auto — that lets elementsFromPoint() find the
     colored spans under the cursor for HTTP Tips. */
  .rep-hl { color:var(--fg); background:var(--bg); z-index:0; scrollbar-width:none; }
  .rep-hl::-webkit-scrollbar { display:none; }         /* only the textarea shows a scrollbar */
  .rep-input { color:transparent; background:transparent; caret-color:var(--accent);
    resize:none; outline:0; z-index:1; }
  .rep-input::selection { background:rgba(127,127,127,.35); }
  .rep-resp { flex:1; min-height:0; overflow:auto; margin:0; padding:12px 14px; box-sizing:border-box;
    white-space:pre-wrap; word-break:break-word; color:var(--fg); background:var(--bg); }
  .rep-resp.err { color:var(--red); }
  /* Token colors — apply to both the request backdrop and the response. */
  .rep-code .tok-method    { color:var(--tok-method); font-weight:600; }
  .rep-code .tok-path      { color:var(--tok-path); }
  .rep-code .tok-version   { color:var(--tok-version); }
  .rep-code .tok-status-2xx{ color:var(--tok-status-2xx); font-weight:600; }
  .rep-code .tok-status-3xx{ color:var(--tok-status-3xx); font-weight:600; }
  .rep-code .tok-status-err{ color:var(--tok-status-err); font-weight:600; }
  .rep-code .tok-reason    { color:var(--tok-reason); }
  .rep-code .tok-hname     { color:var(--tok-hname); font-weight:600; }
  .rep-code .tok-hvalue    { color:var(--tok-hvalue); }
  .rep-code .tok-hsep      { color:var(--tok-hsep); }
  .rep-code .tok-json-key  { color:var(--tok-json-key); }
  .rep-code .tok-json-str  { color:var(--tok-json-str); }
  .rep-code .tok-json-num  { color:var(--tok-json-num); }
  .rep-code .tok-json-bool { color:var(--tok-json-bool); font-weight:600; }
  .rep-code .tok-json-punct{ color:var(--tok-json-punct); }
  .rep-code .tok-xml-tag   { color:var(--tok-xml-tag); }
  .rep-code .tok-xml-attr  { color:var(--tok-xml-attr); }
  .rep-code .tok-xml-str   { color:var(--tok-xml-str); }
  .rep-code .tok-xml-ent   { color:var(--tok-xml-ent); font-weight:600; }
  .rep-code .tok-comment   { color:var(--tok-comment); font-style:italic; }
  .rep-code .tok-kw        { color:var(--tok-kw); font-weight:600; }
  /* When Tips are on, faintly underline the tokens you can hover for help. */
  .rep-split.tips-on .rep-code [data-tip] { text-decoration: underline dotted;
    text-decoration-color: rgba(127,127,127,.55); text-underline-offset: 3px; }

  /* ── AutoRepeater (Intruder-style) ── */
  #pane-autorepeater.active { display:flex; flex-direction:column; overflow:hidden; }
  .ar-toolbar { flex-shrink:0; display:flex; align-items:center; gap:8px; padding:10px;
    background:var(--bg); border-bottom:1px solid var(--border); }
  #ar-target { flex:1; min-width:160px; font:inherit; font-size:13px; color:var(--fg);
    background:var(--panel); border:1px solid var(--border); border-radius:6px; padding:7px 10px; }
  #ar-attack { font:inherit; font-size:13px; color:var(--fg); background:var(--panel);
    border:1px solid var(--border); border-radius:6px; padding:7px 8px; }
  .ar-toolbar .btn2 { font:inherit; font-size:12.5px; color:var(--fg); background:var(--panel);
    border:1px solid var(--border); border-radius:6px; padding:6px 10px; cursor:pointer; }
  .ar-toolbar .btn2:hover { border-color:var(--accent); }
  .ar-progress { font-size:12px; color:var(--muted); white-space:nowrap; }
  .ar-config { flex-shrink:0; height:38%; min-height:150px; display:flex; gap:1px; background:var(--border); }
  .ar-col { flex:1; min-width:0; display:flex; flex-direction:column; background:var(--bg); }
  .ar-colhdr { flex-shrink:0; font-size:11px; letter-spacing:.05em; text-transform:uppercase;
    color:var(--muted); padding:7px 12px; background:var(--panel); border-bottom:1px solid var(--border); }
  .ar-poscount { text-transform:none; letter-spacing:0; color:var(--accent); font-weight:600; margin-left:6px; }
  .ar-editor { flex:1; min-height:0; width:100%; resize:none; border:0; outline:0; margin:0; box-sizing:border-box;
    padding:12px 14px; font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12.5px; line-height:1.55;
    color:var(--fg); background:var(--bg); overflow:auto; white-space:pre; tab-size:2; }
  .ar-editor::selection { background:rgba(127,127,127,.4); }
  .ar-payloads { flex:1; min-height:0; overflow:auto; padding:8px 12px; display:flex; flex-direction:column; gap:8px; }
  .ar-pset-hd { display:flex; align-items:center; gap:8px; font-size:11px; color:var(--muted); margin-bottom:4px; }
  .ar-pset-type { font:inherit; font-size:11.5px; color:var(--fg); background:var(--bg); border:1px solid var(--border);
    border-radius:5px; padding:2px 6px; margin-left:auto; }
  .ar-pset textarea { width:100%; height:70px; resize:vertical; box-sizing:border-box; font-family:ui-monospace,Menlo,monospace;
    font-size:12px; color:var(--fg); background:var(--panel); border:1px solid var(--border); border-radius:6px;
    padding:6px 8px; white-space:pre; }
  .ar-inline { display:flex; align-items:center; gap:6px; font-size:11.5px; color:var(--muted); margin-bottom:5px; flex-wrap:wrap; }
  .ar-inline input { font:inherit; font-size:12px; color:var(--fg); background:var(--panel); border:1px solid var(--border);
    border-radius:5px; padding:4px 7px; width:74px; }
  .ar-inline input.wide { width:100%; font-family:ui-monospace,Menlo,monospace; }
  .ar-proc { flex-shrink:0; border-top:1px solid var(--border); padding:8px 12px; background:var(--panel); }
  .ar-proc-hd { display:flex; align-items:center; font-size:11px; letter-spacing:.04em; text-transform:uppercase;
    color:var(--muted); margin-bottom:6px; }
  .ar-addrule { margin-left:auto; font:inherit; font-size:11.5px; text-transform:none; letter-spacing:0; color:var(--accent);
    background:transparent; border:0; cursor:pointer; }
  .ar-rules { display:flex; flex-direction:column; gap:5px; }
  .ar-rule { display:flex; align-items:center; gap:6px; }
  .ar-rule select { font:inherit; font-size:12px; color:var(--fg); background:var(--bg); border:1px solid var(--border);
    border-radius:5px; padding:4px 6px; }
  .ar-rule input { flex:1; min-width:60px; font:inherit; font-size:12px; color:var(--fg); background:var(--bg);
    border:1px solid var(--border); border-radius:5px; padding:4px 7px; }
  .ar-rule-x { font-size:14px; color:var(--muted); background:transparent; border:0; cursor:pointer; padding:0 4px; }
  .ar-rule-x:hover { color:var(--red); }
  .ar-options { flex-shrink:0; display:flex; flex-wrap:wrap; gap:10px 16px; padding:8px 12px;
    border-top:1px solid var(--border); background:var(--panel); }
  .ar-options label { font-size:11.5px; color:var(--muted); display:flex; align-items:center; gap:6px; }
  .ar-options input { font:inherit; font-size:12px; color:var(--fg); background:var(--bg); border:1px solid var(--border);
    border-radius:5px; padding:4px 7px; width:64px; }
  .ar-options .ar-grep-l input { width:150px; }
  .ar-results { flex:1; min-height:0; display:flex; gap:1px; background:var(--border); }
  .ar-table-wrap { flex:1.4; min-width:0; overflow:auto; background:var(--bg); position:relative; }
  .ar-table { width:100%; border-collapse:collapse; font-size:12px; }
  .ar-table thead th { position:sticky; top:0; z-index:1; text-align:left; padding:7px 10px; background:var(--panel);
    border-bottom:1px solid var(--border); color:var(--muted); font-weight:600; cursor:pointer; white-space:nowrap; }
  .ar-table thead th:hover { color:var(--fg); }
  .ar-table thead th.sorted::after { content:" ▾"; color:var(--accent); }
  .ar-table thead th.sorted.asc::after { content:" ▴"; }
  .ar-table tbody td { padding:6px 10px; border-bottom:1px solid var(--border); white-space:nowrap;
    overflow:hidden; text-overflow:ellipsis; max-width:280px; }
  .ar-table tbody tr { cursor:pointer; }
  .ar-table tbody tr:hover { background:var(--panel); }
  .ar-table tbody tr.sel { background:color-mix(in srgb, var(--accent) 16%, var(--bg)); }
  .ar-st-2xx { color:var(--green); font-weight:600; } .ar-st-3xx { color:var(--blue); font-weight:600; }
  .ar-st-4xx, .ar-st-5xx { color:var(--red); font-weight:600; } .ar-st-err { color:var(--red); }
  .ar-empty { padding:18px 14px; color:var(--muted); font-size:12.5px; font-style:italic; }
  .ar-detail-wrap { flex:1; min-width:0; display:flex; flex-direction:column; background:var(--bg); }
  .ar-dtabs { flex-shrink:0; display:flex; gap:2px; padding:6px 10px 0; border-bottom:1px solid var(--border); }
  .ar-dtabs button { font:inherit; font-size:12px; color:var(--muted); background:transparent; border:0;
    border-bottom:2px solid transparent; padding:6px 12px; cursor:pointer; }
  .ar-dtabs button.active { color:var(--fg); border-bottom-color:var(--accent); }
  #ar-detail { flex:1; min-height:0; }
  /* Settings menu */
  .rep-settings { position:relative; }
  .rep-gear { font:inherit; font-size:13px; color:var(--fg); background:var(--panel);
    border:1px solid var(--border); border-radius:6px; padding:6px 10px; cursor:pointer; }
  .rep-gear:hover { border-color:var(--accent); color:var(--accent); }
  .rep-pop { position:absolute; right:0; top:calc(100% + 6px); z-index:40; width:288px;
    background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:12px 14px;
    box-shadow:0 14px 34px rgba(0,0,0,.4); display:none; }
  .rep-pop.open { display:block; }
  .rep-pop h4 { margin:2px 0 9px; font-size:10.5px; letter-spacing:.07em; text-transform:uppercase;
    color:var(--muted); }
  .rep-frow { display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:9px; }
  .rep-frow > label { font-size:12.5px; color:var(--fg); }
  .rep-frow select { font:inherit; font-size:12.5px; color:var(--fg); background:var(--bg);
    border:1px solid var(--border); border-radius:6px; padding:5px 8px; min-width:158px; }
  .rep-pop details { margin-top:4px; border-top:1px solid var(--border); padding-top:8px; }
  .rep-pop summary { cursor:pointer; font-size:12px; color:var(--muted); margin-bottom:8px; }
  .rep-pop summary:hover { color:var(--fg); }
  .rep-colors { display:grid; grid-template-columns:1fr 1fr; gap:7px 12px; }
  .rep-cfield { display:flex; align-items:center; gap:6px; font-size:11.5px; color:var(--muted); }
  .rep-cfield input[type=color] { width:24px; height:20px; border:1px solid var(--border);
    border-radius:4px; background:none; padding:0; cursor:pointer; flex-shrink:0; }
  .rep-reset { display:block; margin-top:10px; font:inherit; font-size:12px; color:var(--accent);
    background:none; border:0; cursor:pointer; padding:0; }
  .rep-reset:hover { text-decoration:underline; }
  /* HTTP Tips: on/off toggle + hover bubble */
  .rep-tipbtn { font:inherit; font-size:13px; color:var(--muted); background:var(--panel);
    border:1px solid var(--border); border-radius:6px; padding:6px 10px; cursor:pointer;
    white-space:nowrap; }
  .rep-tipbtn:hover { color:var(--fg); }
  .rep-tipbtn.on { color:#08131a; background:var(--accent); border-color:var(--accent); font-weight:600; }
  .rep-split.tips-on .rep-input, .rep-split.tips-on .rep-resp { cursor:help; }
  #rep-tip { position:fixed; z-index:80; display:none; max-width:340px; pointer-events:none;
    background:var(--panel); border:1px solid var(--border); border-radius:9px; padding:9px 11px;
    box-shadow:0 12px 34px rgba(0,0,0,.45); font-size:12.5px; line-height:1.5; }
  #rep-tip .tip-title { font-weight:700; color:var(--accent); margin-bottom:3px; font-size:12.5px; }
  #rep-tip .tip-desc { color:var(--fg); white-space:pre-wrap; word-break:break-word; }
  #rep-tip .tip-sec { margin-top:6px; padding-top:6px; border-top:1px solid var(--border);
    color:var(--yellow); font-size:12px; white-space:pre-wrap; word-break:break-word; }
</style>
</head>
<body>
<canvas id="mrain" aria-hidden="true"></canvas>
<header>
  <div class="menu-wrap">
    <button id="hamburger" class="hamburger" title="Menu" aria-label="Menu">☰</button>
    <div id="app-menu" class="app-menu">
      <div class="menu-session">
        <div class="menu-label">Current session</div>
        <div id="menu-session-name" class="menu-session-name">—</div>
        <div id="menu-session-path" class="menu-session-path"></div>
      </div>
      <button class="menu-item" id="menu-rain" data-act="rain">Matrix rain: on</button>
      <button class="menu-item" data-act="switch">Switch session…</button>
      <button class="menu-item" data-act="new">New session…</button>
      <button class="menu-item" data-act="open">Open session folder…</button>
    </div>
  </div>
  <span class="brand"><span class="brand-name">BEATRIX</span></span>
  <span class="session-chip" id="session-chip" title="Active session"></span>
  <span class="proj-label" id="proj-label">—</span>
  <span class="status"><span class="dot"></span>connected</span>
</header>
<div class="body">
  <aside id="projects" class="projects"></aside>
  <div class="workspace">
    <nav>
      <button data-tab="dashboard" class="active">Dashboard</button>
      <button data-tab="issues">Issues<span id="issues-badge" class="badge"></span></button>
      <button data-tab="scope">Scope</button>
      <button data-tab="auth">Auth</button>
      <button data-tab="ghost">Ghost</button>
      <button data-tab="repeater">Repeater</button>
      <button data-tab="autorepeater">AutoRepeater</button>
    </nav>
    <main>
      <section id="pane-dashboard" class="pane active">
        <aside class="hunt-controls">
          <h2 style="margin-top:0;">New Scan</h2>
          <p class="sub" style="margin:0 0 12px;">Project: <b id="dash-project">—</b></p>

          <label>Target</label>
          <input id="h-target" type="text" placeholder="https://example.com or example.com">

          <label>Presets <span style="font-weight:400; color:var(--muted);">(quick-select)</span></label>
          <div class="presets" id="h-presets"></div>

          <div class="mod-actions">
            <span id="h-selcount">0 selected</span>
            <span class="spacer"></span>
            <a id="h-selall">select all</a>
            <a id="h-selnone">clear</a>
          </div>
          <div class="modules" id="h-modules"></div>

          <button id="h-run" class="run" style="width:100%; margin-top:14px;">Begin Scan</button>
          <button id="h-stop" class="stop" style="width:100%; margin-top:8px;" disabled>Stop Scan</button>
          <div id="h-msg" style="color:var(--muted); font-size:12px; margin-top:8px;"></div>
        </aside>

        <div class="hunt-terminal-wrap">
          <div class="ghost-toolbar" style="margin-top:0;">
            <span>events <b id="h-count">0</b></span>
            <span>findings <b id="h-findings">0</b></span>
            <span>elapsed <b id="h-elapsed">0s</b></span>
            <span id="h-autoscroll" class="autoscroll-toggle" title="click to toggle">⤓ autoscroll: on</span>
            <button id="h-save" class="btn" title="Save this run as a standalone HTML file">Save HTML</button>
          </div>
          <div class="term-chrome">
            <div class="term-titlebar">
              <span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
              <span class="term-title" id="h-term-title">beatrix@hunt</span>
            </div>
            <div id="hunt-log" class="terminal"></div>
          </div>
        </div>
      </section>

      <section id="pane-issues" class="pane">
        <div class="iss-toolbar">
          <span>Project <b id="iss-project">—</b></span>
          <span><b id="iss-count">0</b> issue(s)</span>
          <span class="spacer"></span>
          <label>Sort by
            <select id="iss-sort">
              <option value="severity">Severity</option>
              <option value="title">Issue type</option>
              <option value="host">Host</option>
              <option value="path">URL / path</option>
              <option value="module">Module</option>
              <option value="confidence">Confidence</option>
              <option value="discovered_at">Time found</option>
            </select>
          </label>
          <div class="iss-ghost-wrap">
            <button id="iss-ghost-btn" class="iss-ghost-btn" title="Send issues to the Ghost agent to validate (saves tokens vs a full scan)">Send to Ghost ▾</button>
            <div id="iss-ghost-menu" class="iss-ghost-menu"></div>
          </div>
          <a id="iss-clear" title="Delete all issues in this project">clear all</a>
        </div>
        <div class="iss-split">
          <div class="iss-list-wrap">
            <table class="iss">
              <thead><tr id="iss-head"></tr></thead>
              <tbody id="iss-body"></tbody>
            </table>
            <div id="iss-empty" class="iss-empty">No issues yet — run a Hunt or Ghost scan and findings appear here.</div>
          </div>
          <div class="iss-detail-wrap">
            <div class="iss-dtabs" id="iss-dtabs">
              <button data-dt="advisory" class="active">Advisory</button>
              <button data-dt="request">Request</button>
              <button data-dt="response">Response</button>
              <button data-dt="poc">PoC</button>
            </div>
            <div id="iss-detail" class="iss-detail">
              <div class="none">Select an issue to view its details.</div>
            </div>
          </div>
        </div>
      </section>

      <section id="pane-scope" class="pane">
        <div class="pad">
          <h2>Scope</h2>
          <p class="sub">Paste URLs, domains, or IP addresses that are in scope for
            <b id="scope-project">—</b>. Testing (Ghost's tools) and reported findings (Hunt) are
            limited to these hosts and their subdomains. Leave empty to scan only the target itself.</p>
          <div class="card" style="max-width:720px;">
            <label style="display:block; font-size:12px; color:var(--muted); margin-bottom:6px;">Add to scope</label>
            <textarea id="scope-input" rows="4"
              placeholder="https://example.com&#10;api.example.com&#10;10.0.0.5"
              style="width:100%; font:inherit; font-size:13px; color:var(--fg); background:var(--bg);
                border:1px solid var(--border); border-radius:6px; padding:8px 10px; resize:vertical;"></textarea>
            <div style="display:flex; gap:10px; align-items:center; margin-top:8px;">
              <button id="scope-add" class="run">+ Add to scope</button>
              <span id="scope-msg" style="color:var(--muted); font-size:12px;"></span>
            </div>
          </div>
          <div style="max-width:720px; margin-top:18px;">
            <div style="display:flex; align-items:center; margin-bottom:8px;">
              <b style="font-size:13px;">In scope (<span id="scope-count">0</span>)</b>
              <span class="spacer" style="flex:1;"></span>
              <a id="scope-clear" style="color:var(--accent); font-size:12px; cursor:pointer;">clear all</a>
            </div>
            <div id="scope-list" class="scope-list"></div>
          </div>
        </div>
      </section>

      <section id="pane-auth" class="pane frame"></section>

      <section id="pane-ghost" class="pane">
        <div class="pad">
          <h2>Ghost — autonomous investigation</h2>
          <p class="sub">Enter a target and run. Events stream below in real time.</p>
          <div class="row">
            <div><label>Target</label><input id="g-target" type="text" placeholder="https://example.com"></div>
            <div><label>Objective (optional)</label><input id="g-obj" type="text" placeholder="Find and validate security vulnerabilities."></div>
            <button id="g-run" class="run">Run</button>
            <button id="g-stop" class="stop" disabled>Stop</button>
          </div>
          <div id="g-msg" style="color:var(--muted); font-size:12px;"></div>
          <div class="ghost-toolbar">
            <span>events <b id="g-count">0</b></span>
            <span>tools <b id="g-tools">0</b></span>
            <span>elapsed <b id="g-elapsed">0s</b></span>
            <span id="g-autoscroll" class="autoscroll-toggle" title="click to toggle">⤓ autoscroll: on</span>
            <button id="g-save" class="btn" title="Save this run as a standalone HTML file">Save HTML</button>
          </div>
          <div id="ghost-log"></div>
        </div>
      </section>

      <section id="pane-repeater" class="pane">
        <div class="rep-tabbar" id="rep-tabbar"></div>
        <div class="rep-toolbar">
          <input id="rep-target" type="text" spellcheck="false"
            placeholder="Target — https://host:port (or leave blank to use the Host header)">
          <button id="rep-send" class="run">Send</button>
          <button id="rep-toar" class="rep-tipbtn" title="Send this request to AutoRepeater to fuzz it">⇥ AutoRepeater</button>
          <span class="rep-hist">
            <button id="rep-prev" title="Previous send" disabled>‹</button>
            <span id="rep-histlabel">0 of 0</span>
            <button id="rep-next" title="Next send" disabled>›</button>
          </span>
          <span class="spacer"></span>
          <span id="rep-status" class="rep-status"></span>
          <button id="rep-tips" class="rep-tipbtn" title="Hover any header, method, status code, or tag for an explanation">Tips: off</button>
          <button id="rep-pretty" class="rep-tipbtn" title="Pretty-print the response body (JSON / XML / HTML). Headers are left as-is; toggle off for the raw bytes.">Beautify: off</button>
          <div class="rep-settings">
            <button id="rep-gear" class="rep-gear" title="Font & colors">Aa ▾</button>
            <div id="rep-pop" class="rep-pop">
              <h4>Font</h4>
              <div class="rep-frow"><label for="rep-font">Family</label><select id="rep-font"></select></div>
              <div class="rep-frow"><label for="rep-size">Size</label><select id="rep-size"></select></div>
              <div class="rep-frow"><label for="rep-line">Line spacing</label><select id="rep-line"></select></div>
              <h4>Colors</h4>
              <div class="rep-frow"><label for="rep-theme">Theme</label><select id="rep-theme"></select></div>
              <details>
                <summary>Customize individual colors</summary>
                <div class="rep-colors" id="rep-colors"></div>
              </details>
              <button id="rep-reset" class="rep-reset">Reset to defaults</button>
            </div>
          </div>
        </div>
        <div class="rep-split">
          <div class="rep-col">
            <div class="rep-colhdr">Request</div>
            <div class="rep-editwrap">
              <pre id="rep-request-hl" class="rep-hl rep-code" aria-hidden="true"></pre>
              <textarea id="rep-request" class="rep-input" spellcheck="false"
                placeholder="Raw HTTP request…"></textarea>
            </div>
          </div>
          <div class="rep-col">
            <div class="rep-colhdr">Response</div>
            <pre id="rep-response" class="rep-resp rep-code"></pre>
          </div>
        </div>
      </section>

      <section id="pane-autorepeater" class="pane">
        <div class="ar-toolbar">
          <input id="ar-target" class="ar-target" type="text" spellcheck="false"
            placeholder="Target — https://host:port">
          <select id="ar-attack" title="Attack type">
            <option value="sniper">Sniper</option>
            <option value="batteringram">Battering ram</option>
            <option value="pitchfork">Pitchfork</option>
            <option value="clusterbomb">Cluster bomb</option>
          </select>
          <button id="ar-mark" class="btn2" title="Wrap the selected text in § as a payload position">§ Mark</button>
          <button id="ar-clearpos" class="btn2" title="Remove all § position markers">Clear §</button>
          <span class="spacer"></span>
          <span id="ar-progress" class="ar-progress"></span>
          <button id="ar-start" class="run">Start attack</button>
          <button id="ar-stop" class="stop" disabled>Stop</button>
        </div>
        <div class="ar-config">
          <div class="ar-col">
            <div class="ar-colhdr">Request template — select a value, click “§ Mark” to make it a position</div>
            <textarea id="ar-template" class="ar-editor" spellcheck="false"
              placeholder="Paste a raw HTTP request here, mark the values to fuzz with §, then Start."></textarea>
          </div>
          <div class="ar-col">
            <div class="ar-colhdr">Payloads <span id="ar-poscount" class="ar-poscount"></span></div>
            <div id="ar-payloads" class="ar-payloads"></div>
            <div class="ar-proc">
              <div class="ar-proc-hd">Payload processing <button id="ar-addrule" class="ar-addrule">+ rule</button></div>
              <div id="ar-rules" class="ar-rules"></div>
            </div>
            <div class="ar-options">
              <label>Concurrency <input id="ar-conc" type="number" min="1" max="50" value="10"></label>
              <label>Throttle ms <input id="ar-throttle" type="number" min="0" value="0"></label>
              <label class="ar-grep-l">Grep-match <input id="ar-grep" type="text" placeholder="e.g. error"></label>
              <label class="ar-grep-l">Grep-extract <input id="ar-extract" type="text" placeholder="regex, opt. (capture)"></label>
            </div>
          </div>
        </div>
        <div class="ar-results">
          <div class="ar-table-wrap">
            <table class="ar-table"><thead><tr id="ar-thead"></tr></thead><tbody id="ar-tbody"></tbody></table>
            <div id="ar-empty" class="ar-empty">Configure an attack above and press Start — results stream here. Sort any column to spot anomalies.</div>
          </div>
          <div class="ar-detail-wrap">
            <div class="ar-dtabs">
              <button data-ard="request" class="active">Request</button>
              <button data-ard="response">Response</button>
            </div>
            <pre id="ar-detail" class="rep-resp rep-code"></pre>
          </div>
        </div>
      </section>
    </main>
  </div>
</div>
<div id="ctxmenu" class="ctx"><button id="ctx-del">Delete project</button></div>
<div id="issue-ctx" class="iss-ctx"></div>
<div id="mod-tooltip" class="mod-tooltip"></div>
<div id="rep-tip"></div>
<div id="session-modal" class="modal-overlay">
  <div class="modal">
    <div class="modal-head">
      <h2>Beatrix Session</h2>
      <button id="sess-cancel" class="modal-cancel" hidden>✕</button>
    </div>
    <p class="modal-sub">A <b>session</b> holds a whole workspace — all its projects, scans,
      issues, and Repeater tabs. Open a recent one, or browse anywhere on disk to create or open a session folder.</p>
    <div class="session-tabs">
      <button data-stab="recent" class="active">Recent</button>
      <button data-stab="browse">Browse / New</button>
    </div>
    <div id="sess-recent" class="session-pane">
      <div id="sess-recent-list" class="recent-list"></div>
    </div>
    <div id="sess-browse" class="session-pane" hidden>
      <div class="fs-bar">
        <button id="fs-home" class="fs-btn" title="Home">~</button>
        <button id="fs-root" class="fs-btn" title="Filesystem root (/)">/</button>
        <button id="fs-up" class="fs-btn" title="Up one folder">↑</button>
        <input id="fs-path" class="fs-path-input" spellcheck="false"
          title="Type or paste any absolute path, then press Enter" placeholder="/type/any/path…">
        <button id="fs-go" class="fs-btn" title="Go to the typed path">Go</button>
      </div>
      <div id="fs-list" class="fs-list"></div>
      <div class="fs-actions">
        <input id="fs-newname" type="text" placeholder="new-session-name" spellcheck="false">
        <button id="fs-create" class="run">Create session here</button>
        <button id="fs-open" class="btn2" title="Open the current folder as a session">Open this folder</button>
      </div>
      <div id="sess-msg" class="sess-msg"></div>
    </div>
  </div>
</div>
<script>
const TAGS = { thinking:"[thinking]", system_prompt:"[system]", prompt:"[prompt]",
  reasoning:"[reasoning]", tool_start:"[tool]", tool_end:"[result]", agent_start:"[agent]",
  agent_end:"[/agent]", finding:"[finding]", verdict:"[verdict]", done:"[done]" };
const esc = s => String(s).replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const $ = id => document.getElementById(id);

// ── Tabs: swap panes in-place, never open a new tab/port ──
let authLoaded = false;
document.querySelectorAll("nav button").forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll("nav button").forEach(b => b.classList.toggle("active", b === btn));
    const tab = btn.dataset.tab;
    document.querySelectorAll(".pane").forEach(p => p.classList.toggle("active", p.id === "pane-" + tab));
    if (tab === "auth" && !authLoaded) {           // lazy-load the auth GUI iframe once
      $("pane-auth").innerHTML = '<iframe src="/auth" title="Beatrix Auth"></iframe>';
      authLoaded = true;
    }
    if (tab === "issues") loadIssuesFor(activeProject);   // freshen on view
    if (tab === "repeater") loadRepeaterFor(activeProject);
    if (tab === "autorepeater") loadAutoRepeaterFor(activeProject);
    reclampSplitters();   // a newly-shown pane can now measure itself
  };
});

// ── Resizable panes: a draggable gutter between two flex children ──
// One reusable splitter for every module. `axis` is "x" for side-by-side
// columns (a vertical bar you drag left/right) or "y" for stacked rows (a
// horizontal bar you drag up/down). The first pane gets an explicit pixel
// size; the second flexes to fill the rest. The chosen size persists per
// `storeKey` and is re-clamped on window resize / tab switch so it can never
// collapse a pane or overflow the container. Double-click resets to default;
// arrow keys (when the bar is focused) nudge it for keyboard users.
const _splitters = [];
function makeSplitter(container, axis, storeKey) {
  if (!container) return;
  const kids = Array.prototype.filter.call(container.children,
    n => n.nodeType === 1 && !n.classList.contains("splitter"));
  if (kids.length < 2) return;
  const first = kids[0], horiz = axis === "x";
  const g = document.createElement("div");
  g.className = "splitter " + (horiz ? "splitter-x" : "splitter-y");
  g.tabIndex = 0;
  g.setAttribute("role", "separator");
  g.setAttribute("aria-orientation", horiz ? "vertical" : "horizontal");
  g.title = "Drag to resize · double-click to reset";
  container.insertBefore(g, kids[1]);

  const MIN = 60;                                            // px floor for either pane
  const sizeOf = () => horiz ? container.clientWidth : container.clientHeight;
  const gsz = () => (horiz ? g.offsetWidth : g.offsetHeight) || 7;
  const clamp = (v) => Math.max(MIN, Math.min(v, sizeOf() - MIN - gsz()));
  let px = null;
  const apply = (v) => { px = clamp(v); first.style.flex = "0 0 " + px + "px"; };
  const persist = () => { if (storeKey) { try { localStorage.setItem("beatrix.split." + storeKey, String(px)); } catch (e) {} } };
  const reclamp = () => { if (px != null && sizeOf() > 0) first.style.flex = "0 0 " + clamp(px) + "px"; };

  if (storeKey) {                                            // restore last size (clamped lazily once visible)
    try { const v = parseFloat(localStorage.getItem("beatrix.split." + storeKey));
      if (v > 0) { px = v; first.style.flex = "0 0 " + v + "px"; } } catch (e) {}
  }
  let drag = false;
  g.addEventListener("pointerdown", (e) => {
    drag = true;
    try { g.setPointerCapture(e.pointerId); } catch (_) {}
    document.body.style.cursor = horiz ? "col-resize" : "row-resize";
    document.body.style.userSelect = "none";
    e.preventDefault();
  });
  g.addEventListener("pointermove", (e) => {
    if (!drag) return;
    const r = container.getBoundingClientRect();
    apply(horiz ? (e.clientX - r.left) : (e.clientY - r.top));
    e.preventDefault();
  });
  const end = (e) => {
    if (!drag) return;
    drag = false;
    try { g.releasePointerCapture(e.pointerId); } catch (_) {}
    document.body.style.cursor = ""; document.body.style.userSelect = "";
    persist();
  };
  g.addEventListener("pointerup", end);
  g.addEventListener("pointercancel", end);
  g.addEventListener("dblclick", () => {
    px = null; first.style.flex = "";
    if (storeKey) { try { localStorage.removeItem("beatrix.split." + storeKey); } catch (e) {} }
  });
  g.addEventListener("keydown", (e) => {
    const cur = horiz ? first.offsetWidth : first.offsetHeight;
    const step = e.shiftKey ? 40 : 12;
    let nv = null;
    if (horiz && e.key === "ArrowLeft") nv = cur - step;
    else if (horiz && e.key === "ArrowRight") nv = cur + step;
    else if (!horiz && e.key === "ArrowUp") nv = cur - step;
    else if (!horiz && e.key === "ArrowDown") nv = cur + step;
    if (nv == null) return;
    apply(nv); persist(); e.preventDefault();
  });
  _splitters.push({ reclamp });
}
function reclampSplitters() { for (const s of _splitters) s.reclamp(); }
function initSplitters() {
  makeSplitter(document.querySelector(".iss-split"), "y", "iss");        // list / advisory
  makeSplitter(document.querySelector(".rep-split"), "x", "rep");        // request / response
  makeSplitter(document.querySelector(".ar-config"), "x", "ar-config");  // template / payloads
  makeSplitter(document.querySelector(".ar-results"), "x", "ar-results");// results / detail
}
window.addEventListener("resize", reclampSplitters);
initSplitters();

// ── Ghost: each project has its OWN run + event stream on the server.
// `pollProject` is the project id the in-flight poll loop belongs to; every
// poll checks it's still current before rendering or rescheduling, so a run
// left going in another project can never leak into (or get cut off by
// switching away from) the one currently on screen.
let since = 0, pollProject = null;
// `autoscroll` is a UI preference, not run data — it's intentionally NOT reset
// on project switch, matching the standalone GHOST v2 dashboard.
let ghostTools = 0, autoscroll = true, ghostStarted = null;

function renderEvent(ev) {
  const d = document.createElement("div");
  d.className = "ev " + ev.type;
  const tag = TAGS[ev.type] || ev.type;
  let html = `<span class="ts">${new Date(ev.ts*1000).toLocaleTimeString()}</span><span class="tag">${tag}</span>${esc(ev.text||"")}`;
  if (ev.detail) html += `<span class="detail">${esc(ev.detail)}</span>`;
  d.innerHTML = html;
  $("ghost-log").appendChild(d);
  if (ev.type === "tool_start") { ghostTools++; $("g-tools").textContent = ghostTools; }
}
async function poll(id) {
  if (id !== pollProject) return;               // a different project is on screen now
  let r;
  try {
    r = await (await fetch("/ghost/events?since=" + since + "&project=" + id)).json();
  } catch (e) { setTimeout(() => poll(id), 600); return; }
  if (id !== pollProject) return;                // switched away while this fetch was in flight
  for (const ev of r.events) { renderEvent(ev); since = ev.seq; }
  $("g-count").textContent = since;
  if (autoscroll) $("ghost-log").scrollTop = $("ghost-log").scrollHeight;
  if (ghostStarted) $("g-elapsed").textContent = Math.round(Date.now()/1000 - ghostStarted) + "s";
  if (r.done) { $("g-run").disabled = false; $("g-stop").disabled = true;
    $("g-msg").textContent = "Run finished."; return; }
  $("g-run").disabled = true; $("g-stop").disabled = false;
  setTimeout(() => poll(id), 600);
}
// Rebuild the Ghost pane for `id`: clear the shared log DOM, then replay that
// project's own event history from the server (not from memory — the whole
// point is this survives having been switched away from) and resume polling
// if it's still running.
async function loadGhostViewFor(id) {
  $("ghost-log").innerHTML = ""; since = 0; ghostTools = 0; ghostStarted = null;
  $("g-count").textContent = "0"; $("g-tools").textContent = "0"; $("g-elapsed").textContent = "0s";
  pollProject = id;
  $("g-run").disabled = false; $("g-stop").disabled = true; $("g-msg").textContent = "";
  let st = {};
  try { st = await (await fetch("/ghost/state?project=" + id)).json(); } catch (e) {}
  if (id !== pollProject) return;                 // switched again while loading
  if (st && st.target) {
    $("g-target").value = st.target;
    $("g-obj").value = st.objective || "";
    ghostStarted = st.started || null;
    $("g-run").disabled = !!st.running; $("g-stop").disabled = !st.running;
    $("g-msg").textContent = st.running ? "Running: " + st.target : "Run finished.";
    poll(id);                                     // replays history; keeps going if still running
  } else {
    $("g-target").value = ""; $("g-obj").value = "";
  }
}
$("g-run").onclick = async () => {
  const target = $("g-target").value.trim();
  if (!target) { $("g-msg").textContent = "Enter a target first."; return; }
  $("g-run").disabled = true; $("g-msg").textContent = "Starting…";
  $("ghost-log").innerHTML = ""; since = 0; ghostTools = 0; ghostStarted = Date.now() / 1000;
  $("g-count").textContent = "0"; $("g-tools").textContent = "0"; $("g-elapsed").textContent = "0s";
  pollProject = activeProject;
  try {
    const r = await (await fetch("/ghost/run", { method:"POST",
      body: JSON.stringify({ target, objective: $("g-obj").value.trim(), project: activeProject }) })).json();
    if (!r.ok) { $("g-msg").textContent = "Error: " + (r.error || "could not start"); $("g-run").disabled = false; return; }
    $("g-stop").disabled = false;
    $("g-msg").textContent = "Running: " + target;
    poll(activeProject);
  } catch (e) { $("g-msg").textContent = "Error: " + e; $("g-run").disabled = false; }
};
$("g-stop").onclick = async () => {
  $("g-stop").disabled = true; $("g-msg").textContent = "Stopping…";
  try {
    const r = await (await fetch("/ghost/stop", { method:"POST",
      body: JSON.stringify({ project: activeProject }) })).json();
    if (!r.ok) { $("g-msg").textContent = "Error: " + (r.error || "could not stop"); $("g-stop").disabled = false; }
  } catch (e) { $("g-msg").textContent = "Error: " + e; $("g-stop").disabled = false; }
};

$("g-autoscroll").onclick = () => {
  autoscroll = !autoscroll;
  $("g-autoscroll").textContent = "⤓ autoscroll: " + (autoscroll ? "on" : "off");
};

// Save the CURRENT project's ghost log as a standalone, self-contained HTML
// file for the record — same feature as the standalone GHOST v2 dashboard,
// scoped to just this run's content (not the whole Suite shell/other panes).
function saveGhostHtml() {
  const projName = projectName(activeProject);
  const target = $("g-target").value || "—";
  const objective = $("g-obj").value || "—";
  const statusText = $("g-msg").textContent || "";
  const logHtml = $("ghost-log").innerHTML;
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>GHOST v2 — ${esc(projName)} — ${esc(target)}</title>
<style>
  :root { --bg:#0a0f0c; --panel:#0e150f; --border:#1e2b22; --fg:#d3ddd2; --muted:#6f8175;
    --accent:#35d07e; --red:#ff6b6b; --green:#57d98a; --yellow:#f5c451; --violet:#b98cff; --blue:#5aa9ff; }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f5f8f4; --panel:#ffffff; --border:#d7e0d5; --fg:#1c2620; --muted:#5f7167;
      --accent:#12864e; --red:#c0392b; --green:#1a7f47; --yellow:#9a7b12; --violet:#7a3ff2; --blue:#0969da; } }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
    font:14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; padding:20px 24px 60px; }
  h1 { font-size:16px; margin:0 0 6px; }
  .meta { color:var(--muted); font-size:12px; margin-bottom:2px; }
  .ev { padding:2px 0; white-space:pre-wrap; word-break:break-word; }
  .ev .ts { color:var(--muted); margin-right:8px; font-size:12px; }
  .ev .tag { font-weight:700; margin-right:8px; }
  .ev.tool_start .tag { color:var(--yellow); } .ev.tool_end .tag { color:var(--blue); }
  .ev.agent_start .tag { color:var(--accent); } .ev.agent_end .tag { color:var(--muted); }
  .ev.reasoning .tag, .ev.thinking .tag { color:var(--violet); }
  .ev.finding .tag { color:var(--red); } .ev.verdict .tag { color:var(--green); }
  .ev .detail { display:block; color:var(--muted); margin:2px 0 2px 84px; padding:6px 9px;
    background:var(--panel); border:1px solid var(--border); border-radius:6px; max-height:220px; overflow:auto; }
</style></head><body>
<h1>GHOST v2 — ${esc(projName)}</h1>
<div class="meta">target <b>${esc(target)}</b> · objective <b>${esc(objective)}</b></div>
<div class="meta">${esc(statusText)} · saved ${new Date().toLocaleString()}</div>
<div style="margin-top:14px; border-top:1px solid var(--border); padding-top:12px;">${logHtml}</div>
</body></html>`;
  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const safeProj = projName.replace(/[^a-z0-9.\-]+/gi, "_");
  const safeTarget = target.replace(/[^a-z0-9.\-]+/gi, "_");
  const ts = new Date().toISOString().replace(/[:]/g, "-").replace("T", "_").slice(0, 19);
  a.href = url;
  a.download = "ghost2-" + safeProj + "-" + safeTarget + "-" + ts + ".html";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
$("g-save").onclick = saveGhostHtml;

// ── Hunt: the Dashboard workstation — module/preset control panel + terminal.
// Structurally mirrors the Ghost pane above (own per-project broker on the
// server, same rebuild-not-wipe project-switch pattern, same toolbar), kept
// as its own separate set of functions rather than sharing code with Ghost's,
// since Ghost's per-project streaming took real care to get right and this
// avoids risking a regression there for the sake of DRY-ing working code.
const HUNT_TAGS = { phase:"phase", phase_done:"✓ phase", scanner_start:"▸ scanner",
  scanner_done:"result", scanner_error:"✗ error", finding:"finding",
  verdict:"verdict", info:"ℹ info" };
let hSince = 0, hPollProject = null, hFindings = 0, hAutoscroll = true, hStarted = null;
let hCatalog = { modules: [], presets: [] };
let hSelected = new Set();

function renderHuntEvent(ev) {
  const d = document.createElement("div");
  d.className = "ev " + ev.type;
  const tag = HUNT_TAGS[ev.type] || ev.type;
  let html = `<span class="ts">${new Date(ev.ts*1000).toLocaleTimeString()}</span><span class="tag">${tag}</span>${esc(ev.text||"")}`;
  if (ev.detail) html += `<span class="detail">${esc(ev.detail)}</span>`;
  d.innerHTML = html;
  $("hunt-log").appendChild(d);
  if (ev.type === "finding") { hFindings++; $("h-findings").textContent = hFindings; }
}
async function hPoll(id) {
  if (id !== hPollProject) return;
  let r;
  try { r = await (await fetch("/hunt/events?since=" + hSince + "&project=" + id)).json(); }
  catch (e) { setTimeout(() => hPoll(id), 600); return; }
  if (id !== hPollProject) return;
  for (const ev of r.events) { renderHuntEvent(ev); hSince = ev.seq; }
  $("h-count").textContent = hSince;
  if (hAutoscroll) $("hunt-log").scrollTop = $("hunt-log").scrollHeight;
  if (hStarted) $("h-elapsed").textContent = Math.round(Date.now()/1000 - hStarted) + "s";
  if (r.done) { $("h-run").disabled = false; $("h-stop").disabled = true;
    $("h-msg").textContent = "Run finished."; return; }
  $("h-run").disabled = true; $("h-stop").disabled = false;
  setTimeout(() => hPoll(id), 600);
}
async function loadHuntViewFor(id) {
  $("hunt-log").innerHTML = ""; hSince = 0; hFindings = 0; hStarted = null;
  $("h-count").textContent = "0"; $("h-findings").textContent = "0"; $("h-elapsed").textContent = "0s";
  hPollProject = id;
  $("h-run").disabled = false; $("h-stop").disabled = true; $("h-msg").textContent = "";
  let st = {};
  try { st = await (await fetch("/hunt/state?project=" + id)).json(); } catch (e) {}
  if (id !== hPollProject) return;
  const ap = projects.find(p => p.id === id);
  $("h-term-title").textContent = "beatrix@hunt — " + projectName(id);
  if (st && st.target) {
    hStarted = st.started || null;
    $("h-run").disabled = !!st.running; $("h-stop").disabled = !st.running;
    $("h-msg").textContent = st.running ? "Running: " + st.target : "Run finished.";
    hPoll(id);
  }
}

// ── Module/preset control panel ──
function showModTooltip(x, y, text) {
  const t = $("mod-tooltip");
  t.textContent = text;
  t.style.left = (x + 14) + "px"; t.style.top = (y + 14) + "px";
  t.style.display = "block";
}
function hideModTooltip() { $("mod-tooltip").style.display = "none"; }

function renderModules() {
  const wrap = $("h-modules"); wrap.innerHTML = "";
  let lastCat = null;
  for (const m of hCatalog.modules) {
    if (m.category !== lastCat) {
      const h = document.createElement("div");
      h.className = "mod-cat"; h.textContent = m.category;
      wrap.appendChild(h); lastCat = m.category;
    }
    const row = document.createElement("label");
    row.className = "mod-row"; row.dataset.desc = m.description;
    const cb = document.createElement("input");
    cb.type = "checkbox"; cb.dataset.key = m.key; cb.checked = hSelected.has(m.key);
    cb.onchange = () => {
      if (cb.checked) hSelected.add(m.key); else hSelected.delete(m.key);
      updateSelCount(); syncPresetHighlight();
    };
    row.appendChild(cb);
    row.appendChild(document.createTextNode(" " + m.name));
    wrap.appendChild(row);
  }
  // Hover tooltip via delegation — one listener instead of one per row.
  wrap.onmouseover = (e) => {
    const row = e.target.closest(".mod-row");
    if (row) showModTooltip(e.clientX, e.clientY, row.dataset.desc);
  };
  wrap.onmousemove = (e) => {
    const row = e.target.closest(".mod-row");
    if (row) showModTooltip(e.clientX, e.clientY, row.dataset.desc);
  };
  wrap.onmouseout = (e) => { if (!e.relatedTarget || !e.relatedTarget.closest(".mod-row")) hideModTooltip(); };
}
function updateSelCount() {
  $("h-selcount").textContent = hSelected.size + " selected";
}
function syncPresetHighlight() {
  // A preset chip lights up only when the current selection exactly matches it.
  for (const chip of document.querySelectorAll(".preset-chip")) {
    const preset = hCatalog.presets.find(p => p.key === chip.dataset.key);
    const matches = preset && preset.modules.length === hSelected.size
      && preset.modules.every(k => hSelected.has(k));
    chip.classList.toggle("active", !!matches);
  }
}
function applySelection(keys) {
  hSelected = new Set(keys);
  for (const cb of document.querySelectorAll("#h-modules input[type=checkbox]")) {
    cb.checked = hSelected.has(cb.dataset.key);
  }
  updateSelCount(); syncPresetHighlight();
}
function renderPresets() {
  const wrap = $("h-presets"); wrap.innerHTML = "";
  for (const p of hCatalog.presets) {
    const chip = document.createElement("button");
    chip.type = "button"; chip.className = "preset-chip"; chip.dataset.key = p.key;
    chip.textContent = p.name; chip.title = p.description;
    chip.onclick = () => applySelection(p.modules);
    wrap.appendChild(chip);
  }
}
async function loadHuntCatalog() {
  hCatalog = await (await fetch("/hunt/catalog")).json();
  renderPresets(); renderModules();
  const standard = hCatalog.presets.find(p => p.key === "standard");
  applySelection(standard ? standard.modules : []);  // sensible one-click default
}
$("h-selall").onclick = (e) => { e.preventDefault(); applySelection(hCatalog.modules.map(m => m.key)); };
$("h-selnone").onclick = (e) => { e.preventDefault(); applySelection([]); };

$("h-autoscroll").onclick = () => {
  hAutoscroll = !hAutoscroll;
  $("h-autoscroll").textContent = "⤓ autoscroll: " + (hAutoscroll ? "on" : "off");
};

$("h-run").onclick = async () => {
  const target = $("h-target").value.trim();
  if (!target) { $("h-msg").textContent = "Enter a target first."; return; }
  if (hSelected.size === 0) { $("h-msg").textContent = "Select at least one module."; return; }
  $("h-run").disabled = true; $("h-msg").textContent = "Starting…";
  $("hunt-log").innerHTML = ""; hSince = 0; hFindings = 0; hStarted = Date.now() / 1000;
  $("h-count").textContent = "0"; $("h-findings").textContent = "0"; $("h-elapsed").textContent = "0s";
  hPollProject = activeProject;
  const matchedPreset = hCatalog.presets.find(p =>
    p.modules.length === hSelected.size && p.modules.every(k => hSelected.has(k)));
  try {
    const r = await (await fetch("/hunt/run", { method:"POST", body: JSON.stringify({
      target, modules: Array.from(hSelected), preset: matchedPreset ? matchedPreset.key : "custom",
      project: activeProject,
    }) })).json();
    if (!r.ok) { $("h-msg").textContent = "Error: " + (r.error || "could not start"); $("h-run").disabled = false; return; }
    $("h-stop").disabled = false;
    $("h-msg").textContent = "Running: " + target;
    hPoll(activeProject);
  } catch (e) { $("h-msg").textContent = "Error: " + e; $("h-run").disabled = false; }
};
$("h-stop").onclick = async () => {
  $("h-stop").disabled = true; $("h-msg").textContent = "Stopping…";
  try {
    const r = await (await fetch("/hunt/stop", { method:"POST",
      body: JSON.stringify({ project: activeProject }) })).json();
    if (!r.ok) { $("h-msg").textContent = "Error: " + (r.error || "could not stop"); $("h-stop").disabled = false; }
  } catch (e) { $("h-msg").textContent = "Error: " + e; $("h-stop").disabled = false; }
};

function saveHuntHtml() {
  const projName = projectName(activeProject);
  const target = $("h-target").value || "—";
  const statusText = $("h-msg").textContent || "";
  const logHtml = $("hunt-log").innerHTML;
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Hunt — ${esc(projName)} — ${esc(target)}</title>
<style>
  :root { --bg:#0a0f0c; --panel:#0e150f; --border:#1e2b22; --fg:#d3ddd2; --muted:#6f8175;
    --accent:#35d07e; --red:#ff6b6b; --green:#57d98a; --yellow:#f5c451; --violet:#b98cff; --blue:#5aa9ff; }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f5f8f4; --panel:#ffffff; --border:#d7e0d5; --fg:#1c2620; --muted:#5f7167;
      --accent:#12864e; --red:#c0392b; --green:#1a7f47; --yellow:#9a7b12; --violet:#7a3ff2; --blue:#0969da; } }
  * { box-sizing:border-box; }
  body { margin:0; background:#050607; color:var(--fg);
    font:14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; padding:20px 24px 60px; }
  h1 { font-size:16px; margin:0 0 6px; }
  .meta { color:var(--muted); font-size:12px; margin-bottom:2px; }
  .ev { padding:2px 0; white-space:pre-wrap; word-break:break-word; }
  .ev .ts { color:var(--muted); margin-right:8px; font-size:12px; }
  .ev .tag { font-weight:700; margin-right:8px; }
  .ev.phase .tag { color:var(--accent); } .ev.phase_done .tag { color:var(--green); }
  .ev.scanner_start .tag { color:var(--yellow); } .ev.scanner_done .tag { color:var(--blue); }
  .ev.scanner_error .tag { color:var(--red); } .ev.info .tag { color:var(--muted); }
  .ev.finding .tag { color:var(--red); } .ev.verdict .tag { color:var(--green); }
  .ev .detail { display:block; color:var(--muted); margin:2px 0 2px 84px; padding:6px 9px;
    background:var(--panel); border:1px solid var(--border); border-radius:6px; max-height:220px; overflow:auto; }
</style></head><body>
<h1>BEATRIX HUNT — ${esc(projName)}</h1>
<div class="meta">target <b>${esc(target)}</b></div>
<div class="meta">${esc(statusText)} · saved ${new Date().toLocaleString()}</div>
<div style="margin-top:14px; border-top:1px solid var(--border); padding-top:12px;">${logHtml}</div>
</body></html>`;
  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const safeProj = projName.replace(/[^a-z0-9.\-]+/gi, "_");
  const safeTarget = target.replace(/[^a-z0-9.\-]+/gi, "_");
  const ts = new Date().toISOString().replace(/[:]/g, "-").replace("T", "_").slice(0, 19);
  a.href = url;
  a.download = "hunt-" + safeProj + "-" + safeTarget + "-" + ts + ".html";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
$("h-save").onclick = saveHuntHtml;

// ── Scope: per-project list of in-scope hosts (Burp-style target scope) ──
async function loadScopeFor(id) {
  const ap = projects.find(p => p.id === id);
  $("scope-project").textContent = ap ? ap.name : "—";
  let entries = [];
  try { entries = (await (await fetch("/scope?project=" + id)).json()).scope || []; } catch (e) {}
  renderScopeList(entries);
}
function renderScopeList(entries) {
  const wrap = $("scope-list");
  $("scope-count").textContent = entries.length;
  if (!entries.length) {
    wrap.innerHTML = '<div class="scope-empty">No scope defined — Ghost and Hunt will scan only the target itself.</div>';
    return;
  }
  wrap.innerHTML = "";
  for (const host of entries) {
    const row = document.createElement("div");
    row.className = "scope-item";
    const span = document.createElement("span");
    span.className = "host"; span.textContent = host;
    const btn = document.createElement("button");
    btn.textContent = "✕ remove";
    btn.onclick = () => removeScopeEntry(host);
    row.appendChild(span); row.appendChild(btn);
    wrap.appendChild(row);
  }
}
async function addScopeEntries() {
  const text = $("scope-input").value;
  if (!text.trim()) { $("scope-msg").textContent = "Paste a URL, domain, or IP first."; return; }
  try {
    const r = await (await fetch("/scope/add", { method: "POST",
      body: JSON.stringify({ project: activeProject, text }) })).json();
    if (!r.ok) { $("scope-msg").textContent = "Error: " + (r.error || "could not add"); return; }
    $("scope-input").value = ""; $("scope-msg").textContent = "";
    renderScopeList(r.scope);
  } catch (e) { $("scope-msg").textContent = "Error: " + e; }
}
async function removeScopeEntry(host) {
  const r = await (await fetch("/scope/remove", { method: "POST",
    body: JSON.stringify({ project: activeProject, entry: host }) })).json();
  if (r.ok) renderScopeList(r.scope);
}
$("scope-add").onclick = addScopeEntries;
$("scope-clear").onclick = async () => {
  const r = await (await fetch("/scope/clear", { method: "POST",
    body: JSON.stringify({ project: activeProject }) })).json();
  if (r.ok) renderScopeList(r.scope);
};

// ── Issues: Burp-style master/detail. Every finding from a Hunt or Ghost run
// becomes a persistent, per-project issue you can inspect, re-triage, highlight
// or delete. The list is disk-backed on the server; the client mirrors it and
// re-fetches on tab/project switch and on a light poll so new findings appear
// live as a scan runs.
const SEV_RANK = { critical:0, high:1, medium:2, low:3, "info-high":4, info:5 };
const HL_COLORS = { red:"#ff5f57", orange:"#ff9f43", yellow:"#f7c948", green:"#28c840",
  blue:"#5aa9ff", purple:"#b98cff", gray:"#8a94a6" };
const ISS_COLS = [
  { key:"severity", label:"Severity" }, { key:"title", label:"Issue" },
  { key:"host", label:"Host" }, { key:"path", label:"Path" },
  { key:"module", label:"Module" }, { key:"confidence", label:"Confidence" },
];
let issuesData = [], issueSort = { key:"severity", dir:1 }, selectedIssue = null;
let issueDetailTab = "advisory", issueDetail = null;

function cmpIssues(a, b) {
  const k = issueSort.key;
  let av, bv;
  if (k === "severity") { av = SEV_RANK[a.severity] ?? 9; bv = SEV_RANK[b.severity] ?? 9; }
  else if (k === "discovered_at") { av = a.discovered_at || 0; bv = b.discovered_at || 0; }
  else { av = String(a[k] || "").toLowerCase(); bv = String(b[k] || "").toLowerCase(); }
  if (av < bv) return -1 * issueSort.dir;
  if (av > bv) return 1 * issueSort.dir;
  return (a.id - b.id);   // stable tiebreak by discovery order
}
function renderIssueHead() {
  const tr = $("iss-head"); tr.innerHTML = "";
  for (const c of ISS_COLS) {
    const th = document.createElement("th");
    const arrow = issueSort.key === c.key ? ` <span class="arrow">${issueSort.dir > 0 ? "▲" : "▼"}</span>` : "";
    th.innerHTML = c.label + arrow;
    th.onclick = () => {
      if (issueSort.key === c.key) issueSort.dir *= -1; else { issueSort.key = c.key; issueSort.dir = 1; }
      $("iss-sort").value = issueSort.key;
      renderIssues();
    };
    tr.appendChild(th);
  }
}
function renderIssues() {
  renderIssueHead();
  const body = $("iss-body"); body.innerHTML = "";
  const rows = issuesData.slice().sort(cmpIssues);
  const fpCount = issuesData.filter(i => i.false_positive).length;
  $("iss-count").textContent = fpCount
    ? `${issuesData.length} (${fpCount} false positive)` : issuesData.length;
  $("iss-empty").style.display = rows.length ? "none" : "block";
  for (const it of rows) {
    const tr = document.createElement("tr");
    if (it.highlight) tr.className = "hl-" + it.highlight;
    if (selectedIssue === it.id) tr.className += " sel";
    if (it.false_positive) tr.className += " fp";
    const fpTag = it.false_positive ? ` <span class="fptag">false positive</span>` : "";
    tr.innerHTML =
      `<td><span class="sev ${esc(it.severity)}">${esc(it.severity)}</span></td>` +
      `<td>${esc(it.title)}${fpTag}</td><td>${esc(it.host)}</td><td>${esc(it.path)}</td>` +
      `<td>${esc(it.module)}</td><td class="conf">${esc(it.confidence)}</td>`;
    tr.onclick = () => selectIssue(it.id);
    tr.oncontextmenu = (e) => { e.preventDefault(); showIssueCtx(e, it.id); };
    body.appendChild(tr);
  }
}
function updateIssueBadge(n) {
  const b = $("issues-badge");
  b.textContent = n; b.classList.toggle("show", n > 0);
}
async function loadIssuesFor(id) {
  $("iss-project").textContent = (projects.find(p => p.id === id) || {}).name || "—";
  let list = [];
  try { list = (await (await fetch("/issues?project=" + id)).json()).issues || []; } catch (e) {}
  if (id !== activeProject) return;      // switched away while fetching
  issuesData = list;
  updateIssueBadge(list.filter(i => !i.false_positive).length);
  if (selectedIssue !== null && !list.some(i => i.id === selectedIssue)) {
    selectedIssue = null; issueDetail = null; renderIssueDetail();
  }
  renderIssues();
}
async function selectIssue(id) {
  selectedIssue = id;
  renderIssues();
  try { issueDetail = (await (await fetch("/issues/detail?project=" + activeProject + "&id=" + id)).json()).issue; }
  catch (e) { issueDetail = null; }
  renderIssueDetail();
}
function fld(label, val, opts) {
  opts = opts || {};
  if (!val || (Array.isArray(val) && !val.length)) {
    return opts.hideEmpty ? "" : `<section><div class="lbl">${esc(label)}</div><div class="none">—</div></section>`;
  }
  let inner;
  if (opts.pre) inner = `<pre>${esc(val)}</pre>`;
  else if (opts.links) inner = "<ul>" + val.map(u =>
    /^https?:\/\//.test(u) ? `<li><a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a></li>` : `<li>${esc(u)}</li>`).join("") + "</ul>";
  else if (opts.list) inner = "<ul>" + val.map(s => `<li>${esc(s)}</li>`).join("") + "</ul>";
  else inner = `<div>${esc(val)}</div>`;
  return `<section><div class="lbl">${esc(label)}</div>${inner}</section>`;
}

// Request/Response tabs: show the captured transaction, or a clearly-labeled
// reconstruction, or an explicit "not captured" note — never a bare "—".
function reqRespView(label, val, synthesized, emptyMsg) {
  const lbl = `<div class="lbl">${esc(label)}</div>`;
  if (!val || !String(val).trim())
    return `<section>${lbl}<div class="none">${esc(emptyMsg)}</div></section>`;
  const note = synthesized
    ? `<div class="synthnote">Reconstructed from the finding's metadata — not the exact bytes sent on the wire.</div>`
    : "";
  return `<section>${lbl}${note}<pre>${esc(val)}</pre></section>`;
}
function renderIssueDetail() {
  const box = $("iss-detail");
  const d = issueDetail;
  if (!d) { box.innerHTML = '<div class="none">Select an issue to view its details.</div>'; return; }
  if (issueDetailTab === "advisory") {
    box.innerHTML =
      '<div class="detail-actions">' +
      `<button id="iss-fp" class="btn">${d.false_positive ? "Unmark false positive" : "Mark as false positive"}</button>` +
      '<button id="iss-to-ghost" class="btn">Validate with Ghost</button></div>' +
      (d.false_positive ? '<div class="fpbanner">Marked as a false positive — excluded from the open-issue count.</div>' : "") +
      `<h3>${esc(d.title)}</h3>` +
      `<div class="kv"><span class="sev ${esc(d.severity)}">${esc(d.severity)}</span> · ` +
      `confidence <b>${esc(d.confidence)}</b> · module <b>${esc(d.module)}</b> · ` +
      `found by <b>${esc(d.origin === "ghost" ? "Ghost agent" : "Hunt")}</b>${d.validated ? " · <b>validated</b>" : ""}</div>` +
      `<div class="kv">URL: <b>${esc(d.url || "—")}</b>${d.parameter ? " · parameter <b>" + esc(d.parameter) + "</b>" : ""}</div>` +
      fld("Description", d.description) + fld("Impact", d.impact) + fld("Remediation", d.remediation) +
      fld("Classifications", [d.cwe, d.owasp].filter(Boolean), { list:true, hideEmpty:true }) +
      fld("References / documentation", d.references, { links:true });
    $("iss-to-ghost").onclick = () => sendIssuesToGhost([d.id], "this issue");
    $("iss-fp").onclick = async () => {
      const nv = !d.false_positive;
      await fetch("/issues/update", { method:"POST",
        body: JSON.stringify({ project: activeProject, id: d.id, false_positive: nv }) });
      d.false_positive = nv;
      renderIssueDetail();
      loadIssuesFor(activeProject);
    };
  } else if (issueDetailTab === "request") {
    const canSend = d.request && String(d.request).trim();
    box.innerHTML =
      (canSend ? '<div class="detail-actions"><button id="iss-to-rep" class="btn">↪ Send to Repeater</button>' +
        '<button id="iss-to-ar" class="btn">⇥ Send to AutoRepeater</button></div>' : "") +
      reqRespView("HTTP request", d.request, d.request_synthesized,
        "No HTTP request was captured for this finding.");
    if (canSend) {
      $("iss-to-rep").onclick = () => sendIssueToRepeater(d);
      let arTarget = ""; try { arTarget = new URL(d.url).origin; } catch (e) {}
      $("iss-to-ar").onclick = () => sendToAutoRepeater(d.request, arTarget);
    }
  } else if (issueDetailTab === "response") {
    box.innerHTML = reqRespView("HTTP response", d.response, d.response_synthesized,
      "No HTTP response was captured for this finding.");
  } else {   // poc
    box.innerHTML =
      fld("Evidence", d.evidence, { pre:true }) +
      fld("Payload", d.payload, { pre:true, hideEmpty:true }) +
      fld("curl PoC", d.poc_curl, { pre:true, hideEmpty:true }) +
      fld("Python PoC", d.poc_python, { pre:true, hideEmpty:true }) +
      fld("Reproduction steps", d.reproduction_steps, { list:true });
  }
}
document.querySelectorAll("#iss-dtabs button").forEach(b => {
  b.onclick = () => {
    document.querySelectorAll("#iss-dtabs button").forEach(x => x.classList.toggle("active", x === b));
    issueDetailTab = b.dataset.dt; renderIssueDetail();
  };
});
$("iss-sort").onchange = () => { issueSort.key = $("iss-sort").value; issueSort.dir = 1; renderIssues(); };
$("iss-clear").onclick = async () => {
  if (!issuesData.length) return;
  if (!confirm("Delete all " + issuesData.length + " issue(s) in this project?")) return;
  await fetch("/issues/clear", { method:"POST", body: JSON.stringify({ project: activeProject }) });
  selectedIssue = null; issueDetail = null; renderIssueDetail();
  loadIssuesFor(activeProject);
};

// ── Send issues to Ghost for validation (individual, all, by severity, by module) ──
async function sendIssuesToGhost(ids, label) {
  ids = (ids || []).filter(x => x != null);
  if (!ids.length) return;
  let r;
  try { r = await (await fetch("/ghost/validate", { method:"POST",
    body: JSON.stringify({ project: activeProject, ids }) })).json(); }
  catch (e) { r = { ok:false, error:String(e) }; }
  document.querySelector('nav button[data-tab="ghost"]').click();   // watch the run
  loadGhostViewFor(activeProject);
  $("g-msg").textContent = r.ok
    ? ("Ghost validating " + (r.validating || ids.length) + " finding(s) — " + (label || "selected") + "…")
    : ("Could not start Ghost: " + (r.error || "unknown error"));
}
// The bulk menu: "all", by severity, and by module — computed from the loaded list.
function buildGhostMenu() {
  const menu = $("iss-ghost-menu");
  if (!issuesData.length) { menu.innerHTML = '<div class="ghost-menu-empty">No issues to send.</div>'; return; }
  const bySev = {}, byMod = {};
  for (const it of issuesData) {
    (bySev[it.severity] = bySev[it.severity] || []).push(it.id);
    (byMod[it.module || "unknown"] = byMod[it.module || "unknown"] || []).push(it.id);
  }
  let html = '<button class="ghost-menu-item" data-g="all">Validate all (' + issuesData.length + ')</button>';
  html += '<div class="ghost-menu-sec">By severity</div>';
  for (const s of ["critical", "high", "medium", "low", "info-high", "info"])
    if (bySev[s]) html += '<button class="ghost-menu-item" data-g="sev:' + s + '">' + esc(s) + ' (' + bySev[s].length + ')</button>';
  html += '<div class="ghost-menu-sec">By module</div>';
  for (const m of Object.keys(byMod).sort())
    html += '<button class="ghost-menu-item" data-g="mod:' + escAttr(m) + '">' + esc(m) + ' (' + byMod[m].length + ')</button>';
  menu.innerHTML = html;
  menu.querySelectorAll(".ghost-menu-item").forEach(b => {
    b.onclick = (e) => {
      e.stopPropagation();
      menu.classList.remove("open");
      const g = b.dataset.g;
      if (g === "all") sendIssuesToGhost(issuesData.map(i => i.id), "all issues");
      else if (g.startsWith("sev:")) { const s = g.slice(4); sendIssuesToGhost(bySev[s], s + " issues"); }
      else { const m = g.slice(4); sendIssuesToGhost(byMod[m], m + " issues"); }
    };
  });
}
$("iss-ghost-btn").onclick = (e) => {
  e.stopPropagation();
  const m = $("iss-ghost-menu");
  if (m.classList.toggle("open")) buildGhostMenu();
};
$("iss-ghost-menu").onclick = (e) => e.stopPropagation();
document.addEventListener("click", () => $("iss-ghost-menu").classList.remove("open"));

// Right-click menu: set severity / highlight / delete.
function showIssueCtx(e, id) {
  const m = $("issue-ctx");
  const it = issuesData.find(x => x.id === id) || {};
  const sevBtns = Object.keys(SEV_RANK).map(s =>
    `<button data-act="sev" data-v="${s}">${s}</button>`).join("");
  const swatches = Object.entries(HL_COLORS).map(([name, col]) =>
    `<span class="sw" title="${name}" style="background:${col}" data-act="hl" data-v="${name}"></span>`).join("") +
    `<button data-act="hl" data-v="none" style="font-size:11px; padding:1px 6px;">none</button>`;
  const fpLabel = it.false_positive ? "Unmark false positive" : "Mark as false positive";
  m.innerHTML =
    `<div class="lbl">Set severity</div><div class="opts">${sevBtns}</div>` +
    `<div class="lbl">Highlight</div><div class="opts">${swatches}</div>` +
    `<hr><button class="fp" data-act="fp" data-v="${it.false_positive ? "0" : "1"}">${fpLabel}</button>` +
    `<button class="del" data-act="del">Delete issue</button>`;
  m.dataset.iid = id;
  m.style.display = "block"; m.style.left = e.clientX + "px"; m.style.top = e.clientY + "px";
  // keep the menu on-screen
  const r = m.getBoundingClientRect();
  if (r.right > innerWidth) m.style.left = (innerWidth - r.width - 6) + "px";
  if (r.bottom > innerHeight) m.style.top = (innerHeight - r.height - 6) + "px";
  m.querySelectorAll("[data-act]").forEach(el => {
    el.onclick = async (ev) => {
      ev.stopPropagation();
      const act = el.dataset.act, v = el.dataset.v;
      $("issue-ctx").style.display = "none";
      if (act === "del") {
        await fetch("/issues/delete", { method:"POST", body: JSON.stringify({ project: activeProject, id }) });
        if (selectedIssue === id) { selectedIssue = null; issueDetail = null; renderIssueDetail(); }
      } else {
        const patch = { project: activeProject, id };
        if (act === "sev") patch.severity = v;
        else if (act === "fp") patch.false_positive = (v === "1");
        else patch.highlight = v;
        await fetch("/issues/update", { method:"POST", body: JSON.stringify(patch) });
        if (act === "fp" && issueDetail && issueDetail.id === id) {
          issueDetail.false_positive = (v === "1"); renderIssueDetail();
        }
      }
      loadIssuesFor(activeProject);
    };
  });
}

// ── Projects: left rail (switch / create / delete) ──
let projects = [], activeProject = null;
// A project's `id` identifies it (and keys its data on the server); `label` is
// the number on its tab. They diverge as soon as a project is deleted and its
// number gets reused, so never show an id — route every display through these.
function projectLabel(id) {
  const p = projects.find(x => x.id === id);
  return p && p.label != null ? p.label : id;
}
function projectName(id) {
  const p = projects.find(x => x.id === id);
  return p ? p.name : ("Project " + projectLabel(id));
}
function renderProjects() {
  const rail = $("projects"); rail.innerHTML = "";
  for (const p of projects) {
    const b = document.createElement("button");
    b.className = "proj" + (p.id === activeProject ? " active" : "");
    b.textContent = p.label != null ? p.label : p.id; b.title = p.name;
    b.onclick = () => selectProject(p.id);
    b.oncontextmenu = (e) => { e.preventDefault(); showCtx(e, p.id); };
    rail.appendChild(b);
  }
  const add = document.createElement("button");
  add.className = "proj add"; add.textContent = "+"; add.title = "New project";
  add.onclick = newProject;
  rail.appendChild(add);
  const ap = projects.find(p => p.id === activeProject);
  $("proj-label").textContent = ap ? ap.name : "—";
  $("dash-project").textContent = ap ? ap.name : "—";
}
function applyState(d) { projects = d.projects || []; activeProject = d.active; renderProjects(); }
async function loadProjects() { applyState(await (await fetch("/projects")).json()); }
async function selectProject(id) {
  if (id === activeProject) return;
  await fetch("/projects/select", { method:"POST", body: JSON.stringify({ id }) });
  activeProject = id; renderProjects(); onProjectSwitch();
}
async function newProject() {
  applyState(await (await fetch("/projects/new", { method:"POST", body:"{}" })).json());
  onProjectSwitch();
}
async function deleteProject(id) {
  const d = await (await fetch("/projects/delete", { method:"POST", body: JSON.stringify({ id }) })).json();
  if (d.ok) { applyState(d); onProjectSwitch(); }
}
function onProjectSwitch() {
  // Rebuild (never just clear) the per-project tool views from server state,
  // so a run left going in another project stays visible when you switch back.
  loadGhostViewFor(activeProject);
  loadHuntViewFor(activeProject);
  loadScopeFor(activeProject);
  selectedIssue = null; issueDetail = null; renderIssueDetail();
  loadIssuesFor(activeProject);
  loadRepeaterFor(activeProject);
  loadAutoRepeaterFor(activeProject);
}

// Context menu
function showCtx(e, id) {
  const m = $("ctxmenu");
  m.style.display = "block"; m.style.left = e.clientX + "px"; m.style.top = e.clientY + "px";
  m.dataset.pid = id;
}
document.addEventListener("click", () => {
  $("ctxmenu").style.display = "none"; $("issue-ctx").style.display = "none";
});
$("ctx-del").onclick = () => {
  const id = parseInt($("ctxmenu").dataset.pid, 10);
  $("ctxmenu").style.display = "none";
  deleteProject(id);
};

// ── Repeater: per-project Burp-style compose / send / resend ──
// repTabs mirrors the server's tab list for the active project. `repView` is
// which snapshot is on screen: the live editable buffer, or a past send being
// scrubbed with the ‹ › history nav. Editing the request always drops back to
// live (you can't type into a frozen historical send).
let repTabs = [], repActive = null, repView = { live: true, idx: 0 }, repSaveTimer = null;

const repTab = () => repTabs.find(t => t.id === repActive) || null;
const repCaption = t => (t.name && t.name.trim()) ? t.name : String(t.label != null ? t.label : t.id);
function repBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

// ── HTTP syntax highlighting ──
// Tokenize a raw HTTP message into colored spans so requests/responses are easy
// to scan. Everything is escaped via esc() before it reaches innerHTML.
function repSpan(cls, s) { return '<span class="' + cls + '">' + esc(s) + '</span>'; }
function escAttr(s) { return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
// Like repSpan, but stamps a data-tip key so HTTP Tips can explain the token.
function repSpanTip(cls, s, tip) { return '<span class="' + cls + '" data-tip="' + escAttr(tip) + '">' + esc(s) + '</span>'; }

function hlReqLine(line) {
  const m = line.match(/^(\S+)(\s+)(\S+)(\s*)(.*)$/);
  if (!m) return esc(line);
  return repSpanTip("tok-method", m[1], "m:" + m[1].toLowerCase()) + m[2] +
    repSpan("tok-path", m[3]) + m[4] + (m[5] ? repSpan("tok-version", m[5]) : "");
}
function hlStatusLine(line) {
  const m = line.match(/^(\S+)(\s+)(\d{3})(\s*)(.*)$/);
  if (!m) return esc(line);
  const c = m[3][0];
  const cls = c === "2" ? "tok-status-2xx" : c === "3" ? "tok-status-3xx"
            : (c === "4" || c === "5") ? "tok-status-err" : "tok-version";
  return repSpan("tok-version", m[1]) + m[2] + repSpanTip(cls, m[3], "s:" + m[3]) + m[4] +
    (m[5] ? repSpan("tok-reason", m[5]) : "");
}
function hlHeaderLine(line) {
  const m = line.match(/^([^:\s][^:]*)(:)(\s?)(.*)$/);
  if (!m) return esc(line);
  const nameLower = m[1].trim().toLowerCase();
  return repSpanTip("tok-hname", m[1], "h:" + nameLower) +
    repSpan("tok-hsep", m[2]) + m[3] + hlHeaderValue(nameLower, m[4]);
}

// Wrap regex matches in tip spans while emitting the gaps verbatim (escaped), so
// every character is preserved — the request overlay stays perfectly aligned.
function hlTokens(value, re, decide) {
  let out = "", last = 0, m;
  re.lastIndex = 0;
  while ((m = re.exec(value))) {
    out += esc(value.slice(last, m.index));
    const d = decide(m);
    out += d ? repSpanTip(d.cls || "tok-kw", m[0], d.tip) : esc(m[0]);
    last = re.lastIndex;
    if (m.index === re.lastIndex) re.lastIndex++;      // guard against zero-width matches
  }
  return out + esc(value.slice(last));
}
// Highlight the VALUE side of a header, adding value-level tips for the headers
// whose values carry structured, security-relevant tokens.
function hlHeaderValue(nameLower, value) {
  switch (nameLower) {
    case "set-cookie": case "cookie": return hlCookie(value);
    case "content-security-policy": case "content-security-policy-report-only": return hlCsp(value);
    case "authorization": return hlAuth(value);
    case "cache-control":
      return hlTokens(value, /[a-zA-Z][a-zA-Z-]*/g, m => {
        const k = m[0].toLowerCase(); return HTTP_TIPS.cc[k] ? { tip: "cc:" + k } : null; });
    case "strict-transport-security":
      return hlTokens(value, /[a-zA-Z][a-zA-Z-]*/g, m => {
        const k = m[0].toLowerCase(); return HTTP_TIPS.hsts[k] ? { tip: "hsts:" + k } : null; });
    case "content-type":
      return hlTokens(value, /[a-z0-9.+-]+\/[a-z0-9.+-]+/gi, m => {
        const k = m[0].toLowerCase(); return HTTP_TIPS.ct[k] ? { tip: "ct:" + k } : null; });
    default: return hlValueMaybeJwt(value);
  }
}
function hlCookie(value) {
  // Cookie attributes, SameSite values, and any embedded JWT (session tokens).
  const re = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*|(__(?:Host|Secure)-)|\b(HttpOnly|Secure|SameSite|Domain|Path|Max-Age|Expires|Partitioned)\b|\b(Strict|Lax|None)\b/gi;
  return hlTokens(value, re, m => {
    if (m[0].slice(0, 3).toLowerCase() === "eyj") return { tip: "jwt:" + m[0] };
    if (m[1]) return { tip: "cookie:" + (m[1].toLowerCase() === "__host-" ? "host-prefix" : "secure-prefix") };
    if (m[2]) return { tip: "cookie:" + m[2].toLowerCase() };
    if (m[3]) return { tip: "cookie:samesite-" + m[3].toLowerCase() };
    return null;
  });
}
function hlCsp(value) {
  const re = /'[^']*'|[a-zA-Z][a-zA-Z0-9-]*|\*/g;
  return hlTokens(value, re, m => {
    const t = m[0].toLowerCase();
    if (t[0] === "'") { const kw = t.slice(1, -1); return HTTP_TIPS.csp["kw-" + kw] ? { tip: "csp:kw-" + kw } : null; }
    if (t === "*") return HTTP_TIPS.csp["star"] ? { tip: "csp:star" } : null;
    return HTTP_TIPS.csp[t] ? { tip: "csp:" + t } : null;
  });
}
function hlAuth(value) {
  const m = value.match(/^(\s*)(\S+)(\s+)([\s\S]*)$/);
  if (!m) return hlValueMaybeJwt(value);
  const scheme = m[2].toLowerCase();
  const known = ["basic", "bearer", "digest", "negotiate", "ntlm",
    "aws4-hmac-sha256", "hawk", "signature"];
  const schemeHtml = known.includes(scheme)
    ? repSpanTip("tok-kw", m[2], "auth:" + scheme) : esc(m[2]);
  return esc(m[1]) + schemeHtml + esc(m[3]) + hlValueMaybeJwt(m[4]);
}
function hlValueMaybeJwt(value) {
  return hlTokens(value, /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g,
    m => ({ tip: "jwt:" + m[0] }));
}
// Which HTML attributes deserve a tip. Any on* event handler → the generic "on".
function attrTipKey(name) {
  const n = name.toLowerCase();
  if (/^on[a-z]/.test(n)) return "attr:on";
  const known = ["src", "href", "action", "formaction", "srcdoc", "sandbox", "rel",
    "target", "type", "http-equiv", "content", "integrity", "nonce", "style",
    "autocomplete", "name", "method", "value", "enctype", "formmethod",
    "formenctype", "crossorigin", "referrerpolicy", "ping", "download", "allow",
    "loading"];
  return known.includes(n) ? "attr:" + n : null;
}
function hlJson(s) {
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|([{}\[\],:])/g;
  let out = "", last = 0, m;
  while ((m = re.exec(s))) {
    out += esc(s.slice(last, m.index));
    if (m[1] !== undefined) {
      out += (m[2] !== undefined)
        ? repSpan("tok-json-key", m[1]) + repSpan("tok-json-punct", m[2])
        : repSpan("tok-json-str", m[1]);
    } else if (m[3] !== undefined) { out += repSpan("tok-json-bool", m[3]); }
    else if (m[4] !== undefined) { out += repSpan("tok-json-num", m[4]); }
    else if (m[5] !== undefined) { out += repSpan("tok-json-punct", m[5]); }
    last = re.lastIndex;
  }
  return out + esc(s.slice(last));
}
function hlXmlTag(tag) {
  const m = tag.match(/^(<[!?\/]?)([\w:.-]*)([\s\S]*?)([?\/]?>)$/);
  if (!m) return repSpan("tok-xml-tag", tag);
  const attrs = m[3].replace(/([\w:.-]+)(\s*=\s*)("[^"]*"|'[^']*')|(\s+)|(\S+)/g,
    (w, an, eq, av, ws, other) => {
      if (an !== undefined) {
        const key = attrTipKey(an);
        const nameHtml = key ? repSpanTip("tok-xml-attr", an, key) : repSpan("tok-xml-attr", an);
        return nameHtml + esc(eq) + repSpan("tok-xml-str", av);
      }
      if (ws !== undefined) return esc(ws);
      return esc(other || "");
    });
  const nameSpan = m[2]
    ? repSpanTip("tok-xml-tag", m[2], "t:" + m[2].toLowerCase())
    : repSpan("tok-xml-tag", m[2]);
  return repSpan("tok-xml-tag", m[1]) + nameSpan + attrs + repSpan("tok-xml-tag", m[4]);
}
function hlXml(s) {
  const re = /(&[a-zA-Z#][\w-]*;)|(<!--[\s\S]*?-->)|(<[^>]+>)/g;
  let out = "", last = 0, m;
  while ((m = re.exec(s))) {
    out += esc(s.slice(last, m.index));
    if (m[1] !== undefined) out += repSpan("tok-xml-ent", m[1]);
    else if (m[2] !== undefined) out += repSpan("tok-comment", m[2]);
    else out += hlXmlTag(m[3]);
    last = re.lastIndex;
  }
  return out + esc(s.slice(last));
}
function repDetectCT(headLines) {
  for (const l of headLines) {
    const m = l.match(/^content-type\s*:\s*(.+)$/i);
    if (m) {
      const v = m[1].toLowerCase();
      if (v.includes("json")) return "json";
      if (v.includes("xml") || v.includes("html")) return "xml";
      return "";
    }
  }
  return "";
}
function hlBody(body, ct) {
  let kind = ct;
  if (!kind) { const t = body.replace(/^\s+/, ""); kind = t[0] === "{" || t[0] === "[" ? "json" : t[0] === "<" ? "xml" : ""; }
  if (kind === "json") return hlJson(body);
  if (kind === "xml") return hlXml(body);
  return esc(body);
}
function hlHttp(text, kind) {
  const norm = String(text || "").replace(/\r\n/g, "\n");
  const idx = norm.indexOf("\n\n");
  const head = idx === -1 ? norm : norm.slice(0, idx);
  const body = idx === -1 ? "" : norm.slice(idx + 2);
  const headLines = head.split("\n");
  const html = headLines.map((ln, i) =>
    i === 0 ? (kind === "response" ? hlStatusLine(ln) : hlReqLine(ln)) : hlHeaderLine(ln)
  ).join("\n");
  const bodyHtml = body ? hlBody(body, repDetectCT(headLines)) : "";
  return html + (idx === -1 ? "" : "\n\n") + bodyHtml;
}

// Paint the request backdrop under the (transparent-text) textarea and keep the
// two layers scrolled together, so the caret sits on the colored glyphs.
function repHighlightRequest() {
  const ta = $("rep-request"), hl = $("rep-request-hl");
  if (!hl) return;
  hl.innerHTML = hlHttp(ta.value, "request") + "\n";   // trailing NL keeps heights aligned
  hl.scrollTop = ta.scrollTop; hl.scrollLeft = ta.scrollLeft;
}

// ── Display settings (font / size / colors), persisted in localStorage ──
const REP_FONTS = {
  "System Mono": 'ui-monospace, "SFMono-Regular", Menlo, Consolas, "Liberation Mono", monospace',
  "Cascadia / JetBrains": '"Cascadia Code", "JetBrains Mono", "Fira Code", ui-monospace, Menlo, monospace',
  "IBM Plex Mono": '"IBM Plex Mono", "Roboto Mono", ui-monospace, Menlo, monospace',
  "DejaVu / Menlo": '"DejaVu Sans Mono", Menlo, "Segoe UI Mono", ui-monospace, monospace',
  "Courier": '"Courier New", Courier, monospace',
};
const REP_SIZES = [11, 12, 13, 14, 15, 16, 18, 20];
const REP_LINES = { "Tight": 1.4, "Normal": 1.6, "Relaxed": 1.8, "Loose": 2.0 };
const REP_TOKENS = [
  ["--tok-method", "Method"], ["--tok-path", "Path"], ["--tok-version", "Version"],
  ["--tok-status-2xx", "Status 2xx"], ["--tok-status-3xx", "Status 3xx"], ["--tok-status-err", "Status 4/5xx"],
  ["--tok-hname", "Header name"], ["--tok-hvalue", "Header value"],
  ["--tok-json-key", "JSON key"], ["--tok-json-str", "JSON string"],
  ["--tok-json-num", "JSON number"], ["--tok-json-bool", "JSON bool"],
  ["--tok-xml-tag", "XML tag"], ["--tok-xml-attr", "XML attr"],
  ["--tok-xml-str", "XML value"], ["--tok-xml-ent", "XML entity"],
  ["--tok-kw", "Keyword / attribute"],
];
const REP_THEMES = {
  "Default (adaptive)": {},
  "Vivid": { "--tok-method": "#c678dd", "--tok-hname": "#56b6c2", "--tok-hvalue": "#abb2bf",
    "--tok-status-2xx": "#98c379", "--tok-status-3xx": "#61afef", "--tok-status-err": "#e06c75",
    "--tok-json-key": "#61afef", "--tok-json-str": "#98c379", "--tok-json-num": "#d19a66",
    "--tok-json-bool": "#c678dd", "--tok-xml-tag": "#e06c75", "--tok-xml-attr": "#d19a66",
    "--tok-xml-str": "#98c379", "--tok-xml-ent": "#e5c07b" },
  "Solarized": { "--tok-method": "#6c71c4", "--tok-hname": "#268bd2", "--tok-hvalue": "#586e75",
    "--tok-status-2xx": "#859900", "--tok-status-3xx": "#2aa198", "--tok-status-err": "#dc322f",
    "--tok-json-key": "#268bd2", "--tok-json-str": "#2aa198", "--tok-json-num": "#d33682",
    "--tok-json-bool": "#6c71c4", "--tok-xml-tag": "#268bd2", "--tok-xml-attr": "#b58900",
    "--tok-xml-str": "#2aa198", "--tok-xml-ent": "#cb4b16" },
  "Monochrome": { "--tok-method": "#e6e6e6", "--tok-path": "#c9c9c9", "--tok-version": "#8a8a8a",
    "--tok-status-2xx": "#e6e6e6", "--tok-status-3xx": "#c9c9c9", "--tok-status-err": "#ff9b9b",
    "--tok-reason": "#8a8a8a", "--tok-hname": "#bfbfbf", "--tok-hvalue": "#dcdcdc", "--tok-hsep": "#6b6b6b",
    "--tok-json-key": "#bfbfbf", "--tok-json-str": "#dcdcdc", "--tok-json-num": "#dcdcdc",
    "--tok-json-bool": "#e6e6e6", "--tok-json-punct": "#8a8a8a", "--tok-xml-tag": "#bfbfbf",
    "--tok-xml-attr": "#dcdcdc", "--tok-xml-str": "#dcdcdc", "--tok-xml-ent": "#e6e6e6" },
  "Warm Pastel": { "--tok-method": "#d08ac0", "--tok-hname": "#7fb4c9", "--tok-hvalue": "#d6cfc4",
    "--tok-status-2xx": "#a6cfa1", "--tok-status-3xx": "#8fbcd4", "--tok-status-err": "#e39ba0",
    "--tok-json-key": "#8fbcd4", "--tok-json-str": "#a6cfa1", "--tok-json-num": "#e0b088",
    "--tok-json-bool": "#d08ac0", "--tok-xml-tag": "#e39ba0", "--tok-xml-attr": "#e0b088",
    "--tok-xml-str": "#a6cfa1", "--tok-xml-ent": "#e6c98a" },
};
const REP_TOK_VARS = REP_TOKENS.map(t => t[0]).concat(
  ["--tok-reason", "--tok-hsep", "--tok-json-punct", "--tok-comment"]);
const REP_DISPLAY_DEFAULT = { font: "System Mono", size: 13, line: 1.6,
  theme: "Default (adaptive)", colors: {} };
let repDisplay = Object.assign({}, REP_DISPLAY_DEFAULT);

function applyRepDisplay() {
  const pane = $("pane-repeater"); if (!pane) return;
  pane.style.setProperty("--rep-font", REP_FONTS[repDisplay.font] || REP_FONTS["System Mono"]);
  pane.style.setProperty("--rep-font-size", repDisplay.size + "px");
  pane.style.setProperty("--rep-line", String(repDisplay.line));
  for (const v of REP_TOK_VARS) pane.style.removeProperty(v);    // clear prior overrides
  const theme = REP_THEMES[repDisplay.theme] || {};
  for (const k in theme) pane.style.setProperty(k, theme[k]);
  for (const k in repDisplay.colors) if (repDisplay.colors[k]) pane.style.setProperty(k, repDisplay.colors[k]);
  repHighlightRequest();                                          // resync heights after a size change
}
function saveRepDisplay() { try { localStorage.setItem("beatrix.rep.display", JSON.stringify(repDisplay)); } catch (e) {} }
function loadRepDisplay() {
  try { const s = JSON.parse(localStorage.getItem("beatrix.rep.display")); if (s) repDisplay = Object.assign({}, REP_DISPLAY_DEFAULT, s); } catch (e) {}
}
function rgbToHex(rgb) {
  const m = (rgb || "").match(/(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/);
  if (!m) return "#000000";
  return "#" + [1, 2, 3].map(i => (+m[i]).toString(16).padStart(2, "0")).join("");
}
function repEffectiveColor(varName) {
  const pane = $("pane-repeater");
  const probe = document.createElement("span");
  probe.style.color = "var(" + varName + ")";
  pane.appendChild(probe);
  const hex = rgbToHex(getComputedStyle(probe).color);
  pane.removeChild(probe);
  return hex;
}
function initRepSettings() {
  loadRepDisplay();
  const fill = (sel, opts, val) => {
    sel.innerHTML = "";
    for (const o of opts) {
      const el = document.createElement("option");
      el.value = String(o.v); el.textContent = o.t;
      if (String(o.v) === String(val)) el.selected = true;
      sel.appendChild(el);
    }
  };
  fill($("rep-font"), Object.keys(REP_FONTS).map(k => ({ v: k, t: k })), repDisplay.font);
  fill($("rep-size"), REP_SIZES.map(s => ({ v: s, t: s + " px" })), repDisplay.size);
  fill($("rep-line"), Object.keys(REP_LINES).map(k => ({ v: REP_LINES[k], t: k })), repDisplay.line);
  fill($("rep-theme"), Object.keys(REP_THEMES).map(k => ({ v: k, t: k })), repDisplay.theme);

  $("rep-font").onchange = e => { repDisplay.font = e.target.value; applyRepDisplay(); saveRepDisplay(); };
  $("rep-size").onchange = e => { repDisplay.size = +e.target.value; applyRepDisplay(); saveRepDisplay(); };
  $("rep-line").onchange = e => { repDisplay.line = +e.target.value; applyRepDisplay(); saveRepDisplay(); };
  $("rep-theme").onchange = e => { repDisplay.theme = e.target.value; repDisplay.colors = {}; applyRepDisplay(); saveRepDisplay(); buildRepColorFields(); };

  $("rep-reset").onclick = () => { repDisplay = Object.assign({}, REP_DISPLAY_DEFAULT, { colors: {} }); applyRepDisplay(); saveRepDisplay(); syncRepControls(); };

  const gear = $("rep-gear"), pop = $("rep-pop");
  gear.onclick = (e) => { e.stopPropagation(); const open = pop.classList.toggle("open"); if (open) buildRepColorFields(); };
  pop.onclick = (e) => e.stopPropagation();
  document.addEventListener("click", () => pop.classList.remove("open"));

  // HTTP Tips toggle — restore the last on/off state.
  $("rep-tips").onclick = () => setRepTips(!repTipsOn);
  let tipsSaved = false;
  try { tipsSaved = localStorage.getItem("beatrix.rep.tips") === "1"; } catch (e) {}
  setRepTips(tipsSaved);

  // Beautify toggle — pretty-print the response body; restore the last state.
  $("rep-pretty").onclick = () => setRepPretty(!repPrettyOn);
  let prettySaved = false;
  try { prettySaved = localStorage.getItem("beatrix.rep.pretty") === "1"; } catch (e) {}
  setRepPretty(prettySaved);

  applyRepDisplay();
}
function syncRepControls() {
  $("rep-font").value = repDisplay.font;
  $("rep-size").value = String(repDisplay.size);
  $("rep-line").value = String(repDisplay.line);
  $("rep-theme").value = repDisplay.theme;
  buildRepColorFields();
}
function buildRepColorFields() {
  const box = $("rep-colors"); box.innerHTML = "";
  for (const [varName, label] of REP_TOKENS) {
    const field = document.createElement("label");
    field.className = "rep-cfield";
    const input = document.createElement("input");
    input.type = "color";
    input.value = repDisplay.colors[varName] || repEffectiveColor(varName);
    input.oninput = () => { repDisplay.colors[varName] = input.value; applyRepDisplay(); saveRepDisplay(); };
    field.appendChild(input);
    field.appendChild(document.createTextNode(label));
    box.appendChild(field);
  }
}

// ── HTTP Tips: hover a token for a plain-English explanation ──
// Knowledge base keyed by the data-tip prefixes the highlighter stamps
// (h: header, m: method, s: status, t: tag). Each entry: {title, desc, sec?}
// where sec is a security note. Grow this over time — see
// docs/repeater-http-tips.md for coverage + roadmap.
const HTTP_TIPS = {
  methods: {
    get: { title: "GET", desc: "Requests a resource without a body; meant to be safe and idempotent (no side effects).", sec: "State-changing actions over GET are a red flag — CSRF and cacheable sensitive data." },
    post: { title: "POST", desc: "Submits data in the body to create or process a resource. Not idempotent.", sec: "Check for CSRF protection and whether it accepts unexpected content types." },
    put: { title: "PUT", desc: "Replaces the target resource with the request body; idempotent.", sec: "If unexpectedly enabled, may allow arbitrary file upload or overwrite." },
    patch: { title: "PATCH", desc: "Applies a partial update to a resource.", sec: "Watch for mass assignment — fields you did not expect being writable." },
    delete: { title: "DELETE", desc: "Removes the target resource.", sec: "Test authorization — can you delete objects you do not own (IDOR)?" },
    head: { title: "HEAD", desc: "Like GET but returns headers only, no body. Used to check existence or metadata." },
    options: { title: "OPTIONS", desc: "Asks which methods/capabilities the server allows; used in CORS preflight.", sec: "The Allow and Access-Control-* response headers reveal attack surface." },
    trace: { title: "TRACE", desc: "Echoes the received request back for debugging.", sec: "Should be disabled — enables Cross-Site Tracing (XST) to steal headers/cookies." },
    connect: { title: "CONNECT", desc: "Establishes a tunnel, usually for HTTPS through a proxy.", sec: "An open CONNECT proxy can be abused to reach internal hosts." },
    propfind: { title: "PROPFIND (WebDAV)", desc: "Retrieves properties/metadata of a resource or collection.", sec: "If WebDAV is unexpectedly enabled it can enumerate files and directories." },
    proppatch: { title: "PROPPATCH (WebDAV)", desc: "Sets or removes properties on a resource.", sec: "Writable WebDAV properties can be a foothold — confirm authorization." },
    mkcol: { title: "MKCOL (WebDAV)", desc: "Creates a new collection (directory).", sec: "Creating directories often precedes arbitrary file upload." },
    copy: { title: "COPY (WebDAV)", desc: "Copies a resource to the URL in the Destination header.", sec: "Can duplicate files into web-served paths — test upload-to-webroot." },
    move: { title: "MOVE (WebDAV)", desc: "Moves/renames a resource to the Destination header URL.", sec: "May rename an upload to an executable extension — a classic upload bypass." },
    lock: { title: "LOCK (WebDAV)", desc: "Places a lock on a resource for exclusive editing." },
    unlock: { title: "UNLOCK (WebDAV)", desc: "Removes a WebDAV lock." },
    report: { title: "REPORT (WebDAV/versioning)", desc: "Runs a server-defined report, often over version history." },
    search: { title: "SEARCH (WebDAV)", desc: "Server-side search over a collection.", sec: "Query handling here can expose injection or over-broad access." },
    purge: { title: "PURGE", desc: "Non-standard method that caches (Varnish, Nginx) use to evict an entry.", sec: "An exposed PURGE lets anyone flush the cache — a DoS / cache-poisoning lever." },
    track: { title: "TRACK", desc: "A Microsoft-IIS analog of TRACE that echoes the request back.", sec: "Like TRACE, enables Cross-Site Tracing (XST) — should be disabled." },
    debug: { title: "DEBUG", desc: "Non-standard debugging method exposed by some servers/frameworks.", sec: "May toggle verbose diagnostics or stack traces — probe what it returns." }
  },
  status: {
    "200": { title: "200 OK", desc: "The request succeeded and the body holds the result." },
    "201": { title: "201 Created", desc: "A new resource was created; Location usually points to it." },
    "204": { title: "204 No Content", desc: "Success, with no response body." },
    "206": { title: "206 Partial Content", desc: "A ranged request returned part of the resource." },
    "301": { title: "301 Moved Permanently", desc: "The resource has a new permanent URL in Location." },
    "302": { title: "302 Found", desc: "Temporary redirect to the URL in Location.", sec: "If Location reflects your input, test for open redirect / SSRF." },
    "303": { title: "303 See Other", desc: "Redirect telling the client to GET a different URL." },
    "304": { title: "304 Not Modified", desc: "The cached copy is still valid; no body is sent." },
    "307": { title: "307 Temporary Redirect", desc: "Temporary redirect that preserves the method and body." },
    "308": { title: "308 Permanent Redirect", desc: "Permanent redirect that preserves the method and body." },
    "400": { title: "400 Bad Request", desc: "The server could not parse or accept the request.", sec: "Fuzz around it — error text sometimes leaks parser or stack details." },
    "401": { title: "401 Unauthorized", desc: "Authentication is required or failed; see WWW-Authenticate.", sec: "401-vs-403 differences can reveal valid usernames or paths." },
    "403": { title: "403 Forbidden", desc: "Access is denied regardless of authentication.", sec: "Try header/verb/path tricks (X-Original-URL, method override) for 403 bypass." },
    "404": { title: "404 Not Found", desc: "No resource exists at this URL.", sec: "Compare 404 vs 403/200 to enumerate hidden endpoints." },
    "405": { title: "405 Method Not Allowed", desc: "This method is not allowed here; Allow lists the valid ones.", sec: "Allowed methods like PUT/DELETE may expand the attack surface." },
    "406": { title: "406 Not Acceptable", desc: "No representation matches the Accept headers." },
    "409": { title: "409 Conflict", desc: "The request conflicts with the resource's current state." },
    "415": { title: "415 Unsupported Media Type", desc: "The Content-Type is not accepted.", sec: "Switch content types (json / xml / form) — parsers may differ (XXE, etc.)." },
    "418": { title: "418 I'm a teapot", desc: "A joke status from RFC 2324, occasionally used as a placeholder." },
    "422": { title: "422 Unprocessable Entity", desc: "Syntax is fine but the data failed validation.", sec: "Validation errors often echo field names and rules — useful recon." },
    "429": { title: "429 Too Many Requests", desc: "You are being rate-limited.", sec: "Note the limits and Retry-After; hints at brute-force protections to pace around." },
    "500": { title: "500 Internal Server Error", desc: "The server hit an unhandled error.", sec: "Often leaks stack traces or SQL errors — inspect the body closely." },
    "501": { title: "501 Not Implemented", desc: "The server does not support this functionality." },
    "502": { title: "502 Bad Gateway", desc: "An upstream server returned an invalid response.", sec: "Proxy/upstream boundaries are where smuggling and SSRF live." },
    "503": { title: "503 Service Unavailable", desc: "The server is overloaded or down for maintenance." },
    "504": { title: "504 Gateway Timeout", desc: "An upstream server did not respond in time.", sec: "Timing differences can signal SSRF or slow back-end calls." },
    "100": { title: "100 Continue", desc: "The server will accept the body; the client may proceed (paired with Expect: 100-continue)." },
    "101": { title: "101 Switching Protocols", desc: "Switching protocols per the Upgrade header (WebSocket, h2c).", sec: "Upgrade handling is where WebSocket smuggling and h2c-desync bugs live." },
    "202": { title: "202 Accepted", desc: "Accepted for asynchronous processing; the result isn't ready yet." },
    "203": { title: "203 Non-Authoritative Information", desc: "A proxy returned a modified version of the origin's response." },
    "205": { title: "205 Reset Content", desc: "Success; the client should reset the form/view that made the request." },
    "226": { title: "226 IM Used", desc: "The response is a delta encoding of the resource (RFC 3229)." },
    "300": { title: "300 Multiple Choices", desc: "Several representations exist; the client or user picks one." },
    "305": { title: "305 Use Proxy", desc: "Deprecated — the resource must be reached through the named proxy.", sec: "Historically abused to steer clients at an attacker proxy; browsers ignore it." },
    "402": { title: "402 Payment Required", desc: "Reserved; some APIs use it to signal a billing or quota limit." },
    "407": { title: "407 Proxy Authentication Required", desc: "Like 401, but a proxy demands auth (see Proxy-Authenticate).", sec: "Reveals a proxy hop in the path — relevant to SSRF and header trust." },
    "408": { title: "408 Request Timeout", desc: "The client was too slow sending the request; the connection closes.", sec: "Abused in Slowloris-style DoS and some request-smuggling timing tricks." },
    "410": { title: "410 Gone", desc: "The resource is permanently gone with no forwarding URL." },
    "411": { title: "411 Length Required", desc: "The server refuses the request without a Content-Length." },
    "412": { title: "412 Precondition Failed", desc: "An If-* precondition header evaluated to false." },
    "413": { title: "413 Content Too Large", desc: "The body exceeds the server's size limit.", sec: "The limit itself is useful recon for upload and buffer tests." },
    "414": { title: "414 URI Too Long", desc: "The request URI exceeds what the server will parse.", sec: "Marks the URL-length ceiling — relevant to limit-based and cache-key tricks." },
    "416": { title: "416 Range Not Satisfiable", desc: "The requested Range can't be served.", sec: "Malformed ranges have driven cache-poisoning and DoS bugs." },
    "417": { title: "417 Expectation Failed", desc: "The server can't meet the Expect header's requirement." },
    "421": { title: "421 Misdirected Request", desc: "The request reached a server that can't answer for that authority.", sec: "Central to HTTP/2 connection-coalescing and cross-host desync/smuggling." },
    "423": { title: "423 Locked (WebDAV)", desc: "The resource is locked." },
    "424": { title: "424 Failed Dependency (WebDAV)", desc: "The request failed because a dependent request failed." },
    "425": { title: "425 Too Early", desc: "The server won't risk processing a possibly-replayed request (TLS early data).", sec: "Signals anti-replay handling around 0-RTT — worth probing for replay bugs." },
    "426": { title: "426 Upgrade Required", desc: "The client must switch protocols (see Upgrade) to continue." },
    "428": { title: "428 Precondition Required", desc: "The server requires the request to be conditional (an If-* header)." },
    "431": { title: "431 Request Header Fields Too Large", desc: "One or more headers (or their total) exceed the server's limit.", sec: "The header-size ceiling matters for smuggling, cache-key, and cookie-bomb tests." },
    "451": { title: "451 Unavailable For Legal Reasons", desc: "Access is denied for legal or censorship reasons." },
    "505": { title: "505 HTTP Version Not Supported", desc: "The server won't support the request's HTTP version." },
    "507": { title: "507 Insufficient Storage (WebDAV)", desc: "The server can't store the representation needed to complete the request." },
    "508": { title: "508 Loop Detected (WebDAV)", desc: "An infinite loop was detected while processing the request." },
    "510": { title: "510 Not Extended", desc: "Further extensions to the request are required to fulfill it." },
    "511": { title: "511 Network Authentication Required", desc: "You must authenticate for network access — typically a captive portal.", sec: "A captive-portal interception point; on hostile networks the response may be attacker-controlled." }
  },
  statusClass: {
    "1xx": { title: "1xx Informational", desc: "A provisional response; the request continues." },
    "2xx": { title: "2xx Success", desc: "The request was received, understood, and accepted." },
    "3xx": { title: "3xx Redirection", desc: "Further action (usually following Location) is needed.", sec: "Redirect targets built from user input lead to open redirect / SSRF." },
    "4xx": { title: "4xx Client Error", desc: "The request was rejected as bad or unauthorized." },
    "5xx": { title: "5xx Server Error", desc: "The server failed to fulfill a valid request.", sec: "Server errors frequently leak internal details." }
  },
  headers: {
    "host": { title: "Host", desc: "The domain (and optional port) the request targets; required in HTTP/1.1.", sec: "Spoofing it tests Host-header injection, routing, cache poisoning, and password-reset poisoning." },
    "user-agent": { title: "User-Agent", desc: "Identifies the client software making the request.", sec: "Some apps trust it for routing/blocking — try injection or unusual values." },
    "accept": { title: "Accept", desc: "The media types the client will accept in the response.", sec: "Switching it (e.g. to application/json) can reveal alternate responses." },
    "accept-encoding": { title: "Accept-Encoding", desc: "Compression the client supports (gzip, br, deflate)." },
    "accept-language": { title: "Accept-Language", desc: "Preferred human languages for the response.", sec: "Occasionally reflected unsanitized, enabling injection." },
    "referer": { title: "Referer", desc: "The page that linked to this request (yes, it's misspelled in the spec).", sec: "Apps that trust Referer for auth/CSRF are bypassable; it can also leak URLs." },
    "origin": { title: "Origin", desc: "The scheme+host that initiated the request; central to CORS and CSRF checks.", sec: "A reflected Origin in Access-Control-Allow-Origin is a classic CORS bug." },
    "authorization": { title: "Authorization", desc: "Carries credentials, e.g. 'Basic <base64>' or 'Bearer <token>'.", sec: "Decode Basic; inspect Bearer/JWT for weak signing or excessive scope." },
    "cookie": { title: "Cookie", desc: "Sends stored cookies (session, CSRF, prefs) back to the server.", sec: "Session tokens here are prime targets — test fixation, scope, and predictability." },
    "set-cookie": { title: "Set-Cookie", desc: "The server sets a cookie in the client.", sec: "Check for Secure, HttpOnly, and SameSite — missing flags enable theft or CSRF." },
    "content-type": { title: "Content-Type", desc: "The media type (and charset) of the message body.", sec: "Mismatches enable XXE, JSON/XML confusion, and MIME-sniffing XSS." },
    "content-length": { title: "Content-Length", desc: "The size of the body in bytes.", sec: "With Transfer-Encoding also present, conflicting framing enables request smuggling." },
    "content-encoding": { title: "Content-Encoding", desc: "Compression applied to the body (gzip, br)." },
    "transfer-encoding": { title: "Transfer-Encoding", desc: "How the body is framed on the wire, usually 'chunked'.", sec: "TE plus Content-Length together is the basis of HTTP request smuggling." },
    "connection": { title: "Connection", desc: "Whether the TCP connection stays open (keep-alive) or closes." },
    "cache-control": { title: "Cache-Control", desc: "Directives for how responses may be cached (no-store, max-age, private...).", sec: "Sensitive pages should be no-store; permissive caching enables poisoning or leaks." },
    "pragma": { title: "Pragma", desc: "Legacy caching control; 'no-cache' for HTTP/1.0 compatibility." },
    "date": { title: "Date", desc: "When the server generated the response." },
    "expires": { title: "Expires", desc: "The absolute time after which the response is considered stale." },
    "etag": { title: "ETag", desc: "An opaque version identifier for the resource, used for caching.", sec: "Can act as a tracking vector and sometimes leaks backend info." },
    "last-modified": { title: "Last-Modified", desc: "When the resource last changed; used for conditional requests." },
    "location": { title: "Location", desc: "The redirect URL (with 3xx) or the new resource (with 201).", sec: "If it reflects your input, test open redirect and SSRF." },
    "server": { title: "Server", desc: "Names the server software, often with a version.", sec: "Version disclosure — look up known CVEs for that exact build." },
    "x-powered-by": { title: "X-Powered-By", desc: "Reveals the backend tech or framework (PHP, Express, ...).", sec: "A fingerprinting aid that narrows exploits; should be removed in production." },
    "vary": { title: "Vary", desc: "Which request headers change the response (affects caching).", sec: "A header that varies caching but is not in the cache key enables cache poisoning." },
    "www-authenticate": { title: "WWW-Authenticate", desc: "With 401, tells the client which auth scheme and realm to use.", sec: "Reveals the auth mechanism (Basic/NTLM/Negotiate) to target." },
    "content-disposition": { title: "Content-Disposition", desc: "Whether to show inline or download, plus a suggested filename.", sec: "Reflected filenames can enable header injection or download-based XSS." },
    "x-frame-options": { title: "X-Frame-Options", desc: "Controls whether the page may be framed (DENY / SAMEORIGIN).", sec: "Missing or weak means clickjacking. Superseded by CSP frame-ancestors." },
    "content-security-policy": { title: "Content-Security-Policy", desc: "Restricts where scripts/styles/frames may load from — a key XSS mitigation.", sec: "Look for 'unsafe-inline', 'unsafe-eval', or wildcards that weaken it." },
    "strict-transport-security": { title: "Strict-Transport-Security (HSTS)", desc: "Forces HTTPS for future requests.", sec: "Missing HSTS allows SSL-strip/downgrade; check includeSubDomains and preload." },
    "x-content-type-options": { title: "X-Content-Type-Options", desc: "'nosniff' stops the browser guessing the MIME type.", sec: "Missing it lets MIME sniffing turn uploads into XSS." },
    "x-xss-protection": { title: "X-XSS-Protection", desc: "A legacy browser XSS-filter toggle (deprecated).", sec: "Modern browsers ignore it; rely on CSP instead." },
    "referrer-policy": { title: "Referrer-Policy", desc: "Controls how much of the URL is sent in the Referer header.", sec: "A loose policy can leak tokens embedded in URLs to third parties." },
    "access-control-allow-origin": { title: "Access-Control-Allow-Origin", desc: "Which origins may read this response cross-site (CORS).", sec: "'*' or a reflected Origin — especially with credentials — is a serious CORS flaw." },
    "access-control-allow-credentials": { title: "Access-Control-Allow-Credentials", desc: "If 'true', cross-site requests may include cookies/credentials.", sec: "'true' combined with a reflected Origin exposes authenticated data." },
    "access-control-allow-methods": { title: "Access-Control-Allow-Methods", desc: "Which methods are permitted cross-origin (CORS preflight response).", sec: "Reveals allowed methods; over-broad values widen cross-site attack surface." },
    "access-control-allow-headers": { title: "Access-Control-Allow-Headers", desc: "Which request headers are permitted cross-origin (preflight response).", sec: "A wildcard or reflected value can loosen CORS more than intended." },
    "access-control-expose-headers": { title: "Access-Control-Expose-Headers", desc: "Which response headers cross-origin JS is allowed to read." },
    "access-control-max-age": { title: "Access-Control-Max-Age", desc: "How long (seconds) a CORS preflight result may be cached by the browser." },
    "access-control-request-method": { title: "Access-Control-Request-Method", desc: "In a preflight, the method the real cross-origin request will use." },
    "access-control-request-headers": { title: "Access-Control-Request-Headers", desc: "In a preflight, the headers the real cross-origin request will send." },
    "x-forwarded-for": { title: "X-Forwarded-For", desc: "Client IP chain added by proxies/load balancers.", sec: "Often trusted for auth, rate-limits, or logging — spoof it to bypass IP allowlists or forge audit trails." },
    "x-forwarded-host": { title: "X-Forwarded-Host", desc: "The original Host as seen by an upstream proxy.", sec: "A prime Host-injection vector — password-reset poisoning, cache poisoning, routing tricks." },
    "x-forwarded-proto": { title: "X-Forwarded-Proto", desc: "The scheme (http/https) the client used, per an upstream proxy.", sec: "Trusting it blindly can defeat HTTPS-only checks and redirect logic." },
    "x-forwarded-port": { title: "X-Forwarded-Port", desc: "The port the client connected to, per an upstream proxy." },
    "x-forwarded-server": { title: "X-Forwarded-Server", desc: "Hostname of an upstream proxy that handled the request." },
    "forwarded": { title: "Forwarded", desc: "The standardized (RFC 7239) proxy header carrying for/host/proto.", sec: "Same trust pitfalls as X-Forwarded-*; test spoofing of each element." },
    "x-real-ip": { title: "X-Real-IP", desc: "Client IP set by a reverse proxy (common with Nginx).", sec: "Like X-Forwarded-For, spoofable when the app trusts it for IP checks." },
    "x-original-url": { title: "X-Original-URL", desc: "Original request path, honored by some stacks (IIS/Symfony) for internal routing.", sec: "A well-known 403/authorization bypass — route to a forbidden path via this header." },
    "x-rewrite-url": { title: "X-Rewrite-URL", desc: "Alternate path-override header honored by some frameworks.", sec: "Like X-Original-URL, test it for access-control / 403 bypass." },
    "x-http-method-override": { title: "X-HTTP-Method-Override", desc: "Tells the server to treat the request as a different method (e.g. POST→DELETE).", sec: "Can smuggle a disallowed method past a filter that only checks the real verb." },
    "x-host": { title: "X-Host", desc: "Non-standard host override honored by some back ends.", sec: "Another Host-injection surface — test alongside X-Forwarded-Host." },
    "sec-fetch-site": { title: "Sec-Fetch-Site", desc: "Browser-set metadata: relationship of the request's origin to the target (same-origin, cross-site...).", sec: "Servers use it as a CSRF signal; note whether the app actually enforces it." },
    "sec-fetch-mode": { title: "Sec-Fetch-Mode", desc: "Browser-set: the request mode (navigate, cors, no-cors, ...)." },
    "sec-fetch-dest": { title: "Sec-Fetch-Dest", desc: "Browser-set: the destination of the request (document, script, image, ...)." },
    "sec-fetch-user": { title: "Sec-Fetch-User", desc: "Browser-set: '?1' when the navigation was triggered by a real user gesture." },
    "sec-ch-ua": { title: "Sec-CH-UA (Client Hint)", desc: "User-Agent client hint listing the browser brand(s) and major version." },
    "sec-ch-ua-platform": { title: "Sec-CH-UA-Platform", desc: "User-Agent client hint naming the OS platform." },
    "sec-ch-ua-mobile": { title: "Sec-CH-UA-Mobile", desc: "User-Agent client hint: '?1' on mobile, '?0' otherwise." },
    "permissions-policy": { title: "Permissions-Policy", desc: "Controls which browser features (camera, geolocation, ...) the page and its frames may use.", sec: "Successor to Feature-Policy; a permissive policy can widen what embedded/injected content can do." },
    "feature-policy": { title: "Feature-Policy", desc: "Legacy predecessor of Permissions-Policy controlling browser feature access." },
    "cross-origin-opener-policy": { title: "Cross-Origin-Opener-Policy (COOP)", desc: "Isolates the page's browsing-context group from cross-origin openers.", sec: "Missing COOP leaves the window open to XS-Leaks and Spectre-style cross-origin probing." },
    "cross-origin-embedder-policy": { title: "Cross-Origin-Embedder-Policy (COEP)", desc: "Requires embedded resources to opt in (CORP/CORS); enables cross-origin isolation." },
    "cross-origin-resource-policy": { title: "Cross-Origin-Resource-Policy (CORP)", desc: "Restricts which origins may embed this resource.", sec: "Its absence can enable resource-based XS-Leaks and cross-origin inclusion." },
    "clear-site-data": { title: "Clear-Site-Data", desc: "Instructs the browser to clear cookies, storage, and/or cache for the site.", sec: "Usually seen on logout; if triggerable by an attacker it can wipe client state (nuisance/DoS)." },
    "timing-allow-origin": { title: "Timing-Allow-Origin", desc: "Which origins may read detailed Resource-Timing data for this resource.", sec: "Over-broad values can leak cross-origin timing usable in XS-Leaks." },
    "report-to": { title: "Report-To", desc: "Named reporting endpoints (Reporting API) for CSP, NEL, and other violation reports." },
    "reporting-endpoints": { title: "Reporting-Endpoints", desc: "The newer, structured way to declare Reporting-API endpoints." },
    "nel": { title: "NEL (Network Error Logging)", desc: "Opts the site into browser reporting of network/connection failures.", sec: "Reporting endpoints can leak request metadata to a third party — note where reports go." },
    "content-security-policy-report-only": { title: "Content-Security-Policy-Report-Only", desc: "Evaluates a CSP and reports violations without enforcing it.", sec: "Report-only means NO protection — an easy-to-miss misconfiguration." },
    "x-permitted-cross-domain-policies": { title: "X-Permitted-Cross-Domain-Policies", desc: "Controls Adobe (Flash/PDF) cross-domain policy files.", sec: "'all' historically widened cross-domain data access for plugins." },
    "x-dns-prefetch-control": { title: "X-DNS-Prefetch-Control", desc: "Enables or disables the browser's speculative DNS prefetching." },
    "x-download-options": { title: "X-Download-Options", desc: "'noopen' stops legacy IE from opening downloads in the site's context.", sec: "Absence historically allowed HTML downloads to run in-origin (XSS)." },
    "retry-after": { title: "Retry-After", desc: "How long to wait before retrying (seconds or a date); seen with 429/503.", sec: "Reveals rate-limit / backoff windows to pace brute-force around." },
    "allow": { title: "Allow", desc: "Lists the methods valid for the resource; sent with 405.", sec: "Enumerates the method attack surface (PUT/DELETE/PATCH worth testing)." },
    "age": { title: "Age", desc: "Seconds the response has sat in an intermediary cache.", sec: "A non-zero Age proves a shared cache is in play — relevant to cache poisoning/deception." },
    "via": { title: "Via", desc: "Proxies/gateways the message passed through, with their protocols.", sec: "Exposes intermediary software and hops — recon for smuggling and SSRF." },
    "x-cache": { title: "X-Cache", desc: "Whether a CDN/proxy served a HIT or MISS (non-standard but common).", sec: "HIT/MISS feedback is the key oracle when probing web-cache poisoning/deception." },
    "cf-cache-status": { title: "CF-Cache-Status", desc: "Cloudflare's cache result (HIT/MISS/DYNAMIC/…).", sec: "Same cache-poisoning oracle as X-Cache, specific to Cloudflare." },
    "server-timing": { title: "Server-Timing", desc: "Server-side timing metrics surfaced to the browser.", sec: "Can leak back-end timing and internal component names — minor info disclosure." },
    "x-request-id": { title: "X-Request-ID", desc: "A correlation ID assigned to the request for tracing/logs.", sec: "Predictable IDs can aid log correlation or enumeration; note the format." },
    "x-correlation-id": { title: "X-Correlation-ID", desc: "A cross-service correlation identifier for tracing a request." },
    "x-amzn-trace-id": { title: "X-Amzn-Trace-Id", desc: "AWS ALB/X-Ray trace identifier — signals the request went through AWS infrastructure." },
    "x-ratelimit-limit": { title: "X-RateLimit-Limit", desc: "The request quota for the current rate-limit window.", sec: "Maps the throttle so you can pace brute-force/enumeration under it." },
    "x-ratelimit-remaining": { title: "X-RateLimit-Remaining", desc: "Requests left in the current rate-limit window." },
    "x-ratelimit-reset": { title: "X-RateLimit-Reset", desc: "When the rate-limit window resets (epoch or seconds)." },
    "accept-ranges": { title: "Accept-Ranges", desc: "Whether the server supports ranged requests ('bytes' or 'none')." },
    "range": { title: "Range", desc: "Requests only part of a resource (byte ranges).", sec: "Crafted/overlapping ranges have caused cache-poisoning and DoS — worth fuzzing." },
    "content-range": { title: "Content-Range", desc: "Which byte range of the resource this partial (206) response covers." },
    "if-match": { title: "If-Match", desc: "Run the request only if the resource's ETag matches (optimistic concurrency)." },
    "if-none-match": { title: "If-None-Match", desc: "Conditional request keyed on ETag; drives 304 caching revalidation." },
    "if-modified-since": { title: "If-Modified-Since", desc: "Return the resource only if changed since this date; else 304." },
    "if-unmodified-since": { title: "If-Unmodified-Since", desc: "Run the request only if the resource is unchanged since this date." },
    "if-range": { title: "If-Range", desc: "Serve the Range only if the validator still matches; otherwise send the whole resource." },
    "content-language": { title: "Content-Language", desc: "The natural language(s) of the body." },
    "content-md5": { title: "Content-MD5", desc: "A (legacy) MD5 digest of the body for integrity checking." },
    "link": { title: "Link", desc: "Typed relationships to other resources (preload, prev/next, canonical...).", sec: "preload/preconnect targets and rel=canonical can sometimes be influenced — check the URLs." },
    "te": { title: "TE", desc: "Which transfer encodings the client accepts in the response (e.g. trailers).", sec: "Part of the framing surface — relevant when hunting request smuggling." },
    "expect": { title: "Expect", desc: "Client expectation, usually '100-continue' before sending a large body.", sec: "Mishandled Expect has featured in request-smuggling and DoS research." },
    "upgrade": { title: "Upgrade", desc: "Asks to switch protocols on this connection (WebSocket, h2c).", sec: "The entry point for WebSocket smuggling and h2c-desync — inspect closely." },
    "keep-alive": { title: "Keep-Alive", desc: "Tuning (timeout, max) for a persistent connection." },
    "proxy-authorization": { title: "Proxy-Authorization", desc: "Credentials for an intermediary proxy (not the origin server)." },
    "proxy-authenticate": { title: "Proxy-Authenticate", desc: "With 407, the auth scheme a proxy requires.", sec: "Confirms a proxy in the path and names its auth mechanism." },
    "max-forwards": { title: "Max-Forwards", desc: "Limits how many proxies a TRACE/OPTIONS request may traverse." },
    "dnt": { title: "DNT (Do Not Track)", desc: "Legacy 'do not track' preference; largely ignored today.", sec: "Its uniqueness can add to browser fingerprinting." },
    "x-content-security-policy": { title: "X-Content-Security-Policy (legacy)", desc: "Old, non-standard CSP header for legacy browsers.", sec: "If it's the ONLY CSP present, modern browsers ignore it — effectively no protection." },
    "x-webkit-csp": { title: "X-WebKit-CSP (legacy)", desc: "Old WebKit-prefixed CSP header.", sec: "Superseded by Content-Security-Policy; ignored by modern browsers." }
  },
  tags: {
    "html": { title: "<html>", desc: "The root element of an HTML document." },
    "head": { title: "<head>", desc: "Container for metadata: title, meta, links, and scripts." },
    "title": { title: "<title>", desc: "The document title, shown in the browser tab and search results." },
    "meta": { title: "<meta>", desc: "Metadata such as charset, viewport, or http-equiv directives.", sec: "meta http-equiv can set a CSP or a refresh redirect — check the value." },
    "link": { title: "<link>", desc: "Links external resources, most often stylesheets.", sec: "preload/prefetch/dns-prefetch to attacker URLs can leak or be abused." },
    "script": { title: "<script>", desc: "Embeds or references JavaScript.", sec: "The number-one XSS sink — inspect src origins and any inline or reflected content." },
    "style": { title: "<style>", desc: "Embeds CSS.", sec: "CSS injection can exfiltrate data or aid UI-redress attacks." },
    "iframe": { title: "<iframe>", desc: "Embeds another document inline.", sec: "Check sandbox/allow attributes; framing untrusted content risks clickjacking." },
    "form": { title: "<form>", desc: "A submittable group of inputs; action/method set where and how it sends.", sec: "Note the action URL and whether a CSRF token is present." },
    "input": { title: "<input>", desc: "A form field; the type attribute controls its behavior.", sec: "type=hidden often carries state/IDs worth tampering; watch autocomplete on secrets." },
    "button": { title: "<button>", desc: "A clickable button, often submitting a form or triggering JS." },
    "textarea": { title: "<textarea>", desc: "A multi-line text field.", sec: "A common reflection point — test for stored and reflected XSS." },
    "a": { title: "<a>", desc: "A hyperlink; href is the destination.", sec: "target=_blank without rel=noopener enables reverse tabnabbing; javascript: hrefs are XSS." },
    "img": { title: "<img>", desc: "Embeds an image via src.", sec: "onerror handlers and reflected src are classic XSS vectors." },
    "svg": { title: "<svg>", desc: "Inline vector graphics; can contain script and event handlers.", sec: "A well-known XSS vector when user-supplied SVG is rendered inline." },
    "object": { title: "<object>", desc: "Embeds external resources or plugins.", sec: "Can load untrusted content or plugins — an injection vector." },
    "embed": { title: "<embed>", desc: "Embeds external content such as media or plugins.", sec: "Like <object>, a potential vector for loading attacker content." },
    "base": { title: "<base>", desc: "Sets the base URL for all relative links on the page.", sec: "An injected <base href> hijacks every relative URL — serious." },
    "doctype": { title: "<!DOCTYPE>", desc: "Declares the document type (e.g. html).", sec: "In XML, a DOCTYPE with entities is the gateway to XXE." },
    "body": { title: "<body>", desc: "The document's visible content.", sec: "onload/onpageshow on <body> are common XSS execution points." },
    "video": { title: "<video>", desc: "Embeds video; can autoplay and fire media events.", sec: "onerror/onloadstart handlers make it a filter-dodging XSS vector." },
    "audio": { title: "<audio>", desc: "Embeds audio; can fire media events.", sec: "Like <video>, its event handlers are used in XSS payloads." },
    "source": { title: "<source>", desc: "A media source for <video>/<audio>/<picture>.", sec: "onerror on a bad src is a classic XSS trigger." },
    "template": { title: "<template>", desc: "Holds inert markup that scripts clone at runtime.", sec: "Content is parsed but inert; a known mutation-XSS (mXSS) context to watch." },
    "noscript": { title: "<noscript>", desc: "Content shown when scripting is disabled.", sec: "Its unusual parsing has enabled mutation-XSS bypasses of sanitizers." },
    "math": { title: "<math> (MathML)", desc: "Inline MathML content.", sec: "MathML parsing quirks are a recurring mutation-XSS sanitizer bypass." },
    "annotation-xml": { title: "<annotation-xml> (MathML)", desc: "A MathML container that can switch the parser into HTML integration mode.", sec: "A well-known mXSS gadget for escaping sanitizers." },
    "foreignobject": { title: "<foreignObject> (SVG)", desc: "Embeds HTML inside an SVG document.", sec: "Lets HTML (and scripts/handlers) ride inside otherwise-trusted SVG — an XSS vector." },
    "frame": { title: "<frame>", desc: "A single pane inside a legacy <frameset>.", sec: "Legacy framing; src can load untrusted content — clickjacking/UI-redress." },
    "frameset": { title: "<frameset>", desc: "Legacy replacement for <body> that lays out <frame>s." },
    "applet": { title: "<applet>", desc: "Loads a legacy Java applet (obsolete).", sec: "A dangerous legacy plugin/code-execution vector if ever honored." },
    "select": { title: "<select>", desc: "A drop-down list of <option>s in a form." },
    "option": { title: "<option>", desc: "One choice within a <select>." },
    "label": { title: "<label>", desc: "A caption bound to a form control." },
    "details": { title: "<details>", desc: "A disclosure widget that expands on click.", sec: "ontoggle fires without user script and is used in XSS payloads." },
    "marquee": { title: "<marquee>", desc: "Obsolete scrolling-text element.", sec: "Legacy event handlers here appear in XSS filter-bypass payloads." },
    "dialog": { title: "<dialog>", desc: "A native modal/non-modal dialog box." },
    "portal": { title: "<portal>", desc: "Experimental element for previewing/embedding another page.", sec: "Like <iframe>, embedding untrusted pages warrants navigation/clickjacking review." },
    "table": { title: "<table>", desc: "Tabular data container.", sec: "Table-related parsing (rows/cells) is a frequent mutation-XSS context." },
    "noembed": { title: "<noembed>", desc: "Fallback content when <embed> is unsupported.", sec: "Raw-text parsing mode makes it another mXSS sanitizer-bypass gadget." },
    "xml": { title: "<xml>", desc: "Legacy IE data-island element.", sec: "Historically abused for HTML+time / data-island based XSS in old IE." }
  },
  cookie: {
    "httponly": { title: "HttpOnly", desc: "The cookie can't be read by JavaScript (document.cookie).", sec: "Its absence on a session cookie means XSS can steal it — a finding." },
    "secure": { title: "Secure", desc: "The cookie is only sent over HTTPS.", sec: "Without it, the cookie can leak over plaintext HTTP." },
    "samesite": { title: "SameSite", desc: "Controls whether the cookie rides along on cross-site requests.", sec: "None (without Secure) or missing weakens CSRF defense." },
    "samesite-strict": { title: "SameSite=Strict", desc: "Withheld on all cross-site requests.", sec: "Strongest CSRF protection; can break legitimate cross-site links." },
    "samesite-lax": { title: "SameSite=Lax", desc: "Sent on top-level GET navigations, not on cross-site POST/subrequests.", sec: "The modern browser default; blocks most CSRF." },
    "samesite-none": { title: "SameSite=None", desc: "Sent on all cross-site requests; must be paired with Secure.", sec: "Re-opens CSRF surface — confirm it's intended." },
    "domain": { title: "Domain", desc: "Which host(s) the cookie is scoped to.", sec: "A too-broad parent Domain widens exposure across subdomains." },
    "path": { title: "Path", desc: "The URL path prefix the cookie is scoped to.", sec: "Path scoping is not a security boundary between apps." },
    "max-age": { title: "Max-Age", desc: "Cookie lifetime in seconds (takes precedence over Expires)." },
    "expires": { title: "Expires", desc: "Absolute expiry date/time of the cookie." },
    "partitioned": { title: "Partitioned (CHIPS)", desc: "Binds the cookie to the top-level site, giving it a separate jar per embedding site.", sec: "Limits cross-site tracking; note that it changes how a third-party cookie is scoped." },
    "host-prefix": { title: "__Host- prefix", desc: "A cookie-name prefix the browser only accepts if it's Secure, Path=/, and has no Domain.", sec: "A strong anti-fixation/scoping control — its use is a good sign; forging one cross-domain is blocked." },
    "secure-prefix": { title: "__Secure- prefix", desc: "A cookie-name prefix the browser only accepts if the Secure flag is set.", sec: "Guarantees the cookie was set over HTTPS — resists insecure overwrites." }
  },
  csp: {
    "default-src": { title: "default-src", desc: "The fallback source list for content types without their own directive." },
    "script-src": { title: "script-src", desc: "Where scripts may be loaded/executed from — the core anti-XSS control.", sec: "Wildcards, data:, or missing here is where CSP bypasses start." },
    "style-src": { title: "style-src", desc: "Where stylesheets may load from." },
    "img-src": { title: "img-src", desc: "Where images may load from." },
    "connect-src": { title: "connect-src", desc: "Endpoints fetch/XHR/WebSocket may reach." },
    "font-src": { title: "font-src", desc: "Where fonts may load from." },
    "object-src": { title: "object-src", desc: "Sources for <object>/<embed>.", sec: "Should be 'none' — plugins are a legacy XSS/again vector." },
    "frame-src": { title: "frame-src", desc: "Where frames may be loaded from." },
    "frame-ancestors": { title: "frame-ancestors", desc: "Who may frame THIS page — the modern clickjacking control.", sec: "Missing or permissive → clickjacking (replaces X-Frame-Options)." },
    "base-uri": { title: "base-uri", desc: "Restricts what <base href> may be set to.", sec: "Without it, a <base> injection can hijack every relative URL." },
    "form-action": { title: "form-action", desc: "Where forms may submit.", sec: "Absent, an injected form/formaction can exfiltrate to any host." },
    "report-uri": { title: "report-uri", desc: "Legacy endpoint that receives CSP violation reports." },
    "report-to": { title: "report-to", desc: "Endpoint (via Reporting-API) that receives CSP violation reports." },
    "upgrade-insecure-requests": { title: "upgrade-insecure-requests", desc: "Rewrites http:// subresource requests to https://." },
    "block-all-mixed-content": { title: "block-all-mixed-content", desc: "Blocks any http:// content on an https page." },
    "sandbox": { title: "sandbox (CSP)", desc: "Applies iframe-style sandbox restrictions to the whole document." },
    "kw-unsafe-inline": { title: "'unsafe-inline'", desc: "Allows inline <script>/<style> and on* handlers.", sec: "Largely defeats CSP's XSS protection — a major weakness." },
    "kw-unsafe-eval": { title: "'unsafe-eval'", desc: "Allows eval() and similar string-to-code.", sec: "Enables a broad class of XSS/gadget attacks." },
    "kw-self": { title: "'self'", desc: "Allows content from the page's own origin." },
    "kw-none": { title: "'none'", desc: "Allows nothing for this directive." },
    "kw-strict-dynamic": { title: "'strict-dynamic'", desc: "Trust propagates to scripts loaded by an already-trusted script; host allowlists are ignored.", sec: "Powerful but easy to misconfigure — check the nonce/hash it relies on." },
    "star": { title: "* (wildcard source)", desc: "Allows any origin for this directive.", sec: "A wildcard source is permissive — a common CSP weakness." },
    "child-src": { title: "child-src", desc: "Sources for workers and nested browsing contexts (frames).", sec: "Superseded by frame-src/worker-src but still honored — check what it allows." },
    "worker-src": { title: "worker-src", desc: "Where Web/Shared/Service Workers may be loaded from.", sec: "Permissive worker-src can let injected code spin up a worker outside script-src." },
    "manifest-src": { title: "manifest-src", desc: "Where the web-app manifest may be loaded from." },
    "media-src": { title: "media-src", desc: "Where <audio>/<video> media may load from." },
    "prefetch-src": { title: "prefetch-src", desc: "Sources for prefetch/prerender requests (deprecated)." },
    "script-src-elem": { title: "script-src-elem", desc: "Sources for <script> elements specifically (overrides script-src for them).", sec: "A gap between -elem and -attr can leave one execution path under-restricted." },
    "script-src-attr": { title: "script-src-attr", desc: "Controls inline event-handler attributes (onclick, ...) specifically.", sec: "If this is looser than script-src, on* handler XSS may still fire." },
    "style-src-elem": { title: "style-src-elem", desc: "Sources for <style>/<link rel=stylesheet> specifically." },
    "style-src-attr": { title: "style-src-attr", desc: "Controls inline style attributes specifically." },
    "trusted-types": { title: "trusted-types", desc: "Declares allowed Trusted-Types policy names to lock down DOM-XSS sinks.", sec: "A strong DOM-XSS mitigation; a wildcard or 'allow-duplicates' weakens it." },
    "require-trusted-types-for": { title: "require-trusted-types-for", desc: "Forces Trusted Types on dangerous DOM sinks (usually 'script').", sec: "When present with a tight policy, it blocks a whole class of DOM XSS." },
    "navigate-to": { title: "navigate-to", desc: "Restricts where the document may navigate (proposed, largely unshipped).", sec: "Where supported, it can blunt injected-link/open-redirect navigations." },
    "webrtc": { title: "webrtc", desc: "Allows or blocks the page's use of WebRTC ('allow' / 'block')." },
    "data": { title: "data: (scheme source)", desc: "Allows resources loaded from data: URIs for this directive.", sec: "data: in script-src (or default-src) is a frequent CSP-bypass foothold." },
    "blob": { title: "blob: (scheme source)", desc: "Allows resources loaded from blob: URLs for this directive.", sec: "blob: in script-src can be leveraged to run attacker-built scripts." },
    "https": { title: "https: (scheme source)", desc: "Allows any HTTPS origin for this directive.", sec: "A bare https: source trusts the whole web — nearly as weak as '*'." },
    "kw-wasm-unsafe-eval": { title: "'wasm-unsafe-eval'", desc: "Allows compiling/instantiating WebAssembly without allowing JS eval().", sec: "Narrower than 'unsafe-eval', but still review why Wasm compilation is needed." },
    "kw-unsafe-hashes": { title: "'unsafe-hashes'", desc: "Allows specific inline event handlers/style attributes by hash.", sec: "Loosens script-src-attr — confirm the hashed handlers are truly static." },
    "kw-report-sample": { title: "'report-sample'", desc: "Includes a short sample of the offending code in violation reports." },
    "kw-inline-speculation-rules": { title: "'inline-speculation-rules'", desc: "Allows inline <script type=speculationrules> for prefetch/prerender hints." }
  },
  cc: {
    "no-store": { title: "no-store", desc: "Never cache this response anywhere.", sec: "Correct for sensitive pages; its absence can leak data into shared caches." },
    "no-cache": { title: "no-cache", desc: "May be stored but must be revalidated before reuse." },
    "private": { title: "private", desc: "Only the end-user's browser may cache it, not shared/proxy caches." },
    "public": { title: "public", desc: "Any cache (including shared/CDN) may store it.", sec: "'public' on an authenticated response can leak it to other users." },
    "max-age": { title: "max-age", desc: "How long (seconds) the response is fresh." },
    "s-maxage": { title: "s-maxage", desc: "Like max-age but for shared caches; overrides it there." },
    "must-revalidate": { title: "must-revalidate", desc: "Once stale, the cache must revalidate before serving." },
    "immutable": { title: "immutable", desc: "The response won't change while fresh; skip revalidation." },
    "stale-while-revalidate": { title: "stale-while-revalidate", desc: "Serve stale while revalidating in the background." },
    "no-transform": { title: "no-transform", desc: "Proxies must not modify the body (e.g. re-compress images)." },
    "proxy-revalidate": { title: "proxy-revalidate", desc: "Like must-revalidate, but applies only to shared (proxy) caches." },
    "stale-if-error": { title: "stale-if-error", desc: "Serve a stale response if revalidation errors or the origin is down." },
    "only-if-cached": { title: "only-if-cached", desc: "Request directive: return a cached response or 504, never hit the origin." },
    "max-stale": { title: "max-stale", desc: "Request directive: accept a stale response up to this many seconds old." },
    "min-fresh": { title: "min-fresh", desc: "Request directive: only accept responses fresh for at least this many more seconds." },
    "must-understand": { title: "must-understand", desc: "Cache only if the cache understands the status code's caching rules." }
  },
  hsts: {
    "max-age": { title: "max-age (HSTS)", desc: "Seconds the browser will force HTTPS for this host.", sec: "A very small max-age barely protects; 0 disables HSTS." },
    "includesubdomains": { title: "includeSubDomains", desc: "Applies the HSTS policy to every subdomain too.", sec: "Its absence leaves subdomains open to SSL-strip." },
    "preload": { title: "preload", desc: "Opts the host into browsers' built-in HSTS preload lists." }
  },
  ct: {
    "application/json": { title: "application/json", desc: "A JSON body.", sec: "Try swapping to XML or form encoding — alternate parsers may be laxer." },
    "application/x-www-form-urlencoded": { title: "form-urlencoded", desc: "Classic key=value&key=value form body." },
    "multipart/form-data": { title: "multipart/form-data", desc: "Multi-part body, used for file uploads.", sec: "The upload path — test file type/extension/content bypasses." },
    "application/xml": { title: "application/xml", desc: "An XML body.", sec: "XML parsing is where XXE lives — check for DOCTYPE handling." },
    "text/xml": { title: "text/xml", desc: "An XML body.", sec: "Same XXE surface as application/xml." },
    "text/html": { title: "text/html", desc: "An HTML document.", sec: "Reflected input rendered here is the classic XSS surface." },
    "text/plain": { title: "text/plain", desc: "Unstructured text.", sec: "Sometimes used to dodge CSRF content-type checks." },
    "application/octet-stream": { title: "application/octet-stream", desc: "Arbitrary binary data / a download." },
    "application/javascript": { title: "application/javascript", desc: "JavaScript source.", sec: "If it reflects input, consider JSONP/callback abuse." },
    "application/graphql": { title: "application/graphql", desc: "A GraphQL query body.", sec: "Probe introspection (__schema) and batching/alias abuse." },
    "text/csv": { title: "text/csv", desc: "CSV data.", sec: "User-controlled cells can trigger CSV/formula injection in spreadsheet apps." },
    "image/svg+xml": { title: "image/svg+xml", desc: "An SVG image — which is XML and can carry script and event handlers.", sec: "User-supplied SVG rendered inline (or same-origin) is a classic stored-XSS vector." },
    "application/xhtml+xml": { title: "application/xhtml+xml", desc: "XHTML served as XML.", sec: "Strict XML parsing changes escaping rules — an mXSS and XXE surface." },
    "application/soap+xml": { title: "application/soap+xml", desc: "A SOAP envelope (XML).", sec: "SOAP endpoints are prime XXE and XML-injection targets — probe DOCTYPE handling." },
    "application/ld+json": { title: "application/ld+json", desc: "JSON-LD structured/linked data.", sec: "Often reflected into pages for SEO — check for injection into that context." },
    "application/vnd.api+json": { title: "application/vnd.api+json", desc: "A JSON:API-formatted body." },
    "application/hal+json": { title: "application/hal+json", desc: "HAL hypermedia JSON, exposing linked resources.", sec: "Embedded _links can reveal hidden endpoints worth testing." },
    "application/jwt": { title: "application/jwt", desc: "The body is a JSON Web Token.", sec: "Hover the token itself to decode it and inspect alg/claims." },
    "application/x-yaml": { title: "application/x-yaml", desc: "A YAML body.", sec: "Unsafe YAML deserialization (tags/anchors) can lead to RCE — check the parser." },
    "text/yaml": { title: "text/yaml", desc: "A YAML body.", sec: "Same unsafe-deserialization surface as application/x-yaml." },
    "application/pdf": { title: "application/pdf", desc: "A PDF document." },
    "application/zip": { title: "application/zip", desc: "A ZIP archive.", sec: "Server-side unzip can enable zip-slip path traversal and zip-bomb DoS." },
    "application/wasm": { title: "application/wasm", desc: "A compiled WebAssembly module." },
    "text/event-stream": { title: "text/event-stream", desc: "Server-Sent Events — a long-lived stream of updates." },
    "application/x-ndjson": { title: "application/x-ndjson", desc: "Newline-delimited JSON (one object per line)." },
    "application/x-protobuf": { title: "application/x-protobuf", desc: "Protocol Buffers binary body.", sec: "Tamper with encoded fields to probe validation and mass-assignment." },
    "application/x-amf": { title: "application/x-amf", desc: "Action Message Format (Flash/Flex remoting).", sec: "AMF endpoints have a history of unsafe deserialization — a serious RCE surface." },
    "multipart/mixed": { title: "multipart/mixed", desc: "A body of several parts with differing content types." },
    "application/dns-message": { title: "application/dns-message", desc: "A DNS query/response body (DNS-over-HTTPS)." }
  },
  auth: {
    "basic": { title: "Basic auth", desc: "Credentials are base64('user:pass') — encoding, not encryption.", sec: "Trivially decodable; capture and decode to recover the credentials." },
    "bearer": { title: "Bearer token", desc: "An opaque or JWT token proving the caller's identity.", sec: "If it's a JWT, hover the token itself to decode it and inspect alg/claims." },
    "digest": { title: "Digest auth", desc: "Challenge-response auth that avoids sending the raw password." },
    "negotiate": { title: "Negotiate (SPNEGO)", desc: "Kerberos/NTLM negotiation, common on Windows/AD networks." },
    "ntlm": { title: "NTLM", desc: "Microsoft challenge-response auth.", sec: "Relay and hash-capture attacks are the usual angle." },
    "aws4-hmac-sha256": { title: "AWS Signature v4", desc: "Amazon's SigV4 request-signing scheme; the header carries Credential, SignedHeaders, and Signature.", sec: "Leaks the AWS access-key ID and region/service; check for signature-bypass and replay (SignedHeaders scope)." },
    "hawk": { title: "Hawk", desc: "HMAC-based request auth (id + mac + ts + nonce).", sec: "Weak or leaked shared keys allow request forgery; check nonce/timestamp replay windows." },
    "signature": { title: "HTTP Signature", desc: "Signs selected headers with a keyId and algorithm (IETF HTTP Message Signatures).", sec: "Confirm which headers are actually signed — unsigned ones are tamperable." }
  },
  attr: {
    "on": { title: "Event handler (on*)", desc: "Runs JavaScript when the event fires (onerror, onload, onclick, ...).", sec: "A reflected/injected on* handler is direct XSS execution." },
    "src": { title: "src", desc: "The URL of the resource to load.", sec: "Attacker-controlled src (script/img/iframe) loads or runs external content." },
    "href": { title: "href", desc: "The link destination.", sec: "javascript: URIs execute; user-controlled href enables XSS / open redirect." },
    "action": { title: "action (form)", desc: "Where the form submits.", sec: "A controllable action retargets credentials/data to an attacker." },
    "formaction": { title: "formaction", desc: "Overrides the form's action for one button/input.", sec: "Injected formaction hijacks submission and can dodge some CSP." },
    "srcdoc": { title: "srcdoc (iframe)", desc: "Inline HTML for an iframe's content.", sec: "A sink for HTML-injection / sandbox-escape XSS." },
    "sandbox": { title: "sandbox (iframe)", desc: "Restricts what framed content can do.", sec: "allow-scripts + allow-same-origin together largely defeats the sandbox." },
    "rel": { title: "rel", desc: "The relationship of a link (stylesheet, noopener, preload, ...).", sec: "Missing rel=noopener with target=_blank enables reverse tabnabbing." },
    "target": { title: "target", desc: "Where to open a link (_blank, _self, ...).", sec: "_blank without rel=noopener lets the new page control window.opener." },
    "type": { title: "type", desc: "The kind of input or resource.", sec: "input type=hidden carries tamperable state; password fields shouldn't autofill." },
    "http-equiv": { title: "http-equiv (meta)", desc: "Emulates an HTTP response header from within HTML.", sec: "Can set CSP or a refresh redirect — check the paired content value." },
    "content": { title: "content (meta)", desc: "The value for the meta's name/http-equiv.", sec: "With http-equiv=refresh, the URL here can be an open redirect." },
    "integrity": { title: "integrity (SRI)", desc: "A Subresource-Integrity hash the fetched resource must match.", sec: "Its absence on third-party scripts allows silent supply-chain tampering." },
    "nonce": { title: "nonce", desc: "A per-response token that allowlists this inline script/style under CSP.", sec: "A predictable or reused nonce defeats CSP." },
    "style": { title: "style", desc: "Inline CSS on the element.", sec: "A CSS-injection sink; can aid UI-redress or data exfiltration." },
    "autocomplete": { title: "autocomplete", desc: "Hints whether the browser may autofill a field.", sec: "Sensitive fields should use off / new-password." },
    "name": { title: "name", desc: "The field name submitted with a form.", sec: "Reveals expected parameters — handy for mass-assignment / IDOR." },
    "method": { title: "method (form)", desc: "The HTTP method the form uses (GET/POST)." },
    "value": { title: "value", desc: "The field's current value.", sec: "Hidden field values are tamperable client-side state." },
    "enctype": { title: "enctype (form)", desc: "How form data is encoded on submit (urlencoded / multipart / text/plain).", sec: "Switching to text/plain is used to dodge CSRF content-type checks." },
    "formmethod": { title: "formmethod", desc: "Overrides the form's method for one submit button.", sec: "Can flip a submit to GET/POST to reach a different, less-guarded handler." },
    "formenctype": { title: "formenctype", desc: "Overrides the form's enctype for one submit button.", sec: "Like enctype, can be used to dodge content-type-based CSRF checks." },
    "crossorigin": { title: "crossorigin", desc: "How a subresource is fetched cross-origin (anonymous / use-credentials).", sec: "'use-credentials' sends cookies to third-party resources; pair with SRI (integrity)." },
    "referrerpolicy": { title: "referrerpolicy", desc: "Per-element control of how much Referer is sent when fetching it.", sec: "A loose value can leak tokens embedded in the current URL to third parties." },
    "ping": { title: "ping (a)", desc: "URLs the browser POSTs to when the link is followed (click tracking).", sec: "A controllable ping list fires background POSTs to attacker URLs on click." },
    "download": { title: "download (a)", desc: "Marks the link as a download and suggests a filename.", sec: "A controllable filename can enable reflected-file-download / misleading saves." },
    "allow": { title: "allow (iframe)", desc: "Feature-policy grant list for the framed document (camera, geolocation, ...).", sec: "Over-broad grants let embedded/injected content use powerful browser features." },
    "loading": { title: "loading", desc: "Lazy- or eager-loads an image/iframe ('lazy' / 'eager')." }
  }
};
// Decode a base64url segment to a string (best-effort).
function b64urlToStr(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  try { return decodeURIComponent(escape(atob(s))); } catch (e) { try { return atob(s); } catch (e2) { return ""; } }
}
// Build a live tip for a JWT: decode header+payload and flag common weaknesses.
function decodeJwtTip(token) {
  const parts = String(token).split(".");
  let header = {}, payload = {};
  try { header = JSON.parse(b64urlToStr(parts[0])); } catch (e) {}
  try { payload = JSON.parse(b64urlToStr(parts[1])); } catch (e) {}
  const alg = (header && header.alg) || "?";
  const claims = payload && typeof payload === "object"
    ? Object.keys(payload).slice(0, 8).map(k => {
        const v = payload[k];
        return k + "=" + (typeof v === "object" ? JSON.stringify(v) : String(v));
      }).join(", ")
    : "";
  const desc = "alg=" + alg + (header && header.typ ? ", typ=" + header.typ : "") +
    (claims ? "\nClaims: " + claims : "");
  let sec;
  if (String(alg).toLowerCase() === "none") sec = "alg=none — the token is UNSIGNED; you may be able to forge claims outright. ";
  else if (/^hs/i.test(alg)) sec = "HMAC (HS*) — a weak or guessable secret lets you forge tokens (try 'secret', then brute-force). ";
  else if (/^(rs|es|ps)/i.test(alg)) sec = "Asymmetric — test alg-confusion (swap RS256→HS256 signed with the public key). ";
  else sec = "";
  sec += "Check exp/nbf and whether privileged claims (role/admin/scope) are trusted server-side.";
  return { title: "JWT — JSON Web Token", desc: desc, sec: sec };
}
function lookupTip(raw) {
  if (!raw) return null;
  const i = raw.indexOf(":"); if (i < 0) return null;
  const p = raw.slice(0, i), k = raw.slice(i + 1);
  if (p === "h") return HTTP_TIPS.headers[k] || null;
  if (p === "m") return HTTP_TIPS.methods[k] || null;
  if (p === "s") return HTTP_TIPS.status[k] || HTTP_TIPS.statusClass[(k[0] || "") + "xx"] || null;
  if (p === "t") return HTTP_TIPS.tags[k] || null;
  if (p === "cookie") return HTTP_TIPS.cookie[k] || null;
  if (p === "csp") return HTTP_TIPS.csp[k] || null;
  if (p === "cc") return HTTP_TIPS.cc[k] || null;
  if (p === "hsts") return HTTP_TIPS.hsts[k] || null;
  if (p === "ct") return HTTP_TIPS.ct[k] || null;
  if (p === "auth") return HTTP_TIPS.auth[k] || null;
  if (p === "attr") return HTTP_TIPS.attr[k] || null;
  if (p === "jwt") return decodeJwtTip(k);
  return null;
}
let repTipsOn = false, repTipRAF = 0, repPrettyOn = false;
function repShowTip(tip, x, y) {
  const b = $("rep-tip");
  b.innerHTML = '<div class="tip-title">' + esc(tip.title) + '</div>' +
    '<div class="tip-desc">' + esc(tip.desc) + '</div>' +
    (tip.sec ? '<div class="tip-sec">&#9656; ' + esc(tip.sec) + '</div>' : '');
  b.style.display = "block";
  const pad = 16, bw = b.offsetWidth, bh = b.offsetHeight;
  let left = x + pad, top = y + pad;
  if (left + bw > innerWidth - 8) left = x - bw - pad;
  if (top + bh > innerHeight - 8) top = y - bh - pad;
  b.style.left = Math.max(8, left) + "px";
  b.style.top = Math.max(8, top) + "px";
}
function repHideTip() { $("rep-tip").style.display = "none"; }
function repTipMove(e) {
  const x = e.clientX, y = e.clientY;
  if (repTipRAF) cancelAnimationFrame(repTipRAF);
  repTipRAF = requestAnimationFrame(() => {
    repTipRAF = 0;
    // elementsFromPoint sees THROUGH the request textarea to the colored spans
    // in the backdrop beneath it, so tips work in both panes.
    let el = null;
    for (const n of document.elementsFromPoint(x, y)) {
      if (n.getAttribute && n.getAttribute("data-tip")) { el = n; break; }
    }
    const tip = el && lookupTip(el.getAttribute("data-tip"));
    if (tip) repShowTip(tip, x, y); else repHideTip();
  });
}
function setRepTips(on) {
  repTipsOn = on;
  const split = document.querySelector(".rep-split"), btn = $("rep-tips");
  btn.classList.toggle("on", on);
  btn.textContent = on ? "Tips: on" : "Tips: off";
  split.classList.toggle("tips-on", on);
  if (on) { split.addEventListener("mousemove", repTipMove); split.addEventListener("mouseleave", repHideTip); }
  else { split.removeEventListener("mousemove", repTipMove); split.removeEventListener("mouseleave", repHideTip); repHideTip(); }
  try { localStorage.setItem("beatrix.rep.tips", on ? "1" : "0"); } catch (e) {}
}

async function loadRepeaterFor(pid) {
  if (pid === null) return;
  const d = await (await fetch("/repeater?project=" + pid)).json();
  if (pid !== activeProject) return;          // project switched mid-fetch
  repTabs = d.tabs || []; repActive = d.active;
  renderRepTabbar(); showActiveRepTab();
}

// Hand an issue's request to a fresh Repeater tab, then jump to it — the bridge
// between the Issues and Repeater tools. The request is real raw HTTP (captured
// or reconstructed), so it drops straight in; the target is the issue's origin.
async function sendIssueToRepeater(d) {
  let target = "";
  try { target = new URL(d.url).origin; } catch (e) {}
  await fetch("/repeater/new", { method: "POST", body: JSON.stringify({
    project: activeProject, request: d.request || "", target }) });
  document.querySelector('nav button[data-tab="repeater"]').click();  // loads fresh state; new tab is active
}

function renderRepTabbar() {
  const bar = $("rep-tabbar"); bar.innerHTML = "";
  for (const t of repTabs) {
    const b = document.createElement("button");
    b.className = "rep-tab" + (t.id === repActive ? " active" : "");
    b.title = "Double-click to rename";
    const cap = document.createElement("span");
    cap.textContent = repCaption(t);
    b.appendChild(cap);
    const x = document.createElement("span");
    x.className = "x"; x.textContent = "×"; x.title = "Close tab";
    x.onclick = (e) => { e.stopPropagation(); closeRepTab(t.id); };
    b.appendChild(x);
    b.onclick = () => selectRepTab(t.id);
    b.ondblclick = () => renameRepTab(t.id);
    bar.appendChild(b);
  }
  const add = document.createElement("button");
  add.className = "rep-tab add"; add.textContent = "+"; add.title = "New Repeater tab";
  add.onclick = newRepTab;
  bar.appendChild(add);
}

function showActiveRepTab() {
  const t = repTab();
  repView = { live: true, idx: 0 };
  if (!t) { $("rep-request").value = ""; $("rep-target").value = ""; repHighlightRequest(); renderRepResponse(null); updateRepHistUI(); return; }
  $("rep-request").value = t.request || "";
  $("rep-target").value = t.target || "";
  repHighlightRequest();
  renderRepResponse(t.response || null);
  updateRepHistUI();
}

async function selectRepTab(id) {
  if (id === repActive) return;
  repActive = id; renderRepTabbar(); showActiveRepTab();
  fetch("/repeater/select", { method: "POST", body: JSON.stringify({ project: activeProject, id }) });
}
async function newRepTab() {
  const d = await (await fetch("/repeater/new", { method: "POST",
    body: JSON.stringify({ project: activeProject }) })).json();
  repTabs = d.tabs || []; repActive = d.active; renderRepTabbar(); showActiveRepTab();
}
async function closeRepTab(id) {
  const d = await (await fetch("/repeater/close", { method: "POST",
    body: JSON.stringify({ project: activeProject, id }) })).json();
  if (!d.ok) return;
  repTabs = d.tabs || []; repActive = d.active; renderRepTabbar(); showActiveRepTab();
}
async function renameRepTab(id) {
  const t = repTabs.find(x => x.id === id); if (!t) return;
  const name = prompt("Rename tab", repCaption(t));
  if (name === null) return;
  const d = await (await fetch("/repeater/rename", { method: "POST",
    body: JSON.stringify({ project: activeProject, id, name }) })).json();
  if (d.ok) { repTabs = d.tabs || repTabs; renderRepTabbar(); }
}

// Autosave the editable buffers so a tab survives a project switch / reload.
function scheduleRepSave() {
  const t = repTab(); if (!t) return;
  t.request = $("rep-request").value; t.target = $("rep-target").value;
  clearTimeout(repSaveTimer);
  const id = t.id;
  repSaveTimer = setTimeout(() => {
    fetch("/repeater/save", { method: "POST", body: JSON.stringify({
      project: activeProject, id, request: t.request, target: t.target }) });
  }, 500);
}
$("rep-request").addEventListener("input", () => { repView = { live: true, idx: 0 }; repHighlightRequest(); scheduleRepSave(); updateRepHistUI(); });
$("rep-request").addEventListener("scroll", () => {
  const hl = $("rep-request-hl");
  hl.scrollTop = $("rep-request").scrollTop; hl.scrollLeft = $("rep-request").scrollLeft;
});
$("rep-target").addEventListener("input", scheduleRepSave);
$("rep-request").addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); sendRep(); }
});
$("rep-send").onclick = sendRep;
// Hand a request to AutoRepeater as its attack template, then jump to that tab.
function sendToAutoRepeater(request, target) {
  document.querySelector('nav button[data-tab="autorepeater"]').click();
  $("ar-template").value = request || "";
  if (target) $("ar-target").value = target;
  arRenderPayloadBoxes();                            // recompute § positions for the new template
}
$("rep-toar").onclick = () => sendToAutoRepeater($("rep-request").value, $("rep-target").value);
initRepSettings();

async function sendRep() {
  const t = repTab(); if (!t) return;
  const request = $("rep-request").value, target = $("rep-target").value;
  clearTimeout(repSaveTimer);                       // the send persists the buffers too
  $("rep-send").disabled = true;
  $("rep-status").innerHTML = '<span class="dim">sending…</span>';
  try {
    const d = await (await fetch("/repeater/send", { method: "POST",
      body: JSON.stringify({ project: activeProject, id: t.id, request, target }) })).json();
    if (d.tab) { Object.assign(t, d.tab); }          // adopt server's updated history/response
    else { t.request = request; t.target = target; t.response = d.response;
           (t.history = t.history || []).push({ request, target, response: d.response }); }
    repView = { live: true, idx: 0 };
    renderRepResponse(t.response); updateRepHistUI();
  } catch (e) {
    $("rep-status").innerHTML = '<span class="bad">send failed: ' + esc(e.message || e) + '</span>';
  } finally {
    $("rep-send").disabled = false;
  }
}

// ── Beautify: pretty-print the response BODY, leaving the head untouched ──
// Only JSON and XML/HTML are reformatted; anything else (or a malformed/
// truncated body) is returned verbatim, so the toggle is always safe/lossless
// to flip off. Headers keep their original bytes.
function beautifyHttp(raw) {
  const norm = String(raw || "").replace(/\r\n/g, "\n");
  const idx = norm.indexOf("\n\n");
  if (idx === -1) return raw;                       // headers only, no body
  const head = norm.slice(0, idx), body = norm.slice(idx + 2);
  const kind = repDetectCT(head.split("\n")) ||
    (/^\s*[{\[]/.test(body) ? "json" : /^\s*</.test(body) ? "xml" : "");
  let pretty = null;
  try {
    if (kind === "json") pretty = JSON.stringify(JSON.parse(body), null, 2);
    else if (kind === "xml") pretty = beautifyMarkup(body);
  } catch (e) { pretty = null; }                    // malformed/truncated → leave as-is
  return pretty == null ? raw : head + "\n\n" + pretty;
}
// Reindent XML/HTML by nesting depth. Raw-text elements (script/style/pre/
// textarea), comments, and CDATA are emitted byte-for-byte so we never mangle
// code or significant whitespace.
function beautifyMarkup(src) {
  const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr"]);
  const RAW = new Set(["script", "style", "pre", "textarea"]);
  const s = String(src), out = [];
  let depth = 0, i = 0;
  const pad = () => "  ".repeat(depth < 0 ? 0 : depth);
  const push = (line) => { const t = line.trim(); if (t) out.push(pad() + t); };
  const openRe = /<([a-zA-Z][\w:-]*)\b[^>]*?(\/?)>/y;
  while (i < s.length) {
    if (s[i] === "<") {
      if (s.startsWith("<!--", i)) {                // comment (may contain '>')
        const e = s.indexOf("-->", i); const end = e === -1 ? s.length : e + 3;
        out.push(pad() + s.slice(i, end)); i = end; continue;
      }
      if (s.startsWith("<![CDATA[", i)) {
        const e = s.indexOf("]]>", i); const end = e === -1 ? s.length : e + 3;
        out.push(pad() + s.slice(i, end)); i = end; continue;
      }
      openRe.lastIndex = i;
      const om = openRe.exec(s);
      if (om && om.index === i && om[2] !== "/" && RAW.has(om[1].toLowerCase())) {
        const closeRe = new RegExp("</" + om[1] + "\\s*>", "ig");
        closeRe.lastIndex = openRe.lastIndex;
        const cm = closeRe.exec(s);
        const end = cm ? cm.index + cm[0].length : s.length;
        out.push(pad() + s.slice(i, end)); i = end; continue;
      }
      const gt = s.indexOf(">", i);
      if (gt === -1) { push(s.slice(i)); break; }
      const tag = s.slice(i, gt + 1);
      if (/^<\//.test(tag)) { depth--; push(tag); }                 // closing
      else if (/^<[!?]/.test(tag)) { push(tag); }                   // doctype / PI
      else if (om && om.index === i && (om[2] === "/" || VOID.has(om[1].toLowerCase()))) push(tag);
      else { push(tag); depth++; }                                  // opening
      i = gt + 1;
    } else {
      const gt = s.indexOf("<", i);
      const end = gt === -1 ? s.length : gt;
      push(s.slice(i, end));
      i = end;
    }
  }
  return out.join("\n");
}
// The response currently on screen (live buffer or the scrubbed history entry).
function currentRepResponse() {
  const t = repTab(); if (!t) return null;
  if (repView.live) return t.response || null;
  const h = (t.history || [])[repView.idx];
  return h ? (h.response || null) : null;
}
function setRepPretty(on) {
  repPrettyOn = on;
  const btn = $("rep-pretty");
  if (btn) { btn.classList.toggle("on", on); btn.textContent = on ? "Beautify: on" : "Beautify: off"; }
  try { localStorage.setItem("beatrix.rep.pretty", on ? "1" : "0"); } catch (e) {}
  renderRepResponse(currentRepResponse());          // re-render whatever's shown
}

function renderRepResponse(resp) {
  const pre = $("rep-response");
  if (!resp) { pre.textContent = ""; pre.classList.remove("err"); $("rep-status").textContent = ""; return; }
  if (resp.error) {
    pre.classList.add("err"); pre.textContent = resp.error;
    $("rep-status").innerHTML = '<span class="bad">✕ ' + esc(resp.error) + '</span>';
    return;
  }
  pre.classList.remove("err");
  pre.innerHTML = hlHttp(repPrettyOn ? beautifyHttp(resp.raw || "") : (resp.raw || ""), "response");
  const cls = resp.status >= 200 && resp.status < 300 ? "ok"
            : resp.status >= 400 ? "bad" : "dim";
  const bits = ['<span class="' + cls + '">' + resp.status + " " + esc(resp.reason || "") + "</span>",
    repBytes(resp.size || 0), (resp.time_ms || 0) + " ms"];
  if (resp.truncated) bits.push('<span class="dim">(body truncated)</span>');
  $("rep-status").innerHTML = bits.join(" · ");
}

// History scrub: ‹ › walk the tab's past sends; the newest step forward returns
// to the live editable buffer.
function repHistoryCount() { const t = repTab(); return t && t.history ? t.history.length : 0; }
function showRepSnapshot() {
  const t = repTab(); if (!t) return;
  if (repView.live) {
    $("rep-request").value = t.request || ""; renderRepResponse(t.response || null);
  } else {
    const h = (t.history || [])[repView.idx];
    if (h) { $("rep-request").value = h.request || ""; renderRepResponse(h.response || null); }
  }
  repHighlightRequest();
  updateRepHistUI();
}
function updateRepHistUI() {
  const total = repHistoryCount();
  const pos = repView.live ? total : (repView.idx + 1);
  $("rep-histlabel").textContent = pos + " of " + total;
  $("rep-prev").disabled = total === 0 || (!repView.live && repView.idx === 0);
  $("rep-next").disabled = repView.live || total === 0;
}
$("rep-prev").onclick = () => {
  const total = repHistoryCount(); if (!total) return;
  if (repView.live) repView = { live: false, idx: total - 1 };
  else if (repView.idx > 0) repView = { live: false, idx: repView.idx - 1 };
  showRepSnapshot();
};
$("rep-next").onclick = () => {
  const total = repHistoryCount(); if (repView.live || !total) return;
  if (repView.idx >= total - 1) repView = { live: true, idx: 0 };
  else repView = { live: false, idx: repView.idx + 1 };
  showRepSnapshot();
};

// Live refresh: keep the Issues badge current everywhere, and the list current
// while it's the visible tab, so findings appear as a scan discovers them.
setInterval(() => {
  if (activeProject === null) return;
  const onIssues = document.querySelector('nav button[data-tab="issues"]').classList.contains("active");
  if (onIssues) { loadIssuesFor(activeProject); return; }
  fetch("/issues/count?project=" + activeProject).then(r => r.json())
    .then(d => updateIssueBadge(d.count || 0)).catch(() => {});
}, 2000);

// ── AutoRepeater (Intruder-style automated attacks) ──
let arResults = [], arSince = 0, arPollTimer = null, arSort = { key: "index", dir: 1 },
    arSelected = null, arDetailTab = "request", arDetailRow = null, arSets = [], arRules = [];
const AR_COLS = [
  { key: "index", label: "#" }, { key: "payloads", label: "Payload" },
  { key: "status", label: "Status" }, { key: "length", label: "Length" },
  { key: "time_ms", label: "Time" },
];
function arPositionCount() { return Math.floor(($("ar-template").value.match(/§/g) || []).length / 2); }
function arNeedsPerPosition() { const t = $("ar-attack").value; return t === "pitchfork" || t === "clusterbomb"; }
function arDefaultSet() {
  return { type: "list", items: "", from: 1, to: 100, step: 1,
    charset: "abcdefghijklmnopqrstuvwxyz0123456789", min: 1, max: 3 };
}
// Each payload set is type-aware: a simple list, a number range, or a brute
// forcer over a charset. arSets is the source of truth so state survives
// re-renders when the position count or attack type changes.
function arSetEditor(i, perPos) {
  const s = arSets[i];
  const wrap = document.createElement("div"); wrap.className = "ar-pset";
  const hd = document.createElement("div"); hd.className = "ar-pset-hd";
  hd.innerHTML = "<span>" + esc(perPos ? ("Set " + (i + 1) + " · position " + (i + 1)) : "Payload set") + "</span>";
  const sel = document.createElement("select"); sel.className = "ar-pset-type";
  for (const [v, t] of [["list", "List"], ["numbers", "Numbers"], ["brute", "Brute forcer"]]) {
    const o = document.createElement("option"); o.value = v; o.textContent = t;
    if (s.type === v) o.selected = true; sel.appendChild(o);
  }
  sel.onchange = () => { s.type = sel.value; arRenderPayloadBoxes(); };
  hd.appendChild(sel); wrap.appendChild(hd);
  const body = document.createElement("div"); body.className = "ar-pset-body";
  if (s.type === "list") {
    const ta = document.createElement("textarea"); ta.spellcheck = false;
    ta.placeholder = "one payload per line"; ta.value = s.items || "";
    ta.oninput = () => { s.items = ta.value; };
    body.appendChild(ta);
  } else if (s.type === "numbers") {
    body.innerHTML = '<div class="ar-inline">from <input type="number" data-k="from" value="' + s.from +
      '"> to <input type="number" data-k="to" value="' + s.to +
      '"> step <input type="number" data-k="step" value="' + s.step + '"></div>';
  } else if (s.type === "brute") {
    body.innerHTML = '<div class="ar-inline">charset <input class="wide" data-k="charset" value="' + escAttr(s.charset) + '"></div>' +
      '<div class="ar-inline">min len <input type="number" data-k="min" value="' + s.min +
      '"> max len <input type="number" data-k="max" value="' + s.max + '"></div>';
  }
  body.querySelectorAll("[data-k]").forEach(inp => {
    inp.oninput = () => { s[inp.dataset.k] = inp.type === "number" ? (+inp.value) : inp.value; };
  });
  wrap.appendChild(body); return wrap;
}
function arRenderPayloadBoxes() {
  const pos = arPositionCount(), perPos = arNeedsPerPosition(), count = perPos ? Math.max(1, pos) : 1;
  $("ar-poscount").textContent = pos ? (pos + " position" + (pos === 1 ? "" : "s")) : "no positions yet";
  while (arSets.length < count) arSets.push(arDefaultSet());
  const box = $("ar-payloads"); box.innerHTML = "";
  for (let i = 0; i < count; i++) box.appendChild(arSetEditor(i, perPos));
}
function arGatherSets() {
  const perPos = arNeedsPerPosition(), pos = arPositionCount(), count = perPos ? Math.max(1, pos) : 1;
  const out = [];
  for (let i = 0; i < count; i++) {
    const s = arSets[i] || arDefaultSet();
    if (s.type === "numbers") out.push({ type: "numbers", from: +s.from, to: +s.to, step: +s.step });
    else if (s.type === "brute") out.push({ type: "brute", charset: s.charset, min: +s.min, max: +s.max });
    else out.push({ type: "list", items: (s.items || "").split("\n").filter(x => x.length) });
  }
  return out;
}
// Payload processing rules — applied in order to every payload before it's sent.
const AR_RULE_TYPES = [["prefix", "Add prefix"], ["suffix", "Add suffix"], ["urlencode", "URL-encode"],
  ["base64", "Base64-encode"], ["upper", "Uppercase"], ["lower", "Lowercase"],
  ["md5", "Hash MD5"], ["sha1", "Hash SHA-1"], ["sha256", "Hash SHA-256"], ["replace", "Match/replace"]];
$("ar-addrule").onclick = () => { arRules.push({ type: "prefix", value: "" }); arRenderRules(); };
function arRenderRules() {
  const box = $("ar-rules"); box.innerHTML = "";
  arRules.forEach((r, idx) => {
    const row = document.createElement("div"); row.className = "ar-rule";
    const sel = document.createElement("select");
    for (const [v, t] of AR_RULE_TYPES) {
      const o = document.createElement("option"); o.value = v; o.textContent = t;
      if (r.type === v) o.selected = true; sel.appendChild(o);
    }
    sel.onchange = () => { r.type = sel.value; arRenderRules(); };
    row.appendChild(sel);
    if (r.type === "prefix" || r.type === "suffix") {
      const inp = document.createElement("input"); inp.placeholder = "text"; inp.value = r.value || "";
      inp.oninput = () => { r.value = inp.value; }; row.appendChild(inp);
    } else if (r.type === "replace") {
      const f = document.createElement("input"); f.placeholder = "find"; f.value = r.find || "";
      f.oninput = () => { r.find = f.value; }; row.appendChild(f);
      const rp = document.createElement("input"); rp.placeholder = "replace"; rp.value = r.replace || "";
      rp.oninput = () => { r.replace = rp.value; }; row.appendChild(rp);
    }
    const del = document.createElement("button"); del.className = "ar-rule-x"; del.textContent = "×";
    del.onclick = () => { arRules.splice(idx, 1); arRenderRules(); };
    row.appendChild(del); box.appendChild(row);
  });
}
$("ar-template").addEventListener("input", arRenderPayloadBoxes);
$("ar-attack").addEventListener("change", arRenderPayloadBoxes);
$("ar-mark").onclick = () => {
  const ta = $("ar-template"), s = ta.selectionStart, e = ta.selectionEnd, v = ta.value;
  if (s === e) return;                               // nothing selected → no position
  ta.value = v.slice(0, s) + "§" + v.slice(s, e) + "§" + v.slice(e);
  arRenderPayloadBoxes();
};
$("ar-clearpos").onclick = () => { $("ar-template").value = $("ar-template").value.replace(/§/g, ""); arRenderPayloadBoxes(); };
$("ar-start").onclick = arStart;
$("ar-stop").onclick = arStop;

async function arStart() {
  const body = { project: activeProject, target: $("ar-target").value, attack_type: $("ar-attack").value,
    template: $("ar-template").value, payload_sets: arGatherSets(),
    processing: arRules.map(r => ({ ...r })), grep: $("ar-grep").value, extract: $("ar-extract").value,
    concurrency: parseInt($("ar-conc").value, 10) || 10, throttle: parseInt($("ar-throttle").value, 10) || 0 };
  const r = await (await fetch("/autorepeater/run", { method: "POST", body: JSON.stringify(body) })).json();
  if (!r.ok) { $("ar-progress").innerHTML = '<span class="bad">' + esc(r.error || "could not start") + '</span>'; return; }
  arResults = []; arSince = 0; arSelected = null; arDetailRow = null;
  $("ar-detail").textContent = ""; $("ar-empty").style.display = "none";
  $("ar-start").disabled = true; $("ar-stop").disabled = false;
  arRenderTable(); arPoll();
}
async function arStop() { await fetch("/autorepeater/stop", { method: "POST", body: JSON.stringify({ project: activeProject }) }); }

async function arPoll() {
  clearTimeout(arPollTimer);
  let d;
  try { d = await (await fetch("/autorepeater/events?since=" + arSince + "&project=" + activeProject)).json(); }
  catch (e) { arPollTimer = setTimeout(arPoll, 600); return; }
  for (const row of d.results) { arResults.push(row); arSince = Math.max(arSince, row.index); }
  if (d.results.length) arRenderTable();
  const done = d.done && d.count >= d.total;
  $("ar-progress").textContent = (d.count || 0) + " / " + (d.total || 0) + (d.running ? " · running" : done ? " · done" : "");
  if (d.error) $("ar-progress").innerHTML += ' <span class="bad">' + esc(d.error) + '</span>';
  if (!d.running) { $("ar-start").disabled = false; $("ar-stop").disabled = true; }
  else arPollTimer = setTimeout(arPoll, 400);
}
function arStatusCls(s) {
  if (s == null) return "ar-st-err";
  if (s >= 200 && s < 300) return "ar-st-2xx";
  if (s >= 300 && s < 400) return "ar-st-3xx";
  if (s >= 400 && s < 500) return "ar-st-4xx";
  if (s >= 500) return "ar-st-5xx";
  return "";
}
function arRenderTable() {
  const hasGrep = arResults.some(r => r.grep != null);
  const hasExtract = arResults.some(r => r.extract != null);
  let cols = AR_COLS.slice();
  if (hasGrep) cols = cols.concat([{ key: "grep", label: "Grep" }]);
  if (hasExtract) cols = cols.concat([{ key: "extract", label: "Extract" }]);
  const thead = $("ar-thead"); thead.innerHTML = "";
  for (const c of cols) {
    const th = document.createElement("th");
    th.textContent = c.label;
    if (arSort.key === c.key) th.className = "sorted" + (arSort.dir > 0 ? " asc" : "");
    th.onclick = () => { if (arSort.key === c.key) arSort.dir *= -1; else arSort = { key: c.key, dir: 1 }; arRenderTable(); };
    thead.appendChild(th);
  }
  const rows = arResults.slice().sort((a, b) => {
    if (arSort.key === "payloads")
      return arSort.dir * String((a.payloads || []).join(" ")).localeCompare(String((b.payloads || []).join(" ")));
    let x = a[arSort.key], y = b[arSort.key];
    x = x == null ? -Infinity : x; y = y == null ? -Infinity : y;
    return arSort.dir * (x < y ? -1 : x > y ? 1 : 0);
  });
  const tb = $("ar-tbody"); tb.innerHTML = "";
  for (const r of rows) {
    const tr = document.createElement("tr");
    if (arSelected === r.index) tr.className = "sel";
    const cells = [String(r.index), esc((r.payloads || []).join(" · ")),
      r.error ? '<span class="ar-st-err">error</span>' : '<span class="' + arStatusCls(r.status) + '">' + r.status + "</span>",
      String(r.length), (r.time_ms || 0) + " ms"];
    if (hasGrep) cells.push(r.grep == null ? "—" : String(r.grep));
    if (hasExtract) cells.push(r.extract == null ? "—" : esc(r.extract));
    tr.innerHTML = cells.map(c => "<td>" + c + "</td>").join("");
    tr.onclick = () => arSelectRow(r.index);
    tb.appendChild(tr);
  }
  $("ar-empty").style.display = arResults.length ? "none" : "block";
}
async function arSelectRow(index) {
  arSelected = index; arRenderTable();
  const d = await (await fetch("/autorepeater/result?project=" + activeProject + "&index=" + index)).json();
  if (!d.result) return;
  arDetailRow = d.result; arRenderDetail();
}
function arRenderDetail() {
  const pre = $("ar-detail");
  if (!arDetailRow) { pre.textContent = ""; return; }
  if (arDetailTab === "request") pre.innerHTML = hlHttp(arDetailRow.request || "", "request");
  else pre.innerHTML = arDetailRow.response ? hlHttp(arDetailRow.response, "response") : (arDetailRow.error ? esc(arDetailRow.error) : "");
}
document.querySelectorAll("#pane-autorepeater .ar-dtabs button").forEach(b => {
  b.onclick = () => {
    document.querySelectorAll("#pane-autorepeater .ar-dtabs button").forEach(x => x.classList.toggle("active", x === b));
    arDetailTab = b.dataset.ard; arRenderDetail();
  };
});
async function loadAutoRepeaterFor(pid) {
  if (pid === null) return;
  let d; try { d = await (await fetch("/autorepeater/state?project=" + pid)).json(); } catch (e) { return; }
  if (pid !== activeProject) return;
  arResults = (d.results || []).slice();
  arSince = arResults.reduce((m, r) => Math.max(m, r.index), 0);
  arSelected = null; arDetailRow = null; $("ar-detail").textContent = "";
  arRenderTable();
  $("ar-progress").textContent = d.total != null ? ((d.count || 0) + " / " + (d.total || 0) + (d.running ? " · running" : "")) : "";
  $("ar-start").disabled = !!d.running; $("ar-stop").disabled = !d.running;
  clearTimeout(arPollTimer);
  if (d.running) arPoll();
}
arRenderPayloadBoxes();
arRenderRules();

// ── Sessions: choose the workspace (session > projects) before the dashboard ──
let sessionActive = false, fsCurrentPath = null;

async function initSession() {
  let s;
  try { s = await (await fetch("/session")).json(); } catch (e) { s = { active: false }; }
  sessionActive = !!s.active;
  if (!s.active) { openSessionModal("recent"); return; }
  setSessionLabel(s);
  loadDashboard();
}
function loadDashboard() {
  loadProjects().then(() => {
    loadGhostViewFor(activeProject); loadHuntViewFor(activeProject);
    loadScopeFor(activeProject); loadIssuesFor(activeProject); loadRepeaterFor(activeProject);
    loadAutoRepeaterFor(activeProject);
  });  // restore any run in progress + the active project's scope/issues
}
function setSessionLabel(s) {
  $("session-chip").textContent = s.name ? ("· " + s.name) : "";
  $("menu-session-name").textContent = s.name || "—";
  $("menu-session-path").textContent = s.path || "";
  document.title = s.name ? ("Beatrix — " + s.name) : "Beatrix Suite";
}

const appMenu = $("app-menu");
$("hamburger").onclick = (e) => { e.stopPropagation(); appMenu.classList.toggle("open"); };
appMenu.onclick = (e) => e.stopPropagation();
document.addEventListener("click", () => appMenu.classList.remove("open"));
appMenu.querySelectorAll(".menu-item").forEach(b => {
  b.onclick = () => {
    appMenu.classList.remove("open");
    if (b.dataset.act === "rain") { setMatrixRain(!mrainOn); return; }
    openSessionModal(b.dataset.act === "recent" ? "recent" : "browse");
  };
});

// ── Matrix rain: subtle phosphor drizzle behind the UI (toggle in the menu) ──
const MRAIN_CHARS = "アカサタナハマヤラワ0123456789<>[]{}=+*/#$%BEATRIX".split("");
let mrainOn = true, mrainRAF = 0, mrainDrops = [], mrainCtx = null;
const MRAIN_FONT = 14;
function mrainResize() {
  const c = $("mrain"); if (!c) return;
  mrainCtx = c.getContext("2d");
  c.width = innerWidth; c.height = innerHeight;
  mrainDrops = new Array(Math.ceil(innerWidth / MRAIN_FONT)).fill(0)
    .map(() => Math.floor(Math.random() * -60));
  mrainCtx.font = MRAIN_FONT + "px ui-monospace, monospace";
}
function mrainStep() {
  if (!mrainOn || !mrainCtx) return;
  mrainCtx.fillStyle = "rgba(10,15,12,0.09)";                 // fade → trails, matches --bg
  mrainCtx.fillRect(0, 0, innerWidth, innerHeight);
  for (let i = 0; i < mrainDrops.length; i++) {
    const y = mrainDrops[i] * MRAIN_FONT;
    mrainCtx.fillStyle = "rgba(74,220,138," + (Math.random() * 0.35 + 0.35) + ")";
    mrainCtx.fillText(MRAIN_CHARS[(Math.random() * MRAIN_CHARS.length) | 0], i * MRAIN_FONT, y);
    if (y > innerHeight && Math.random() > 0.975) mrainDrops[i] = 0;
    else mrainDrops[i] += 0.5;                                 // fall speed
  }
  mrainRAF = requestAnimationFrame(mrainStep);
}
function setMatrixRain(on) {
  mrainOn = on;
  $("mrain").classList.toggle("off", !on);
  const label = $("menu-rain"); if (label) label.textContent = "Matrix rain: " + (on ? "on" : "off");
  try { localStorage.setItem("beatrix.mrain", on ? "1" : "0"); } catch (e) {}
  cancelAnimationFrame(mrainRAF);
  if (on) { mrainResize(); mrainRAF = requestAnimationFrame(mrainStep); }
}
addEventListener("resize", () => { if (mrainOn) mrainResize(); });
(function () {
  let v = "1"; try { const s = localStorage.getItem("beatrix.mrain"); if (s !== null) v = s; } catch (e) {}
  setMatrixRain(v === "1");
})();

function openSessionModal(tab) {
  $("sess-cancel").hidden = !sessionActive;          // the first launch must pick something
  switchSessionTab(tab || "recent");
  $("session-modal").classList.add("open");
}
function closeSessionModal() { if (sessionActive) $("session-modal").classList.remove("open"); }
$("sess-cancel").onclick = closeSessionModal;
function switchSessionTab(name) {
  document.querySelectorAll(".session-tabs button").forEach(b => b.classList.toggle("active", b.dataset.stab === name));
  $("sess-recent").hidden = name !== "recent";
  $("sess-browse").hidden = name !== "browse";
  $("sess-msg").textContent = "";
  if (name === "recent") loadRecentSessions(); else fsBrowse(fsCurrentPath);
}
document.querySelectorAll(".session-tabs button").forEach(b => b.onclick = () => switchSessionTab(b.dataset.stab));

async function loadRecentSessions() {
  const box = $("sess-recent-list"); box.innerHTML = "<div class='recent-empty'>Loading…</div>";
  let d; try { d = await (await fetch("/sessions")).json(); } catch (e) { d = { sessions: [] }; }
  if (fsCurrentPath === null) fsCurrentPath = d.default_root || d.home || null;
  box.innerHTML = "";
  if (!d.sessions.length) { box.innerHTML = "<div class='recent-empty'>No sessions yet — use “Browse / New” to create your first one.</div>"; return; }
  for (const s of d.sessions) {
    const row = document.createElement("div");
    row.className = "recent-item" + (s.exists ? "" : " missing");
    row.innerHTML = '<div><div class="ri-name">' + esc(s.name) + '</div><div class="ri-path">' + esc(s.path) + '</div></div>' +
      '<div class="ri-meta">' + (s.exists ? (s.has_data ? "has projects" : "empty") : "missing") + '</div>';
    if (s.exists) row.onclick = () => doOpenSession(s.path);
    box.appendChild(row);
  }
}

async function fsBrowse(path) {
  let d; try { d = await (await fetch("/fs/list?path=" + encodeURIComponent(path || ""))).json(); } catch (e) { return; }
  fsCurrentPath = d.path;
  $("fs-path").value = d.path;
  $("fs-up").dataset.parent = d.parent || "";
  const list = $("fs-list"); list.innerHTML = "";
  if (!d.entries.length) list.innerHTML = "<div class='fs-empty'>No sub-folders here. Name a session below and click Create.</div>";
  for (const e of d.entries) {
    const row = document.createElement("div");
    row.className = "fs-row";
    row.innerHTML = '<span class="fs-ico">▸</span><span>' + esc(e.name) + '</span>' +
      (e.is_session ? '<span class="fs-badge">session</span>' : '');
    row.onclick = () => e.is_session ? doOpenSession(e.path) : fsBrowse(e.path);
    list.appendChild(row);
  }
}
$("fs-home").onclick = () => fsBrowse("");            // "" → server resolves to home
$("fs-root").onclick = () => fsBrowse("/");
$("fs-go").onclick = () => fsBrowse($("fs-path").value);
$("fs-path").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); fsBrowse($("fs-path").value); } });
$("fs-up").onclick = () => { const p = $("fs-up").dataset.parent; if (p) fsBrowse(p); };
$("fs-create").onclick = () => doCreateSession(fsCurrentPath, $("fs-newname").value);
$("fs-open").onclick = () => doOpenSession(fsCurrentPath);

async function doCreateSession(parent, name) {
  $("sess-msg").textContent = "";
  const r = await (await fetch("/session/new", { method: "POST", body: JSON.stringify({ parent, name }) })).json();
  if (r.ok) location.reload(); else $("sess-msg").textContent = r.error || "Could not create session.";
}
async function doOpenSession(path) {
  $("sess-msg").textContent = "";
  const r = await (await fetch("/session/open", { method: "POST", body: JSON.stringify({ path }) })).json();
  if (r.ok) location.reload(); else $("sess-msg").textContent = r.error || "Could not open session.";
}

loadHuntCatalog();
initSession();
</script>
</body>
</html>"""


# ── Repeater ─────────────────────────────────────────────────────────────────
# A Burp-style Repeater: manually compose a raw HTTP request, fire it at a
# target, read the raw response, tweak, resend. Unlike Ghost/Hunt this is NOT
# scope-gated — a Repeater fires wherever you point it, matching Burp exactly.
_REPEATER_TIMEOUT = 30.0            # seconds; a manual send should never hang a tab
_REPEATER_MAX_BODY = 2_000_000     # cap stored/shown response body at 2 MB
_REPEATER_MAX_READ = 10_000_000    # cap bytes read off the wire (hostile/huge responses)
_REPEATER_MAX_HISTORY = 50         # per-tab send history kept for the < > nav
_REPEATER_TEMPLATE = (
    "GET / HTTP/1.1\r\n"
    "Host: \r\n"
    "User-Agent: beatrix-repeater\r\n"
    "Accept: */*\r\n"
    "\r\n"
)


def _parse_raw_request(raw: str):
    """Split a raw HTTP request into (method, request_target, version, headers, body).

    Headers are a list of (name, value) pairs so duplicates survive (a real
    request can carry two of the same header, and that matters when you're
    testing).

    Header parsing stops at the first blank line (the standard body delimiter)
    OR the first line that isn't a valid ``Token: value`` header — everything
    from there on is the body. That second rule matters: it keeps body content
    that merely contains a colon (an XML ``<!ENTITY … "http://…">`` line, a JSON
    value) from being mis-read as a header, which otherwise produces an illegal
    header and a failed send.
    """
    text = (raw or "").replace("\r\n", "\n")
    lines = text.split("\n")
    request_line = lines[0].strip() if lines else ""
    parts = request_line.split()
    method = parts[0] if parts else "GET"
    target = parts[1] if len(parts) > 1 else "/"
    version = parts[2] if len(parts) > 2 else "HTTP/1.1"
    headers: List[tuple] = []
    body = ""
    i = 1
    while i < len(lines):
        line = lines[i]
        if line.strip() == "":                       # blank line ⇒ body follows
            body = "\n".join(lines[i + 1:])
            break
        name, sep, value = line.partition(":")
        if sep and _HEADER_NAME_RE.match(name.strip()):
            headers.append((name.strip(), value.strip()))
            i += 1
            continue
        body = "\n".join(lines[i:])                   # not a header ⇒ body starts here
        break
    return method, target, version, headers, body


def _resolve_target(rtarget: str, target_base: str, headers: List[tuple]):
    """Work out (scheme, host, port, wire_path) for the socket.

    Precedence mirrors what a tester expects: an absolute request-target on the
    request line wins; otherwise the Target field supplies scheme+host; failing
    that, the Host header lets a pasted request "just work". The path put on the
    wire is always origin-form (``/path?query``) regardless of which supplied it.
    """
    def split(scheme: str, netloc: str, path: str):
        host = netloc.split("@")[-1]
        if host.startswith("["):                       # IPv6 literal [::1]:8080
            hostname, _, port_s = host[1:].partition("]")
            port_s = port_s.lstrip(":")
        elif ":" in host:
            hostname, port_s = host.rsplit(":", 1)
        else:
            hostname, port_s = host, ""
        port = int(port_s) if port_s.isdigit() else (443 if scheme == "https" else 80)
        return scheme, hostname, port, (path or "/")

    if rtarget.lower().startswith(("http://", "https://")):
        p = urlparse(rtarget)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        return split(p.scheme.lower(), p.netloc, path)

    base = (target_base or "").strip().rstrip("/")
    if not base:
        base = next((v.strip() for (k, v) in headers
                     if k.lower() == "host" and v.strip()), "")
        if not base:
            return None
        base = "https://" + base                        # default to TLS, like Burp
    if not base.lower().startswith(("http://", "https://")):
        base = "https://" + base
    p = urlparse(base)
    path = rtarget if rtarget.startswith("/") else "/" + rtarget
    return split(p.scheme.lower(), p.netloc, path)


def _build_wire_request(method: str, version: str, path: str, headers: List[tuple],
                        body: str, host: str, port: int, scheme: str) -> bytes:
    """Assemble the exact request bytes to put on the wire.

    Faithful by default — this is the reason the Repeater sends over a raw socket
    instead of httpx: header order, duplicates, and name casing are preserved
    verbatim, and nothing is silently added. The only touch-ups are the minimum
    needed to be a valid request, and only when the tester didn't already set
    them:
      * Host — added from the target if no non-empty Host header was typed
        (a typed Host, even a spoofed one, is sent unchanged — host-header tests).
      * Content-Length — added (correct) only if there's a body and no
        Content-Length header. A Content-Length the tester DID type is sent as-is,
        even if wrong, so smuggling / request-splitting payloads go out intact.
      * Connection: close — added if absent, so a one-shot send frames cleanly
        and never hangs waiting on a kept-alive socket.
    """
    have = {k.lower() for (k, _) in headers}
    default_port = 443 if scheme == "https" else 80
    lines = ["%s %s %s" % (method, path, version or "HTTP/1.1")]
    for k, v in headers:
        lines.append("%s: %s" % (k, v))
    if "host" not in have or not any(k.lower() == "host" and v.strip() for k, v in headers):
        hostval = host if port == default_port else "%s:%d" % (host, port)
        lines.append("Host: " + hostval)
    body_bytes = body.encode("utf-8", "surrogateescape") if body else b""
    if body_bytes and "content-length" not in have and "transfer-encoding" not in have:
        lines.append("Content-Length: %d" % len(body_bytes))
    if "connection" not in have:
        lines.append("Connection: close")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", "surrogateescape")
    return head + body_bytes


def _read_line(f) -> bytes:
    return f.readline(65536)


def _read_headers(f):
    """Read status line + headers off the wire, preserving order/dupes/case."""
    status_line = _read_line(f).decode("latin-1").rstrip("\r\n")
    parts = status_line.split(" ", 2)
    http_version = parts[0] if parts else ""
    try:
        status = int(parts[1])
    except (IndexError, ValueError):
        status = 0
    reason = parts[2] if len(parts) > 2 else ""
    headers: List[list] = []
    while True:
        line = _read_line(f)
        if line in (b"\r\n", b"\n", b"", b"\r"):
            break
        s = line.decode("latin-1").rstrip("\r\n")
        name, sep, value = s.partition(":")
        if sep:
            headers.append([name.strip(), value.strip()])
    return http_version, status, reason, headers


def _read_chunked(f, cap: int) -> bytes:
    out = bytearray()
    while len(out) < cap:
        size_line = _read_line(f).split(b";", 1)[0].strip()
        if not size_line:
            break
        try:
            n = int(size_line, 16)
        except ValueError:
            break
        if n == 0:
            while True:                                   # consume trailer headers
                t = _read_line(f)
                if t in (b"\r\n", b"\n", b"", b"\r"):
                    break
            break
        out += f.read(n)
        f.read(2)                                         # CRLF after each chunk
    return bytes(out)


def _read_body(f, headers: List[list], status: int, method: str, cap: int):
    """Read the body per HTTP/1.1 framing. Returns (body_bytes, truncated)."""
    if method.upper() == "HEAD" or status in (204, 304) or (100 <= status < 200):
        return b"", False
    hmap = {k.lower(): v for k, v in headers}            # last value wins (framing only)
    if "chunked" in hmap.get("transfer-encoding", "").lower():
        data = _read_chunked(f, cap + 1)
    elif "content-length" in hmap:
        try:
            n = int(hmap["content-length"])
        except ValueError:
            n = 0
        data = f.read(min(n, cap + 1))
    else:                                                 # until EOF (Connection: close)
        data = f.read(cap + 1)
    truncated = len(data) > cap
    return (data[:cap] if truncated else data), truncated


def _decompress_body(headers: List[list], body: bytes) -> bytes:
    """Decode Content-Encoding for display (gzip / deflate / br). Best-effort:
    if decoding fails, the raw bytes are shown as-is."""
    enc = ""
    for k, v in headers:
        if k.lower() == "content-encoding":
            enc = v.lower()
            break
    try:
        if "gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)   # raw deflate
        if "br" in enc:
            import brotli  # optional dependency
            return brotli.decompress(body)
    except Exception:  # noqa: BLE001 — show the raw bytes rather than fail the send
        pass
    return body


def _exec_repeater_request(raw_request: str, target_base: str) -> Dict[str, Any]:
    """Send one raw request over a socket and return a response (or error) record.

    v2 — byte-faithful. The request goes out exactly as typed (see
    :func:`_build_wire_request`): header order, duplicate headers, name casing,
    and even a deliberately-wrong Content-Length are all preserved, so smuggling,
    request-splitting, and host-header payloads reach the server intact — the
    thing httpx could not do. Redirects are NOT followed (you see the 3xx, like
    Burp's default) and TLS certificate verification is off (pentest targets are
    routinely self-signed). Compressed response bodies are shown decoded.
    """
    method, rtarget, version, headers, body = _parse_raw_request(raw_request)

    # The first line must be a real request line. If the method isn't even a
    # valid HTTP token (e.g. someone pasted a bare XML/JSON body), say so plainly.
    if not _HEADER_NAME_RE.match(method):
        return {"error": "Not an HTTP request: the first line must be a request "
                "line like 'POST /path HTTP/1.1'. If you pasted a body or payload, "
                "add a request line and a blank line above it.",
                "status": None, "headers": [], "body": "", "size": 0,
                "time_ms": 0, "raw": ""}

    resolved = _resolve_target(rtarget, target_base, headers)
    if resolved is None:
        return {"error": "No target: set a target URL, or put a Host header in the request.",
                "status": None, "headers": [], "body": "", "size": 0,
                "time_ms": 0, "raw": ""}
    scheme, host, port, path = resolved

    wire = _build_wire_request(method, version, path, headers, body, host, port, scheme)

    t0 = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=_REPEATER_TIMEOUT)
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(_REPEATER_TIMEOUT)
        sock.sendall(wire)
        f = sock.makefile("rb")
        http_version, status, reason, resp_headers = _read_headers(f)
        raw_body, truncated = _read_body(f, resp_headers, status, method, _REPEATER_MAX_READ)
    except Exception as e:  # noqa: BLE001 — any transport failure is shown in the tab
        return {"error": f"{type(e).__name__}: {e}", "status": None, "headers": [],
                "body": "", "size": 0, "time_ms": int((time.perf_counter() - t0) * 1000),
                "raw": ""}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass
    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    decoded = _decompress_body(resp_headers, raw_body)
    size = len(raw_body)
    text = decoded.decode("utf-8", "replace")
    if len(text) > _REPEATER_MAX_BODY:
        text = text[:_REPEATER_MAX_BODY]
        truncated = True
    status_line = ("%s %d %s" % (http_version, status, reason)).rstrip()
    raw_response = status_line + "\r\n" + \
        "\r\n".join("%s: %s" % (k, v) for k, v in resp_headers) + "\r\n\r\n" + text
    return {
        "error": None,
        "status": status,
        "reason": reason,
        "http_version": http_version,
        "url": "%s://%s%s" % (scheme, host if port in (80, 443) else "%s:%d" % (host, port), path),
        "headers": resp_headers,
        "body": text,
        "truncated": truncated,
        "size": size,
        "time_ms": elapsed_ms,
        "raw": raw_response,
    }


class _RepeaterStore:
    """Per-project Repeater tabs, persisted to ``<project>/repeater.json``.

    A project holds a set of Repeater tabs; each is one editable raw request +
    the target base URL to send it to + a bounded history of sends (so the < >
    nav can flick through prior request/response pairs like Burp). Same on-disk
    discipline as :class:`_IssueStore`: no long-lived cache, every op holds one
    lock, and a project deleted out from under it simply reads back empty.

    Each tab carries a monotonic ``id`` (identity, keys nothing on disk but is
    the handle the client sends back) and a recycled ``label`` — the lowest free
    integer, so tab numbers stay coherent as you open and close them, the same
    scheme the project rail uses.
    """

    def __init__(self, projects: "_ProjectStore"):
        self._projects = projects
        self._lock = threading.Lock()

    def _file(self, pid: Any) -> Path:
        return self._projects.workspace_dir(pid) / "repeater.json"

    def _read(self, pid: Any) -> Dict[str, Any]:
        try:
            d = json.loads(self._file(pid).read_text())
            d.setdefault("tabs", [])
            d.setdefault("active", None)
            d.setdefault("next_id", 1)
            return d
        except Exception:
            return {"tabs": [], "active": None, "next_id": 1}

    def _write(self, pid: Any, data: Dict[str, Any]) -> None:
        try:
            self._file(pid).write_text(json.dumps(data, indent=2, default=str))
        except Exception:
            pass

    @staticmethod
    def _next_label(tabs: List[Dict[str, Any]]) -> int:
        taken = {t.get("label") for t in tabs}
        label = 1
        while label in taken:
            label += 1
        return label

    def _new_tab_locked(self, data: Dict[str, Any]) -> Dict[str, Any]:
        tid = data["next_id"]
        data["next_id"] = tid + 1
        tab = {"id": tid, "label": self._next_label(data["tabs"]), "name": "",
               "target": "", "request": _REPEATER_TEMPLATE, "response": None,
               "history": []}
        data["tabs"].append(tab)
        data["active"] = tid
        return tab

    def _ensure_seeded(self, data: Dict[str, Any]) -> bool:
        """Guarantee at least one tab (a Repeater pane is never empty). Returns
        True if it had to seed, so the caller knows to persist."""
        if not data["tabs"]:
            self._new_tab_locked(data)
            return True
        return False

    def _find(self, data: Dict[str, Any], tid: Any) -> Optional[Dict[str, Any]]:
        for t in data["tabs"]:
            if str(t["id"]) == str(tid):
                return t
        return None

    # ── API ──────────────────────────────────────────────────────────────
    def state(self, pid: Any) -> Dict[str, Any]:
        with self._lock:
            data = self._read(pid)
            if self._ensure_seeded(data):
                self._write(pid, data)
            return {"tabs": list(data["tabs"]), "active": data["active"]}

    def new(self, pid: Any, request: Optional[str] = None,
            target: Optional[str] = None) -> Dict[str, Any]:
        """Open a new tab, made active. With request/target given, the tab is
        seeded with them (that's how "Send to Repeater" hands a request over)
        instead of the blank template."""
        with self._lock:
            data = self._read(pid)
            self._ensure_seeded(data)
            tab = self._new_tab_locked(data)
            if request is not None:
                tab["request"] = request
            if target is not None:
                tab["target"] = target
            self._write(pid, data)
            return {"ok": True, "tabs": list(data["tabs"]), "active": data["active"]}

    def close(self, pid: Any, tid: Any) -> Dict[str, Any]:
        with self._lock:
            data = self._read(pid)
            before = len(data["tabs"])
            data["tabs"] = [t for t in data["tabs"] if str(t["id"]) != str(tid)]
            if len(data["tabs"]) == before:
                return {"ok": False, "error": "no such tab"}
            # Keep the pane non-empty, and keep `active` valid.
            if not data["tabs"]:
                self._new_tab_locked(data)
            elif str(data["active"]) == str(tid):
                data["active"] = data["tabs"][-1]["id"]
            self._write(pid, data)
            return {"ok": True, "tabs": list(data["tabs"]), "active": data["active"]}

    def select(self, pid: Any, tid: Any) -> Dict[str, Any]:
        with self._lock:
            data = self._read(pid)
            tab = self._find(data, tid)
            if tab is None:
                return {"ok": False, "error": "no such tab"}
            data["active"] = tab["id"]  # canonical int id, never the query-string str
            self._write(pid, data)
            return {"ok": True, "active": data["active"]}

    def save(self, pid: Any, tid: Any, request: Optional[str],
             target: Optional[str]) -> Dict[str, Any]:
        """Autosave the editable buffers (request text / target) for a tab."""
        with self._lock:
            data = self._read(pid)
            tab = self._find(data, tid)
            if tab is None:
                return {"ok": False, "error": "no such tab"}
            if request is not None:
                tab["request"] = request
            if target is not None:
                tab["target"] = target
            self._write(pid, data)
            return {"ok": True}

    def rename(self, pid: Any, tid: Any, name: str) -> Dict[str, Any]:
        with self._lock:
            data = self._read(pid)
            tab = self._find(data, tid)
            if tab is None:
                return {"ok": False, "error": "no such tab"}
            tab["name"] = (name or "").strip()[:60]
            self._write(pid, data)
            return {"ok": True, "tabs": list(data["tabs"])}

    def record_send(self, pid: Any, tid: Any, request: str, target: str,
                    response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Persist a send: update the tab's buffers + last response, append to
        its bounded history. Returns the updated tab (or None if it's gone)."""
        with self._lock:
            data = self._read(pid)
            tab = self._find(data, tid)
            if tab is None:
                return None
            tab["request"] = request
            tab["target"] = target
            tab["response"] = response
            tab.setdefault("history", []).append(
                {"request": request, "target": target, "response": response,
                 "sent_at": response.get("sent_at")})
            if len(tab["history"]) > _REPEATER_MAX_HISTORY:
                tab["history"] = tab["history"][-_REPEATER_MAX_HISTORY:]
            data["active"] = tab["id"]
            self._write(pid, data)
            return dict(tab)


# ── Sessions ─────────────────────────────────────────────────────────────────
# A *session* is the top of the hierarchy: session > projects. It's just a
# directory that holds a whole workspace (its projects.json, per-project scan
# output, issues, repeater tabs, scope). Users pick or create one when the suite
# launches, and can store it anywhere on disk via the file explorer.
class _SessionManager:
    """A small on-disk index of known sessions (for the picker's "recent" list)
    plus create/register helpers. The actual per-session data lives in the
    session directory and is owned by the stores, not here."""

    def __init__(self, registry_path: Path, default_root: Path,
                 legacy_dir: Optional[Path] = None):
        self.registry_path = Path(registry_path)
        self.default_root = Path(default_root)
        self.legacy_dir = Path(legacy_dir) if legacy_dir else None
        self._lock = threading.Lock()

    # ── registry persistence (created lazily, so merely constructing a server
    # for a test never writes to the user's home) ────────────────────────────
    def _read(self) -> Dict[str, Any]:
        try:
            d = json.loads(self.registry_path.read_text())
            d.setdefault("sessions", [])
            return d
        except Exception:
            return {"sessions": []}

    def _write(self, d: Dict[str, Any]) -> None:
        try:
            self.registry_path.parent.mkdir(parents=True, exist_ok=True)
            self.registry_path.write_text(json.dumps(d, indent=2))
        except Exception:
            pass

    def _seed_legacy(self, d: Dict[str, Any]) -> bool:
        """Register the pre-session data dir once as "default" so existing
        projects aren't stranded when sessions land. Caller holds the lock."""
        if self.legacy_dir is None or not (self.legacy_dir / "projects.json").exists():
            return False
        p = str(self.legacy_dir)
        if any(s.get("path") == p for s in d["sessions"]):
            return False
        d["sessions"].append({"name": "default", "path": p,
                              "created_at": time.time(), "last_opened": 0})
        return True

    def register(self, path: Any, name: str) -> None:
        p = str(Path(path))
        with self._lock:
            d = self._read()
            now = time.time()
            for s in d["sessions"]:
                if s.get("path") == p:
                    s["last_opened"] = now
                    s["name"] = name or s.get("name") or Path(p).name
                    self._write(d)
                    return
            d["sessions"].append({"name": name or Path(p).name, "path": p,
                                  "created_at": now, "last_opened": now})
            self._write(d)

    def list(self) -> List[Dict[str, Any]]:
        with self._lock:
            d = self._read()
            if self._seed_legacy(d):
                self._write(d)
            out = []
            for s in d["sessions"]:
                p = Path(s.get("path", ""))
                out.append({"name": s.get("name") or p.name, "path": str(p),
                            "exists": p.exists(),
                            "has_data": (p / "projects.json").exists(),
                            "last_opened": s.get("last_opened", 0)})
        out.sort(key=lambda x: x["last_opened"], reverse=True)
        return out

    def create(self, parent: Any, name: str) -> Dict[str, Any]:
        name = (name or "").strip()
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            return {"ok": False, "error": "Enter a valid session name (no slashes)."}
        parent = Path(parent).expanduser() if parent else self.default_root
        target = parent / name
        try:
            target.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            return {"ok": False, "error": f"'{name}' already exists in that folder."}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
        try:
            (target / "session.json").write_text(
                json.dumps({"name": name, "created_at": time.time()}, indent=2))
        except Exception:
            pass
        return {"ok": True, "path": str(target), "name": name}


def _fs_list(path: Optional[str]) -> Dict[str, Any]:
    """List the sub-folders of ``path`` for the session picker's file explorer.

    Folders only (a session is a folder); hidden dot-folders are skipped to keep
    the view clean. This browses the machine running the suite — which is the
    user's own box — so no path sandbox is imposed, matching a native
    open-folder dialog."""
    home = Path.home()
    try:
        base = Path(path).expanduser() if path else home
        if base.is_file():          # pasted a file path → show its folder
            base = base.parent
        if not base.is_dir():       # nonexistent / unreadable → fall back home
            base = home
        base = base.resolve()
    except Exception:
        base = home
    def _is_session(child: Path) -> bool:
        # A dir we can't search (e.g. /root, mode 700) raises here — treat it as
        # "not a session" instead of letting it abort the whole listing.
        try:
            return (child / "session.json").exists() or (child / "projects.json").exists()
        except OSError:
            return False

    entries: List[Dict[str, Any]] = []
    try:
        children = sorted(base.iterdir(), key=lambda c: c.name.lower())
    except OSError:
        children = []
    for child in children:
        # Every per-entry probe is guarded, so one unreadable folder never drops
        # the rest of the listing (the /root bug that hid /workspaces at root).
        try:
            if child.name.startswith(".") or not child.is_dir():
                continue
        except OSError:
            continue
        entries.append({
            "name": child.name,
            "path": str(child),
            "is_session": _is_session(child),
        })
    parent = str(base.parent) if base != base.parent else None
    return {"path": str(base), "parent": parent, "home": str(home), "entries": entries}


def _fs_mkdir(parent: str, name: str) -> Dict[str, Any]:
    name = (name or "").strip()
    if not name or "/" in name or "\\" in name or name in (".", ".."):
        return {"ok": False, "error": "invalid folder name"}
    try:
        target = Path(parent).expanduser() / name
        target.mkdir(parents=True, exist_ok=False)
        return {"ok": True, "path": str(target)}
    except FileExistsError:
        return {"ok": False, "error": "already exists"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


# ── AutoRepeater (Burp-Intruder-style automated attacks) ─────────────────────
# A base request with payload positions marked by § § pairs, an attack type that
# decides how payloads fill the positions, and a table of results (status /
# length / time / grep) you scan for anomalies. Sends reuse the Repeater's
# byte-faithful engine; runs stream into a per-project attack store.
_AR_MARKER = "§"          # the § position marker (Burp's convention)
_AR_MAX_REQUESTS = 20000       # v1 guard against a runaway attack
_AR_MAX_SET = 100000           # cap a single generated payload set
_AR_MAX_CONCURRENCY = 50
_ATTACK_TYPES = ("sniper", "batteringram", "pitchfork", "clusterbomb")


def _ar_fmt_num(n: float) -> str:
    return str(int(n)) if float(n).is_integer() else repr(n)


def _ar_expand_set(spec: Any) -> List[str]:
    """Expand a payload-set spec into a concrete list of payload strings.

    A spec is either a plain list (back-compat) or a dict with a ``type``:
      * list    — {"items": [...]}
      * numbers — {"from", "to", "step"} (integer when all bounds are integers)
      * brute   — {"charset", "min", "max"} — every string over the charset
    Each set is capped at ``_AR_MAX_SET`` so a wide brute-force can't blow up."""
    if isinstance(spec, list):
        return [str(x) for x in spec]
    t = (spec or {}).get("type", "list")
    if t == "list":
        return [str(x) for x in (spec.get("items") or [])]
    if t == "numbers":
        try:
            frm, to, step = float(spec.get("from", 0)), float(spec.get("to", 0)), float(spec.get("step", 1))
        except (TypeError, ValueError):
            return []
        if step == 0:
            step = 1
        out, n = [], frm
        while (step > 0 and n <= to) or (step < 0 and n >= to):
            out.append(_ar_fmt_num(n))
            if len(out) >= _AR_MAX_SET:
                break
            n += step
        return out
    if t == "brute":
        charset = spec.get("charset") or "abcdefghijklmnopqrstuvwxyz0123456789"
        try:
            mn, mx = int(spec.get("min", 1)), int(spec.get("max", 3))
        except (TypeError, ValueError):
            return []
        out: List[str] = []
        for length in range(max(1, mn), max(max(1, mn), mx) + 1):
            for combo in itertools.product(charset, repeat=length):
                out.append("".join(combo))
                if len(out) >= _AR_MAX_SET:
                    return out
        return out
    return []


def _ar_process(value: str, rules: Any) -> str:
    """Apply payload-processing rules (in order) to one payload string —
    encoding, prefix/suffix, case, and hashing for WAF evasion / fuzzing."""
    for r in (rules or []):
        t = (r or {}).get("type")
        try:
            if t == "prefix":
                value = str(r.get("value", "")) + value
            elif t == "suffix":
                value = value + str(r.get("value", ""))
            elif t == "urlencode":
                from urllib.parse import quote
                value = quote(value, safe=str(r.get("safe", "")))
            elif t == "base64":
                value = base64.b64encode(value.encode("utf-8", "surrogateescape")).decode()
            elif t == "upper":
                value = value.upper()
            elif t == "lower":
                value = value.lower()
            elif t in ("md5", "sha1", "sha256"):
                value = hashlib.new(t, value.encode("utf-8", "surrogateescape")).hexdigest()
            elif t == "replace":
                value = value.replace(str(r.get("find", "")), str(r.get("replace", "")))
        except Exception:  # noqa: BLE001 — a bad rule shouldn't kill the attack
            pass
    return value


def _ar_parse_positions(template: str):
    """Split a template on § markers into (literals, base_values).

    The markers come in pairs: ``lit §base§ lit §base§ lit``. Splitting on § puts
    literals at even indices and position base-values at odd ones, so an even
    number of markers (odd number of parts) is required. Returns (None, None)
    when the markers are unbalanced."""
    parts = (template or "").split(_AR_MARKER)
    if len(parts) % 2 == 0:                     # unbalanced § markers
        return None, None
    return parts[0::2], parts[1::2]             # literals (n+1), base values (n)


def _ar_build(literals, values) -> str:
    """Reassemble a request: lit[0] + val[0] + lit[1] + val[1] + ... + lit[n]."""
    s = literals[0]
    for i, v in enumerate(values):
        s += v + literals[i + 1]
    return s


def _ar_count(n: int, attack_type: str, sets) -> int:
    """How many requests an attack will send, for the given position count `n`."""
    if n <= 0:
        return 0
    if attack_type == "sniper":
        return n * len(sets[0]) if sets and sets[0] else 0
    if attack_type == "batteringram":
        return len(sets[0]) if sets and sets[0] else 0
    if attack_type == "pitchfork":
        use = sets[:n]
        return min((len(s) for s in use), default=0) if use else 0
    if attack_type == "clusterbomb":
        use = [sets[i] if i < len(sets) else [] for i in range(n)]
        total = 1
        for s in use:
            total *= len(s)
        return total
    return 0


def _ar_generate(literals, bases, attack_type: str, sets, rules=None):
    """Yield (payloads, built_request) for every request the attack makes.

    Payload-processing ``rules`` are applied to each payload (never to a
    position's base value), and the processed value is what's recorded/sent.

    * sniper       — one set, one position at a time (others keep their base).
    * battering ram — one set, the SAME payload in every position at once.
    * pitchfork    — one set per position, advanced in lockstep (zip).
    * cluster bomb  — one set per position, every combination (cartesian product).
    """
    n = len(bases)
    if n == 0:
        return
    proc = lambda v: _ar_process(v, rules)
    if attack_type == "sniper":
        s0 = sets[0] if sets else []
        for pos in range(n):
            for p in s0:
                pv = proc(p)
                values = list(bases)
                values[pos] = pv
                yield [pv], _ar_build(literals, values)
    elif attack_type == "batteringram":
        s0 = sets[0] if sets else []
        for p in s0:
            pv = proc(p)
            yield [pv], _ar_build(literals, [pv] * n)
    elif attack_type == "pitchfork":
        use = sets[:n]
        if not use or any(not s for s in use):
            return
        for k in range(min(len(s) for s in use)):
            combo = [proc(use[i][k]) for i in range(n)]
            yield combo, _ar_build(literals, combo)
    elif attack_type == "clusterbomb":
        use = [sets[i] if i < len(sets) else [] for i in range(n)]
        for combo in itertools.product(*use):
            pc = [proc(v) for v in combo]
            yield pc, _ar_build(literals, pc)


class _AutoAttack:
    """In-flight/finished attack for one project: config, streamed results, and
    stop control. Results are structured rows (unlike the ghost/hunt event
    broker, which flattens to text), so the table keeps status/length/time/grep
    per request and can serve the full request/response for any row on demand."""

    _SUMMARY = ("index", "payloads", "status", "length", "time_ms", "error", "grep", "extract")

    def __init__(self, config: Dict[str, Any], total: int):
        self._lock = threading.Lock()
        self.config = config
        self.total = total
        self.results: List[Dict[str, Any]] = []
        self.running = True
        self.error: Optional[str] = None
        self.stop_event = threading.Event()
        self.started = time.time()

    def add(self, result: Dict[str, Any]) -> None:
        with self._lock:
            self.results.append(result)

    @classmethod
    def _summary(cls, r: Dict[str, Any]) -> Dict[str, Any]:
        return {k: r.get(k) for k in cls._SUMMARY}

    def summaries_since(self, idx: int) -> List[Dict[str, Any]]:
        with self._lock:
            return [self._summary(r) for r in self.results if r["index"] > idx]

    def get(self, idx: Any) -> Optional[Dict[str, Any]]:
        with self._lock:
            for r in self.results:
                if str(r["index"]) == str(idx):
                    return dict(r)
        return None

    def state(self) -> Dict[str, Any]:
        with self._lock:
            return {"running": self.running, "total": self.total,
                    "count": len(self.results), "error": self.error,
                    "attack_type": self.config.get("attack_type"),
                    "grep": bool(self.config.get("grep")),
                    "extract": bool(self.config.get("extract")),
                    "results": [self._summary(r) for r in self.results]}


# ── Ghost validation (feed already-found issues to the agent) ────────────────
# Instead of a full autonomous investigation (which re-discovers everything and
# burns tokens), hand Ghost the issues a scan already found and tell it to go
# straight to targeted validation. That's the whole point — the recon is done.
_GHOST_VALIDATE_MAX = 40           # cap issues per validation run (keep the seed compact)


def _ghost_validation_target(issues: List[Dict[str, Any]]) -> str:
    """Derive the scheme://host[:port] Ghost should investigate from the issues."""
    for iss in issues:
        u = (iss.get("url") or "").strip()
        if not u:
            continue
        p = urlparse(u if "://" in u else "https://" + u)
        if p.netloc:
            return f"{p.scheme or 'https'}://{p.netloc}"
    return ""


def _ghost_validation_objective(issues: List[Dict[str, Any]]) -> str:
    """Build a compact, token-efficient objective: a digest of the findings plus
    an instruction to validate (not re-discover) each one."""
    shown = issues[:_GHOST_VALIDATE_MAX]
    lines = []
    for i, iss in enumerate(shown, 1):
        row = [f"{i}. [{iss.get('severity', 'info')}] {iss.get('title', 'finding')}",
               f"   URL: {iss.get('url', '') or '—'}"]
        if iss.get("parameter"):
            row.append(f"   Parameter: {iss['parameter']}")
        if iss.get("module"):
            row.append(f"   Found by: {iss['module']}")
        ev = (iss.get("evidence") or "").strip()
        if ev:
            row.append(f"   Evidence: {ev[:200]}")
        lines.append("\n".join(row))
    digest = "\n".join(lines)
    n = len(shown)
    more = f" (showing the first {n} of {len(issues)})" if len(issues) > n else ""
    plural = "s" if n != 1 else ""
    return (
        f"Validate {n} finding{plural} that a previous scan already discovered on this "
        f"target{more}. Do NOT run a full scan or re-crawl — the reconnaissance is done. "
        f"For EACH finding below: load_skill for its class, make one or two focused probes "
        f"to confirm real, exploitable impact or dismiss it as a false positive, and call "
        f"record_finding ONLY for the ones you confirm, with concrete evidence "
        f"(validated=True only with proof). Work through the list efficiently and stop when "
        f"you have checked them all.\n\nFINDINGS TO VALIDATE:\n{digest}"
    )


def _needs_session(path: str) -> bool:
    """True if a route touches per-session data and so requires a mounted
    session. The shell, the auth GUI, the static hunt catalog, and every session
    / filesystem route work without one."""
    if path in ("/", "/index.html", "/auth", "/hunt/catalog"):
        return False
    if path.startswith("/session") or path.startswith("/fs/"):
        return False
    if path in _AUTH_GET or path in _AUTH_POST:
        return False
    return True


class SuiteServer:
    """The single central-dashboard server. One port, all tools + projects."""

    def __init__(self, host: str = "0.0.0.0", port: int = DEFAULT_PORT,
                 state_dir: Optional[Path] = None,
                 sessions_registry: Optional[Path] = None):
        self.host = host
        self.port = port
        self._httpd: Optional[ThreadingHTTPServer] = None
        self.url: str = ""
        self.public_url: Optional[str] = None
        # The active session and its stores. When no session is mounted the suite
        # shows the picker instead of a dashboard; passing ``state_dir`` mounts one
        # up front (the back-compatible path the tests use).
        self.session_dir: Optional[Path] = None
        self.projects: Optional[_ProjectStore] = None
        self.issues: Optional[_IssueStore] = None
        self.repeater: Optional[_RepeaterStore] = None
        # One ghost run + event broker PER project (keyed by str(project id)), so
        # switching projects preserves each project's live run view.
        self.ghost_brokers: Dict[str, _Broker] = {}
        # Same per-project isolation for Hunt (the deterministic scanner pipeline).
        self.hunt_brokers: Dict[str, _Broker] = {}
        # (loop, task) for each in-flight run, keyed the same way, so the Stop
        # button can cancel a run from the HTTP handler thread.
        self.ghost_tasks: Dict[str, Any] = {}
        self.hunt_tasks: Dict[str, Any] = {}
        # AutoRepeater (Intruder-style) attack per project, keyed str(project id).
        self.ar_attacks: Dict[str, _AutoAttack] = {}
        self._lock = threading.Lock()
        registry = Path(sessions_registry) if sessions_registry \
            else DEFAULT_STATE_DIR.parent / "sessions.json"
        self.sessions = _SessionManager(registry, DEFAULT_STATE_DIR.parent / "sessions",
                                        legacy_dir=DEFAULT_STATE_DIR)
        if state_dir is not None:
            self.mount_session(state_dir, register=False)

    # ── Session lifecycle ────────────────────────────────────────────────
    def mount_session(self, session_dir: Any, register: bool = True) -> Dict[str, Any]:
        """Point the suite at ``session_dir`` — (re)create the per-session stores
        and clear any prior session's live run state."""
        d = Path(session_dir).expanduser()
        d.mkdir(parents=True, exist_ok=True)
        with self._lock:
            self.session_dir = d
            self.projects = _ProjectStore(d)
            self.issues = _IssueStore(self.projects)
            self.repeater = _RepeaterStore(self.projects)
            self.ghost_brokers.clear()
            self.hunt_brokers.clear()
            self.ghost_tasks.clear()
            self.hunt_tasks.clear()
            self.ar_attacks.clear()
        if register:
            self.sessions.register(str(d), d.name)
        return self.session_info()

    def session_info(self) -> Dict[str, Any]:
        return {"active": self.session_dir is not None,
                "path": str(self.session_dir) if self.session_dir else None,
                "name": self.session_dir.name if self.session_dir else None}

    # ── Repeater ─────────────────────────────────────────────────────────
    def repeater_send(self, project_id: Any, tab_id: Any, request: str,
                      target: str) -> Dict[str, Any]:
        """Send one raw request synchronously and record it against the tab.

        Synchronous by design: a manual send is a single quick round trip, so
        (unlike the long-running Ghost/Hunt scans) it needs no background broker
        — the HTTP handler thread just makes the call and returns the response.
        """
        resp = _exec_repeater_request(request or "", target or "")
        resp["sent_at"] = time.time()
        tab = self.repeater.record_send(project_id, tab_id, request or "",
                                        target or "", resp)
        return {"ok": True, "response": resp, "tab": tab}

    # ── Ghost run lifecycle ──────────────────────────────────────────────
    def start_ghost_run(self, target: str, objective: str, project_id: Any) -> Dict[str, Any]:
        """Launch a GHOST v2 investigation in a background thread, scoped to
        ``project_id``.

        Each project keeps its own event broker (keyed by ``str(project_id)``)
        so switching projects never loses or clobbers another project's live
        run view — that was the v1 bug: a single shared broker meant creating
        or switching to a different project blew away whatever the previous
        project's run had streamed, even though the run itself kept going.

        Returns an ack dict; run output is streamed via that project's broker.
        Guards the ``[agent]`` extra + missing-API-key the same way the CLI does.
        """
        target = (target or "").strip()
        if not target:
            return {"ok": False, "error": "target required"}

        key = str(project_id)
        with self._lock:
            existing = self.ghost_brokers.get(key)
            # since(<huge>) is a read-only way to ask "is this broker done?"
            # without reaching into _Broker's private _done attribute.
            if existing is not None and not existing.since(10**9)["done"]:
                return {"ok": False, "error": "A scan is already running for this project."}

        try:
            from beatrix.ai.ghost2.config import GhostV2Config
            from beatrix.ai.ghost2.core.runner import run_investigation
        except ImportError:
            return {"ok": False, "error": "GHOST v2 needs the 'agent' extra "
                    "(pip install 'beatrix-cli[agent]')."}

        cfg = GhostV2Config.load()
        key_hint = cfg.missing_key_message()
        if key_hint:
            return {"ok": False, "error": key_hint}

        objective = (objective or "").strip() or "Find and validate security vulnerabilities."
        allowed_hosts = self.projects.get_scope(project_id)
        broker = _Broker(meta={"target": target, "model": cfg.model,
                               "objective": objective, "auth": "none",
                               "scope": allowed_hosts})
        with self._lock:
            self.ghost_brokers[key] = broker

        # Live Issues-tab capture: every finding the agent records (root or any
        # subagent) streams into this project's issue log with full detail.
        def _capture(finding: Any) -> None:
            try:
                self.issues.add_finding(project_id, finding,
                                        getattr(finding, "scanner_module", "") or "ghost2", "ghost")
            except Exception:
                pass

        def _run() -> None:
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            task = loop.create_task(run_investigation(
                target, cfg=cfg, objective=objective,
                allowed_hosts=allowed_hosts,
                on_event=broker.emit, on_finding=_capture, persist=True,
            ))
            with self._lock:
                self.ghost_tasks[key] = (loop, task)
            try:
                result = loop.run_until_complete(task)
                # Completion backstop: sweep the authoritative final findings
                # into the issue log (idempotent — the live sink already added
                # most; dedup keeps this from double-counting).
                for f in (result.get("findings") or []):
                    _capture(f)
                broker.emit({"type": "verdict", "text": result.get("verdict", "done"),
                             "detail": result.get("final_output") or ""})
            except asyncio.CancelledError:
                broker.emit({"type": "verdict", "text": "stopped",
                             "detail": "Scan stopped by user."})
            except Exception as e:  # noqa: BLE001 — surface any failure to the pane
                broker.emit({"type": "verdict", "text": "error",
                             "detail": f"{type(e).__name__}: {e}"})
            finally:
                _shutdown_loop(loop)
                with self._lock:
                    self.ghost_tasks.pop(key, None)
                broker.finish()

        threading.Thread(target=_run, daemon=True).start()
        return {"ok": True, "target": target}

    def start_ghost_validation(self, project_id: Any, ids: List[Any]) -> Dict[str, Any]:
        """Launch a Ghost run seeded with existing issues to VALIDATE (not
        re-discover). ``ids`` is the set of issue ids the user selected — one for
        a single-issue check, many for a bulk/by-severity/by-module batch."""
        if self.issues is None:
            return {"ok": False, "error": "no active session"}
        issues = [self.issues.get(project_id, i) for i in (ids or [])]
        issues = [x for x in issues if x]
        if not issues:
            return {"ok": False, "error": "No matching issues to validate."}
        target = _ghost_validation_target(issues)
        if not target:
            return {"ok": False, "error": "Could not derive a target host from the selected issues."}
        result = self.start_ghost_run(target, _ghost_validation_objective(issues), project_id)
        if result.get("ok"):
            result["validating"] = len(issues[:_GHOST_VALIDATE_MAX])
        return result

    def stop_ghost_run(self, project_id: Any) -> Dict[str, Any]:
        """Cancel the in-flight GHOST run for ``project_id``, if any.

        Cancelling the task raises ``asyncio.CancelledError`` at its current
        await point — since that's a ``BaseException``, not ``Exception``, it
        passes straight through every broad ``except Exception`` in the run
        (session/agent teardown still happens via their own ``finally``
        blocks) and is caught here as a distinct "stopped" outcome.
        """
        with self._lock:
            entry = self.ghost_tasks.get(str(project_id))
        if entry is None:
            return {"ok": False, "error": "No scan running for this project."}
        loop, task = entry
        loop.call_soon_threadsafe(task.cancel)
        return {"ok": True}

    def ghost_events(self, since: int, project_id: Any) -> Dict[str, Any]:
        b = self.ghost_brokers.get(str(project_id))
        # No broker for this project => nothing has run there; report "done"
        # so a client never sits in a poll loop for a project with no run.
        return b.since(since) if b is not None else {"events": [], "done": True}

    def ghost_state(self, project_id: Any) -> Dict[str, Any]:
        b = self.ghost_brokers.get(str(project_id))
        if b is None:
            return {}
        state = dict(b.meta)
        state["running"] = not b.since(10**9)["done"]
        return state

    # ── Hunt run lifecycle ───────────────────────────────────────────────
    def start_hunt_run(self, target: str, modules: List[str], preset_label: str,
                        ai: bool, project_id: Any) -> Dict[str, Any]:
        """Launch a deterministic Hunt scan in a background thread, scoped to
        ``project_id`` exactly like Ghost — its own broker, its own
        concurrent-run guard, and its scan output rooted in the project's own
        workspace dir so projects' scan data stays separated.

        ``modules`` must be a non-empty explicit list: ``BeatrixEngine.hunt()``
        treats an *empty* list as "run every module" (see kill_chain's
        module-filter: ``if requested_modules and name not in requested_modules:
        skip`` — empty is falsy, so nothing gets filtered out). Silently running
        the entire arsenal on a selection the user meant to leave blank would
        be a nasty surprise, so this is rejected instead.
        """
        target = (target or "").strip()
        if not target:
            return {"ok": False, "error": "target required"}
        modules = [m for m in (modules or []) if m]
        if not modules:
            return {"ok": False, "error": "select at least one module"}

        key = str(project_id)
        with self._lock:
            existing = self.hunt_brokers.get(key)
            if existing is not None and not existing.since(10**9)["done"]:
                return {"ok": False, "error": "A scan is already running for this project."}

        # Empty scope == unrestricted (same convention as everywhere else in
        # the suite): scan/report on whatever the target and its crawl turn up.
        scope_hosts = self.projects.get_scope(project_id)

        broker = _Broker(meta={"target": target, "preset": preset_label,
                               "modules": modules, "ai": bool(ai), "scope": scope_hosts})
        with self._lock:
            self.hunt_brokers[key] = broker

        def _on_event(event: str, data: dict) -> None:
            # Scope backstop #1: never even show an out-of-scope finding in
            # the live terminal, regardless of whether the scanner that found
            # it consulted the crawler's scope patterns.
            if event == "finding" and scope_hosts:
                f = data.get("finding")
                url = (getattr(f, "url", "") if f else "") or target
                if not _host_in_scope(url, scope_hosts):
                    host = urlparse(url).hostname or url
                    broker.emit({"type": "info", "text": f"Skipped out-of-scope finding on {host}"})
                    return
            # Live Issues-tab capture: an in-scope finding becomes an issue the
            # moment the scanner reports it (Burp-style), with full detail.
            if event == "finding":
                f = data.get("finding")
                if f is not None:
                    try:
                        self.issues.add_finding(project_id, f, data.get("scanner", "") or "", "hunt")
                    except Exception:
                        pass
            line = _hunt_event_to_line(event, data)
            if line is not None:
                broker.emit(line)

        def _run() -> None:
            import asyncio
            from datetime import datetime

            from beatrix.core.engine import BeatrixEngine, EngineConfig
            from beatrix.core.scan_output import ScanOutputManager

            output_mgr = None
            try:
                output_mgr = ScanOutputManager(
                    target, base_dir=self.projects.workspace_dir(project_id))
            except Exception:
                pass

            engine = BeatrixEngine(config=EngineConfig(), on_event=_on_event,
                                   output_manager=output_mgr)
            crawler_scope = _expand_for_crawler(scope_hosts) if scope_hosts else None

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            # preset="full" always opens every phase (1-7), so an arbitrary,
            # cross-category module selection can never be silently blocked
            # by a narrower preset's phase gate — the explicit `modules` list
            # is what actually restricts which scanners run (see kill_chain's
            # per-scanner filter above).
            task = loop.create_task(engine.hunt(target=target, preset="full", ai=ai,
                                                modules=modules, scope=crawler_scope))
            with self._lock:
                self.hunt_tasks[key] = (loop, task)

            try:
                state = loop.run_until_complete(task)

                # Scope backstop #2: the same filter as _on_event above, but
                # against the final, deduplicated findings list — covers
                # anything a scanner recorded through a path that bypassed the
                # live per-event stream, before it's counted or persisted.
                if scope_hosts:
                    kept = [f for f in engine.findings
                            if _host_in_scope((getattr(f, "url", "") or target), scope_hosts)]
                    dropped = len(engine.findings) - len(kept)
                    engine.findings = kept
                    if dropped:
                        broker.emit({"type": "info",
                                     "text": f"{dropped} out-of-scope finding(s) excluded from the final report"})

                duration = (datetime.now() - state.started_at).total_seconds()
                modules_run = set()
                for pr in state.phase_results.values():
                    modules_run.update(pr.modules_run)

                hunt_id = None
                try:
                    from beatrix.core.findings_db import FindingsDB
                    with FindingsDB() as db:
                        hunt_id = db.save_hunt(
                            target=target, preset=preset_label, findings=engine.findings,
                            duration=duration, modules_run=sorted(modules_run),
                            ai_enabled=ai, started_at=state.started_at,
                        )
                except Exception:
                    pass

                n = len(engine.findings)
                detail = f"{duration:.1f}s · modules: {', '.join(sorted(modules_run)) or 'none'}"
                if hunt_id:
                    detail += f" · hunt #{hunt_id}"
                broker.emit({"type": "verdict",
                             "text": f"Hunt complete — {n} finding{'s' if n != 1 else ''}",
                             "detail": detail})
            except asyncio.CancelledError:
                n = len(engine.findings)
                broker.emit({"type": "verdict", "text": "stopped",
                             "detail": f"Scan stopped by user — {n} finding{'s' if n != 1 else ''} "
                                       "recorded before stop."})
            except Exception as e:  # noqa: BLE001 — surface any failure to the pane
                broker.emit({"type": "verdict", "text": "error",
                             "detail": f"{type(e).__name__}: {e}"})
            finally:
                _shutdown_loop(loop)
                with self._lock:
                    self.hunt_tasks.pop(key, None)
                broker.finish()

        threading.Thread(target=_run, daemon=True).start()
        return {"ok": True, "target": target}

    def stop_hunt_run(self, project_id: Any) -> Dict[str, Any]:
        """Cancel the in-flight Hunt scan for ``project_id``, if any (see
        ``stop_ghost_run`` for why ``asyncio.CancelledError`` cleanly
        distinguishes a user-requested stop from a real error)."""
        with self._lock:
            entry = self.hunt_tasks.get(str(project_id))
        if entry is None:
            return {"ok": False, "error": "No scan running for this project."}
        loop, task = entry
        loop.call_soon_threadsafe(task.cancel)
        return {"ok": True}

    def hunt_events(self, since: int, project_id: Any) -> Dict[str, Any]:
        b = self.hunt_brokers.get(str(project_id))
        return b.since(since) if b is not None else {"events": [], "done": True}

    def hunt_state(self, project_id: Any) -> Dict[str, Any]:
        b = self.hunt_brokers.get(str(project_id))
        if b is None:
            return {}
        state = dict(b.meta)
        state["running"] = not b.since(10**9)["done"]
        return state

    # ── AutoRepeater run lifecycle ───────────────────────────────────────
    def start_autorepeater_run(self, project_id: Any, payload: Dict[str, Any]) -> Dict[str, Any]:
        key = str(project_id)
        existing = self.ar_attacks.get(key)
        if existing is not None and existing.running:
            return {"ok": False, "error": "An attack is already running for this project."}
        attack_type = payload.get("attack_type", "sniper")
        if attack_type not in _ATTACK_TYPES:
            return {"ok": False, "error": "Unknown attack type."}
        lits, bases = _ar_parse_positions(payload.get("template", ""))
        if lits is None:
            return {"ok": False, "error": "Unbalanced § markers — every position needs an opening and a closing §."}
        n = len(bases)
        if n == 0:
            return {"ok": False, "error": "Mark at least one payload position with § in the request template."}
        # Each payload set is a spec (list / numbers / brute) expanded here.
        sets = [_ar_expand_set(s) for s in (payload.get("payload_sets") or [])]
        if attack_type in ("sniper", "batteringram"):
            if not sets or not sets[0]:
                return {"ok": False, "error": "Add at least one payload."}
            sets = [sets[0]]
        else:  # pitchfork / clusterbomb → one payload set per position
            if len(sets) < n or any(not s for s in sets[:n]):
                return {"ok": False,
                        "error": f"{attack_type} needs a non-empty payload set for each of the {n} positions."}
            sets = sets[:n]
        total = _ar_count(n, attack_type, sets)
        if total == 0:
            return {"ok": False, "error": "That configuration produces no requests."}
        if total > _AR_MAX_REQUESTS:
            return {"ok": False,
                    "error": f"That would send {total} requests (max {_AR_MAX_REQUESTS}). Narrow the payloads."}
        rules = payload.get("processing") or []
        extract = (payload.get("extract") or "").strip()
        if extract:
            try:
                re.compile(extract)
            except re.error as e:
                return {"ok": False, "error": f"Invalid grep-extract regex: {e}"}
        config = {"template": payload.get("template", ""), "target": payload.get("target", ""),
                  "attack_type": attack_type, "payload_sets": sets, "processing": rules,
                  "grep": payload.get("grep", "") or "", "extract": extract,
                  "concurrency": payload.get("concurrency", 10),
                  "throttle": payload.get("throttle", 0)}
        attack = _AutoAttack(config, total)
        self.ar_attacks[key] = attack
        threading.Thread(target=self._run_autoattack, args=(attack, lits, bases),
                         daemon=True).start()
        return {"ok": True, "total": total}

    def _run_autoattack(self, attack: "_AutoAttack", lits, bases) -> None:
        cfg = attack.config
        target, grep = cfg["target"], cfg["grep"]
        extract_re = re.compile(cfg["extract"]) if cfg.get("extract") else None
        conc = max(1, min(_AR_MAX_CONCURRENCY, int(cfg.get("concurrency") or 10)))
        throttle = max(0, int(cfg.get("throttle") or 0))
        counter = itertools.count(1)

        def do_one(index: int, payloads, req: str) -> None:
            if attack.stop_event.is_set():
                return
            resp = _exec_repeater_request(req, target)
            body = resp.get("body") or ""
            extract = None
            if extract_re is not None:
                m = extract_re.search(body)
                extract = (m.group(1) if (m and m.groups()) else m.group(0)) if m else ""
            attack.add({
                "index": index, "payloads": payloads,
                "status": resp.get("status"), "length": resp.get("size", 0),
                "time_ms": resp.get("time_ms", 0), "error": resp.get("error"),
                "grep": (body.count(grep) if grep else None), "extract": extract,
                "request": req, "response": resp.get("raw", ""),
            })

        try:
            with ThreadPoolExecutor(max_workers=conc) as ex:
                futures = []
                for payloads, req in _ar_generate(lits, bases, cfg["attack_type"],
                                                  cfg["payload_sets"], cfg.get("processing")):
                    if attack.stop_event.is_set():
                        break
                    futures.append(ex.submit(do_one, next(counter), payloads, req))
                    if throttle:
                        time.sleep(throttle / 1000.0)
                for f in futures:
                    try:
                        f.result()
                    except Exception:  # noqa: BLE001
                        pass
        except Exception as e:  # noqa: BLE001
            attack.error = f"{type(e).__name__}: {e}"
        finally:
            with attack._lock:
                attack.running = False

    def stop_autorepeater_run(self, project_id: Any) -> Dict[str, Any]:
        a = self.ar_attacks.get(str(project_id))
        if a is None:
            return {"ok": False, "error": "no attack"}
        a.stop_event.set()
        return {"ok": True}

    def autorepeater_events(self, since: int, project_id: Any) -> Dict[str, Any]:
        a = self.ar_attacks.get(str(project_id))
        if a is None:
            return {"results": [], "done": True, "running": False, "total": 0, "count": 0}
        return {"results": a.summaries_since(int(since)), "done": not a.running,
                "running": a.running, "total": a.total, "count": len(a.results),
                "error": a.error}

    def autorepeater_state(self, project_id: Any) -> Dict[str, Any]:
        a = self.ar_attacks.get(str(project_id))
        return a.state() if a is not None else {}

    def autorepeater_result(self, project_id: Any, index: Any) -> Dict[str, Any]:
        a = self.ar_attacks.get(str(project_id))
        return {"result": a.get(index) if a is not None else None}

    # ── HTTP ─────────────────────────────────────────────────────────────
    def start(self, open_browser: bool = True) -> str:
        suite = self

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _send(self, code: int, body: bytes, ctype: str):
                try:
                    self.send_response(code)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(body)))
                    # The shell's HTML/CSS/JS is baked into this module, so a
                    # cached copy survives a server restart and silently keeps
                    # running the old dashboard against the new backend. Nothing
                    # here is worth caching — every response is live state.
                    self.send_header("Cache-Control", "no-store, must-revalidate")
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    # The browser closed the connection before we finished
                    # writing (a reload/navigation mid-request). Harmless — don't
                    # dump a traceback to the console for it.
                    pass

            def _json(self, obj: Any):
                self._send(200, json.dumps(obj).encode("utf-8"), "application/json")

            def do_GET(self):
                path = urlparse(self.path).path
                if suite.session_dir is None and _needs_session(path):
                    self._json({"needs_session": True})
                    return
                if path in ("/", "/index.html"):
                    self._send(200, _PAGE.encode("utf-8"), "text/html; charset=utf-8")
                elif path == "/session":
                    self._json(suite.session_info())
                elif path == "/sessions":
                    self._json({"sessions": suite.sessions.list(),
                                "home": str(Path.home()),
                                "default_root": str(suite.sessions.default_root)})
                elif path == "/fs/list":
                    q = parse_qs(urlparse(self.path).query)
                    self._json(_fs_list((q.get("path") or [None])[0]))
                elif path == "/auth":
                    # Existing auth GUI, verbatim, same origin (its /api/* calls
                    # resolve to the handlers below).
                    self._send(200, _AUTH_PAGE.encode("utf-8"), "text/html; charset=utf-8")
                elif path == "/projects":
                    self._json(suite.projects.state())
                elif path in _AUTH_GET:
                    try:
                        result = _AUTH_GET[path]()
                    except Exception as e:  # noqa: BLE001
                        result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                    self._json(result)
                elif path == "/ghost/events":
                    q = parse_qs(urlparse(self.path).query)
                    since = int((q.get("since") or ["0"])[0])
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.ghost_events(since, proj))
                elif path == "/ghost/state":
                    q = parse_qs(urlparse(self.path).query)
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.ghost_state(proj))
                elif path == "/hunt/catalog":
                    self._json(_build_hunt_catalog())
                elif path == "/hunt/events":
                    q = parse_qs(urlparse(self.path).query)
                    since = int((q.get("since") or ["0"])[0])
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.hunt_events(since, proj))
                elif path == "/hunt/state":
                    q = parse_qs(urlparse(self.path).query)
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.hunt_state(proj))
                elif path == "/scope":
                    q = parse_qs(urlparse(self.path).query)
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json({"scope": suite.projects.get_scope(proj)})
                elif path == "/issues":
                    q = parse_qs(urlparse(self.path).query)
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json({"issues": suite.issues.list(proj)})
                elif path == "/issues/count":
                    q = parse_qs(urlparse(self.path).query)
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json({"count": suite.issues.count(proj)})
                elif path == "/issues/detail":
                    q = parse_qs(urlparse(self.path).query)
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    iid = (q.get("id") or [None])[0]
                    self._json({"issue": suite.issues.get(proj, iid)})
                elif path == "/repeater":
                    q = parse_qs(urlparse(self.path).query)
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.repeater.state(proj))
                elif path == "/autorepeater/events":
                    q = parse_qs(urlparse(self.path).query)
                    since = int((q.get("since") or ["0"])[0])
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.autorepeater_events(since, proj))
                elif path == "/autorepeater/state":
                    q = parse_qs(urlparse(self.path).query)
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.autorepeater_state(proj))
                elif path == "/autorepeater/result":
                    q = parse_qs(urlparse(self.path).query)
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.autorepeater_result(proj, (q.get("index") or [None])[0]))
                else:
                    self._send(404, b"not found", "text/plain")

            def do_POST(self):
                path = urlparse(self.path).path
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    payload = json.loads(raw or b"{}")
                except Exception:
                    payload = {}

                if suite.session_dir is None and _needs_session(path):
                    self._json({"needs_session": True})
                    return
                if path == "/session/new":
                    res = suite.sessions.create(payload.get("parent"), payload.get("name", ""))
                    if res.get("ok"):
                        suite.mount_session(res["path"])
                        self._json({"ok": True, "session": suite.session_info()})
                    else:
                        self._json(res)
                elif path == "/session/open":
                    p = payload.get("path")
                    if not p or not Path(p).expanduser().is_dir():
                        self._json({"ok": False, "error": "That folder doesn't exist."})
                    else:
                        suite.mount_session(p)
                        self._json({"ok": True, "session": suite.session_info()})
                elif path == "/fs/mkdir":
                    self._json(_fs_mkdir(payload.get("parent", ""), payload.get("name", "")))
                elif path in _AUTH_POST:
                    try:
                        result = _AUTH_POST[path](payload)
                    except Exception as e:  # noqa: BLE001
                        result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                    self._json(result)
                elif path == "/ghost/run":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.start_ghost_run(
                        payload.get("target", ""), payload.get("objective", ""), proj))
                elif path == "/ghost/validate":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.start_ghost_validation(proj, payload.get("ids") or []))
                elif path == "/ghost/stop":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.stop_ghost_run(proj))
                elif path == "/hunt/run":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.start_hunt_run(
                        payload.get("target", ""), payload.get("modules") or [],
                        payload.get("preset", "custom"), bool(payload.get("ai")), proj))
                elif path == "/hunt/stop":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.stop_hunt_run(proj))
                elif path == "/scope/add":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    entries = _parse_scope_text(payload.get("text", ""))
                    if not entries:
                        self._json({"ok": False, "error": "no valid hosts/URLs found"})
                    else:
                        self._json(suite.projects.add_scope(proj, entries))
                elif path == "/scope/remove":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.projects.remove_scope(proj, payload.get("entry", "")))
                elif path == "/scope/clear":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.projects.clear_scope(proj))
                elif path == "/issues/update":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.issues.update(
                        proj, payload.get("id"),
                        severity=payload.get("severity"),
                        highlight=payload.get("highlight"),
                        false_positive=payload.get("false_positive")))
                elif path == "/issues/delete":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.issues.delete(proj, payload.get("id")))
                elif path == "/issues/clear":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.issues.clear(proj))
                elif path == "/repeater/new":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.repeater.new(proj, payload.get("request"),
                        payload.get("target")))
                elif path == "/repeater/close":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.repeater.close(proj, payload.get("id")))
                elif path == "/repeater/select":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.repeater.select(proj, payload.get("id")))
                elif path == "/repeater/save":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.repeater.save(proj, payload.get("id"),
                        payload.get("request"), payload.get("target")))
                elif path == "/repeater/rename":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.repeater.rename(proj, payload.get("id"),
                        payload.get("name", "")))
                elif path == "/repeater/send":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.repeater_send(proj, payload.get("id"),
                        payload.get("request", ""), payload.get("target", "")))
                elif path == "/autorepeater/run":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.start_autorepeater_run(proj, payload))
                elif path == "/autorepeater/stop":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.stop_autorepeater_run(proj))
                elif path == "/projects/new":
                    self._json(suite.projects.new())
                elif path == "/projects/select":
                    self._json(suite.projects.select(payload.get("id")))
                elif path == "/projects/delete":
                    self._json(suite.projects.delete(payload.get("id")))
                else:
                    self._send(404, b"not found", "text/plain")

        try:
            self._httpd = ThreadingHTTPServer((self.host, self.port), _H)
        except OSError:
            # Port busy — fall back to an ephemeral free port rather than fail.
            self._httpd = ThreadingHTTPServer((self.host, 0), _H)
        self.port = self._httpd.server_address[1]
        display_host = "127.0.0.1" if self.host in ("0.0.0.0", "::") else self.host
        self.url = f"http://{display_host}:{self.port}/"
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

        codespace = os.environ.get("CODESPACE_NAME")
        fwd = os.environ.get("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN")
        if codespace and fwd:
            self.public_url = f"https://{codespace}-{self.port}.{fwd}/"

        if open_browser:
            threading.Thread(target=lambda: webbrowser.open(self.url), daemon=True).start()
        return self.url

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


def main(host: Optional[str] = None, port: Optional[int] = None,
         open_browser: Optional[bool] = None) -> None:
    """Launch the Beatrix Suite dashboard and block until Ctrl-C.

    Reachable two ways, and it behaves correctly for both:

    * As the ``beatrix-suite`` console script (the ``suite:main`` entry point) it
      is called with no arguments — so it parses ``--host`` / ``--port`` /
      ``--no-browser`` from the command line itself. That way the standalone
      command honors its flags on *any* install, not only via the dev wrapper
      that routes through ``beatrix suite``. Also covers ``python -m
      beatrix.cli.suite ...``.
    * From the ``beatrix suite`` click subcommand it is called with host/port/
      open_browser given explicitly; argv is then left untouched (click already
      parsed it).

    The regular ``beatrix`` CLI and all its utilities are entirely independent of
    this — they live in ``beatrix.cli.main`` and are unaffected by running the
    GUI.
    """
    if host is None and port is None and open_browser is None:
        import argparse
        parser = argparse.ArgumentParser(
            prog="beatrix-suite",
            description="Launch the Beatrix Suite central dashboard (GUI). "
                        "The full 'beatrix' CLI remains available separately.")
        parser.add_argument("--host", default="0.0.0.0",
                            help="Bind address (default: 0.0.0.0)")
        parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                            help=f"Port to serve on (default: {DEFAULT_PORT})")
        parser.add_argument("--no-browser", action="store_true",
                            help="Do not open a browser tab automatically")
        args = parser.parse_args()
        host, port, open_browser = args.host, args.port, not args.no_browser

    host = "0.0.0.0" if host is None else host
    port = DEFAULT_PORT if port is None else port
    open_browser = True if open_browser is None else open_browser

    # Load ~/.beatrix/.env so AI keys are available to the Ghost tool, matching
    # the CLI startup path.
    try:
        from beatrix.cli.auth_gui import load_beatrix_env
        load_beatrix_env()
    except Exception:
        pass

    server = SuiteServer(host=host, port=port)
    server.start(open_browser=open_browser)
    print(f"Beatrix Suite → {server.url}", flush=True)
    if server.public_url:
        print(f"   Codespaces → {server.public_url}", flush=True)
    print("Press Ctrl-C to stop.", flush=True)
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
