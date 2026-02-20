"""
BEATRIX Issue Consolidator

Ported from Burp Suite's ConsolidationAction pattern.

Deduplicates findings so the same bug isn't reported twice.
Uses multi-dimensional similarity: URL, parameter, vuln type,
payload, evidence hash.
"""

import hashlib
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional
from urllib.parse import urlparse

from beatrix.core.types import Finding, Severity


class ConsolidationAction(Enum):
    """What to do when a new finding overlaps an existing one."""
    KEEP_EXISTING = auto()  # Drop the new one
    KEEP_NEW = auto()       # Replace existing with new
    KEEP_BOTH = auto()      # Both are distinct, keep both


@dataclass
class ConsolidationResult:
    """Result of attempting to add a finding."""
    action: ConsolidationAction
    finding: Finding
    existing: Optional[Finding] = None
    reason: str = ""


class IssueConsolidator:
    """
    Deduplicates findings based on configurable similarity dimensions.

    Mirrors Burp's consolidateIssues() pattern but with richer heuristics.

    Usage:
        consolidator = IssueConsolidator()
        for finding in raw_findings:
            result = consolidator.add(finding)
            if result.action != ConsolidationAction.KEEP_EXISTING:
                # This is a genuinely new finding
                report(result.finding)

        unique = consolidator.unique_findings()
    """

    def __init__(self, *, strict: bool = False):
        """
        Args:
            strict: If True, requires more dimensions to match for dedup.
        """
        self._findings: List[Finding] = []
        self._fingerprints: Dict[str, int] = {}  # hash -> index in _findings
        self._strict = strict

    def _fingerprint(self, f: Finding) -> str:
        """
        Generate a dedup fingerprint for a finding.

        Dimensions considered:
        1. Vulnerability type (scanner_module + title pattern)
        2. Host + path (not full URL with params)
        3. Parameter name
        4. Injection point type
        """
        parsed = urlparse(f.url)
        host = parsed.netloc.lower()
        path = parsed.path.rstrip("/").lower()

        # Normalize title to vuln-type (strip specifics)
        vuln_type = self._normalize_title(f.title)

        param = (f.parameter or "").lower()
        module = f.scanner_module.lower()

        components = [host, path, vuln_type, param, module]

        if not self._strict:
            # In non-strict mode, same host+path+vuln+param = same issue
            raw = "|".join(components)
        else:
            # Strict mode adds injection point type
            ip_type = str(f.injection_point) if f.injection_point else ""
            components.append(ip_type)
            raw = "|".join(components)

        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _normalize_title(self, title: str) -> str:
        """
        Reduce a finding title to its vulnerability class.

        e.g. "SQL Injection in search parameter" -> "sql_injection"
             "Reflected XSS via q parameter" -> "reflected_xss"
        """
        title_lower = title.lower()

        PATTERNS = [
            (r"sql\s*inject", "sqli"),
            (r"cross.site\s*script|xss", "xss"),
            (r"ssrf|server.side\s*request", "ssrf"),
            (r"idor|insecure\s*direct", "idor"),
            (r"cors", "cors"),
            (r"csrf|cross.site\s*request\s*forg", "csrf"),
            (r"open\s*redirect", "open_redirect"),
            (r"path\s*traversal|directory\s*traversal|lfi", "path_traversal"),
            (r"command\s*inject|rce|remote\s*code", "rce"),
            (r"xxe|xml\s*external", "xxe"),
            (r"ssti|template\s*inject", "ssti"),
            (r"jwt", "jwt"),
            (r"auth.*bypass|broken\s*auth", "auth_bypass"),
            (r"info.*disclos|information\s*leak", "info_disclosure"),
            (r"header\s*inject", "header_injection"),
            (r"priv.*escal", "privilege_escalation"),
            (r"rate\s*limit", "rate_limit"),
            (r"brute\s*force", "brute_force"),
        ]

        import re
        for pattern, label in PATTERNS:
            if re.search(pattern, title_lower):
                return label

        # Fallback: slugify the title
        return re.sub(r"[^a-z0-9]+", "_", title_lower).strip("_")

    def add(self, finding: Finding) -> ConsolidationResult:
        """
        Attempt to add a finding. Returns what action was taken.
        """
        fp = self._fingerprint(finding)

        if fp in self._fingerprints:
            idx = self._fingerprints[fp]
            existing = self._findings[idx]

            # Decide: keep existing, replace, or keep both
            action = self._decide(existing, finding)

            if action == ConsolidationAction.KEEP_NEW:
                self._findings[idx] = finding
                return ConsolidationResult(
                    action=action, finding=finding,
                    existing=existing,
                    reason="Replaced: new has higher severity/confidence",
                )
            elif action == ConsolidationAction.KEEP_EXISTING:
                return ConsolidationResult(
                    action=action, finding=existing,
                    existing=existing,
                    reason="Duplicate of existing finding",
                )
            else:
                # KEEP_BOTH — different enough to warrant both
                self._findings.append(finding)
                new_fp = fp + f"_{len(self._findings)}"
                self._fingerprints[new_fp] = len(self._findings) - 1
                return ConsolidationResult(
                    action=action, finding=finding,
                    existing=existing,
                    reason="Distinct variant, keeping both",
                )
        else:
            self._findings.append(finding)
            self._fingerprints[fp] = len(self._findings) - 1
            return ConsolidationResult(
                action=ConsolidationAction.KEEP_BOTH,
                finding=finding,
                reason="New unique finding",
            )

    def _decide(self, existing: Finding, new: Finding) -> ConsolidationAction:
        """
        Decide what to do when two findings have the same fingerprint.
        """
        SEVERITY_ORDER = {
            Severity.CRITICAL: 5, Severity.HIGH: 4,
            Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1,
        }

        existing_score = SEVERITY_ORDER.get(existing.severity, 0)
        new_score = SEVERITY_ORDER.get(new.severity, 0)

        # Higher severity wins
        if new_score > existing_score:
            return ConsolidationAction.KEEP_NEW

        # Same severity: check if evidence differs significantly
        if new_score == existing_score:
            # Different payloads = might be worth keeping both
            if (new.payload and existing.payload and
                    new.payload != existing.payload):
                return ConsolidationAction.KEEP_BOTH

            # Different evidence values = distinct findings (e.g. different secrets)
            if new.evidence and existing.evidence:
                new_ev = str(sorted(new.evidence.items())) if isinstance(new.evidence, dict) else str(new.evidence)
                old_ev = str(sorted(existing.evidence.items())) if isinstance(existing.evidence, dict) else str(existing.evidence)
                if new_ev != old_ev:
                    return ConsolidationAction.KEEP_BOTH

            # Different descriptions with unique content (e.g. different secret values)
            if (new.description and existing.description and
                    new.description != existing.description and
                    len(new.description) > 20):
                return ConsolidationAction.KEEP_BOTH

            # Validated > unvalidated
            if new.validated and not existing.validated:
                return ConsolidationAction.KEEP_NEW

        return ConsolidationAction.KEEP_EXISTING

    def unique_findings(self) -> List[Finding]:
        """Return all unique findings."""
        return list(self._findings)

    def stats(self) -> Dict[str, int]:
        """Return dedup stats."""
        by_type: Dict[str, int] = {}
        for f in self._findings:
            vtype = self._normalize_title(f.title)
            by_type[vtype] = by_type.get(vtype, 0) + 1
        return {
            "total_unique": len(self._findings),
            "by_type": by_type,
        }

    def clear(self):
        """Reset the consolidator."""
        self._findings.clear()
        self._fingerprints.clear()
