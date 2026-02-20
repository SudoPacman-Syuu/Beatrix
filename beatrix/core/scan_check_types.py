"""
BEATRIX Scan Check Types

Ported from Burp Suite's ScanCheckType + ActiveScanCheck/PassiveScanCheck pattern.

Defines the granularity at which scan checks operate and provides
protocol classes (interfaces) for implementing custom checks.
"""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from beatrix.core.types import Finding, InsertionPoint


class ScanCheckGranularity(Enum):
    """
    How often a scan check should run (from Burp's ScanCheckType).

    PER_HOST:             Once per unique host
    PER_REQUEST:          Once per unique URL/endpoint
    PER_INSERTION_POINT:  Once per injectable parameter
    """
    PER_HOST = auto()
    PER_REQUEST = auto()
    PER_INSERTION_POINT = auto()


class ScanPhase(Enum):
    """When in the pipeline this check runs."""
    PASSIVE = auto()     # Analyze existing responses (no new requests)
    ACTIVE = auto()      # Send attack payloads
    BOTH = auto()        # Has both passive and active components


@runtime_checkable
class PassiveScanCheck(Protocol):
    """
    Protocol for passive scan checks (analyze without sending requests).

    Mirrors Burp's PassiveScanCheck interface.
    """

    @property
    def check_name(self) -> str: ...

    @property
    def granularity(self) -> ScanCheckGranularity: ...

    async def do_passive_check(
        self,
        url: str,
        status_code: int,
        headers: Dict[str, str],
        body: str,
    ) -> List[Finding]: ...


@runtime_checkable
class ActiveScanCheck(Protocol):
    """
    Protocol for active scan checks (send payloads to insertion points).

    Mirrors Burp's ActiveScanCheck interface.
    """

    @property
    def check_name(self) -> str: ...

    @property
    def granularity(self) -> ScanCheckGranularity: ...

    async def do_active_check(
        self,
        url: str,
        insertion_point: InsertionPoint,
        send_request: Any,  # Callable to send modified requests
    ) -> List[Finding]: ...


# =============================================================================
# SCAN CHECK REGISTRY
# =============================================================================

@dataclass
class RegisteredCheck:
    """A scan check registered with the engine."""
    name: str
    phase: ScanPhase
    granularity: ScanCheckGranularity
    check: Any  # PassiveScanCheck | ActiveScanCheck | both
    enabled: bool = True

    # Tracking
    findings_produced: int = 0
    requests_sent: int = 0
    errors: int = 0


class ScanCheckRegistry:
    """
    Central registry for all scan checks.

    Mirrors Burp's Scanner.registerActiveScanCheck() / registerPassiveScanCheck().
    """

    def __init__(self):
        self._checks: Dict[str, RegisteredCheck] = {}

    def register_passive(
        self,
        check: PassiveScanCheck,
        granularity: ScanCheckGranularity = ScanCheckGranularity.PER_REQUEST,
    ) -> str:
        """Register a passive scan check."""
        name = check.check_name
        self._checks[name] = RegisteredCheck(
            name=name,
            phase=ScanPhase.PASSIVE,
            granularity=granularity,
            check=check,
        )
        return name

    def register_active(
        self,
        check: ActiveScanCheck,
        granularity: ScanCheckGranularity = ScanCheckGranularity.PER_INSERTION_POINT,
    ) -> str:
        """Register an active scan check."""
        name = check.check_name
        self._checks[name] = RegisteredCheck(
            name=name,
            phase=ScanPhase.ACTIVE,
            granularity=granularity,
            check=check,
        )
        return name

    def get_passive_checks(
        self,
        granularity: Optional[ScanCheckGranularity] = None,
    ) -> List[RegisteredCheck]:
        """Get all enabled passive checks, optionally filtered by granularity."""
        results = []
        for rc in self._checks.values():
            if not rc.enabled:
                continue
            if rc.phase not in (ScanPhase.PASSIVE, ScanPhase.BOTH):
                continue
            if granularity and rc.granularity != granularity:
                continue
            results.append(rc)
        return results

    def get_active_checks(
        self,
        granularity: Optional[ScanCheckGranularity] = None,
    ) -> List[RegisteredCheck]:
        """Get all enabled active checks, optionally filtered by granularity."""
        results = []
        for rc in self._checks.values():
            if not rc.enabled:
                continue
            if rc.phase not in (ScanPhase.ACTIVE, ScanPhase.BOTH):
                continue
            if granularity and rc.granularity != granularity:
                continue
            results.append(rc)
        return results

    def enable(self, name: str):
        if name in self._checks:
            self._checks[name].enabled = True

    def disable(self, name: str):
        if name in self._checks:
            self._checks[name].enabled = False

    def list_checks(self) -> List[Dict[str, Any]]:
        """List all registered checks with their status."""
        return [
            {
                "name": rc.name,
                "phase": rc.phase.name,
                "granularity": rc.granularity.name,
                "enabled": rc.enabled,
                "findings": rc.findings_produced,
                "requests": rc.requests_sent,
                "errors": rc.errors,
            }
            for rc in self._checks.values()
        ]

    @property
    def count(self) -> int:
        return len(self._checks)
