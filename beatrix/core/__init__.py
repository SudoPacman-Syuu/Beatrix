"""
BEATRIX Core Module

Engine, methodology, and kill chain orchestration.
"""

from .engine import BeatrixEngine
from .kill_chain import KillChainPhase, KillChainState
from .types import Confidence, Finding, ScanResult, Severity, Target

__all__ = [
    "BeatrixEngine",
    "Finding",
    "Target",
    "ScanResult",
    "Severity",
    "Confidence",
    "KillChainPhase",
    "KillChainState",
]
