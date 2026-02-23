"""
BEATRIX Core Module

Engine, methodology, and kill chain orchestration.
"""

from .engine import BeatrixEngine
from .kill_chain import KillChainPhase, KillChainState
from .types import Confidence, Finding, ScanResult, Severity, Target
# Lazy-loaded modules (available but not forced at import time)
# from .response_analyzer import ResponseVariationsAnalyzer, responses_differ, is_blind_indicator
# from .smart_fuzzer import SmartFuzzer
# from .poc_chain_engine import PoCChainEngine
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
