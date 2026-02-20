"""
BEATRIX Validators

Post-scan validation layer that prevents theoretical reports.
Born from 3 informative closures on Bykea (2026-02-05).

Every finding must pass through:
1. ImpactValidator - Does this have REAL, demonstrable impact?
2. ReportReadinessGate - Would this survive hostile triage?

"Theory is the enemy of triage."
"""

from .impact_validator import ImpactCheck, ImpactValidator, ImpactVerdict
from .readiness_gate import ReadinessCheck, ReadinessVerdict, ReportReadinessGate

__all__ = [
    "ImpactValidator",
    "ImpactVerdict",
    "ImpactCheck",
    "ReportReadinessGate",
    "ReadinessVerdict",
    "ReadinessCheck",
]
