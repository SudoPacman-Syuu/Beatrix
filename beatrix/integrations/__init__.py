"""
BEATRIX Integrations

External service integrations: HackerOne, GitHub, etc.
"""

from beatrix.integrations.hackerone import H1ReportDraft, HackerOneClient

__all__ = [
    "HackerOneClient",
    "H1ReportDraft",
]
