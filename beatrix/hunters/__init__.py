"""
BEATRIX Hunters

Consolidated hunting modules from standalone scripts.
Each hunter is a specialized workflow combining scanners, AI, and recon.
"""

from beatrix.hunters.haiku import HaikuHunter
from beatrix.hunters.rapid import RapidHunter

__all__ = [
    "RapidHunter",
    "HaikuHunter",
]
