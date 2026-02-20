"""
Compatibility layer for ReconX modules imported into Beatrix.

ReconX modules inherit from BaseModule with a simple run() interface.
This shim provides that interface so imported modules work without
rewriting their internals.
"""

from typing import Any, Dict, Optional


class ReconXBaseModule:
    """
    Compatibility base class matching ReconX's BaseModule interface.

    ReconX modules use:
        class MyScanner(BaseModule):
            async def run(self, target: str) -> dict:
                ...

    This shim preserves that contract within Beatrix's package structure.
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.name = self.__class__.__name__

    async def run(self, target: str) -> Dict[str, Any]:
        """Override this method in subclasses"""
        raise NotImplementedError("Module must implement run() method")

    def validate_target(self, target: str) -> bool:
        """Basic target validation"""
        return bool(target and len(target) > 0)
