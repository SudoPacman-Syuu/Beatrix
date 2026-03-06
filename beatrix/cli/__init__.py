"""
BEATRIX CLI Module
"""

__all__ = ["cli"]


def __getattr__(name):
    if name == "cli":
        from .main import cli
        return cli
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
