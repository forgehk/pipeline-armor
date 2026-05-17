"""pipeline-armor: a drop-in security gate for CI."""

from .findings import Finding, Severity

__version__ = "0.1.0"
__all__ = ["Finding", "Severity"]
