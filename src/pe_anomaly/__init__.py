"""PE Anomaly - Scan Portable Executable files for structural anomalies."""

from .parser import PEParser
from .scanner import scan

__version__ = "0.1.0"
__all__ = ["PEParser", "scan"]
