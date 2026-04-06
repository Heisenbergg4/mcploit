"""
MCPloit Payload Library

Comprehensive payload collections for MCP vulnerability testing.
"""

from .base import Payload, PayloadCategory, PayloadSeverity
from .manager import PayloadManager

__all__ = [
    "Payload",
    "PayloadCategory",
    "PayloadSeverity",
    "PayloadManager",
]
