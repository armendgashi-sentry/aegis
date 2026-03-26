"""Aegis SDK — Python client for the Aegis AI agent security proxy."""

from aegis.client import AegisClient, AsyncAegisClient
from aegis.decorators import guarded_tool, guarded, configure
from aegis.types import Verdict, Decision
from aegis.exceptions import AegisBlocked, AegisError, AegisConnectionError

__all__ = [
    "AegisClient",
    "AsyncAegisClient",
    "guarded_tool",
    "guarded",
    "configure",
    "Verdict",
    "Decision",
    "AegisBlocked",
    "AegisError",
    "AegisConnectionError",
]

__version__ = "0.1.0"
