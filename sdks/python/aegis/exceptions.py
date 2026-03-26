"""Exception types for the Aegis SDK."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aegis.types import Verdict


class AegisError(Exception):
    """Base exception for Aegis SDK."""


class AegisBlocked(AegisError):
    """Raised when Aegis blocks an action."""

    def __init__(self, verdict: "Verdict") -> None:
        self.verdict = verdict
        super().__init__(f"Blocked by Aegis: {verdict.reason} ({verdict.source})")


class AegisConnectionError(AegisError):
    """Raised when unable to connect to Aegis."""
