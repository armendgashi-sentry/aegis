"""Type definitions for the Aegis SDK."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, List


class Decision(str, Enum):
    """Aegis policy decision."""
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class Verdict:
    """Result of an Aegis policy evaluation."""
    decision: Decision
    reason: str
    source: str

    @property
    def allowed(self) -> bool:
        """True if the action is allowed."""
        return self.decision == Decision.ALLOW

    @property
    def denied(self) -> bool:
        """True if the action is denied."""
        return self.decision == Decision.DENY

    @classmethod
    def from_dict(cls, data: dict) -> "Verdict":
        """Create a Verdict from an API response dict."""
        return cls(
            decision=Decision(data["decision"]),
            reason=data.get("reason", ""),
            source=data.get("source", ""),
        )


@dataclass
class AuditEntry:
    """A single audit log entry."""
    id: str
    timestamp: str
    decision: Decision
    reason: str
    source: str
    method: str
    url: str
    host: str
    layer: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    content_type: Optional[str] = None
    secrets_applied: List[dict] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEntry":
        """Create an AuditEntry from an API response dict."""
        return cls(
            id=data.get("id", ""),
            timestamp=data.get("timestamp", ""),
            decision=Decision(data.get("decision", "allow")),
            reason=data.get("reason", ""),
            source=data.get("source", ""),
            method=data.get("method", ""),
            url=data.get("url", ""),
            host=data.get("host", ""),
            layer=data.get("layer", ""),
            headers=data.get("headers", {}),
            body=data.get("body"),
            content_type=data.get("content_type"),
            secrets_applied=data.get("secrets_applied", []),
        )


@dataclass
class SnapshotInfo:
    """Information about a filesystem snapshot."""
    id: str
    method: str
    root: str
    timestamp: str
    branch: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> "SnapshotInfo":
        """Create a SnapshotInfo from an API response dict."""
        return cls(
            id=data["id"],
            method=data.get("method", ""),
            root=data.get("root", ""),
            timestamp=data.get("timestamp", ""),
            branch=data.get("branch"),
        )


@dataclass
class FileDiff:
    """Filesystem diff relative to a snapshot."""
    added: List[str]
    modified: List[str]
    deleted: List[str]
    summary: str

    @classmethod
    def from_dict(cls, data: dict) -> "FileDiff":
        """Create a FileDiff from an API response dict."""
        return cls(
            added=data.get("added", []),
            modified=data.get("modified", []),
            deleted=data.get("deleted", []),
            summary=data.get("summary", ""),
        )


@dataclass
class SecretStatus:
    """Secrets configuration status (no secret values exposed)."""
    enabled: bool
    rules: List[dict]
    strip_env_count: int

    @classmethod
    def from_dict(cls, data: dict) -> "SecretStatus":
        """Create a SecretStatus from an API response dict."""
        return cls(
            enabled=data.get("enabled", False),
            rules=data.get("rules", []),
            strip_env_count=data.get("strip_env_count", 0),
        )
