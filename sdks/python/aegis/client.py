"""Synchronous and asynchronous HTTP clients for the Aegis API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import httpx

from aegis.exceptions import AegisConnectionError, AegisError
from aegis.types import (
    AuditEntry,
    FileDiff,
    SecretStatus,
    SnapshotInfo,
    Verdict,
)


class AegisClient:
    """Synchronous client for the Aegis web API.

    Usage::

        from aegis import AegisClient

        client = AegisClient()  # defaults to http://127.0.0.1:19002
        verdict = client.evaluate_shell("nmap -sV 10.0.0.1")
        if verdict.denied:
            print(f"Blocked: {verdict.reason}")
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:19002",
        timeout: float = 5.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
        )

    # -- lifecycle -----------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._client.close()

    def __enter__(self) -> "AegisClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- helpers -------------------------------------------------------------

    def _get(self, path: str, params: Optional[dict] = None) -> Any:
        try:
            resp = self._client.get(path, params=params)
            resp.raise_for_status()
            return resp.json()
        except httpx.ConnectError as exc:
            raise AegisConnectionError(
                f"Cannot connect to Aegis at {self.base_url}: {exc}"
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise AegisError(
                f"Aegis API error {exc.response.status_code}: {exc.response.text}"
            ) from exc

    def _post(self, path: str, json: Optional[dict] = None) -> Any:
        try:
            resp = self._client.post(path, json=json or {})
            resp.raise_for_status()
            return resp.json()
        except httpx.ConnectError as exc:
            raise AegisConnectionError(
                f"Cannot connect to Aegis at {self.base_url}: {exc}"
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise AegisError(
                f"Aegis API error {exc.response.status_code}: {exc.response.text}"
            ) from exc

    # -- health / stats ------------------------------------------------------

    def health(self) -> dict:
        """Check if Aegis is running.

        Returns:
            ``{"status": "ok"}`` when Aegis is reachable.
        """
        return self._get("/api/health")

    def stats(self) -> dict:
        """Get aggregate request statistics.

        Returns:
            Dict with ``total``, ``allowed``, ``denied``, ``version``, and
            ``status`` keys.
        """
        return self._get("/api/stats")

    # -- evaluate ------------------------------------------------------------

    def evaluate_shell(
        self,
        command: str,
        tool_name: str = "shell",
        cwd: Optional[str] = None,
    ) -> Verdict:
        """Check a shell command against Aegis policies.

        Args:
            command: The shell command string to evaluate.
            tool_name: Logical name of the tool invoking the command.
            cwd: Optional working directory context.

        Returns:
            A :class:`~aegis.types.Verdict` with the decision.
        """
        payload: Dict[str, Any] = {"command": command, "tool_name": tool_name}
        if cwd is not None:
            payload["cwd"] = cwd
        data = self._post("/api/evaluate/shell", json=payload)
        return Verdict.from_dict(data)

    def evaluate_http(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> Verdict:
        """Check an HTTP request against Aegis policies.

        Args:
            method: HTTP method (GET, POST, etc.).
            url: Target URL.
            headers: Optional request headers.
            body: Optional request body.

        Returns:
            A :class:`~aegis.types.Verdict` with the decision.
        """
        payload: Dict[str, Any] = {"method": method, "url": url}
        if headers is not None:
            payload["headers"] = headers
        if body is not None:
            payload["body"] = body
        data = self._post("/api/evaluate/http", json=payload)
        return Verdict.from_dict(data)

    # -- secrets -------------------------------------------------------------

    def secrets_status(self) -> SecretStatus:
        """Get secrets configuration status.

        No secret values are exposed -- only rule metadata and counts.

        Returns:
            A :class:`~aegis.types.SecretStatus` instance.
        """
        data = self._get("/api/secrets/status")
        return SecretStatus.from_dict(data)

    # -- snapshots -----------------------------------------------------------

    def create_snapshot(self) -> SnapshotInfo:
        """Create a filesystem snapshot.

        Returns:
            A :class:`~aegis.types.SnapshotInfo` describing the new snapshot.
        """
        data = self._post("/api/snapshot/create")
        return SnapshotInfo.from_dict(data)

    def snapshot_diff(self, snapshot_id: str) -> FileDiff:
        """Get the diff between a snapshot and the current filesystem state.

        Args:
            snapshot_id: The ID returned by :meth:`create_snapshot`.

        Returns:
            A :class:`~aegis.types.FileDiff` with lists of changed files.
        """
        data = self._get(f"/api/snapshot/{snapshot_id}/diff")
        return FileDiff.from_dict(data)

    def snapshot_rollback(self, snapshot_id: str) -> bool:
        """Rollback the filesystem to a previous snapshot.

        Args:
            snapshot_id: The ID returned by :meth:`create_snapshot`.

        Returns:
            ``True`` if the rollback succeeded.
        """
        data = self._post(f"/api/snapshot/{snapshot_id}/rollback")
        return bool(data.get("ok", False))

    def snapshot_commit(self, snapshot_id: str) -> bool:
        """Accept changes and mark a snapshot as committed.

        Args:
            snapshot_id: The ID returned by :meth:`create_snapshot`.

        Returns:
            ``True`` if the commit succeeded.
        """
        data = self._post(f"/api/snapshot/{snapshot_id}/commit")
        return bool(data.get("ok", False))

    # -- audit logs ----------------------------------------------------------

    def logs(self) -> List[dict]:
        """List available audit log files.

        Returns:
            A list of dicts, each with ``name``, ``path``, ``size``,
            ``session``, and ``current`` keys.
        """
        data = self._get("/api/logs")
        return data.get("logs", [])

    def log_entries(
        self,
        file: str,
        limit: int = 100,
        decision: Optional[str] = None,
    ) -> List[AuditEntry]:
        """Read entries from an audit log file.

        Args:
            file: Path to the audit log file (as returned by :meth:`logs`).
            limit: Maximum number of entries to return.
            decision: Optional filter -- ``"allow"`` or ``"deny"``.

        Returns:
            A list of :class:`~aegis.types.AuditEntry` instances.
        """
        params: Dict[str, Any] = {"file": file, "limit": limit}
        if decision is not None:
            params["decision"] = decision
        data = self._get("/api/logs/entries", params=params)
        entries = data.get("entries", [])
        return [AuditEntry.from_dict(e) for e in entries]


class AsyncAegisClient:
    """Asynchronous client for the Aegis web API.

    Usage::

        import asyncio
        from aegis import AsyncAegisClient

        async def main():
            async with AsyncAegisClient() as client:
                verdict = await client.evaluate_shell("id")
                print(verdict)

        asyncio.run(main())
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:19002",
        timeout: float = 5.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
        )

    # -- lifecycle -----------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncAegisClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    # -- helpers -------------------------------------------------------------

    async def _get(self, path: str, params: Optional[dict] = None) -> Any:
        try:
            resp = await self._client.get(path, params=params)
            resp.raise_for_status()
            return resp.json()
        except httpx.ConnectError as exc:
            raise AegisConnectionError(
                f"Cannot connect to Aegis at {self.base_url}: {exc}"
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise AegisError(
                f"Aegis API error {exc.response.status_code}: {exc.response.text}"
            ) from exc

    async def _post(self, path: str, json: Optional[dict] = None) -> Any:
        try:
            resp = await self._client.post(path, json=json or {})
            resp.raise_for_status()
            return resp.json()
        except httpx.ConnectError as exc:
            raise AegisConnectionError(
                f"Cannot connect to Aegis at {self.base_url}: {exc}"
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise AegisError(
                f"Aegis API error {exc.response.status_code}: {exc.response.text}"
            ) from exc

    # -- health / stats ------------------------------------------------------

    async def health(self) -> dict:
        """Check if Aegis is running."""
        return await self._get("/api/health")

    async def stats(self) -> dict:
        """Get aggregate request statistics."""
        return await self._get("/api/stats")

    # -- evaluate ------------------------------------------------------------

    async def evaluate_shell(
        self,
        command: str,
        tool_name: str = "shell",
        cwd: Optional[str] = None,
    ) -> Verdict:
        """Check a shell command against Aegis policies."""
        payload: Dict[str, Any] = {"command": command, "tool_name": tool_name}
        if cwd is not None:
            payload["cwd"] = cwd
        data = await self._post("/api/evaluate/shell", json=payload)
        return Verdict.from_dict(data)

    async def evaluate_http(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> Verdict:
        """Check an HTTP request against Aegis policies."""
        payload: Dict[str, Any] = {"method": method, "url": url}
        if headers is not None:
            payload["headers"] = headers
        if body is not None:
            payload["body"] = body
        data = await self._post("/api/evaluate/http", json=payload)
        return Verdict.from_dict(data)

    # -- secrets -------------------------------------------------------------

    async def secrets_status(self) -> SecretStatus:
        """Get secrets configuration status."""
        data = await self._get("/api/secrets/status")
        return SecretStatus.from_dict(data)

    # -- snapshots -----------------------------------------------------------

    async def create_snapshot(self) -> SnapshotInfo:
        """Create a filesystem snapshot."""
        data = await self._post("/api/snapshot/create")
        return SnapshotInfo.from_dict(data)

    async def snapshot_diff(self, snapshot_id: str) -> FileDiff:
        """Get diff for a snapshot."""
        data = await self._get(f"/api/snapshot/{snapshot_id}/diff")
        return FileDiff.from_dict(data)

    async def snapshot_rollback(self, snapshot_id: str) -> bool:
        """Rollback to a snapshot."""
        data = await self._post(f"/api/snapshot/{snapshot_id}/rollback")
        return bool(data.get("ok", False))

    async def snapshot_commit(self, snapshot_id: str) -> bool:
        """Accept changes and commit snapshot."""
        data = await self._post(f"/api/snapshot/{snapshot_id}/commit")
        return bool(data.get("ok", False))

    # -- audit logs ----------------------------------------------------------

    async def logs(self) -> List[dict]:
        """List available audit log files."""
        data = await self._get("/api/logs")
        return data.get("logs", [])

    async def log_entries(
        self,
        file: str,
        limit: int = 100,
        decision: Optional[str] = None,
    ) -> List[AuditEntry]:
        """Read entries from an audit log file."""
        params: Dict[str, Any] = {"file": file, "limit": limit}
        if decision is not None:
            params["decision"] = decision
        data = await self._get("/api/logs/entries", params=params)
        entries = data.get("entries", [])
        return [AuditEntry.from_dict(e) for e in entries]
