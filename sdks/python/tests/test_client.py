"""Tests for the Aegis SDK client."""

import pytest
import httpx

from aegis.client import AegisClient, AsyncAegisClient
from aegis.types import Decision, Verdict, SecretStatus, SnapshotInfo, FileDiff, AuditEntry
from aegis.exceptions import AegisConnectionError, AegisError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_transport(handler):
    """Create an httpx.MockTransport from a handler function."""
    return httpx.MockTransport(handler)


def _json_response(data, status_code=200):
    return httpx.Response(status_code, json=data)


def _make_client(handler) -> AegisClient:
    """Build an AegisClient backed by a mock transport."""
    client = AegisClient.__new__(AegisClient)
    client.base_url = "http://127.0.0.1:19002"
    client.timeout = 5.0
    client._client = httpx.Client(
        base_url=client.base_url,
        transport=_mock_transport(handler),
    )
    return client


def _make_async_client(handler) -> AsyncAegisClient:
    """Build an AsyncAegisClient backed by a mock transport."""
    client = AsyncAegisClient.__new__(AsyncAegisClient)
    client.base_url = "http://127.0.0.1:19002"
    client.timeout = 5.0
    client._client = httpx.AsyncClient(
        base_url=client.base_url,
        transport=httpx.MockTransport(handler),
    )
    return client


# ---------------------------------------------------------------------------
# Sync client tests
# ---------------------------------------------------------------------------


class TestHealth:
    def test_health_ok(self):
        def handler(request: httpx.Request):
            assert request.url.path == "/api/health"
            return _json_response({"status": "ok"})

        client = _make_client(handler)
        result = client.health()
        assert result == {"status": "ok"}

    def test_health_connection_error(self):
        def handler(request: httpx.Request):
            raise httpx.ConnectError("Connection refused")

        client = _make_client(handler)
        with pytest.raises(AegisConnectionError, match="Cannot connect"):
            client.health()


class TestStats:
    def test_stats(self):
        payload = {
            "total": 42,
            "allowed": 30,
            "denied": 12,
            "version": "0.1.0",
            "status": "running",
        }

        def handler(request: httpx.Request):
            assert request.url.path == "/api/stats"
            return _json_response(payload)

        client = _make_client(handler)
        result = client.stats()
        assert result["total"] == 42
        assert result["denied"] == 12


class TestEvaluateShell:
    def test_allow(self):
        def handler(request: httpx.Request):
            assert request.url.path == "/api/evaluate/shell"
            import json
            body = json.loads(request.content)
            assert body["command"] == "ls -la"
            assert body["tool_name"] == "shell"
            return _json_response({
                "decision": "allow",
                "reason": "command is safe",
                "source": "policy:default",
            })

        client = _make_client(handler)
        verdict = client.evaluate_shell("ls -la")
        assert isinstance(verdict, Verdict)
        assert verdict.allowed
        assert not verdict.denied
        assert verdict.decision == Decision.ALLOW
        assert verdict.reason == "command is safe"
        assert verdict.source == "policy:default"

    def test_deny(self):
        def handler(request: httpx.Request):
            return _json_response({
                "decision": "deny",
                "reason": "destructive command blocked",
                "source": "policy:shell-deny",
            })

        client = _make_client(handler)
        verdict = client.evaluate_shell("rm -rf /")
        assert verdict.denied
        assert verdict.reason == "destructive command blocked"

    def test_custom_tool_name_and_cwd(self):
        def handler(request: httpx.Request):
            import json
            body = json.loads(request.content)
            assert body["tool_name"] == "my-tool"
            assert body["cwd"] == "/tmp"
            return _json_response({
                "decision": "allow",
                "reason": "ok",
                "source": "policy:default",
            })

        client = _make_client(handler)
        verdict = client.evaluate_shell("whoami", tool_name="my-tool", cwd="/tmp")
        assert verdict.allowed


class TestEvaluateHttp:
    def test_allow(self):
        def handler(request: httpx.Request):
            assert request.url.path == "/api/evaluate/http"
            import json
            body = json.loads(request.content)
            assert body["method"] == "GET"
            assert body["url"] == "http://example.com"
            return _json_response({
                "decision": "allow",
                "reason": "domain allowed",
                "source": "policy:http-allow",
            })

        client = _make_client(handler)
        verdict = client.evaluate_http("GET", "http://example.com")
        assert verdict.allowed

    def test_deny_with_headers_and_body(self):
        def handler(request: httpx.Request):
            import json
            body = json.loads(request.content)
            assert body["headers"]["Authorization"] == "Bearer secret"
            assert body["body"] == '{"data": 1}'
            return _json_response({
                "decision": "deny",
                "reason": "external API blocked",
                "source": "policy:http-deny",
            })

        client = _make_client(handler)
        verdict = client.evaluate_http(
            "POST",
            "https://evil.com/exfil",
            headers={"Authorization": "Bearer secret"},
            body='{"data": 1}',
        )
        assert verdict.denied


class TestSecretsStatus:
    def test_secrets_enabled(self):
        def handler(request: httpx.Request):
            return _json_response({
                "enabled": True,
                "rules": [{"pattern": "AWS_.*", "action": "redact"}],
                "strip_env_count": 3,
            })

        client = _make_client(handler)
        status = client.secrets_status()
        assert isinstance(status, SecretStatus)
        assert status.enabled is True
        assert len(status.rules) == 1
        assert status.strip_env_count == 3

    def test_secrets_disabled(self):
        def handler(request: httpx.Request):
            return _json_response({
                "enabled": False,
                "rules": [],
                "strip_env_count": 0,
            })

        client = _make_client(handler)
        status = client.secrets_status()
        assert status.enabled is False


class TestSnapshots:
    def test_create_snapshot(self):
        def handler(request: httpx.Request):
            return _json_response({
                "id": "snap-001",
                "method": "git",
                "root": "/workspace",
                "timestamp": "2026-03-26T12:00:00Z",
            })

        client = _make_client(handler)
        info = client.create_snapshot()
        assert isinstance(info, SnapshotInfo)
        assert info.id == "snap-001"
        assert info.method == "git"

    def test_snapshot_diff(self):
        def handler(request: httpx.Request):
            assert "/api/snapshot/snap-001/diff" in str(request.url)
            return _json_response({
                "added": ["new_file.txt"],
                "modified": ["changed.py"],
                "deleted": [],
                "summary": "1 added, 1 modified",
            })

        client = _make_client(handler)
        diff = client.snapshot_diff("snap-001")
        assert isinstance(diff, FileDiff)
        assert diff.added == ["new_file.txt"]
        assert diff.modified == ["changed.py"]
        assert diff.deleted == []

    def test_snapshot_rollback(self):
        def handler(request: httpx.Request):
            return _json_response({"ok": True})

        client = _make_client(handler)
        assert client.snapshot_rollback("snap-001") is True

    def test_snapshot_commit(self):
        def handler(request: httpx.Request):
            return _json_response({"ok": True})

        client = _make_client(handler)
        assert client.snapshot_commit("snap-001") is True


class TestLogs:
    def test_list_logs(self):
        def handler(request: httpx.Request):
            return _json_response({
                "logs": [
                    {"name": "aegis-2026-03-26.jsonl", "path": "/logs/aegis-2026-03-26.jsonl", "size": 1024},
                ],
                "current_session": "2026-03-26_12-00-00",
            })

        client = _make_client(handler)
        logs = client.logs()
        assert len(logs) == 1
        assert logs[0]["name"] == "aegis-2026-03-26.jsonl"

    def test_log_entries(self):
        def handler(request: httpx.Request):
            return _json_response({
                "entries": [
                    {
                        "id": "e1",
                        "timestamp": "2026-03-26T12:00:00Z",
                        "decision": "allow",
                        "reason": "ok",
                        "source": "policy:default",
                        "method": "GET",
                        "url": "http://example.com",
                        "host": "example.com",
                        "layer": "http",
                    },
                    {
                        "id": "e2",
                        "timestamp": "2026-03-26T12:01:00Z",
                        "decision": "deny",
                        "reason": "blocked",
                        "source": "policy:deny",
                        "method": "POST",
                        "url": "http://evil.com",
                        "host": "evil.com",
                        "layer": "http",
                    },
                ],
                "stats": {"total": 2, "allowed": 1, "denied": 1},
            })

        client = _make_client(handler)
        entries = client.log_entries("/logs/test.jsonl", limit=50)
        assert len(entries) == 2
        assert isinstance(entries[0], AuditEntry)
        assert entries[0].decision == Decision.ALLOW
        assert entries[1].decision == Decision.DENY

    def test_log_entries_with_decision_filter(self):
        def handler(request: httpx.Request):
            assert "decision=deny" in str(request.url)
            return _json_response({"entries": [], "stats": {"total": 0, "allowed": 0, "denied": 0}})

        client = _make_client(handler)
        entries = client.log_entries("/logs/test.jsonl", decision="deny")
        assert entries == []


class TestContextManager:
    def test_sync_context_manager(self):
        def handler(request: httpx.Request):
            return _json_response({"status": "ok"})

        client = _make_client(handler)
        with client as c:
            result = c.health()
            assert result["status"] == "ok"


class TestHttpError:
    def test_server_error_raises_aegis_error(self):
        def handler(request: httpx.Request):
            return httpx.Response(500, json={"error": "internal"})

        client = _make_client(handler)
        with pytest.raises(AegisError, match="500"):
            client.health()


# ---------------------------------------------------------------------------
# Async client tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestAsyncHealth:
    async def test_health_ok(self):
        def handler(request: httpx.Request):
            return _json_response({"status": "ok"})

        client = _make_async_client(handler)
        try:
            result = await client.health()
            assert result == {"status": "ok"}
        finally:
            await client.close()


@pytest.mark.asyncio
class TestAsyncEvaluateShell:
    async def test_allow(self):
        def handler(request: httpx.Request):
            return _json_response({
                "decision": "allow",
                "reason": "ok",
                "source": "policy:default",
            })

        client = _make_async_client(handler)
        try:
            verdict = await client.evaluate_shell("echo hello")
            assert verdict.allowed
        finally:
            await client.close()

    async def test_deny(self):
        def handler(request: httpx.Request):
            return _json_response({
                "decision": "deny",
                "reason": "blocked",
                "source": "policy:shell-deny",
            })

        client = _make_async_client(handler)
        try:
            verdict = await client.evaluate_shell("rm -rf /")
            assert verdict.denied
        finally:
            await client.close()


@pytest.mark.asyncio
class TestAsyncEvaluateHttp:
    async def test_allow(self):
        def handler(request: httpx.Request):
            return _json_response({
                "decision": "allow",
                "reason": "allowed",
                "source": "policy:http",
            })

        client = _make_async_client(handler)
        try:
            verdict = await client.evaluate_http("GET", "http://example.com")
            assert verdict.allowed
        finally:
            await client.close()


@pytest.mark.asyncio
class TestAsyncContextManager:
    async def test_async_context_manager(self):
        def handler(request: httpx.Request):
            return _json_response({"status": "ok"})

        client = _make_async_client(handler)
        async with client as c:
            result = await c.health()
            assert result["status"] == "ok"


@pytest.mark.asyncio
class TestAsyncSnapshots:
    async def test_create_snapshot(self):
        def handler(request: httpx.Request):
            return _json_response({
                "id": "snap-async-001",
                "method": "git",
                "root": "/workspace",
                "timestamp": "2026-03-26T12:00:00Z",
            })

        client = _make_async_client(handler)
        try:
            info = await client.create_snapshot()
            assert info.id == "snap-async-001"
        finally:
            await client.close()

    async def test_snapshot_diff(self):
        def handler(request: httpx.Request):
            return _json_response({
                "added": [],
                "modified": ["file.py"],
                "deleted": ["old.txt"],
                "summary": "1 modified, 1 deleted",
            })

        client = _make_async_client(handler)
        try:
            diff = await client.snapshot_diff("snap-async-001")
            assert diff.modified == ["file.py"]
            assert diff.deleted == ["old.txt"]
        finally:
            await client.close()


@pytest.mark.asyncio
class TestAsyncLogs:
    async def test_list_logs(self):
        def handler(request: httpx.Request):
            return _json_response({"logs": [], "current_session": "test"})

        client = _make_async_client(handler)
        try:
            logs = await client.logs()
            assert logs == []
        finally:
            await client.close()

    async def test_log_entries(self):
        def handler(request: httpx.Request):
            return _json_response({
                "entries": [{
                    "id": "e1",
                    "timestamp": "2026-03-26T12:00:00Z",
                    "decision": "allow",
                    "reason": "ok",
                    "source": "default",
                    "method": "GET",
                    "url": "http://test.com",
                    "host": "test.com",
                    "layer": "http",
                }],
                "stats": {"total": 1, "allowed": 1, "denied": 0},
            })

        client = _make_async_client(handler)
        try:
            entries = await client.log_entries("/logs/test.jsonl")
            assert len(entries) == 1
            assert entries[0].id == "e1"
        finally:
            await client.close()
