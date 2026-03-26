"""Tests for the Aegis SDK decorators."""

import pytest
from unittest.mock import MagicMock, patch

from aegis.client import AegisClient
from aegis.decorators import guarded_tool, guarded, configure, _default_client
from aegis.types import Decision, Verdict
from aegis.exceptions import AegisBlocked


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _verdict_allow() -> Verdict:
    return Verdict(decision=Decision.ALLOW, reason="ok", source="test")


def _verdict_deny() -> Verdict:
    return Verdict(decision=Decision.DENY, reason="blocked", source="test")


def _mock_client(verdict: Verdict) -> AegisClient:
    client = MagicMock(spec=AegisClient)
    client.evaluate_shell.return_value = verdict
    return client


# ---------------------------------------------------------------------------
# guarded_tool tests
# ---------------------------------------------------------------------------


class TestGuardedTool:
    def test_allow_passes_through(self):
        mock = _mock_client(_verdict_allow())

        @guarded_tool(client=mock)
        def run_shell(command: str) -> str:
            return f"executed: {command}"

        result = run_shell("ls -la")
        assert result == "executed: ls -la"
        mock.evaluate_shell.assert_called_once_with("ls -la", tool_name="run_shell")

    def test_deny_raises(self):
        mock = _mock_client(_verdict_deny())

        @guarded_tool(client=mock)
        def run_shell(command: str) -> str:
            return f"executed: {command}"

        with pytest.raises(AegisBlocked, match="blocked"):
            run_shell("rm -rf /")

    def test_custom_tool_name(self):
        mock = _mock_client(_verdict_allow())

        @guarded_tool(client=mock, tool_name="my-shell")
        def execute(cmd: str) -> str:
            return cmd

        execute("whoami")
        mock.evaluate_shell.assert_called_once_with("whoami", tool_name="my-shell")

    def test_bare_decorator_syntax(self):
        """Test @guarded_tool without parentheses."""
        mock = _mock_client(_verdict_allow())

        @guarded_tool
        def run_shell(command: str) -> str:
            return f"done: {command}"

        # Patch the default client
        with patch("aegis.decorators._get_client", return_value=mock):
            result = run_shell("echo hello")
            assert result == "done: echo hello"

    def test_keyword_command_argument(self):
        mock = _mock_client(_verdict_allow())

        @guarded_tool(client=mock)
        def execute(command: str) -> str:
            return command

        execute(command="id")
        mock.evaluate_shell.assert_called_once_with("id", tool_name="execute")

    def test_keyword_cmd_argument(self):
        mock = _mock_client(_verdict_allow())

        @guarded_tool(client=mock)
        def execute(cmd: str) -> str:
            return cmd

        execute(cmd="uname -a")
        mock.evaluate_shell.assert_called_once_with("uname -a", tool_name="execute")

    def test_no_string_arg_skips_check(self):
        """When no string argument is found, skip the Aegis check."""
        mock = _mock_client(_verdict_deny())

        @guarded_tool(client=mock)
        def process(count: int) -> int:
            return count * 2

        # Should NOT raise even though verdict would be deny,
        # because no string argument was found.
        result = process(5)
        assert result == 10
        mock.evaluate_shell.assert_not_called()

    def test_preserves_function_metadata(self):
        mock = _mock_client(_verdict_allow())

        @guarded_tool(client=mock)
        def my_function(command: str) -> str:
            """My docstring."""
            return command

        assert my_function.__name__ == "my_function"
        assert my_function.__doc__ == "My docstring."


class TestGuardedToolAsync:
    @pytest.mark.asyncio
    async def test_allow_passes_through(self):
        mock = _mock_client(_verdict_allow())

        @guarded_tool(client=mock)
        async def run_shell(command: str) -> str:
            return f"executed: {command}"

        result = await run_shell("ls -la")
        assert result == "executed: ls -la"

    @pytest.mark.asyncio
    async def test_deny_raises(self):
        mock = _mock_client(_verdict_deny())

        @guarded_tool(client=mock)
        async def run_shell(command: str) -> str:
            return f"executed: {command}"

        with pytest.raises(AegisBlocked):
            await run_shell("rm -rf /")


# ---------------------------------------------------------------------------
# guarded tests
# ---------------------------------------------------------------------------


class TestGuarded:
    def test_allow(self):
        mock = _mock_client(_verdict_allow())

        @guarded(client=mock)
        def execute(command: str) -> str:
            return f"ran: {command}"

        result = execute("ls")
        assert result == "ran: ls"
        mock.evaluate_shell.assert_called_once_with("ls", tool_name="execute")

    def test_deny(self):
        mock = _mock_client(_verdict_deny())

        @guarded(client=mock)
        def execute(command: str) -> str:
            return command

        with pytest.raises(AegisBlocked):
            execute("cat /etc/shadow")

    def test_bare_syntax(self):
        """Test @guarded without parentheses."""
        mock = _mock_client(_verdict_allow())

        @guarded
        def execute(command: str) -> str:
            return command

        with patch("aegis.decorators._get_client", return_value=mock):
            result = execute("pwd")
            assert result == "pwd"

    def test_preserves_function_metadata(self):
        mock = _mock_client(_verdict_allow())

        @guarded(client=mock)
        def my_tool(command: str) -> str:
            """Tool docs."""
            return command

        assert my_tool.__name__ == "my_tool"
        assert my_tool.__doc__ == "Tool docs."


class TestGuardedAsync:
    @pytest.mark.asyncio
    async def test_allow(self):
        mock = _mock_client(_verdict_allow())

        @guarded(client=mock)
        async def execute(command: str) -> str:
            return f"ran: {command}"

        result = await execute("echo ok")
        assert result == "ran: echo ok"

    @pytest.mark.asyncio
    async def test_deny(self):
        mock = _mock_client(_verdict_deny())

        @guarded(client=mock)
        async def execute(command: str) -> str:
            return command

        with pytest.raises(AegisBlocked):
            await execute("rm -rf /")


# ---------------------------------------------------------------------------
# configure tests
# ---------------------------------------------------------------------------


class TestConfigure:
    def test_configure_sets_default_client(self):
        import aegis.decorators as mod

        old = mod._default_client
        try:
            configure(base_url="http://localhost:9999", timeout=2.0)
            assert mod._default_client is not None
            assert mod._default_client.base_url == "http://localhost:9999"
        finally:
            mod._default_client = old


# ---------------------------------------------------------------------------
# AegisBlocked exception tests
# ---------------------------------------------------------------------------


class TestAegisBlocked:
    def test_message_format(self):
        verdict = _verdict_deny()
        exc = AegisBlocked(verdict)
        assert "blocked" in str(exc)
        assert "test" in str(exc)
        assert exc.verdict is verdict

    def test_inherits_from_aegis_error(self):
        from aegis.exceptions import AegisError

        verdict = _verdict_deny()
        exc = AegisBlocked(verdict)
        assert isinstance(exc, AegisError)
