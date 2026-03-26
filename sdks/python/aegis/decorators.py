"""Decorators for guarding tool calls through Aegis."""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Optional, TypeVar, overload

from aegis.client import AegisClient
from aegis.exceptions import AegisBlocked

F = TypeVar("F", bound=Callable[..., Any])

_default_client: Optional[AegisClient] = None


def configure(base_url: str = "http://127.0.0.1:19002", **kwargs: Any) -> None:
    """Set up the default Aegis client used by decorators.

    Args:
        base_url: Aegis API base URL.
        **kwargs: Extra keyword arguments forwarded to
            :class:`~aegis.client.AegisClient`.
    """
    global _default_client
    _default_client = AegisClient(base_url=base_url, **kwargs)


def _get_client() -> AegisClient:
    global _default_client
    if _default_client is None:
        _default_client = AegisClient()
    return _default_client


def _extract_command(args: tuple, kwargs: dict) -> Optional[str]:
    """Best-effort extraction of a command string from function arguments.

    Looks for a ``command`` or ``cmd`` keyword argument first, then falls back
    to the first positional string argument.
    """
    for key in ("command", "cmd"):
        if key in kwargs:
            return str(kwargs[key])
    for arg in args:
        if isinstance(arg, str):
            return arg
    return None


# --------------------------------------------------------------------------- #
# guarded_tool
# --------------------------------------------------------------------------- #


@overload
def guarded_tool(func: F) -> F: ...


@overload
def guarded_tool(
    *,
    client: Optional[AegisClient] = None,
    tool_name: Optional[str] = None,
) -> Callable[[F], F]: ...


def guarded_tool(
    func: Optional[F] = None,
    *,
    client: Optional[AegisClient] = None,
    tool_name: Optional[str] = None,
) -> Any:
    """Decorator that checks shell commands through Aegis before execution.

    Can be used with or without arguments::

        @guarded_tool
        def run_shell(command: str) -> str:
            return subprocess.check_output(command, shell=True).decode()

        @guarded_tool(tool_name="custom-shell")
        def my_exec(cmd: str) -> str:
            ...

    The decorator extracts the command string from the function's arguments
    (looks for ``command`` / ``cmd`` keyword args, or the first positional
    string) and evaluates it against Aegis. If denied, an
    :class:`~aegis.exceptions.AegisBlocked` exception is raised *before* the
    function body runs.

    Args:
        func: The function to wrap (when used without parentheses).
        client: Optional :class:`~aegis.client.AegisClient` override.
        tool_name: Logical tool name sent to Aegis.  Defaults to the
            decorated function's ``__name__``.
    """

    def decorator(fn: F) -> F:
        name = tool_name or fn.__name__

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                command = _extract_command(args, kwargs)
                if command is not None:
                    c = client or _get_client()
                    verdict = c.evaluate_shell(command, tool_name=name)
                    if verdict.denied:
                        raise AegisBlocked(verdict)
                return await fn(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]
        else:

            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                command = _extract_command(args, kwargs)
                if command is not None:
                    c = client or _get_client()
                    verdict = c.evaluate_shell(command, tool_name=name)
                    if verdict.denied:
                        raise AegisBlocked(verdict)
                return fn(*args, **kwargs)

            return sync_wrapper  # type: ignore[return-value]

    if func is not None:
        # Called as @guarded_tool without parentheses.
        return decorator(func)
    # Called as @guarded_tool(...) with arguments.
    return decorator


# --------------------------------------------------------------------------- #
# guarded (general-purpose)
# --------------------------------------------------------------------------- #


@overload
def guarded(func: F) -> F: ...


@overload
def guarded(*, client: Optional[AegisClient] = None) -> Callable[[F], F]: ...


def guarded(
    func: Optional[F] = None,
    *,
    client: Optional[AegisClient] = None,
) -> Any:
    """General-purpose guard decorator.

    Evaluates the first string argument of the decorated function as a shell
    command against Aegis policies. Raises :class:`~aegis.exceptions.AegisBlocked`
    if the action is denied.

    Usage::

        @guarded
        def execute(command: str) -> str:
            ...

        @guarded(client=my_client)
        def execute(command: str) -> str:
            ...
    """

    def decorator(fn: F) -> F:
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                command = _extract_command(args, kwargs)
                if command is not None:
                    c = client or _get_client()
                    verdict = c.evaluate_shell(command, tool_name=fn.__name__)
                    if verdict.denied:
                        raise AegisBlocked(verdict)
                return await fn(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]
        else:

            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                command = _extract_command(args, kwargs)
                if command is not None:
                    c = client or _get_client()
                    verdict = c.evaluate_shell(command, tool_name=fn.__name__)
                    if verdict.denied:
                        raise AegisBlocked(verdict)
                return fn(*args, **kwargs)

            return sync_wrapper  # type: ignore[return-value]

    if func is not None:
        return decorator(func)
    return decorator
