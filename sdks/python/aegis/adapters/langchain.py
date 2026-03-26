"""LangChain integration for Aegis.

Requires the ``langchain`` extra::

    pip install aegis-sdk[langchain]
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from aegis.client import AegisClient
from aegis.exceptions import AegisBlocked

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.tools import BaseTool

    _HAS_LANGCHAIN = True
except ImportError:
    _HAS_LANGCHAIN = False


def _require_langchain() -> None:
    if not _HAS_LANGCHAIN:
        raise ImportError(
            "langchain-core is required for this adapter.  "
            "Install it with:  pip install aegis-sdk[langchain]"
        )


# --------------------------------------------------------------------------- #
# Callback handler
# --------------------------------------------------------------------------- #


class AegisCallbackHandler:
    """LangChain callback handler that monitors tool calls through Aegis.

    Intercepts ``on_tool_start`` events and evaluates them against Aegis
    policies.  If a tool call is denied, an :class:`~aegis.exceptions.AegisBlocked`
    exception is raised, preventing the tool from executing.

    Usage::

        from aegis.adapters.langchain import AegisCallbackHandler

        handler = AegisCallbackHandler()
        agent = create_agent(callbacks=[handler])
    """

    def __init__(self, client: Optional[AegisClient] = None) -> None:
        _require_langchain()
        self._client = client or AegisClient()
        # Dynamically inherit from BaseCallbackHandler so that LangChain
        # recognises this object as a valid callback.
        if _HAS_LANGCHAIN:
            self.__class__ = type(
                "AegisCallbackHandler",
                (BaseCallbackHandler,),  # type: ignore[misc]
                {
                    "on_tool_start": self._on_tool_start,
                    # Keep other lifecycle methods as no-ops inherited from
                    # BaseCallbackHandler.
                },
            )

    def _on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Evaluate the tool input against Aegis before execution."""
        tool_name = serialized.get("name", "unknown")
        verdict = self._client.evaluate_shell(input_str, tool_name=tool_name)
        if verdict.denied:
            raise AegisBlocked(verdict)


# --------------------------------------------------------------------------- #
# Tool wrapper
# --------------------------------------------------------------------------- #


def guarded_tool(
    tool: Any,
    client: Optional[AegisClient] = None,
) -> Any:
    """Wrap a LangChain tool with Aegis guardrails.

    Returns a new tool whose ``_run`` (and ``_arun``) methods first evaluate
    the input through Aegis.  If denied, :class:`~aegis.exceptions.AegisBlocked`
    is raised.

    Usage::

        from langchain_community.tools import ShellTool
        from aegis.adapters.langchain import guarded_tool

        safe_shell = guarded_tool(ShellTool())

    Args:
        tool: A LangChain :class:`BaseTool` instance to wrap.
        client: Optional :class:`~aegis.client.AegisClient` override.

    Returns:
        A new tool instance with Aegis guardrails applied.
    """
    _require_langchain()

    aegis = client or AegisClient()
    original_run = tool._run
    original_arun = getattr(tool, "_arun", None)
    tool_name = getattr(tool, "name", tool.__class__.__name__)

    def guarded_run(
        input_text: str, **kwargs: Any
    ) -> Any:
        verdict = aegis.evaluate_shell(input_text, tool_name=tool_name)
        if verdict.denied:
            raise AegisBlocked(verdict)
        return original_run(input_text, **kwargs)

    tool._run = guarded_run  # type: ignore[assignment]

    if original_arun is not None:

        async def guarded_arun(
            input_text: str, **kwargs: Any
        ) -> Any:
            verdict = aegis.evaluate_shell(input_text, tool_name=tool_name)
            if verdict.denied:
                raise AegisBlocked(verdict)
            return await original_arun(input_text, **kwargs)

        tool._arun = guarded_arun  # type: ignore[assignment]

    return tool
