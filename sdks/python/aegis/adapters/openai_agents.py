"""OpenAI Agents SDK integration for Aegis.

Requires the ``openai-agents`` extra::

    pip install aegis-sdk[openai-agents]
"""

from __future__ import annotations

from typing import Any, Optional

from aegis.client import AegisClient
from aegis.exceptions import AegisBlocked

try:
    from agents import (  # type: ignore[import-untyped]
        Agent,
        InputGuardrail,
        GuardrailFunctionOutput,
        RunContextWrapper,
    )

    _HAS_OPENAI_AGENTS = True
except ImportError:
    _HAS_OPENAI_AGENTS = False


def _require_openai_agents() -> None:
    if not _HAS_OPENAI_AGENTS:
        raise ImportError(
            "openai-agents is required for this adapter.  "
            "Install it with:  pip install aegis-sdk[openai-agents]"
        )


def aegis_input_guardrail(
    client: Optional[AegisClient] = None,
) -> Any:
    """Create an input guardrail for the OpenAI Agents SDK.

    The guardrail evaluates incoming user messages as shell commands against
    Aegis policies. If the message is denied, the guardrail signals a tripwire.

    Usage::

        from aegis.adapters.openai_agents import aegis_input_guardrail

        agent = Agent(
            name="pentester",
            input_guardrails=[aegis_input_guardrail()],
        )

    Args:
        client: Optional :class:`~aegis.client.AegisClient` override.

    Returns:
        An ``InputGuardrail`` instance compatible with the OpenAI Agents SDK.
    """
    _require_openai_agents()

    aegis = client or AegisClient()

    async def _guardrail_fn(
        ctx: "RunContextWrapper[Any]",
        agent: "Agent[Any]",
        input: str,
    ) -> "GuardrailFunctionOutput":
        verdict = aegis.evaluate_shell(input, tool_name=agent.name)
        if verdict.denied:
            return GuardrailFunctionOutput(
                output_info={"reason": verdict.reason, "source": verdict.source},
                tripwire_triggered=True,
            )
        return GuardrailFunctionOutput(
            output_info={"decision": "allow"},
            tripwire_triggered=False,
        )

    return InputGuardrail(guardrail_function=_guardrail_fn, name="aegis")
