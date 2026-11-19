"""OpenAI Agents SDK adapter: tool guardrails.

The SDK has first-class hooks for this. A `ToolInputGuardrail` runs before
a tool and can replace its result with a message (`reject_content`); a
`ToolOutputGuardrail` runs after it and can do the same with its output.

`make_aegis_tool_guardrails` returns both: the input guardrail authorizes
the call, and the output guardrail applies the masking obligation of that
same decision (matched by tool call id).

    input_gr, output_gr = make_aegis_tool_guardrails(client)

    @function_tool(tool_input_guardrails=[input_gr], tool_output_guardrails=[output_gr])
    def lookup_employee(employee_id: str) -> dict: ...

    await Runner.run(agent, prompt, context=AegisContext(...))

`make_aegis_tool_input_guardrail` (authorize only, no masking) is kept for
existing code.
"""

import json
from collections.abc import Callable
from typing import Any

from agents import (
    ToolGuardrailFunctionOutput,
    ToolInputGuardrail,
    ToolInputGuardrailData,
    ToolOutputGuardrail,
    ToolOutputGuardrailData,
)

from aegis.client import AegisClient
from aegis.core import (
    AegisContext,
    Guard,
    ResourceDescriptor,
    ResourceResolver,
    Verdict,
    default_resource_resolver,
)

__all__ = [
    "AegisContext",
    "ResourceDescriptor",
    "context_from_run_context",
    "default_resource_resolver",
    "make_aegis_tool_guardrails",
    "make_aegis_tool_input_guardrail",
]


def context_from_run_context(data: ToolInputGuardrailData | ToolOutputGuardrailData) -> AegisContext:
    run_context = data.context.context
    if isinstance(run_context, AegisContext):
        return run_context
    if isinstance(run_context, dict) and "tenant_id" in run_context:
        return AegisContext(**run_context)
    raise ValueError(
        "Aegis tool guardrails require Runner.run(..., context=AegisContext(...)) (or a dict with the same fields)"
    )


def _arguments(data: ToolInputGuardrailData) -> dict[str, Any]:
    try:
        parsed = json.loads(data.context.tool_arguments or "{}")
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


class _Guardrails:
    def __init__(self, guard: Guard, context_provider, resource_resolver: ResourceResolver) -> None:
        self.guard = guard
        self.context_provider = context_provider
        self.resource_resolver = resource_resolver
        # Decisions awaiting their tool's output, by tool call id.
        self.pending: dict[str, Verdict] = {}

    async def before(self, data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
        verdict = await self.guard.acheck(
            lambda: self.context_provider(data),
            data.context.tool_name,
            _arguments(data),
            self.resource_resolver,
        )
        if not verdict.allowed:
            return ToolGuardrailFunctionOutput.reject_content(message=verdict.message)
        if verdict.mask_fields:
            self.pending[data.context.tool_call_id] = verdict
        return ToolGuardrailFunctionOutput.allow()

    async def after(self, data: ToolOutputGuardrailData) -> ToolGuardrailFunctionOutput:
        verdict = self.pending.pop(data.context.tool_call_id, None)
        if verdict is None:
            return ToolGuardrailFunctionOutput.allow()
        finished = self.guard.finish(verdict, data.output)
        message = finished if isinstance(finished, str) else json.dumps(finished, default=str)
        return ToolGuardrailFunctionOutput.reject_content(message=message)


def make_aegis_tool_guardrails(
    aegis_client: AegisClient | None = None,
    context_provider: Callable[[Any], AegisContext] = context_from_run_context,
    resource_resolver: ResourceResolver = default_resource_resolver,
    *,
    guard: Guard | None = None,
) -> tuple[ToolInputGuardrail, ToolOutputGuardrail]:
    """Returns (input guardrail, output guardrail) sharing one decision per call."""
    if guard is None and aegis_client is None:
        raise ValueError("make_aegis_tool_guardrails needs aegis_client or guard")
    pair = _Guardrails(guard or Guard(aegis_client), context_provider, resource_resolver)
    return (
        ToolInputGuardrail(guardrail_function=pair.before, name="aegis_authorize"),
        ToolOutputGuardrail(guardrail_function=pair.after, name="aegis_mask"),
    )


def make_aegis_tool_input_guardrail(
    aegis_client: AegisClient | None = None,
    context_provider: Callable[[ToolInputGuardrailData], AegisContext] = context_from_run_context,
    resource_resolver: ResourceResolver = default_resource_resolver,
    *,
    guard: Guard | None = None,
) -> Callable[[ToolInputGuardrailData], Any]:
    """Authorize-only guardrail function (no masking). Prefer
    `make_aegis_tool_guardrails`."""
    if guard is None and aegis_client is None:
        raise ValueError("make_aegis_tool_input_guardrail needs aegis_client or guard")
    return _Guardrails(guard or Guard(aegis_client), context_provider, resource_resolver).before
