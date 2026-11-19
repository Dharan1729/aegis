"""CrewAI adapter. Two ways in:

1. `register_aegis_hooks` (preferred): one global registration through
   CrewAI's `crewai.hooks.before_tool_call` / `after_tool_call`. Covers
   every tool call in the process.
2. `SecureTool`: wraps one `BaseTool`. For CrewAI versions without hooks,
   or to govern only some tools.

Both return a denial as text instead of raising, so the crew keeps going.

A note on failing closed. CrewAI's hook dispatcher catches any exception a
`before_tool_call` hook raises (other than `HookAborted`), logs it, and runs
the tool anyway. An exception in an authorization hook would therefore fail
open. The guard used here never raises: errors become denials.

Returning False from `before_tool_call` blocks the call, and CrewAI then
shows a generic "blocked by hook" message unless an `after_tool_call` hook
returns a replacement. The before-hook stashes Aegis's message (or the
masking obligation) in `tool_input`, which is the same dict object in both
hooks, and the after-hook returns or applies it.

    register_aegis_hooks(client, context_provider=lambda hook_ctx: my_context)
"""

from collections.abc import Callable
from typing import Any

from crewai.hooks import after_tool_call, before_tool_call
from crewai.tools import BaseTool

from aegis.client import AegisClient
from aegis.core import AegisContext, Guard, ResourceDescriptor, ResourceResolver, default_resource_resolver

__all__ = [
    "AegisContext",
    "ResourceDescriptor",
    "SecureTool",
    "default_resource_resolver",
    "register_aegis_hooks",
]

_DENIAL_KEY = "__aegis_denial_message__"
_VERDICT_KEY = "__aegis_verdict__"


class SecureTool(BaseTool):
    """Wraps `wrapped_tool` so every call is authorized through Aegis first."""

    model_config = {"arbitrary_types_allowed": True}  # noqa: RUF012 - pydantic config, not a mutable default

    wrapped_tool: BaseTool
    guard: Any
    aegis_context: AegisContext
    resource_resolver: ResourceResolver = default_resource_resolver

    def __init__(
        self,
        wrapped_tool: BaseTool,
        aegis_client: AegisClient | None = None,
        aegis_context: AegisContext | None = None,
        resource_resolver: ResourceResolver = default_resource_resolver,
        *,
        guard: Guard | None = None,
        **kwargs: Any,
    ) -> None:
        if guard is None and aegis_client is None:
            raise ValueError("SecureTool needs aegis_client or guard")
        if aegis_context is None:
            raise ValueError("SecureTool needs aegis_context")
        super().__init__(
            name=wrapped_tool.name,
            description=wrapped_tool.description,
            args_schema=wrapped_tool.args_schema,
            wrapped_tool=wrapped_tool,
            guard=guard or Guard(aegis_client),
            aegis_context=aegis_context,
            resource_resolver=resource_resolver,
            **kwargs,
        )

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        verdict = self.guard.check(self.aegis_context, self.wrapped_tool.name, kwargs, self.resource_resolver)
        if not verdict.allowed:
            return verdict.message
        return self.guard.finish(verdict, self.wrapped_tool._run(*args, **kwargs))

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        verdict = await self.guard.acheck(
            self.aegis_context, self.wrapped_tool.name, kwargs, self.resource_resolver
        )
        if not verdict.allowed:
            return verdict.message
        return self.guard.finish(verdict, await self.wrapped_tool._arun(*args, **kwargs))


def _no_context_provider(context: Any) -> AegisContext:
    raise ValueError(
        "register_aegis_hooks needs a context_provider: CrewAI's global hooks carry no per-call "
        "identity, so derive it from the hook context (context.crew, context.agent) or a closure"
    )


def register_aegis_hooks(
    aegis_client: AegisClient | None = None,
    context_provider: Callable[[Any], AegisContext] = _no_context_provider,
    resource_resolver: ResourceResolver = default_resource_resolver,
    *,
    guard: Guard | None = None,
) -> None:
    """Registers global hooks that authorize every CrewAI tool call in the
    process. A missing context_provider denies every call."""
    if guard is None and aegis_client is None:
        raise ValueError("register_aegis_hooks needs aegis_client or guard")
    guard = guard or Guard(aegis_client)

    @before_tool_call
    def _aegis_before(context: Any) -> bool | None:
        tool_input = context.tool_input
        arguments = {k: v for k, v in tool_input.items() if not k.startswith("__aegis")}
        verdict = guard.check(
            lambda: context_provider(context), context.tool_name, arguments, resource_resolver
        )
        if not verdict.allowed:
            tool_input[_DENIAL_KEY] = verdict.message
            return False
        if verdict.mask_fields:
            tool_input[_VERDICT_KEY] = verdict
        return None

    @after_tool_call
    def _aegis_after(context: Any) -> str | None:
        denial = context.tool_input.pop(_DENIAL_KEY, None)
        if denial is not None:
            return denial
        verdict = context.tool_input.pop(_VERDICT_KEY, None)
        if verdict is None:
            return None
        raw = getattr(context, "raw_tool_result", None)
        finished = guard.finish(verdict, raw if raw is not None else context.tool_result)
        return finished if isinstance(finished, str) else str(finished)
