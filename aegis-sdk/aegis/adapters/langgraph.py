"""LangGraph adapter: `SecureToolNode`, a drop-in replacement for `ToolNode`.

Uses `ToolNode`'s `wrap_tool_call` / `awrap_tool_call` hooks. Each call is
authorized before it runs; a denial comes back to the model as a
`ToolMessage` it can read; an allowed call's output is masked as the policy
requires.

Identity cannot be inferred from graph state, so the caller supplies it.
By default it is read from `config["configurable"]["aegis"]`:

    app.invoke(inputs, config={"configurable": {"aegis": {
        "tenant_id": ..., "human_token": ..., "service_token": ...,
        "session_id": ..., "workflow_id": ...,
    }}})
"""

from collections.abc import Callable, Sequence
from typing import Any

from langchain_core.messages import ToolMessage
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.tool_node import ToolCallRequest

from aegis.client import AegisClient
from aegis.core import AegisContext, Guard, ResourceDescriptor, Verdict

__all__ = [
    "AegisContext",
    "ResourceDescriptor",
    "SecureToolNode",
    "context_from_config",
    "default_resource_resolver",
]


def context_from_config(request: ToolCallRequest) -> AegisContext:
    configurable = (request.runtime.config or {}).get("configurable", {})
    aegis_cfg = configurable.get("aegis")
    if not aegis_cfg:
        raise ValueError(
            "SecureToolNode requires config['configurable']['aegis'] "
            "(tenant_id, human_token, service_token, session_id, workflow_id)"
        )
    return aegis_cfg if isinstance(aegis_cfg, AegisContext) else AegisContext(**aegis_cfg)


def default_resource_resolver(request: ToolCallRequest) -> ResourceDescriptor:
    """The tool itself is the resource. Override to authorize on arguments,
    e.g. map a SQL tool's `table` argument to `urn:db:<table>`."""
    return ResourceDescriptor(type="tool", urn=f"urn:tool:{request.tool_call['name']}")


class SecureToolNode(ToolNode):
    """`ToolNode` that authorizes every call through Aegis."""

    def __init__(
        self,
        tools: Sequence[Any],
        *,
        aegis_client: AegisClient | None = None,
        guard: Guard | None = None,
        context_resolver: Callable[[ToolCallRequest], AegisContext] = context_from_config,
        resource_resolver: Callable[[ToolCallRequest], ResourceDescriptor] = default_resource_resolver,
        **kwargs: Any,
    ) -> None:
        if guard is None and aegis_client is None:
            raise ValueError("SecureToolNode needs aegis_client or guard")
        self._guard = guard or Guard(aegis_client)
        self._context_resolver = context_resolver
        self._resource_resolver = resource_resolver
        super().__init__(tools, wrap_tool_call=self._sync_wrap, awrap_tool_call=self._async_wrap, **kwargs)

    def _check_args(self, request: ToolCallRequest) -> dict[str, Any]:
        return {
            "context": lambda: self._context_resolver(request),
            "tool_name": request.tool_call["name"],
            "arguments": request.tool_call.get("args") or {},
            "resource_resolver": lambda _name, _args: self._resource_resolver(request),
        }

    def _message(self, request: ToolCallRequest, content: Any) -> ToolMessage:
        return ToolMessage(
            content=content, name=request.tool_call["name"], tool_call_id=request.tool_call["id"]
        )

    def _finish(self, request: ToolCallRequest, verdict: Verdict, result: Any) -> Any:
        if not verdict.mask_fields:
            return result
        if isinstance(result, ToolMessage):
            return result.model_copy(update={"content": self._guard.finish(verdict, result.content)})
        # A Command or other non-message result: nothing we can mask in place.
        return self._message(request, self._guard.finish(verdict, object()))

    def _sync_wrap(self, request: ToolCallRequest, execute):
        verdict = self._guard.check(**self._check_args(request))
        if not verdict.allowed:
            return self._message(request, verdict.message)
        return self._finish(request, verdict, execute(request))

    async def _async_wrap(self, request: ToolCallRequest, execute):
        verdict = await self._guard.acheck(**self._check_args(request))
        if not verdict.allowed:
            return self._message(request, verdict.message)
        return self._finish(request, verdict, await execute(request))
