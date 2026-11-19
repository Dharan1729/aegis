"""MCP (Model Context Protocol) adapter: the `governed` decorator.

MCP's authorization spec stops at authentication (OAuth 2.1, scopes). A
scope such as `files:write` cannot say "only these paths, only for this
user, only with approval". `governed` adds that per-call decision behind
any MCP server, using the identity the server has already authenticated.

It wraps the tool handler itself, not a server class, so it works with any
server implementation (the official SDK's `FastMCP`, the low-level server,
or your own):

    @mcp.tool()
    @governed(aegis_client, context_provider=my_context_provider)
    async def send_email(to: str, body: str) -> str:
        ...

`context_provider` gets the tool's arguments and returns an
`AegisContext`. There is no default: how an MCP host exposes the caller's
identity depends on how it set up authorization, so you bridge it.
"""

import functools
import inspect
from collections.abc import Callable
from typing import Any

from aegis.client import AegisClient
from aegis.core import AegisContext, Guard, ResourceDescriptor, ResourceResolver, default_resource_resolver

__all__ = ["AegisContext", "ResourceDescriptor", "default_resource_resolver", "governed"]


def governed(
    aegis_client: AegisClient | None = None,
    context_provider: Callable[..., AegisContext] | None = None,
    resource_resolver: ResourceResolver = default_resource_resolver,
    *,
    guard: Guard | None = None,
) -> Callable[[Callable], Callable]:
    """Authorizes each call to the decorated handler (sync or async). A
    denial is returned as the tool's text result, so the model sees a normal
    tool response rather than a protocol error."""
    if context_provider is None:
        raise ValueError("governed() needs a context_provider")
    if guard is None and aegis_client is None:
        raise ValueError("governed() needs aegis_client or guard")
    guard = guard or Guard(aegis_client)

    def decorator(fn: Callable) -> Callable:
        tool_name = fn.__name__

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                verdict = await guard.acheck(
                    lambda: context_provider(*args, **kwargs), tool_name, kwargs, resource_resolver
                )
                if not verdict.allowed:
                    return verdict.message
                return guard.finish(verdict, await fn(*args, **kwargs))

            return async_wrapper

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            verdict = guard.check(
                lambda: context_provider(*args, **kwargs), tool_name, kwargs, resource_resolver
            )
            if not verdict.allowed:
                return verdict.message
            return guard.finish(verdict, fn(*args, **kwargs))

        return sync_wrapper

    return decorator
