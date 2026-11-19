"""Semantic Kernel adapter: a function-invocation filter.

Semantic Kernel sends every function and plugin call, whether invoked
directly or chosen by the model, through its `FUNCTION_INVOCATION` filter
chain. The filter authorizes the call; on a denial it sets the result to
the denial message and does not call `next()`, so the function never runs.
On an allowed call it masks the result as the policy requires.

    kernel.add_filter(FilterTypes.FUNCTION_INVOCATION, make_aegis_function_filter(client))
    await kernel.invoke(fn, KernelArguments(aegis_context=AegisContext(...), ...))
"""

from collections.abc import Awaitable, Callable
from typing import Any

from semantic_kernel.filters import FunctionInvocationContext
from semantic_kernel.functions.function_result import FunctionResult

from aegis.client import AegisClient
from aegis.core import AegisContext, Guard, ResourceDescriptor, default_resource_resolver

__all__ = [
    "AegisContext",
    "ResourceDescriptor",
    "context_from_arguments",
    "default_resource_resolver",
    "make_aegis_function_filter",
]


def context_from_arguments(context: FunctionInvocationContext) -> AegisContext:
    aegis_ctx = context.arguments.get("aegis_context") if context.arguments else None
    if aegis_ctx is None:
        raise ValueError("Aegis function filter requires KernelArguments(aegis_context=AegisContext(...))")
    return aegis_ctx


def _arguments(context: FunctionInvocationContext) -> dict[str, Any]:
    if not context.arguments:
        return {}
    return {k: v for k, v in context.arguments.items() if k != "aegis_context"}


def make_aegis_function_filter(
    aegis_client: AegisClient | None = None,
    context_provider: Callable[[FunctionInvocationContext], AegisContext] = context_from_arguments,
    resource_resolver: Callable[[str, Any], ResourceDescriptor] = default_resource_resolver,
    *,
    guard: Guard | None = None,
) -> Callable[
    [FunctionInvocationContext, Callable[[FunctionInvocationContext], Awaitable[None]]], Awaitable[None]
]:
    if guard is None and aegis_client is None:
        raise ValueError("make_aegis_function_filter needs aegis_client or guard")
    guard = guard or Guard(aegis_client)

    async def aegis_filter(
        context: FunctionInvocationContext,
        next: Callable[[FunctionInvocationContext], Awaitable[None]],
    ) -> None:
        name = context.function.name
        verdict = await guard.acheck(
            lambda: context_provider(context), name, _arguments(context), resource_resolver
        )
        if not verdict.allowed:
            context.result = FunctionResult(function=context.function.metadata, value=verdict.message)
            return  # next() is never called, so the function never runs

        await next(context)
        if verdict.mask_fields and context.result is not None:
            context.result = FunctionResult(
                function=context.function.metadata,
                value=guard.finish(verdict, context.result.value),
            )

    return aegis_filter
