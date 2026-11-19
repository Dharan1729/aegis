"""What every framework adapter shares.

An adapter only knows how its framework intercepts a tool call. Everything
else is here, so the rules are identical in every framework:

1. `Guard.check` asks aegis-server whether the call may run. It never
   raises: a network error, a 5xx, a bad response or a failing context
   provider all come back as a denial, so no adapter can fail open.
2. A denial becomes a natural-language message the model can read and
   recover from, instead of an exception that ends the run.
3. After an allowed call runs, `Guard.finish` removes the fields the policy
   says must be masked. If the output cannot be masked reliably, it is
   withheld (or, if you choose `on_unmaskable="allow"`, passed through).
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from aegis.client import AegisClient, EvaluateResult
from aegis.masking import mask

logger = logging.getLogger("aegis")


@dataclass
class AegisContext:
    """Who is acting: the tenant, the end user's token, the agent's own
    token, and the session the call belongs to."""

    tenant_id: str
    human_token: str
    service_token: str
    session_id: str
    workflow_id: str


@dataclass
class ResourceDescriptor:
    """What the call acts on, as Cedar sees it: `Resource::"<urn>"` with a
    `type` attribute."""

    type: str
    urn: str


ResourceResolver = Callable[[str, dict[str, Any]], ResourceDescriptor]


def default_resource_resolver(tool_name: str, arguments: dict[str, Any]) -> ResourceDescriptor:
    """The tool itself is the resource. Override for finer control, e.g.
    map a SQL tool's `table` argument to `urn:db:<table>`."""
    return ResourceDescriptor(type="tool", urn=f"urn:tool:{tool_name}")


@dataclass
class Verdict:
    allowed: bool
    tool_name: str
    message: str | None = None  # what the model sees when the call is refused
    mask_fields: list[str] = field(default_factory=list)
    result: EvaluateResult | None = None  # None when the check itself failed


def _denied(tool_name: str, message: str, result: EvaluateResult | None = None) -> Verdict:
    return Verdict(allowed=False, tool_name=tool_name, message=message, result=result)


class Guard:
    """Authorizes tool calls through aegis-server. One per client is enough;
    it holds no per-call state."""

    def __init__(
        self,
        client: AegisClient,
        *,
        on_unmaskable: Literal["deny", "allow"] = "deny",
    ) -> None:
        self.client = client
        self.on_unmaskable = on_unmaskable

    def _request(
        self,
        context: AegisContext | Callable[[], AegisContext],
        tool_name: str,
        arguments: dict[str, Any] | None,
        resolver: ResourceResolver,
    ) -> dict[str, Any]:
        ctx = context() if callable(context) else context
        resource = resolver(tool_name, arguments or {})
        return {
            "tenant_id": ctx.tenant_id,
            "human_token": ctx.human_token,
            "service_token": ctx.service_token,
            "session_id": ctx.session_id,
            "workflow_id": ctx.workflow_id,
            "action": tool_name,
            "resource_type": resource.type,
            "resource_urn": resource.urn,
            "context": {"tool_name": tool_name},
        }

    def _verdict(self, tool_name: str, result: EvaluateResult) -> Verdict:
        if not result.allowed:
            return _denied(
                tool_name,
                result.graceful_rejection_message or f"Access Denied: '{tool_name}' is not permitted.",
                result,
            )
        fields = result.execution_policy.mask_fields if result.execution_policy else []
        return Verdict(allowed=True, tool_name=tool_name, mask_fields=list(fields), result=result)

    def _failed(self, tool_name: str, exc: Exception) -> Verdict:
        logger.warning("aegis check for %r failed; denying: %s", tool_name, exc)
        return _denied(
            tool_name,
            f"Access Denied: unable to verify authorization for '{tool_name}' ({type(exc).__name__}).",
        )

    def check(
        self,
        context: AegisContext | Callable[[], AegisContext],
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        resource_resolver: ResourceResolver = default_resource_resolver,
    ) -> Verdict:
        """Never raises. `context` may be a callable, so that an error while
        working out who is calling is also a denial."""
        try:
            return self._verdict(
                tool_name,
                self.client.evaluate(**self._request(context, tool_name, arguments, resource_resolver)),
            )
        except Exception as exc:  # noqa: BLE001 - fail closed on anything
            return self._failed(tool_name, exc)

    async def acheck(
        self,
        context: AegisContext | Callable[[], AegisContext],
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        resource_resolver: ResourceResolver = default_resource_resolver,
    ) -> Verdict:
        try:
            request = self._request(context, tool_name, arguments, resource_resolver)
            return self._verdict(tool_name, await self.client.aevaluate(**request))
        except Exception as exc:  # noqa: BLE001 - fail closed on anything
            return self._failed(tool_name, exc)

    def finish(self, verdict: Verdict, output: Any) -> Any:
        """Applies the verdict's masking obligation to an allowed call's output."""
        if not verdict.mask_fields:
            return output
        masked = mask(output, verdict.mask_fields)
        if masked.ok:
            return masked.value
        if self.on_unmaskable == "allow":
            logger.warning(
                "output of %r is not structured; passing it through unmasked (on_unmaskable='allow')",
                verdict.tool_name,
            )
            return output
        return (
            f"Access Denied: the result of '{verdict.tool_name}' must have "
            f"{', '.join(verdict.mask_fields)} masked, and it is not in a form that can be masked "
            "(return a dict or JSON to allow masking)."
        )
