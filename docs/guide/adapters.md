# Framework adapters

```bash
pip install -e "aegis-sdk[langgraph]"    # or crewai, semantic-kernel, openai-agents, mcp
```

Every adapter is a thin layer over `aegis.Guard` ([`aegis/core.py`](../../aegis-sdk/aegis/core.py)), so they all behave the same:

| | |
|---|---|
| **Before the tool runs** | `Guard.check` asks aegis-server. It never raises: a network error, a 5xx, a malformed response, or an exception from your context provider all come back as a denial. |
| **On a denial** | the tool does not run; the model gets the denial text as the tool's result. |
| **After an allowed tool runs** | `Guard.finish` applies `mask_fields`: matching keys become `[MASKED]` at any depth, case-insensitively, in dicts, lists, pydantic models and JSON strings. |
| **Output that cannot be masked** | free text, a bare value, an arbitrary object. Withheld and replaced by a denial message, unless you build the guard with `Guard(client, on_unmaskable="allow")`. |

Every adapter accepts either `aegis_client=AegisClient(url)` or `guard=Guard(...)` (to share one guard or change `on_unmaskable`).

Identity is per call and comes from your application, never from the model: each adapter asks you how to find the `AegisContext` (tenant, the user's token, the agent's token, session, workflow) for the call in hand.

## LangGraph

`SecureToolNode` replaces `ToolNode` and uses its `wrap_tool_call` / `awrap_tool_call` hooks.

```python
from aegis import AegisClient
from aegis.adapters.langgraph import SecureToolNode

tools = SecureToolNode([lookup_employee, transfer_funds], aegis_client=AegisClient(AEGIS_URL))
graph.add_node("tools", tools)

graph.compile().invoke(inputs, config={"configurable": {"aegis": {
    "tenant_id": "acme", "human_token": user_jwt, "service_token": agent_jwt,
    "session_id": session_id, "workflow_id": "hr-assistant",
}}})
```

`context_resolver=` takes the `ToolCallRequest` if identity lives elsewhere. A denial or a masked result is returned as a `ToolMessage`.

**Resuming paused runs.** A graph checkpointed on Monday and resumed on Friday should not run under Monday's policy. `GovernedCheckpointer` wraps any checkpointer: it stamps the tenant's policy version on every save and raises `StaleAuthorizationError` on load if the policy has changed since.

```python
from aegis.adapters.langgraph_checkpoint import GovernedCheckpointer
checkpointer = GovernedCheckpointer(InMemorySaver(), AegisClient(AEGIS_URL), tenant_id="acme")
```

## CrewAI

One global registration covers every tool call in the process:

```python
from aegis.adapters.crewai import register_aegis_hooks

register_aegis_hooks(AegisClient(AEGIS_URL), context_provider=lambda hook_ctx: context_for(hook_ctx.crew))
```

Or wrap individual tools: `SecureTool(wrapped_tool=my_tool, aegis_client=client, aegis_context=ctx)`.

CrewAI's hook dispatcher catches an exception raised by a `before_tool_call` hook and runs the tool anyway. The Aegis hook never raises, so this cannot fail open; a missing `context_provider` denies every call. The after-hook replaces the generic "blocked by hook" message with Aegis's, and masks the raw tool result.

## Semantic Kernel

A function-invocation filter: every function call, chosen by the model or invoked directly, goes through it.

```python
from semantic_kernel.filters import FilterTypes
from aegis.adapters.semantic_kernel import make_aegis_function_filter

kernel.add_filter(FilterTypes.FUNCTION_INVOCATION, make_aegis_function_filter(AegisClient(AEGIS_URL)))
await kernel.invoke(fn, KernelArguments(aegis_context=AegisContext(...), **args))
```

On a denial, `next()` is never called, so the function never runs.

## OpenAI Agents SDK

Tool guardrails are the SDK's own hook for this. The input guardrail authorizes; the output guardrail masks the same call's result (matched by tool call ID).

```python
from agents import Runner, function_tool
from aegis.adapters.openai_agents import make_aegis_tool_guardrails

authorize, mask = make_aegis_tool_guardrails(AegisClient(AEGIS_URL))

@function_tool(tool_input_guardrails=[authorize], tool_output_guardrails=[mask])
def lookup_employee(employee_id: str) -> dict: ...

await Runner.run(agent, prompt, context=AegisContext(...))
```

`make_aegis_tool_input_guardrail` (authorize only, no masking) remains for code written against 0.1.

## MCP servers

MCP's authorization spec covers authentication (OAuth 2.1 and scopes). A scope cannot say "only this user, only these records, only with approval". `@governed` adds that decision to each tool, using whatever identity your server authenticated:

```python
from mcp.server.mcpserver import MCPServer   # mcp 2.x; on 1.x: from mcp.server.fastmcp import FastMCP
from aegis.adapters.mcp import governed

mcp = MCPServer("hr")

@mcp.tool()
@governed(AegisClient(AEGIS_URL), context_provider=lambda **args: context_from_current_request())
async def lookup_employee(employee_id: str) -> dict: ...
```

It wraps the handler function, not a server class, so it works with any MCP server implementation, and with both MCP 1.x (`FastMCP`) and 2.x (`MCPServer`); the tests run against whichever CI installs. There is no default `context_provider`: how a host exposes the authenticated caller depends on how its authorization is wired.

## Anything else

```python
from aegis import AegisClient, Guard

guard = Guard(AegisClient(AEGIS_URL))
verdict = guard.check(context, "lookup_employee", arguments)   # never raises
if not verdict.allowed:
    return verdict.message
return guard.finish(verdict, lookup_employee(**arguments))
```

`acheck` is the async form.

## Authorizing on arguments

By default the resource is the tool: `Resource::"urn:tool:<name>"`, type `tool`. To let policies see what a call touches, pass a resource resolver:

```python
from aegis import ResourceDescriptor

def resolve(tool_name: str, args: dict) -> ResourceDescriptor:
    if tool_name == "run_sql":
        return ResourceDescriptor(type="table", urn=f"urn:db:{args['table']}")
    return ResourceDescriptor(type="tool", urn=f"urn:tool:{tool_name}")

SecureToolNode(tools, aegis_client=client, resource_resolver=lambda req: resolve(req.tool_call["name"], req.tool_call["args"]))
governed(client, context_provider=..., resource_resolver=resolve)
```

(LangGraph's resolver takes the `ToolCallRequest`; the others take the tool name and its arguments.)

## Tested versions

0.2.0 was tested with LangGraph 1.2, CrewAI 1.15, Semantic Kernel 1.47, OpenAI Agents SDK 0.20 and MCP 1.30; these are the minimums in [`aegis-sdk/pyproject.toml`](../../aegis-sdk/pyproject.toml). CI installs the newest release of each, so a framework change that breaks an adapter shows up as a failing CI job. Agent frameworks change their hooks often; older releases are not tested.
