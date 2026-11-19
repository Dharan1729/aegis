# aegis-sdk

Authorize AI agent tool calls through an [Aegis](../README.md) decision runtime, from inside the agent framework you already use.

```bash
pip install "aegis-sdk[langgraph]"   # or crewai, semantic-kernel, openai-agents, mcp
```

| Framework | Entry point |
|---|---|
| LangGraph | `aegis.adapters.langgraph.SecureToolNode` (drop-in for `ToolNode`) and `langgraph_checkpoint.GovernedCheckpointer` |
| CrewAI | `aegis.adapters.crewai.register_aegis_hooks` (global) or `SecureTool` (per tool) |
| Semantic Kernel | `aegis.adapters.semantic_kernel.make_aegis_function_filter` |
| OpenAI Agents SDK | `aegis.adapters.openai_agents.make_aegis_tool_guardrails` |
| MCP servers | `aegis.adapters.mcp.governed` (decorator on a tool handler) |
| Anything else | `aegis.Guard`: `check()` before the call, `finish()` after it |

Every adapter behaves the same way:

- **It fails closed.** A network error, a 5xx, or a failure to work out who is calling is a denial. Nothing raises into your agent loop.
- **A denial is a message, not a crash.** The model receives a tool result it can read, such as "Access Denied: 'transfer_funds' requires approval that was not granted", and can change course.
- **Masking is applied.** If the policy that allowed the call names `@mask_fields`, those keys are replaced with `[MASKED]` in the tool's output, at any depth. Output that cannot be masked reliably, such as free text, is withheld unless you choose `Guard(client, on_unmaskable="allow")`.

See [docs/guide/adapters.md](../docs/guide/adapters.md) for each framework.
