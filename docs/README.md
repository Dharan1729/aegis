# Documentation

**Using Aegis**

- [Quickstart](guide/quickstart.md): the demo stack, step by step
- [Concepts](guide/concepts.md): execution principal, decisions, obligations, failing closed, tenants
- [Writing policies](guide/policies.md): Cedar for agents, annotations, schemas
- [Tenants and identity](guide/tenants.md): issuers, audiences, single-use or reusable tokens, admin access
- [Framework adapters](guide/adapters.md): LangGraph, CrewAI, Semantic Kernel, OpenAI Agents SDK, MCP, anything else
- [Approvals](guide/approvals.md): the signed webhook protocol
- [Audit log](guide/audit.md): the hash chain, verifying it, and its limits
- [API reference](guide/api.md)

**Running Aegis**

- [Deployment](guide/deployment.md): configuration, production checklist, migrations, scaling
- [Operations](guide/operations.md): service levels, playbooks, backup and restore

**How it was built and measured**

- [Architecture](architecture.md): components, the request path, and the decisions behind them
- [Benchmarks](benchmarks.md): attacks, fault injection, a masking bug, latency
