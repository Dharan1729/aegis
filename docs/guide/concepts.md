# Concepts

## The question Aegis answers

> May **this person**, acting through **this agent**, perform **this action** on **this resource**, right now?

Every tool call an agent makes is one such question. Aegis answers `ALLOW` (with obligations) or `DENY` (with a message the model can read).

## Execution principal

A tool call has two actors: the person who asked for the work and the agent doing it. Aegis requires a token for each, on every call:

| Header | Token | Becomes, in Cedar |
|---|---|---|
| `X-Aegis-User-Token` | the end user's JWT, from your identity provider | `principal`: `Human::"<sub>"` with `role` and `department` from the token's claims |
| `Authorization: Bearer` | the agent's own JWT (a service identity) | `context.agent`: `Agent::"<sub>"` with `agent_name`; also `context.agent_id` |
| `X-Aegis-Tenant-Id` | which tenant's identity provider and policy to use | selects the policy set |

Both tokens are verified independently against the tenant's configuration ([tenants](tenants.md)). A policy can then constrain either actor or both: "analysts may query", "only the batch agent may export", "only analysts, and only through the reporting agent, may read salaries".

The agent's identity always comes from its verified token. Anything the caller puts in the request's `context` is passed to Cedar, but the server-derived fields (`agent_id`, `agent`, `session_id`, `workflow_id`) are written last and overwrite whatever the caller sent.

## Action and resource

- **Action** is the tool's name: `Action::"transfer_funds"`.
- **Resource** is what the call acts on: `Resource::"<urn>"` with a `type` attribute. The SDK's default is the tool itself (`urn:tool:transfer_funds`, type `tool`). To authorize on arguments (which account, which table), give the adapter a resource resolver that reads the tool's arguments ([adapters](adapters.md#authorizing-on-arguments)).

## Decision and obligations

Cedar returns allow or deny, plus the policies that determined it. The annotations on those policies become **obligations** the caller must honour:

| Annotation | Meaning | Who enforces it |
|---|---|---|
| `@mask_fields("ssn,salary")` | replace these keys in the tool's output with `[MASKED]` | the SDK, after the tool runs |
| `@approval_required("true")` | a human (or an approval system) must agree first | aegis-server, before answering |
| `@risk_tier("low")` | with `approval_required`, approve automatically | aegis-server |

When several policies allow a call, their obligations are merged strictly: every field any of them masks, approval if any of them requires it, and automatic approval only if all of them say `low`. See [policies](policies.md#annotations).

## Failing closed

The response is `ALLOW` only if every step succeeded: identity verified, policy found, Cedar allowed, approval granted (if needed), and the decision written to the audit log. Anything else is `DENY`, with a message and an audit entry where possible. The SDK adds the same rule on the client side: if it cannot reach aegis-server, or cannot work out who is calling, the tool does not run.

The one non-decision answer is HTTP 429, when a tenant is over its rate limit, so clients can back off.

## Tenants

A tenant is an isolated unit: its own identity provider configuration, its own Cedar policy (and optional schema), its own approval webhook, rate limit and audit chain. One aegis-server deployment serves many tenants. A request names its tenant in `X-Aegis-Tenant-Id`, and its tokens must have been issued by that tenant's configured issuers, so naming another tenant gains nothing.

## The audit chain

Every decision, `ALLOW` or `DENY`, is appended to the tenant's audit log. Each entry's hash covers its contents and the previous entry's hash, keyed with a secret held by aegis-server and not stored in the database. Editing, removing or reordering an entry breaks verification from that point on. See [audit](audit.md).
