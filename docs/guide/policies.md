# Writing policies

Aegis policies are [Cedar](https://docs.cedarpolicy.com). Each tenant has one policy set (any number of `permit` and `forbid` statements) and, optionally, a schema.

## The shape of a request

| Cedar | Value | Attributes |
|---|---|---|
| `principal` | `Human::"<sub of the user token>"` | `role`, `department` (from the token's claims; empty string if absent) |
| `action` | `Action::"<tool name>"` | |
| `resource` | `Resource::"<urn>"` | `type` |
| `context.agent` | `Agent::"<sub of the agent token>"` | `agent_name` |
| `context.agent_id` | the agent token's `sub` | |
| `context.session_id`, `context.workflow_id` | from the request | |
| `context.tool_name` | the tool's name, as sent by the adapter | |
| other `context.*` | whatever the caller sends | not trustworthy for identity: see below |

## Rules Cedar gives you

- **Default deny.** If no `permit` matches, the answer is deny.
- **`forbid` wins.** If any `forbid` matches, the answer is deny, whatever permits match.
- **No side effects.** A policy only reads the request.

## Examples

Analysts may query; results must have two fields masked:

```cedar
@mask_fields("ssn,compensation")
permit(principal, action == Action::"execute_query", resource)
when { principal.role == "Analyst" };
```

Only a specific agent may export, whoever asked it to:

```cedar
permit(principal, action == Action::"export_all", resource)
when { context.agent.agent_name == "nightly_export" };
```

The person *and* the agent must qualify:

```cedar
permit(principal, action == Action::"read_salary", resource)
when { principal.department == "Finance" && context.agent.agent_name == "payroll_assistant" };
```

Never, for anyone:

```cedar
forbid(principal, action == Action::"delete_audit_log", resource);
```

Authorize on what the call touches (needs a [resource resolver](adapters.md#authorizing-on-arguments) that maps the tool's arguments to a resource):

```cedar
permit(principal, action == Action::"run_sql", resource)
when { resource.type == "table" && principal.role == "Analyst" };

forbid(principal, action == Action::"run_sql", resource == Resource::"urn:db:payroll")
unless { principal.department == "Finance" };
```

Approval for anything over a threshold the agent reports (the amount comes from `context`, so make sure your adapter sets it from the tool's arguments, not from the model's free text):

```cedar
@approval_required("true")
@risk_tier("high")
permit(principal, action == Action::"transfer_funds", resource)
when { principal.role == "Manager" && context.amount > 10000 };

@approval_required("true")
@risk_tier("low")
permit(principal, action == Action::"transfer_funds", resource)
when { principal.role == "Manager" && context.amount <= 10000 };
```

## Annotations

| Annotation | Values | Effect on an ALLOW |
|---|---|---|
| `@mask_fields("a,b")` | comma-separated key names | the SDK replaces those keys with `[MASKED]` at any depth in the tool's output, case-insensitively |
| `@approval_required("true")` | `"true"` / `"false"` | aegis-server must get approval before answering ALLOW |
| `@risk_tier("low")` | `low`, `medium`, `high`, `critical` | with approval required, `low` means approve automatically |

Annotations are read from the policies that **determined** the decision: on an ALLOW, every `permit` that matched. If several matched, they are merged ([`merge_annotations`](../../cedar-sidecar/src/lib.rs)):

- `mask_fields`: the union.
- `approval_required`: `"true"` if any says `"true"`.
- `risk_tier`: the most severe. A matching policy with no tier counts as more severe than any tier, so automatic low-risk approval happens only when every matching policy says `low`.

Before 0.2.0 the last policy read won, which dropped masks at random ([benchmark B3](../benchmarks.md#b3-overlapping-policies-and-masking-a-bug-found-and-fixed)).

## Don't trust `context` for identity

Callers can put anything in `context`. The server overwrites `agent_id`, `agent`, `session_id` and `workflow_id` with verified values, but any other key, such as `context.amount` or `context.user_is_admin`, is exactly what the caller said. Use it for facts about the call that your adapter derives from the tool's arguments, never for who the caller is.

## Schemas and validation

Without a schema, policies are only checked for syntax. With one, every save is validated in Cedar's strict mode: a typo such as `principal.rol`, or an action applied to a resource type it does not declare, is rejected before it can go live.

The demo schema, [examples/policies/acme.schema.json](../../examples/policies/acme.schema.json), declares the entity types above and one action per tool. Save a schema, then a policy:

```bash
export AEGIS_ADMIN_TOKEN=...          # an OIDC token with the aegis:admin scope
aegisctl policy validate --policy-file my.cedar --tenant-id acme   # exits 1 with errors; usable in CI
aegisctl policy put acme --policy-file my.cedar
```

A saved policy is versioned (the history endpoint lists every version), written to Postgres, and pushed to every aegis-server replica at once through Redis. The next request uses it; no restart, no cache wait.

## Testing policies

- `aegisctl policy validate` in CI, against the tenant's schema.
- Write the decisions you expect as integration tests: mint tokens with the claims you care about (`scripts/mint_token.py`) and assert on `/v1/evaluate`. The attack suite, [benchmarks/attacks.py](../../benchmarks/attacks.py), is a worked example.
