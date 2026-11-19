"""aegisctl: operator CLI for Aegis.

The `tenant`, `policy` and `audit` commands call aegis-server's admin API
over HTTP and work against any deployment. The dev commands (seed-tenant,
mint-token, verify-audit, load-test) import modules from this repository's
`scripts/` and `benchmarks/` at runtime, so they need a checkout.

Every command takes --base-url (or AEGIS_URL) and the admin token from
--token (or AEGIS_ADMIN_TOKEN).
"""

import asyncio
import json
import os
import sys
from pathlib import Path

import httpx
import typer

app = typer.Typer(
    help="Operator CLI for Aegis — seed tenants, mint dev tokens, manage policies, verify audit."
)
policy_app = typer.Typer(help="Manage tenant Cedar policies via the admin API.")
app.add_typer(policy_app, name="policy")
tenant_app = typer.Typer(help="Manage tenants (identity, approvals, rate limit) via the admin API.")
app.add_typer(tenant_app, name="tenant")


def _repo_root() -> Path:
    # This file lives at <repo>/aegis-cli/aegis_cli/main.py.
    return Path(__file__).resolve().parents[2]


def _add_scripts_to_path() -> None:
    for path in (_repo_root() / "scripts", _repo_root()):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


BASE_URL = typer.Option(
    "http://localhost:8000", "--base-url", envvar="AEGIS_URL", help="aegis-server base URL."
)
TOKEN = typer.Option(..., "--token", envvar="AEGIS_ADMIN_TOKEN", help="Admin bearer token.")


@app.command("seed-tenant")
def seed_tenant() -> None:
    """Seed the demo 'acme' tenant (identity config, Cedar schema, sample
    policy) through the admin API. Dev stack only: signs its admin token with
    the dev key. See scripts/seed_tenant.py."""
    _add_scripts_to_path()
    import seed_tenant as seed_tenant_script

    seed_tenant_script.main()


@app.command("mint-token")
def mint_token(
    sub: str = typer.Option(..., "--sub", help="JWT 'sub' claim."),
    role: str = typer.Option("", "--role", help="Extra 'role' claim, e.g. Analyst, Manager."),
    department: str = typer.Option("", "--department", help="Extra 'department' claim."),
    agent_name: str = typer.Option("", "--agent-name", help="Extra 'agent_name' claim."),
    iss: str = typer.Option("", "--iss", help="JWT 'iss' claim, e.g. https://idp.aegis-admin.test."),
    scope: str = typer.Option("", "--scope", help="Extra 'scope' claim, e.g. aegis:admin."),
    ttl_seconds: int = typer.Option(300, "--ttl-seconds", help="Token lifetime in seconds."),
) -> None:
    """Mint a dev JWT signed with dev/jwks/private_key.pem (see scripts/mint_token.py).

    Prints only the token to stdout, so it's pipeable:

        export AEGIS_ADMIN_TOKEN=$(aegisctl mint-token --sub me \\
            --iss https://idp.aegis-admin.test --scope aegis:admin)
    """
    _add_scripts_to_path()
    from mint_token import mint

    # Mirrors scripts/mint_token.py's own argparse main(): sub/iss/ttl_seconds are
    # handled specially, everything else non-empty becomes an extra claim.
    extra_claims = {
        k: v
        for k, v in {"role": role, "department": department, "agent_name": agent_name, "scope": scope}.items()
        if v
    }
    token = mint(sub, ttl_seconds=ttl_seconds, iss=iss or None, **extra_claims)
    typer.echo(token)


@app.command("verify-audit")
def verify_audit(
    dsn: str | None = typer.Option(
        None, "--dsn", help="Postgres DSN to verify (default: local docker-compose)."
    ),
    hmac_secret: str | None = typer.Option(
        None, "--hmac-secret", help="Audit-chain HMAC secret (default: local dev secret)."
    ),
) -> None:
    """Independently recompute and verify the hash chain for every tenant's
    audit_ledger. See scripts/verify_audit_chain.py. Exits non-zero if any
    tenant's chain is broken."""
    # Only set these if explicitly passed — otherwise leave verify_audit_chain.py's
    # own AEGIS_VERIFY_DSN/AEGIS_VERIFY_HMAC_SECRET-aware defaults untouched.
    if dsn is not None:
        os.environ["AEGIS_VERIFY_DSN"] = dsn
    if hmac_secret is not None:
        os.environ["AEGIS_VERIFY_HMAC_SECRET"] = hmac_secret

    _add_scripts_to_path()
    import verify_audit_chain

    # verify_audit_chain.main() raises SystemExit(1) on a broken chain — let it
    # propagate so this command's own exit code reflects the real result.
    asyncio.run(verify_audit_chain.main())


@app.command("load-test")
def load_test(
    requests: int = typer.Option(1000, "--requests", help="Requests per concurrency level."),
    levels: str = typer.Option("1,10,25,50", "--levels", help="Comma-separated concurrency levels."),
) -> None:
    """Run the latency benchmark (benchmarks/latency.py) against the dev stack."""
    _add_scripts_to_path()
    sys.argv = ["latency", "--requests", str(requests), "--levels", levels]
    from benchmarks import latency

    latency.main()


def _fail(resp: httpx.Response) -> None:
    typer.echo(f"error {resp.status_code}: {resp.text}", err=True)
    raise typer.Exit(code=1)


@policy_app.command("get")
def policy_get(
    tenant_id: str = typer.Argument(..., help="Tenant ID."),
    base_url: str = BASE_URL,
    token: str = TOKEN,
    raw: bool = typer.Option(False, "--raw", help="Print only the policy_script text, not the full JSON."),
) -> None:
    """GET /admin/policies/{tenant_id} and print the current policy."""
    resp = httpx.get(
        f"{base_url}/admin/policies/{tenant_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )
    if resp.is_error:
        _fail(resp)
    data = resp.json()
    typer.echo(data["policy_script"] if raw else json.dumps(data, indent=2))


@policy_app.command("validate")
def policy_validate(
    policy_file: Path = typer.Option(
        ..., "--policy-file", exists=True, readable=True, help="Cedar policy file."
    ),
    tenant_id: str | None = typer.Option(
        None, "--tenant-id", help="Validate against this tenant's Cedar schema, if it has one."
    ),
    base_url: str = BASE_URL,
    token: str = TOKEN,
) -> None:
    """POST /admin/policies/validate. Exits non-zero and prints errors if the
    policy is invalid — usable as a CI gate."""
    resp = httpx.post(
        f"{base_url}/admin/policies/validate",
        headers={"Authorization": f"Bearer {token}"},
        json={"policy_script": policy_file.read_text(), "tenant_id": tenant_id},
        timeout=10.0,
    )
    if resp.is_error:
        _fail(resp)
    data = resp.json()
    if not data["valid"]:
        typer.echo("INVALID:", err=True)
        for error in data["errors"]:
            typer.echo(f"  - {error}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"valid (schema_checked={data['schema_checked']})")


@policy_app.command("put")
def policy_put(
    tenant_id: str = typer.Argument(..., help="Tenant ID."),
    policy_file: Path = typer.Option(
        ..., "--policy-file", exists=True, readable=True, help="Cedar policy file."
    ),
    base_url: str = BASE_URL,
    token: str = TOKEN,
) -> None:
    """PUT /admin/policies/{tenant_id}. Validates, persists, and pushes the update
    into Redis server-side. Exits non-zero on a 4xx/5xx response (e.g. invalid
    policy)."""
    resp = httpx.put(
        f"{base_url}/admin/policies/{tenant_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"policy_script": policy_file.read_text(), "tenant_id": tenant_id},
        timeout=10.0,
    )
    if resp.is_error:
        _fail(resp)
    typer.echo(f"policy_version={resp.json()['policy_version']}")


@tenant_app.command("get")
def tenant_get(
    tenant_id: str = typer.Argument(..., help="Tenant ID."), base_url: str = BASE_URL, token: str = TOKEN
) -> None:
    """GET /admin/tenants/{tenant_id}. The webhook secret is never returned."""
    resp = httpx.get(
        f"{base_url}/admin/tenants/{tenant_id}", headers={"Authorization": f"Bearer {token}"}, timeout=10.0
    )
    if resp.is_error:
        _fail(resp)
    typer.echo(json.dumps(resp.json(), indent=2))


@tenant_app.command("put")
def tenant_put(
    tenant_id: str = typer.Argument(..., help="Tenant ID."),
    config_file: Path = typer.Option(
        ..., "--file", exists=True, readable=True, help="JSON tenant config (see docs/guide/tenants.md)."
    ),
    base_url: str = BASE_URL,
    token: str = TOKEN,
) -> None:
    """PUT /admin/tenants/{tenant_id} from a JSON file. Creates or replaces."""
    resp = httpx.put(
        f"{base_url}/admin/tenants/{tenant_id}",
        headers={"Authorization": f"Bearer {token}"},
        json=json.loads(config_file.read_text()),
        timeout=10.0,
    )
    if resp.is_error:
        _fail(resp)
    typer.echo(json.dumps(resp.json(), indent=2))


@app.command("audit")
def audit(
    tenant_id: str = typer.Argument(..., help="Tenant ID."),
    limit: int = typer.Option(50, "--limit"),
    offset: int = typer.Option(0, "--offset"),
    action: str | None = typer.Option(None, "--action", help="Exact-match filter on action."),
    decision: str | None = typer.Option(None, "--decision", help="Exact-match filter on decision."),
    base_url: str = BASE_URL,
    token: str = TOKEN,
) -> None:
    """GET /admin/audit/{tenant_id} and print a readable table (most recent first)."""
    params: dict[str, str | int] = {"limit": limit, "offset": offset}
    if action:
        params["action"] = action
    if decision:
        params["decision"] = decision

    resp = httpx.get(
        f"{base_url}/admin/audit/{tenant_id}",
        headers={"Authorization": f"Bearer {token}"},
        params=params,
        timeout=10.0,
    )
    if resp.is_error:
        _fail(resp)
    rows = resp.json()
    if not rows:
        typer.echo("no audit entries")
        return
    for row in rows:
        typer.echo(
            f"{row['timestamp']}  {row['action']:<24} {row['decision']:<6} "
            f"policy={row['matched_policy'] or '-':<20} resource={row['resource_urn']}"
        )


if __name__ == "__main__":
    app()
