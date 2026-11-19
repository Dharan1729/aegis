# Quickstart

Ten minutes, Docker and Python 3.11+. No LLM or API key is needed.

## 1. Start the stack

```bash
git clone https://github.com/Dharan1729/aegis && cd aegis
python -m venv .venv && . .venv/bin/activate
pip install -e aegis-sdk -e aegis-cli "pyjwt[crypto]" httpx

python scripts/gen_test_keys.py
docker compose up --build -d
curl -s localhost:8000/ready
# {"status":"ok","checks":{"postgres":"ok","redis":"ok","cedar_sidecar":"ok"}}
```

`gen_test_keys.py` makes a signing key for a stand-in identity provider (`jwks-mock`), so you can mint tokens locally. The first build compiles the Rust sidecar and takes a few minutes.

Ports are bound to 127.0.0.1. If one is taken, move it: `AEGIS_PORT=18000 AEGIS_PG_PORT=15432 docker compose up -d` (the variables are listed at the top of `docker-compose.yml`), then set `AEGIS_URL=http://localhost:18000` for the scripts.

## 2. Create a tenant

```bash
python scripts/seed_tenant.py
```

Through the admin API, this creates tenant `acme` from [examples/tenant.json](../../examples/tenant.json) (which issuers to trust, the approval webhook), saves the Cedar schema [examples/policies/acme.schema.json](../../examples/policies/acme.schema.json), and saves the policy [examples/policies/acme.cedar](../../examples/policies/acme.cedar):

| Who | May | Obligation |
|---|---|---|
| Analyst | `execute_query` | `ssn` and `compensation` masked |
| Manager | `transfer_funds` | approval, low risk: automatic |
| Manager | `transfer_medium_funds` | approval from the webhook (the mock approves) |
| Manager | `transfer_large_funds` | approval from the webhook (the mock refuses) |
| anyone else | nothing | Cedar denies by default |

## 3. See every outcome

```bash
python examples/quickstart.py
```

It plays an agent calling five tools as different users, through the same `Guard` every framework adapter uses, then points the guard at an address where nothing is listening to show that an unreachable server means "deny".

## 4. Call the API yourself

```bash
H=$(python scripts/mint_token.py --sub alice --role Analyst --iss https://idp.acme.test/human)
A=$(python scripts/mint_token.py --sub bot --agent_name demo --iss https://idp.acme.test/service)
curl -s localhost:8000/v1/evaluate \
  -H "X-Aegis-Tenant-Id: acme" -H "X-Aegis-User-Token: $H" -H "Authorization: Bearer $A" \
  -H 'Content-Type: application/json' \
  -d '{"execution_principal":{"session_id":"s1","workflow_id":"w1"},
       "action":"execute_query","resource":{"type":"table","urn":"urn:db:payroll"}}'
```

Send the same command again with the same tokens: the demo tenant uses single-use tokens, so the second request is a replay and is denied.

## 5. Look at the audit log

```bash
export AEGIS_ADMIN_TOKEN=$(aegisctl mint-token --sub you --iss https://idp.aegis-admin.test --scope aegis:admin)
aegisctl audit acme --limit 10
python scripts/verify_audit_chain.py
```

## 6. Change the policy

Edit `examples/policies/acme.cedar` (for example, let `Junior Analyst` query too), then:

```bash
aegisctl policy validate --policy-file examples/policies/acme.cedar --tenant-id acme
aegisctl policy put acme --policy-file examples/policies/acme.cedar
python examples/quickstart.py
```

The change applies to the next request. Or edit it in the browser at <http://localhost:8000/admin-ui/>, with the same token.

## 7. Put it in front of a real agent

[Framework adapters](adapters.md). Then read [tenants and identity](tenants.md) to point a tenant at your identity provider, and the [production checklist](deployment.md#production-checklist).

## Clean up

```bash
docker compose down -v
```
