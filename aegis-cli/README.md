# aegis-cli

`aegisctl`, the operator CLI for [Aegis](../README.md).

```bash
pip install -e ./aegis-cli
export AEGIS_URL=http://localhost:8000
export AEGIS_ADMIN_TOKEN=...      # OIDC token with the aegis:admin scope
```

**Against any deployment** (admin API over HTTP):

```bash
aegisctl tenant put acme --file examples/tenant.json
aegisctl tenant get acme
aegisctl policy validate --policy-file my.cedar --tenant-id acme     # exits 1 on errors; use in CI
aegisctl policy put acme --policy-file my.cedar
aegisctl policy get acme --raw
aegisctl audit acme --limit 20 --decision DENY
```

**Development helpers** (need a checkout of this repository and the dev stack):

```bash
aegisctl seed-tenant                       # demo tenant "acme"
aegisctl mint-token --sub you --iss https://idp.aegis-admin.test --scope aegis:admin
aegisctl verify-audit [--dsn ...] [--hmac-secret ...]
aegisctl load-test --requests 1000 --levels 1,10,25,50
```
