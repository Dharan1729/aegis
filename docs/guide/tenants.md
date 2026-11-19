# Tenants and identity

A tenant record tells aegis-server how to verify that tenant's two tokens and where to send its approvals. Create or replace one with the admin API or the CLI:

```bash
aegisctl tenant put acme --file tenant.json
aegisctl tenant get acme          # the webhook secret is never returned
```

```json
{
  "jwks_uri_human": "https://login.example.com/.well-known/jwks.json",
  "jwks_uri_service": "https://workload-idp.example.com/jwks",
  "expected_issuer_human": "https://login.example.com/",
  "expected_issuer_service": "https://workload-idp.example.com",
  "expected_audience_human": "aegis",
  "expected_audience_service": "aegis",
  "single_use_tokens": false,
  "rate_limit_per_minute": 600,
  "approval_webhook_url": "https://approvals.example.com/aegis",
  "approval_webhook_hmac_secret": "<at least 16 characters; use 32+ random bytes>"
}
```

| Field | Required | Meaning |
|---|---|---|
| `jwks_uri_human`, `jwks_uri_service` | yes | where to fetch the signing keys for the user's and the agent's tokens; may be the same |
| `expected_issuer_human`, `expected_issuer_service` | yes | the exact `iss` each token must carry. Without both, every request for the tenant is denied |
| `expected_audience_human`, `expected_audience_service` | no | if set, the token's `aud` must contain it. Set it whenever your identity provider issues tokens for other applications too, or a token meant for them would be accepted here |
| `single_use_tokens` | no (default `true`) | see below |
| `rate_limit_per_minute` | no | per-tenant limit across all replicas; default 600 |
| `approval_webhook_url` | no | where approval-required decisions go. Without it, they are denied |
| `approval_webhook_hmac_secret` | with a webhook | shared secret for signing both directions; a webhook without one is refused |

In production (`ENVIRONMENT=production`), JWKS and webhook URLs must be `https`.

## Token checks

Every request, for both tokens:

- signature verifies against a key from the configured JWKS (RS256 or ES256 only; `none` and HMAC algorithms are refused);
- `iss` equals the configured issuer;
- `exp`, `iat` and `sub` are present; the token has not expired and was not issued in the future (5 s of clock skew allowed);
- `aud` matches, if an audience is configured.

### Single-use tokens (default)

With `single_use_tokens: true`, each token must also carry a `jti`, be younger than `MAX_TOKEN_AGE_SECONDS` (default 300), and never have been seen before: the `jti` is recorded in Redis, shared by every replica, until the token expires. A second use is a replay and is denied.

This suits a setup where something in front of Aegis mints a short-lived token pair for each tool call, for example an OAuth 2.0 token exchange (RFC 8693) that turns the user's session token into a per-call token scoped to the agent. A stolen per-call token is worth one call.

### Reusable tokens

With `single_use_tokens: false`, tokens are ordinary bearer tokens: valid for every call until `exp`, with no `jti` or age requirement. Use this when your agent holds the user's normal access token and the agent's service token for the session. It is what most identity providers issue out of the box. The other checks still apply, and an audience should be configured.

Single-use tokens add a Redis write per token: 0.2 ms against 0.4 to 4 ms for the identity step in [benchmark B4](../benchmarks.md#b4-latency-throughput-and-where-the-time-goes).

## Admin access

The admin API (`/admin/*`) is platform-level, not per tenant. It takes an OIDC bearer token from the identity provider configured by `ADMIN_OIDC_JWKS_URI` and `ADMIN_OIDC_ISSUER`, which must carry the scope `ADMIN_OIDC_REQUIRED_SCOPE` (default `aegis:admin`). Admin tokens are ordinary reusable access tokens.

## In development

The compose stack runs `jwks-mock`, which serves the public half of `dev/jwks/private_key.pem`. `scripts/mint_token.py` signs tokens with the private half, for any issuer, subject and claims:

```bash
python scripts/mint_token.py --sub alice --role Analyst --department Finance --iss https://idp.acme.test/human
python scripts/mint_token.py --sub you --iss https://idp.aegis-admin.test --scope aegis:admin
```

The dev key is generated per checkout (`scripts/gen_test_keys.py`) and gitignored. Never point a production tenant at `jwks-mock`.
