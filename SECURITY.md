# Security

## Reporting a vulnerability

Report it privately through GitHub's **Report a vulnerability** button on this repository's Security tab, not in a public issue. Include the version or commit, the steps to reproduce, and what an attacker gains. Expect a first reply within a few days. This is a small project with no formal SLA and no bug bounty.

A finding that turns any request into an unwarranted `ALLOW` is the most serious class, and will be treated first.

## Threat model

### What Aegis protects

| Threat | Defence | Tested by |
|---|---|---|
| A caller forges or alters a token | signature against the tenant's JWKS; RS256/ES256 only (`none` and HMAC refused) | unit tests, attack suite (B1) |
| A token from another tenant, issuer or application | exact `iss` per tenant and token type; optional `aud`; a tenant without issuers denies everything | unit tests, B1 |
| A captured token is replayed | single-use mode: unique `jti`, maximum age, replay guard shared by all replicas | B1 |
| An agent claims to be a more trusted agent | agent identity only from its verified token; server fields overwrite the request context | B1 |
| Cedar syntax smuggled into action or resource names | entity IDs are escaped and parsed as data | B1 |
| A dependency is down, slow or failing | every failure is a DENY; circuit breaker on cedar-sidecar; SDK denies when it cannot reach the server | fault injection (B2), unit tests |
| One of several matching policies' obligations is lost | strict merge in cedar-sidecar | B3, Rust tests |
| A forged or replayed approval | HMAC-signed request and response, response bound to a per-request ID; webhooks without a secret refused | integration tests |
| Audit history is edited, inserted or deleted by someone with database access | per-tenant HMAC chain, key held outside the database; independent verifier | integration tests |
| A production deployment runs with dev settings | `ENVIRONMENT=production` refuses to start with dev secrets, the dev identity provider, or localhost CORS | unit tests |
| Sensitive fields reach the model | `@mask_fields` applied by the SDK; unmaskable output withheld by default | SDK tests |

### What it does not protect against

- **A compromised aegis-server.** It holds the audit HMAC key and makes the decisions. Anchor chain heads externally ([audit](docs/guide/audit.md#what-it-does-not-protect-against)).
- **A compromised identity provider.** Aegis trusts the keys the tenant's JWKS serves.
- **Tools that bypass the adapter.** Aegis governs calls that go through it. A tool that the agent can reach some other way, or that has side effects beyond its declared arguments, is outside its view.
- **What the model does with allowed data.** Aegis decides whether a call may run and masks named fields in its result. It does not filter prompts, detect prompt injection, or inspect free text.
- **Untrusted `context` values.** Fields in the request `context` other than the server-set identity fields are whatever the caller sent. Policies must not use them to establish identity ([policies](docs/guide/policies.md#dont-trust-context-for-identity)).
- **Denial of service.** Per-tenant rate limits exist; there is no other protection against floods.
- **Tenant enumeration.** `GET /v1/policy-version/{tenant}` is unauthenticated and reveals whether a tenant exists.
- **Transport.** aegis-server serves plain HTTP; terminate TLS in front of it.

## Deployment hygiene

See the [production checklist](docs/guide/deployment.md#production-checklist). In short: `ENVIRONMENT=production`, a random 32+ character `AUDIT_CHAIN_HMAC_SECRET` from a secret store, a real identity provider for admin access, `https` everywhere, private networking for cedar-sidecar, Postgres and Redis, and a scheduled audit-chain verification.

## Supply chain

CI builds every image, produces an SPDX SBOM, and fails on fixable HIGH or CRITICAL vulnerabilities (Trivy); `cargo audit` checks the Rust dependencies. Runtime images run as non-root users and do not ship pip or build tools.
