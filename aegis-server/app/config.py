from typing import Literal

from pydantic_settings import BaseSettings

DEV_AUDIT_SECRET = "dev-audit-chain-secret-do-not-use-in-prod"
DEV_ADMIN_ISSUER = "https://idp.aegis-admin.test"
MIN_SECRET_LENGTH = 32


class UnsafeConfigurationError(RuntimeError):
    """Raised at startup when a production deployment still uses a dev default."""


class Settings(BaseSettings):
    # "production" turns the dev defaults below into startup errors
    # (check_production_safety). Everything else behaves the same.
    environment: Literal["development", "production"] = "development"

    database_url: str = "postgresql+asyncpg://aegis:aegis@localhost:5432/aegis"
    # SQLAlchemy's default pool (5 + 10 overflow) queued requests under a
    # concurrency-20 load test until raised; see docs/benchmarks.md.
    db_pool_size: int = 20
    db_max_overflow: int = 20
    cedar_sidecar_url: str = "http://localhost:8180"
    redis_url: str = "redis://localhost:6379/0"
    # For tenants with single-use tokens: how old a token's `iat` may be.
    max_token_age_seconds: int = 300
    # In-process copy of a tenant's policy, to skip a Redis round trip per
    # call. Kept fresh by Redis pub/sub invalidation (policy_store.py); the
    # TTL is only a safety net if a message is missed.
    policy_local_cache_ttl_seconds: float = 5.0
    # Safety-net TTL on the shared Redis copy, in case Postgres is updated
    # without going through the publish path.
    policy_redis_cache_ttl_seconds: int = 300
    rate_limit_window_seconds: int = 60
    default_rate_limit_per_window: int = 600
    # The /admin/* API takes an OIDC bearer token: JWKS signature, issuer,
    # and a required scope. Platform-level, independent of any tenant's IdP.
    # The defaults point at the dev JWKS in docker-compose.yml.
    admin_oidc_jwks_uri: str = "http://jwks-mock:80/jwks.json"
    admin_oidc_issuer: str = DEV_ADMIN_ISSUER
    admin_oidc_required_scope: str = "aegis:admin"
    # HMAC key for the audit hash chain (app/audit_hash.py). An unkeyed chain
    # can be recomputed by anyone with database write access after editing a
    # row; keying it means a forger also needs this secret. It does not
    # protect against a compromised aegis-server, which holds the secret.
    audit_chain_hmac_secret: str = DEV_AUDIT_SECRET
    # OTLP gRPC endpoint (e.g. http://jaeger:4317). Empty disables export.
    otel_exporter_otlp_endpoint: str = ""
    # Browser origins allowed to call the API (a separate admin console).
    # Server-to-server callers are not subject to CORS. Env takes a JSON
    # array, e.g. '["https://console.example.com"]'.
    console_cors_origins: list[str] = ["http://localhost:5173"]

    def check_production_safety(self) -> None:
        """Refuses to start a production deployment that still carries a
        development default. Called once from the app's lifespan."""
        if self.environment != "production":
            return
        problems = []
        if self.audit_chain_hmac_secret == DEV_AUDIT_SECRET:
            problems.append("AUDIT_CHAIN_HMAC_SECRET is the development default")
        elif len(self.audit_chain_hmac_secret) < MIN_SECRET_LENGTH:
            problems.append(f"AUDIT_CHAIN_HMAC_SECRET is shorter than {MIN_SECRET_LENGTH} characters")
        if self.admin_oidc_issuer == DEV_ADMIN_ISSUER:
            problems.append("ADMIN_OIDC_ISSUER is the development identity provider")
        if "jwks-mock" in self.admin_oidc_jwks_uri:
            problems.append("ADMIN_OIDC_JWKS_URI points at the development JWKS")
        if any(origin.startswith("http://localhost") for origin in self.console_cors_origins):
            problems.append("CONSOLE_CORS_ORIGINS allows a localhost origin")
        if problems:
            raise UnsafeConfigurationError(
                "refusing to start with ENVIRONMENT=production: " + "; ".join(problems)
            )


settings = Settings()
