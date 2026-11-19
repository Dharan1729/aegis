import time
from dataclasses import dataclass, field
from typing import Any

import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import TenantConfig
from app.redis_client import redis_client

_jwks_clients: dict[str, jwt.PyJWKClient] = {}


class PrincipalValidationError(Exception):
    pass


@dataclass
class ExecutionPrincipalIdentity:
    tenant_id: str
    human_id: str
    human_claims: dict[str, Any] = field(default_factory=dict)
    agent_id: str = ""
    agent_claims: dict[str, Any] = field(default_factory=dict)


def _jwks_client(jwks_uri: str) -> jwt.PyJWKClient:
    client = _jwks_clients.get(jwks_uri)
    if client is None:
        client = jwt.PyJWKClient(jwks_uri)
        _jwks_clients[jwks_uri] = client
    return client


def _decode(
    token: str,
    jwks_uri: str,
    expected_issuer: str | None,
    expected_audience: str | None,
    single_use: bool,
) -> dict[str, Any]:
    # A tenant with no expected issuer would accept a token from any issuer
    # whose key happens to be at its JWKS URI. Deny instead.
    if not expected_issuer:
        raise PrincipalValidationError("tenant has no expected issuer configured")

    required = ["exp", "iat", "sub", "iss"] + (["jti"] if single_use else [])
    try:
        signing_key = _jwks_client(jwks_uri).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            issuer=expected_issuer,
            audience=expected_audience,
            options={"require": required, "verify_aud": expected_audience is not None},
        )
    except jwt.PyJWTError as exc:
        raise PrincipalValidationError(f"token validation failed: {exc}") from exc

    now = time.time()
    if claims["iat"] > now + 5:  # small clock-skew allowance
        raise PrincipalValidationError("token issued in the future")
    if single_use and now - claims["iat"] > settings.max_token_age_seconds:
        raise PrincipalValidationError("token too old, possible replay")
    return claims


async def _check_and_record_nonce(tenant_id: str, jti: str, exp: float) -> None:
    """Atomic check-and-set replay guard, shared across every aegis-server
    replica via Redis (SET NX EX) — a per-worker dict would let a replayed
    token through whenever it happens to land on a different worker than the
    one that saw the original request."""
    ttl = max(1, int(exp - time.time()))
    key = f"aegis:nonce:{tenant_id}:{jti}"
    was_newly_set = await redis_client.set(key, "1", nx=True, ex=ttl)
    if not was_newly_set:
        raise PrincipalValidationError("nonce replay detected")


async def validate_principal(
    session: AsyncSession,
    tenant_id: str,
    human_token: str,
    service_token: str,
) -> ExecutionPrincipalIdentity:
    tenant_config = await session.get(TenantConfig, tenant_id)
    if tenant_config is None:
        raise PrincipalValidationError(f"unknown tenant: {tenant_id}")

    single_use = tenant_config.single_use_tokens is not False
    human_claims = _decode(
        human_token,
        tenant_config.jwks_uri_human,
        tenant_config.expected_issuer_human,
        tenant_config.expected_audience_human,
        single_use,
    )
    agent_claims = _decode(
        service_token,
        tenant_config.jwks_uri_service,
        tenant_config.expected_issuer_service,
        tenant_config.expected_audience_service,
        single_use,
    )

    if single_use:
        # Both tokens must present a fresh, unique jti; replay of either is rejected.
        await _check_and_record_nonce(tenant_id, human_claims["jti"], human_claims["exp"])
        await _check_and_record_nonce(tenant_id, agent_claims["jti"], agent_claims["exp"])

    return ExecutionPrincipalIdentity(
        tenant_id=tenant_id,
        human_id=human_claims["sub"],
        human_claims=human_claims,
        agent_id=agent_claims["sub"],
        agent_claims=agent_claims,
    )
