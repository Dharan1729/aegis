import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class ExecutionPolicy:
    allowed_tools: list[str] = field(default_factory=list)
    mask_fields: list[str] = field(default_factory=list)
    approval_required: bool = False
    risk_tier: str | None = None
    approved_by: str | None = None


@dataclass
class EvaluateResult:
    decision: str
    correlation_id: str
    latency_ms: float
    execution_policy: ExecutionPolicy | None = None
    graceful_rejection_message: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"


class AegisClient:
    """Client for the Aegis decision runtime. Raises on transport errors and
    non-2xx responses; use `aegis.Guard` (as every adapter does) to turn
    those into denials. Connections are pooled and reused."""

    def __init__(self, base_url: str, *, timeout: float = 2.0, policy_version_cache_ttl: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        # A caller like GovernedCheckpointer may call policy_version() once
        # per checkpoint save/load — for a graph that checkpoints every
        # node, that's a network round trip per step. A short TTL bounds
        # that load to "at most one real check per tenant per TTL window"
        # while still catching a policy change within a few seconds, not
        # hours — the same tradeoff aegis-server's own local policy cache
        # makes (see aegis-server/app/config.py's policy_local_cache_ttl_seconds).
        self._policy_version_cache_ttl = policy_version_cache_ttl
        self._policy_version_cache: dict[str, tuple[str, float]] = {}
        self._sync_client: httpx.Client | None = None
        # An AsyncClient is bound to the event loop it was first used on.
        self._async_client: tuple[asyncio.AbstractEventLoop, httpx.AsyncClient] | None = None

    def _sync(self) -> httpx.Client:
        if self._sync_client is None or self._sync_client.is_closed:
            self._sync_client = httpx.Client(timeout=self.timeout)
        return self._sync_client

    def _async(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        if self._async_client is None or self._async_client[0] is not loop or self._async_client[1].is_closed:
            self._async_client = (loop, httpx.AsyncClient(timeout=self.timeout))
        return self._async_client[1]

    def close(self) -> None:
        if self._sync_client is not None:
            self._sync_client.close()

    async def aclose(self) -> None:
        if self._async_client is not None:
            await self._async_client[1].aclose()

    def _build_request(
        self,
        *,
        tenant_id: str,
        human_token: str,
        service_token: str,
        session_id: str,
        workflow_id: str,
        action: str,
        resource_type: str,
        resource_urn: str,
        context: dict[str, Any] | None,
    ) -> tuple[dict[str, str], dict[str, Any]]:
        headers = {
            "X-Aegis-Tenant-Id": tenant_id,
            "X-Aegis-User-Token": human_token,
            "Authorization": f"Bearer {service_token}",
        }
        body = {
            "execution_principal": {"session_id": session_id, "workflow_id": workflow_id},
            "action": action,
            "resource": {"type": resource_type, "urn": resource_urn},
            "context": context or {},
        }
        return headers, body

    def _parse_response(self, data: dict[str, Any]) -> EvaluateResult:
        policy = data.get("execution_policy")
        return EvaluateResult(
            decision=data["decision"],
            correlation_id=data["correlation_id"],
            latency_ms=data["latency_ms"],
            execution_policy=ExecutionPolicy(**policy) if policy else None,
            graceful_rejection_message=data.get("graceful_rejection_message"),
        )

    def evaluate(
        self,
        *,
        tenant_id: str,
        human_token: str,
        service_token: str,
        session_id: str,
        workflow_id: str,
        action: str,
        resource_type: str,
        resource_urn: str,
        context: dict[str, Any] | None = None,
    ) -> EvaluateResult:
        headers, body = self._build_request(
            tenant_id=tenant_id,
            human_token=human_token,
            service_token=service_token,
            session_id=session_id,
            workflow_id=workflow_id,
            action=action,
            resource_type=resource_type,
            resource_urn=resource_urn,
            context=context,
        )
        resp = self._sync().post(f"{self.base_url}/v1/evaluate", headers=headers, json=body)
        resp.raise_for_status()
        return self._parse_response(resp.json())

    async def aevaluate(
        self,
        *,
        tenant_id: str,
        human_token: str,
        service_token: str,
        session_id: str,
        workflow_id: str,
        action: str,
        resource_type: str,
        resource_urn: str,
        context: dict[str, Any] | None = None,
    ) -> EvaluateResult:
        headers, body = self._build_request(
            tenant_id=tenant_id,
            human_token=human_token,
            service_token=service_token,
            session_id=session_id,
            workflow_id=workflow_id,
            action=action,
            resource_type=resource_type,
            resource_urn=resource_urn,
            context=context,
        )
        resp = await self._async().post(f"{self.base_url}/v1/evaluate", headers=headers, json=body)
        resp.raise_for_status()
        return self._parse_response(resp.json())

    def _cached_policy_version(self, tenant_id: str) -> str | None:
        cached = self._policy_version_cache.get(tenant_id)
        if cached is None:
            return None
        version, expires_at = cached
        return version if expires_at > time.monotonic() else None

    def _store_policy_version(self, tenant_id: str, version: str) -> None:
        self._policy_version_cache[tenant_id] = (
            version,
            time.monotonic() + self._policy_version_cache_ttl,
        )

    def policy_version(self, tenant_id: str) -> str:
        cached = self._cached_policy_version(tenant_id)
        if cached is not None:
            return cached
        resp = self._sync().get(f"{self.base_url}/v1/policy-version/{tenant_id}")
        resp.raise_for_status()
        version = resp.json()["policy_version"]
        self._store_policy_version(tenant_id, version)
        return version

    async def apolicy_version(self, tenant_id: str) -> str:
        cached = self._cached_policy_version(tenant_id)
        if cached is not None:
            return cached
        resp = await self._async().get(f"{self.base_url}/v1/policy-version/{tenant_id}")
        resp.raise_for_status()
        version = resp.json()["policy_version"]
        self._store_policy_version(tenant_id, version)
        return version
