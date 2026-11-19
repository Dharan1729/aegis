import time
from dataclasses import dataclass

import httpx

from app.config import settings
from app.principal_validator import ExecutionPrincipalIdentity
from app.schemas import EvaluateRequest


class CedarEngineError(Exception):
    pass


# Measured directly against the live cedar-sidecar (100 sequential
# /authorize calls, fresh connections, no pooling): p99 ~4.7ms, max
# ~4.7ms — an in-process Rust policy engine on the same Docker network is
# not where multi-hundred-millisecond latency comes from. The previous
# flat 2.0s timeout was ~400x that p99, which means a hung/degraded
# cedar-sidecar could block an /v1/evaluate call — and every request
# behind it in that caller's own budget — for two full seconds before
# aegis-server's existing fail-closed CedarEngineError handling ever
# kicked in. Read/write timeout below still leaves ~100x margin over the
# measured p99; connect should be sub-millisecond on the same bridge
# network, so its budget is generous specifically for cold-start/network
# hiccups, not steady-state latency.
_CEDAR_TIMEOUT = httpx.Timeout(connect=0.25, read=0.5, write=0.5, pool=0.5)

# A single shared, connection-pooling client instead of opening a fresh
# TCP connection (and, for the sidecar being on the same host, a fresh
# handshake) on every single call — both faster in steady state and a
# prerequisite for the tight timeout above being meaningful rather than
# dominated by per-call connection setup.
_client = httpx.AsyncClient(timeout=_CEDAR_TIMEOUT)

# Simple consecutive-failure circuit breaker: after enough back-to-back
# network-level failures (timeouts, connection refused — NOT a non-200
# response, which reflects this specific request being invalid rather
# than cedar-sidecar being unhealthy, and shouldn't trip a breaker meant
# to protect against a genuinely down dependency), stop attempting the
# network call for a cooldown window and fail fast instead. Existing
# fail-closed handling in main.py means the *security* outcome (DENY) is
# identical either way — this is purely about not making every in-flight
# caller wait out a full timeout, and not piling up connections/requests
# against a dependency that's already down. Deliberately per-process, not
# shared via Redis: each aegis-server replica independently gauging its
# own connection health to cedar-sidecar is the right granularity here,
# not a global cross-replica circuit.
_BREAKER_FAILURE_THRESHOLD = 5
_BREAKER_RECOVERY_SECONDS = 10.0


@dataclass
class _CircuitBreakerState:
    consecutive_failures: int = 0
    opened_at: float | None = None
    trial_in_flight: bool = False


_breaker = _CircuitBreakerState()


def _breaker_allow_request() -> bool:
    if _breaker.opened_at is None:
        return True
    if time.monotonic() - _breaker.opened_at < _BREAKER_RECOVERY_SECONDS:
        return False
    # Cooldown elapsed: admit exactly one trial request (single-flight —
    # a plain time check here, with no claim/lock, would let every
    # concurrent caller past the cooldown treat itself as "the" trial,
    # reproducing the exact request pile-up this breaker exists to
    # prevent). Safe without an asyncio.Lock: this function has no
    # `await` in it, so nothing else can run between the check and the
    # set within a single asyncio event loop.
    if _breaker.trial_in_flight:
        return False
    _breaker.trial_in_flight = True
    return True


def _breaker_record_success() -> None:
    _breaker.consecutive_failures = 0
    _breaker.opened_at = None
    _breaker.trial_in_flight = False


def _breaker_record_network_failure() -> None:
    _breaker.consecutive_failures += 1
    if _breaker.trial_in_flight:
        # The half-open trial itself failed — re-open with a *fresh*
        # cooldown. Without this, opened_at would stay at its old value
        # (already >= _BREAKER_RECOVERY_SECONDS in the past, since we
        # only get here after that cooldown elapsed), and the very next
        # caller would immediately claim another trial with no actual
        # wait.
        _breaker.trial_in_flight = False
        _breaker.opened_at = time.monotonic()
    elif _breaker.consecutive_failures >= _BREAKER_FAILURE_THRESHOLD and _breaker.opened_at is None:
        _breaker.opened_at = time.monotonic()


async def healthy() -> bool:
    """For /ready. Does not touch the circuit breaker."""
    try:
        resp = await _client.get(f"{settings.cedar_sidecar_url}/health")
    except httpx.HTTPError:
        return False
    return resp.status_code == 200


async def shutdown() -> None:
    """Closes the shared client's connection pool — called from main.py's
    lifespan shutdown, not left for process exit to clean up implicitly."""
    await _client.aclose()


@dataclass
class CedarDecision:
    allow: bool
    determining_policies: list[str]
    errors: list[str]
    annotations: dict[str, str]


def _cedar_euid(entity_type: str, entity_id: str) -> str:
    escaped = entity_id.replace("\\", "\\\\").replace('"', '\\"')
    return f'{entity_type}::"{escaped}"'


def _build_entities(identity: ExecutionPrincipalIdentity, req: EvaluateRequest) -> list[dict]:
    return [
        {
            "uid": {"type": "Human", "id": identity.human_id},
            "attrs": {
                "role": identity.human_claims.get("role", ""),
                "department": identity.human_claims.get("department", ""),
            },
            "parents": [],
        },
        {
            "uid": {"type": "Resource", "id": req.resource.urn},
            "attrs": {"type": req.resource.type},
            "parents": [],
        },
        {
            # Previously the agent only rode along as a flat string in
            # context. Making it a full entity lets policies reason over
            # agent-specific attributes directly (e.g. "only verified
            # agent types may do X") instead of only the human's role —
            # the "blended identity" pattern (principal = human, but the
            # acting agent is independently evaluable, not just logged).
            "uid": {"type": "Agent", "id": identity.agent_id},
            "attrs": {"agent_name": identity.agent_claims.get("agent_name", "")},
            "parents": [],
        },
    ]


async def authorize(
    policy_script: str,
    identity: ExecutionPrincipalIdentity,
    req: EvaluateRequest,
    correlation_id: str = "",
) -> CedarDecision:
    payload = {
        "policy_set": policy_script,
        "entities": _build_entities(identity, req),
        "principal": _cedar_euid("Human", identity.human_id),
        "action": _cedar_euid("Action", req.action),
        "resource": _cedar_euid("Resource", req.resource.urn),
        "context": {
            # req.context is caller-supplied and fully free-form — it must
            # be spread FIRST so the server-derived identity fields below
            # always win. Spreading it last would let any caller override
            # agent_id/session_id/workflow_id in the request body, which
            # would let a lower-privileged caller impersonate a different
            # (trusted) agent_id in exactly the kind of policy this "Agent"
            # entity feature exists to support (e.g.
            # `context.agent_id == "trusted-batch-agent"`).
            **req.context,
            # Kept as a flat string for backward compatibility with any
            # policy written before "agent" became a real entity below.
            "agent_id": identity.agent_id,
            "agent": {"__entity": {"type": "Agent", "id": identity.agent_id}},
            "session_id": req.execution_principal.session_id,
            "workflow_id": req.execution_principal.workflow_id,
        },
    }

    if not _breaker_allow_request():
        raise CedarEngineError("cedar-sidecar circuit breaker open (too many recent connection failures)")

    try:
        resp = await _client.post(
            f"{settings.cedar_sidecar_url}/authorize",
            json=payload,
            headers={"X-Correlation-Id": correlation_id} if correlation_id else None,
        )
    except httpx.HTTPError as exc:
        _breaker_record_network_failure()
        raise CedarEngineError(f"cedar-sidecar unreachable: {exc}") from exc

    if resp.status_code != 200:
        # A non-200 reflects this specific request (e.g. a malformed
        # policy) rather than cedar-sidecar's own health — doesn't count
        # against the breaker, which exists to detect a down dependency.
        raise CedarEngineError(f"cedar-sidecar returned {resp.status_code}: {resp.text}")

    _breaker_record_success()
    body = resp.json()
    return CedarDecision(
        allow=body["decision"] == "Allow",
        determining_policies=body.get("determining_policies", []),
        errors=body.get("errors", []),
        annotations=body.get("annotations", {}),
    )


async def validate_policy(policy_script: str, schema: str | None = None) -> tuple[bool, list[str], bool]:
    """Returns (valid, errors, schema_checked). schema_checked is False
    whenever no schema was supplied — callers should not present a
    schema-less pass as having verified anything beyond syntax."""
    payload: dict = {"policy_set": policy_script}
    if schema:
        payload["schema"] = schema

    if not _breaker_allow_request():
        raise CedarEngineError("cedar-sidecar circuit breaker open (too many recent connection failures)")

    try:
        resp = await _client.post(f"{settings.cedar_sidecar_url}/validate", json=payload)
    except httpx.HTTPError as exc:
        _breaker_record_network_failure()
        raise CedarEngineError(f"cedar-sidecar unreachable: {exc}") from exc

    _breaker_record_success()
    body = resp.json()
    return body["valid"], body.get("errors", []), body.get("schema_checked", False)
