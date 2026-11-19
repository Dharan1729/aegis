"""HTTP layer. The decision logic lives in app/decision.py."""

import time
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app import admin, cedar_client, models  # noqa: F401 - models import registers tables on Base.metadata
from app.config import settings
from app.db import get_session
from app.decision import decide
from app.observability import DECISIONS, instrument_app
from app.policy_store import PolicyNotFoundError, policy_store
from app.rate_limiter import RateLimitExceededError
from app.redis_client import redis_client
from app.schemas import EvaluateRequest, EvaluateResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.check_production_safety()
    # The schema is owned by Alembic: the image runs `alembic upgrade head`
    # before uvicorn starts.
    await policy_store.start()
    yield
    await policy_store.stop()
    await cedar_client.shutdown()


app = FastAPI(title="Aegis Decision Runtime", lifespan=lifespan)
instrument_app(app)
# Bearer tokens travel in the Authorization header, not cookies, so
# credentials are not needed for the browser console.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.console_cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(admin.router)
app.mount("/admin-ui", StaticFiles(directory="static/admin", html=True), name="admin-ui")


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness: the process is up. Says nothing about dependencies."""
    return {"status": "ok"}


@app.get("/ready")
async def ready(session: AsyncSession = Depends(get_session)) -> JSONResponse:
    """Readiness: Postgres, Redis and cedar-sidecar all answer. While any of
    them is down, /v1/evaluate denies every request, so a load balancer
    should stop sending traffic here."""
    checks: dict[str, str] = {}
    try:
        await session.execute(text("SELECT 1"))
        checks["postgres"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["postgres"] = f"error: {type(exc).__name__}"
    try:
        await redis_client.ping()
        checks["redis"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["redis"] = f"error: {type(exc).__name__}"
    checks["cedar_sidecar"] = "ok" if await cedar_client.healthy() else "error: unreachable"
    status = 200 if all(v == "ok" for v in checks.values()) else 503
    return JSONResponse({"status": "ok" if status == 200 else "degraded", "checks": checks}, status)


@app.get("/v1/policy-version/{tenant_id}")
async def get_policy_version(tenant_id: str) -> dict[str, str]:
    """Unauthenticated on purpose: returns only a hash of the tenant's
    policy, so SDK adapters (the LangGraph checkpointer) can cheaply detect
    a policy change. The cost is that a caller can tell which tenant IDs
    exist (200 vs 404)."""
    try:
        cached_policy = await policy_store.get(tenant_id)
    except PolicyNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"tenant_id": tenant_id, "policy_version": cached_policy.policy_version}


@app.post("/v1/evaluate", response_model=EvaluateResponse)
async def evaluate(
    req: EvaluateRequest,
    x_aegis_tenant_id: str = Header(...),
    x_aegis_user_token: str = Header(...),
    authorization: str = Header(...),
    session: AsyncSession = Depends(get_session),
) -> EvaluateResponse:
    start = time.perf_counter()
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="malformed Authorization header")

    try:
        result = await decide(
            session,
            tenant_id=x_aegis_tenant_id,
            user_token=x_aegis_user_token,
            service_token=authorization.removeprefix("Bearer "),
            req=req,
            correlation_id=f"eval_{uuid.uuid4().hex[:12]}",
        )
    except RateLimitExceededError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc

    DECISIONS.labels(decision=result.decision).inc()
    return EvaluateResponse(
        decision=result.decision,
        correlation_id=result.correlation_id,
        latency_ms=round((time.perf_counter() - start) * 1000, 2),
        execution_policy=result.execution_policy,
        graceful_rejection_message=result.graceful_rejection_message,
    )
