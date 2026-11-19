"""Shared helpers for the benchmarks: they all drive the real docker-compose
stack over HTTP, set tenants up through the admin API, and mint tokens with
the dev signing key.

Environment (defaults match docker-compose.yml):
    AEGIS_URL               http://localhost:8000
    AEGIS_COMPOSE_PROJECT   the compose project to stop/start services in
                            (fail_closed.py only; default: compose's own)
"""

import json
import os
import platform
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from mint_token import KID, _private_key, mint

__all__ = ["KID", "_private_key", "mint"]  # re-exported for the benchmark scripts

BASE_URL = os.environ.get("AEGIS_URL", "http://localhost:8000")
RESULTS = ROOT / "results"
ADMIN_ISSUER = "https://idp.aegis-admin.test"
DEV_JWKS = "http://jwks-mock:80/jwks.json"
APPROVAL_URL = "http://approval-mock:8090/approve"
APPROVAL_SECRET = "dev-approval-webhook-secret"


def issuers(tenant_id: str) -> tuple[str, str]:
    return f"https://idp.{tenant_id}.test/human", f"https://idp.{tenant_id}.test/service"


def admin_client() -> httpx.Client:
    token = mint("benchmark-admin", ttl_seconds=3600, iss=ADMIN_ISSUER, scope="aegis:admin")
    return httpx.Client(base_url=BASE_URL, headers={"Authorization": f"Bearer {token}"}, timeout=30.0)


def setup_tenant(tenant_id: str, policy: str, **overrides) -> None:
    """Creates or replaces a tenant and its policy through the admin API."""
    human_iss, service_iss = issuers(tenant_id)
    body = {
        "jwks_uri_human": DEV_JWKS,
        "jwks_uri_service": DEV_JWKS,
        "expected_issuer_human": human_iss,
        "expected_issuer_service": service_iss,
        "rate_limit_per_minute": 10_000_000,
        "approval_webhook_url": APPROVAL_URL,
        "approval_webhook_hmac_secret": APPROVAL_SECRET,
        **overrides,
    }
    with admin_client() as admin:
        for path, payload in (
            (f"/admin/tenants/{tenant_id}", body),
            (f"/admin/policies/{tenant_id}", {"policy_script": policy}),
        ):
            resp = admin.put(path, json=payload)
            if resp.status_code != 200:
                raise SystemExit(f"PUT {path} failed ({resp.status_code}): {resp.text}")


def token_pair(tenant_id: str, role: str = "Analyst", **human_claims) -> tuple[str, str]:
    human_iss, service_iss = issuers(tenant_id)
    human = mint(
        f"human-{uuid.uuid4().hex[:6]}", iss=human_iss, role=role, department="Finance", **human_claims
    )
    service = mint("agent-1", iss=service_iss, agent_name="benchmark_agent")
    return human, service


def evaluate_request(
    tenant_id: str, human: str, service: str, action: str, urn: str = "urn:x:report", context=None
):
    return {
        "url": f"{BASE_URL}/v1/evaluate",
        "headers": {
            "X-Aegis-Tenant-Id": tenant_id,
            "X-Aegis-User-Token": human,
            "Authorization": f"Bearer {service}",
        },
        "json": {
            "execution_principal": {"session_id": "bench", "workflow_id": "bench"},
            "action": action,
            "resource": {"type": "report", "urn": urn},
            "context": {"tool_name": action, **(context or {})},
        },
    }


def wait_ready(timeout: float = 90.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(f"{BASE_URL}/ready", timeout=3.0).status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(1.0)
    return False


def compose(*args: str) -> None:
    cmd = ["docker", "compose"]
    project = os.environ.get("AEGIS_COMPOSE_PROJECT")
    if project:
        cmd += ["-p", project]
    subprocess.run([*cmd, *args], cwd=ROOT, check=True, capture_output=True)


def environment() -> dict:
    return {
        "date": datetime.now(UTC).strftime("%Y-%m-%d"),
        "machine": f"{platform.system()} {platform.machine()}",
        "python": platform.python_version(),
        "stack": "docker-compose, single aegis-server replica, one machine",
    }


def write_result(name: str, payload: dict) -> Path:
    out_dir = Path(os.environ.get("AEGIS_RESULTS_DIR", RESULTS))
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.json"
    path.write_text(json.dumps({"environment": environment(), **payload}, indent=2) + "\n")
    return path
