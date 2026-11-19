"""Fault injection: stop one dependency at a time and check that nothing is
allowed while it is down, that the server answers with a decision rather
than an error, and that it recovers once the dependency is back.

Every request sent is one that is ALLOWED when the stack is healthy, so any
ALLOW during a fault would be a fail-open.

    AEGIS_COMPOSE_PROJECT=<project> python -m benchmarks.fail_closed

This stops and starts containers in that compose project. Do not point it at
a stack you care about.
"""

import statistics
import sys
import time
from collections import Counter

import httpx

from benchmarks._stack import (
    ROOT,
    compose,
    evaluate_request,
    setup_tenant,
    token_pair,
    wait_ready,
    write_result,
)

sys.path.insert(0, str(ROOT / "aegis-sdk"))
from aegis import AegisClient, AegisContext, Guard

TENANT = "faults"
POLICY = """
permit(principal, action == Action::"read_report", resource)
when { principal.role == "Analyst" };

@approval_required("true")
@risk_tier("medium")
permit(principal, action == Action::"wire_medium_funds", resource)
when { principal.role == "Analyst" };
"""

# (label, compose service to stop, action, what we expect while it is down)
FAULTS = [
    ("healthy stack (control)", None, "read_report", "ALLOW"),
    ("cedar-sidecar stopped", "cedar-sidecar", "read_report", "DENY"),
    ("redis stopped", "redis", "read_report", "DENY"),
    ("postgres stopped", "postgres", "read_report", "DENY"),
    ("approval webhook stopped", "approval-mock", "wire_medium_funds", "DENY"),
    ("identity provider (JWKS) stopped", "jwks-mock", "read_report", "ALLOW"),
]


def _summarise(outcomes: list[tuple[str, float]]) -> dict:
    counts = Counter(o for o, _ in outcomes)
    latencies = sorted(ms for _, ms in outcomes)
    return {
        "requests": len(outcomes),
        "outcomes": dict(counts),
        "latency_ms_p50": round(statistics.median(latencies), 1),
        "latency_ms_max": round(latencies[-1], 1),
    }


def _send(client: httpx.Client, action: str, n: int) -> list[tuple[str, float]]:
    out = []
    for _ in range(n):
        req = evaluate_request(TENANT, *token_pair(TENANT), action)
        start = time.perf_counter()
        try:
            resp = client.post(**req)
            outcome = resp.json()["decision"] if resp.status_code == 200 else f"HTTP {resp.status_code}"
        except httpx.HTTPError as exc:
            outcome = f"transport error ({type(exc).__name__})"
        out.append((outcome, (time.perf_counter() - start) * 1000))
    return out


def _seconds_to_recover(client: httpx.Client, action: str, limit: float = 90.0) -> float | None:
    """Seconds from restarting the dependency until requests are allowed
    again (five in a row, so one lucky request does not count)."""
    start = time.perf_counter()
    streak = 0
    while time.perf_counter() - start < limit:
        outcome, _ = _send(client, action, 1)[0]
        streak = streak + 1 if outcome == "ALLOW" else 0
        if streak == 5:
            return round(time.perf_counter() - start, 1)
        time.sleep(0.2)
    return None


def _sdk_with_server_down(n: int) -> dict:
    """aegis-server itself unreachable: the SDK's guard must deny."""
    guard = Guard(AegisClient("http://localhost:1", timeout=1.0))
    ctx = AegisContext(TENANT, "h", "s", "sess", "wf")
    outcomes = []
    for _ in range(n):
        start = time.perf_counter()
        verdict = guard.check(ctx, "read_report")
        outcomes.append(("ALLOW" if verdict.allowed else "DENY", (time.perf_counter() - start) * 1000))
    return _summarise(outcomes)


def run(per_fault: int = 40) -> dict:
    setup_tenant(TENANT, POLICY)
    rows = []
    with httpx.Client(timeout=15.0) as client:
        for label, service, action, expected in FAULTS:
            if service:
                compose("stop", service)
                time.sleep(2.0)
            during = _summarise(_send(client, action, per_fault))
            recovered = None
            if service:
                compose("start", service)
                recovered = _seconds_to_recover(client, action)
            allowed = during["outcomes"].get("ALLOW", 0)
            errors = sum(v for k, v in during["outcomes"].items() if k not in ("ALLOW", "DENY"))
            rows.append(
                {
                    "fault": label,
                    "action": action,
                    "expected_while_down": expected,
                    "during": during,
                    "fail_open_allows": allowed if expected == "DENY" else 0,
                    "errors_instead_of_decisions": errors,
                    "seconds_to_recover": recovered,
                    "passed": during["outcomes"].get(expected, 0) == per_fault
                    and (service is None or recovered is not None),
                }
            )
    rows.append(
        {
            "fault": "aegis-server unreachable (SDK guard)",
            "action": "read_report",
            "expected_while_down": "DENY",
            "during": (sdk := _sdk_with_server_down(per_fault)),
            "fail_open_allows": sdk["outcomes"].get("ALLOW", 0),
            "errors_instead_of_decisions": 0,
            "seconds_to_recover": None,
            "passed": sdk["outcomes"].get("DENY", 0) == per_fault,
        }
    )
    return {
        "per_fault_requests": per_fault,
        "summary": {
            "faults": len(rows) - 1,
            "fail_open_allows": sum(r["fail_open_allows"] for r in rows),
            "errors_instead_of_decisions": sum(r["errors_instead_of_decisions"] for r in rows),
            "all_passed": all(r["passed"] for r in rows),
        },
        "faults": rows,
    }


def main() -> None:
    if not wait_ready(10):
        raise SystemExit("aegis-server is not ready; start the stack first")
    result = run()
    for r in result["faults"]:
        mark = "ok  " if r["passed"] else "FAIL"
        d = r["during"]
        print(
            f"{mark} {r['fault']:<38} {d['outcomes']}  p50 {d['latency_ms_p50']} ms, "
            f"max {d['latency_ms_max']} ms, back in {r['seconds_to_recover']} s"
        )
    print(result["summary"])
    print("wrote", write_result("fail_closed", result))
    if not result["summary"]["all_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
