"""Latency and throughput of POST /v1/evaluate, and where the time goes.

Sends allowed requests at several concurrency levels against one
aegis-server replica, with tokens minted before the clock starts. Reports
client-side p50/p95/p99 and throughput, and the server's own per-stage
breakdown (from the Prometheus histogram it exports), so a slow stage can be
told apart from a slow client or network.

Compared: single-use tokens (a Redis write per token, the default) against
reusable tokens, and one tenant against the same load spread over several
(each tenant's audit chain is written under its own lock).

    python -m benchmarks.latency --requests 1000
"""

import argparse
import asyncio
import re
import statistics
import time

import httpx

from benchmarks._stack import BASE_URL, evaluate_request, setup_tenant, token_pair, write_result

POLICY = """
permit(principal, action == Action::"read_report", resource)
when { principal.role == "Analyst" };
"""

STAGE_RE = re.compile(r'aegis_evaluate_stage_latency_seconds_(sum|count)\{stage="([a-z_]+)"\} ([0-9.e+-]+)')


def _stage_totals() -> dict[str, dict[str, float]]:
    totals: dict[str, dict[str, float]] = {}
    for kind, stage, value in STAGE_RE.findall(httpx.get(f"{BASE_URL}/metrics", timeout=10).text):
        totals.setdefault(stage, {})[kind] = float(value)
    return totals


def _stage_means(before: dict, after: dict) -> dict[str, float]:
    means = {}
    for stage, a in after.items():
        b = before.get(stage, {"sum": 0.0, "count": 0.0})
        count = a.get("count", 0) - b.get("count", 0)
        if count:
            means[stage] = round((a["sum"] - b["sum"]) / count * 1000, 2)
    return means


async def _run(tenant: str | list[str], concurrency: int, n: int) -> dict:
    tenants = tenant if isinstance(tenant, list) else [tenant]
    requests = [
        evaluate_request(t, *token_pair(t), "read_report")
        for t in (tenants[i % len(tenants)] for i in range(n))
    ]
    latencies: list[float] = []
    outcomes: dict[str, int] = {}
    sem = asyncio.Semaphore(concurrency)
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)

    async with httpx.AsyncClient(timeout=30.0, limits=limits) as client:

        async def one(req):
            async with sem:
                start = time.perf_counter()
                resp = await client.post(**req)
                latencies.append((time.perf_counter() - start) * 1000)
                key = resp.json().get("decision") if resp.status_code == 200 else f"HTTP {resp.status_code}"
                outcomes[key] = outcomes.get(key, 0) + 1

        before = _stage_totals()
        start = time.perf_counter()
        await asyncio.gather(*(one(r) for r in requests))
        wall = time.perf_counter() - start
        after = _stage_totals()

    latencies.sort()

    def pct(p: float) -> float:
        return round(latencies[min(int(len(latencies) * p), len(latencies) - 1)], 1)

    return {
        "tenants": len(tenants),
        "concurrency": concurrency,
        "requests": n,
        "outcomes": outcomes,
        "throughput_rps": round(n / wall, 1),
        "latency_ms": {
            "p50": pct(0.50),
            "p95": pct(0.95),
            "p99": pct(0.99),
            "max": round(latencies[-1], 1),
            "mean": round(statistics.mean(latencies), 1),
        },
        "server_stage_mean_ms": _stage_means(before, after),
    }


async def run(n: int, levels: list[int], spread: int, only_spread: bool) -> dict:
    spread_tenants = [f"latency-spread-{i}" for i in range(spread)]
    for t in spread_tenants:
        setup_tenant(t, POLICY)
    setup_tenant("latency-single-use", POLICY, single_use_tokens=True)
    setup_tenant("latency-reusable", POLICY, single_use_tokens=False)
    await _run("latency-single-use", 10, 200)  # warm up pools, JWKS and policy caches
    await _run(spread_tenants, 10, 200)
    result = {}
    if not only_spread:
        result["single_use_tokens"] = [await _run("latency-single-use", c, n) for c in levels]
        result["reusable_tokens"] = [await _run("latency-reusable", c, n) for c in levels]
    result[f"spread_over_{spread}_tenants"] = [await _run(spread_tenants, c, n) for c in levels]
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--levels", default="1,10,25,50")
    parser.add_argument("--spread", type=int, default=8, help="tenants for the spread-load run")
    parser.add_argument("--only-spread", action="store_true")
    parser.add_argument("--label", default="latency", help="results file name")
    parser.add_argument(
        "--server-workers",
        type=int,
        default=1,
        help="uvicorn workers the server runs with (AEGIS_WORKERS); stage means are only kept for 1",
    )
    args = parser.parse_args()
    levels = [int(x) for x in args.levels.split(",")]
    result = asyncio.run(run(args.requests, levels, args.spread, args.only_spread))
    if args.server_workers > 1:
        # Each /metrics scrape reads one worker's counters, so deltas are meaningless.
        for rows in result.values():
            for r in rows if isinstance(rows, list) else []:
                r.pop("server_stage_mean_ms", None)
    result["server_workers"] = args.server_workers
    for mode, rows in result.items():
        if not isinstance(rows, list):
            continue
        print(f"\n{mode}")
        for r in rows:
            lat = r["latency_ms"]
            print(
                f"  c={r['concurrency']:<3} {r['throughput_rps']:>7} req/s  p50 {lat['p50']:>6} ms  "
                f"p95 {lat['p95']:>6}  p99 {lat['p99']:>6}  {r['outcomes']}"
            )
            print(f"         stages (server mean ms): {r['server_stage_mean_ms']}")
    print("wrote", write_result(args.label, result))


if __name__ == "__main__":
    main()
