"""Figures for the README and docs/benchmarks.md. Every plotted number is read
from a committed file in results/; nothing is typed in by hand.

    pip install matplotlib
    python -m benchmarks.plots            # writes results/figures/*.png
"""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

RESULTS = Path(__file__).resolve().parent.parent / "results"
OUT = RESULTS / "figures"

# Validated categorical slots (light surface); see docs/benchmarks.md for tables.
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
GRID = "#e4e3df"
BLUE, ORANGE, AQUA, YELLOW = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"

plt.rcParams.update(
    {
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
        "font.size": 11,
        "axes.edgecolor": GRID,
        "axes.labelcolor": INK_2,
        "xtick.color": INK_2,
        "ytick.color": INK_2,
        "text.color": INK,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.titleweight": "bold",
        "axes.titlesize": 12,
        "axes.titlelocation": "left",
    }
)


def _load(name: str) -> dict:
    return json.loads((RESULTS / f"{name}.json").read_text())


def _grid(ax, axis: str = "y") -> None:
    ax.grid(axis=axis, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _save(fig, name: str, note: str) -> None:
    # Below everything; bbox_inches="tight" grows the canvas to include it.
    fig.text(0.01, -0.02, note, fontsize=8.5, color=INK_2, ha="left", va="top")
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / name, dpi=160, bbox_inches="tight")
    plt.close(fig)
    print("wrote", OUT / name)


def fail_closed() -> None:
    rows = [r for r in _load("fail_closed")["faults"] if r["seconds_to_recover"] is not None]
    rows.sort(key=lambda r: r["seconds_to_recover"])
    labels = [r["fault"].replace(" stopped", "").replace(" (approval-required action)", "") for r in rows]
    secs = [r["seconds_to_recover"] for r in rows]

    fig, ax = plt.subplots(figsize=(8, 3.4))
    bars = ax.barh(labels, secs, color=BLUE, height=0.55, edgecolor=SURFACE, linewidth=2)
    for bar, r in zip(bars, rows, strict=True):
        during = r["during"]["outcomes"]
        what = f"{during.get('DENY', 0)}/40 denied" if "DENY" in during else "40/40 allowed (cached keys)"
        ax.text(
            bar.get_width() + 0.2,
            bar.get_y() + bar.get_height() / 2,
            f"{bar.get_width():.1f} s   ·   during outage: {what}",
            va="center",
            fontsize=9.5,
            color=INK,
        )
    ax.set_xlim(0, max(secs) * 1.9)
    ax.set_xlabel("seconds from restart until requests are allowed again")
    ax.set_title("Each dependency stopped in turn: nothing allowed while down, automatic recovery")
    _grid(ax, "x")
    fig.tight_layout()
    _save(
        fig,
        "fig1_fail_closed.png",
        "Source: results/fail_closed.json · 40 requests per fault · cedar-sidecar recovery = circuit-breaker cooldown",
    )


def masking_merge() -> None:
    versions = [("0.1.0", _load("annotation_merge_before")), ("0.2.0", _load("annotation_merge_after"))]
    parts = [
        ("both fields masked", "salary,ssn", BLUE),
        ("salary left unmasked", "ssn", ORANGE),
        ("ssn left unmasked", "salary", AQUA),
    ]
    fig, ax = plt.subplots(figsize=(8, 2.6))
    for y, (label, data) in enumerate(versions):
        left = 0
        for name, key, color in parts:
            n = data["outcomes"].get(key, 0)
            if not n:
                continue
            ax.barh(y, n, left=left, color=color, height=0.55, edgecolor=SURFACE, linewidth=2, label=name)
            ax.text(
                left + n / 2,
                y,
                f"{n}",
                ha="center",
                va="center",
                color="white",
                fontsize=10,
                fontweight="bold",
            )
            left += n
    ax.set_yticks(range(len(versions)), [f"cedar-sidecar {v}" for v, _ in versions])
    ax.invert_yaxis()
    ax.set_xlim(0, 500)
    ax.set_xlabel("requests (of 500) with two matching policies: one masks ssn, one masks salary")
    ax.set_title("Overlapping policies: 0.1.0 dropped a mask on every request; 0.2.0 keeps both", pad=30)
    handles, names = ax.get_legend_handles_labels()
    uniq = dict(zip(names, handles, strict=True))
    ax.legend(
        [uniq[n] for n, _, _ in parts if n in uniq],
        [n for n, _, _ in parts if n in uniq],
        frameon=False,
        ncol=3,
        loc="lower left",
        bbox_to_anchor=(0, 1.0),
        fontsize=9.5,
    )
    fig.tight_layout()
    _save(fig, "fig2_masking_merge.png", "Source: results/annotation_merge_{before,after}.json")


def latency() -> None:
    single = _load("latency")["single_use_tokens"]
    spread = _load("latency_spread_1worker")["spread_over_8_tenants"]
    series = [("1 tenant", single, BLUE), ("same load over 8 tenants", spread, ORANGE)]

    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8))
    for ax, pct in zip(axes, ("p50", "p95"), strict=True):
        for name, rows, color in series:
            xs = [r["concurrency"] for r in rows]
            ys = [r["latency_ms"][pct] for r in rows]
            ax.plot(
                xs,
                ys,
                color=color,
                linewidth=2,
                marker="o",
                markersize=7,
                markeredgecolor=SURFACE,
                markeredgewidth=2,
                label=name,
            )
            ax.annotate(
                f"{ys[-1]:.0f} ms",
                (xs[-1], ys[-1]),
                xytext=(6, 0),
                textcoords="offset points",
                va="center",
                fontsize=9.5,
                color=INK,
            )
        ax.set_title(f"{pct} latency")
        ax.set_xlabel("concurrent requests")
        ax.set_ylabel("ms (client side)")
        ax.set_xticks([1, 10, 25, 50])
        ax.set_xlim(0, 60)
        ax.set_ylim(0)
        _grid(ax)
    axes[0].legend(frameon=False, loc="upper left", fontsize=9.5)
    fig.suptitle(
        "Spreading load over 8 tenants cuts the p95 tail but not the median: one process is the next limit",
        x=0.01,
        ha="left",
        fontweight="bold",
        fontsize=12,
    )
    fig.tight_layout(rect=(0, 0, 1, 0.98))
    _save(
        fig,
        "fig3_latency.png",
        "Source: results/latency.json, results/latency_spread_1worker.json · 1,000 requests per point · one run each",
    )


def stages() -> None:
    panels = [
        ("1 tenant", _load("latency")["single_use_tokens"]),
        ("same load over 8 tenants", _load("latency_spread_1worker")["spread_over_8_tenants"]),
    ]
    parts = [
        ("rate limit", "rate_limit", BLUE),
        ("identity", "principal_validation", ORANGE),
        ("Cedar", "cedar_call", AQUA),
        ("audit write", "audit_write", YELLOW),
    ]

    fig, axes = plt.subplots(1, 2, figsize=(10, 3.9), sharey=True)
    for ax, (title, rows) in zip(axes, panels, strict=True):
        xs = [str(r["concurrency"]) for r in rows]
        bottom = [0.0] * len(rows)
        for name, key, color in parts:
            vals = [r["server_stage_mean_ms"].get(key, 0.0) for r in rows]
            ax.bar(
                xs, vals, bottom=bottom, color=color, width=0.6, edgecolor=SURFACE, linewidth=2, label=name
            )
            bottom = [b + v for b, v in zip(bottom, vals, strict=True)]
        audit = [r["server_stage_mean_ms"]["audit_write"] for r in rows]
        for i, (total, a) in enumerate(zip(bottom, audit, strict=True)):
            ax.text(i, total + 2, f"audit {a:.0f}", ha="center", fontsize=9, color=INK)
        ax.set_title(title)
        ax.set_xlabel("concurrent requests")
        _grid(ax)
    axes[0].set_ylabel("server time per request, mean ms")
    axes[1].legend(frameon=False, loc="upper left", fontsize=9.5)
    fig.suptitle(
        "Where the server's time goes: on one tenant the audit-chain lock dominates under load",
        x=0.01,
        ha="left",
        fontweight="bold",
        fontsize=12,
    )
    fig.tight_layout(rect=(0, 0, 1, 0.98))
    _save(
        fig,
        "fig4_stages.png",
        "Source: server Prometheus histogram in results/latency*.json · policy lookup (<0.2 ms) omitted · one worker",
    )


def main() -> None:
    fail_closed()
    masking_merge()
    latency()
    stages()


if __name__ == "__main__":
    main()
