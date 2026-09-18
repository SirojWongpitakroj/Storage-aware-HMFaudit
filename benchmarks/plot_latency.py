#!/usr/bin/env python3
"""Summarize and graph HMF verification/localization latency samples."""

from __future__ import annotations

import argparse
import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path


OPERATION_TITLES = {
    "hmf_verification": "HMF verification",
    "tamper_localization": "Tamper localization",
    "localization_proof_verification": "Localization-proof verification",
}


def nearest_rank(values: list[int], quantile: float) -> int:
    ordered = sorted(values)
    index = max(0, math.ceil(quantile * len(ordered)) - 1)
    return ordered[index]


def read_samples(path: Path) -> dict[tuple[str, str, int], list[int]]:
    groups: dict[tuple[str, str, int], list[int]] = defaultdict(list)
    with path.open(newline="", encoding="utf-8") as source:
        for row in csv.DictReader(source):
            key = (row["operation"], row["placement"], int(row["batch_size"]))
            groups[key].append(int(row["latency_ns"]))
    if not groups:
        raise ValueError(f"no samples found in {path}")
    return groups


def summarize(groups: dict[tuple[str, str, int], list[int]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for (operation, placement, batch_size), values in sorted(groups.items()):
        rows.append(
            {
                "operation": operation,
                "placement": placement,
                "batch_size": batch_size,
                "samples": len(values),
                "mean_ms": statistics.fmean(values) / 1_000_000,
                "p50_ms": nearest_rank(values, 0.50) / 1_000_000,
                "p95_ms": nearest_rank(values, 0.95) / 1_000_000,
                "p99_ms": nearest_rank(values, 0.99) / 1_000_000,
                "min_ms": min(values) / 1_000_000,
                "max_ms": max(values) / 1_000_000,
            }
        )
    return rows


def write_summary(path: Path, rows: list[dict[str, object]]) -> None:
    fields = [
        "operation",
        "placement",
        "batch_size",
        "samples",
        "mean_ms",
        "p50_ms",
        "p95_ms",
        "p99_ms",
        "min_ms",
        "max_ms",
    ]
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def plot(path: Path, rows: list[dict[str, object]]) -> None:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as error:
        raise SystemExit("matplotlib is required: python -m pip install matplotlib") from error

    operations = [operation for operation in OPERATION_TITLES if any(row["operation"] == operation for row in rows)]
    figure, axes = plt.subplots(1, len(operations), figsize=(6 * len(operations), 5), squeeze=False)
    colors = {"clustered": "#2563eb", "scattered": "#dc2626"}
    styles = {"p50_ms": ("-", "o", "P50"), "p95_ms": ("--", "^", "P95"), "p99_ms": (":", "x", "P99")}

    for column, operation in enumerate(operations):
        axis = axes[0][column]
        operation_rows = [row for row in rows if row["operation"] == operation]
        for placement in ("clustered", "scattered"):
            selected = sorted(
                (row for row in operation_rows if row["placement"] == placement),
                key=lambda row: int(row["batch_size"]),
            )
            if not selected:
                continue
            x_values = [int(row["batch_size"]) for row in selected]
            for field, (line_style, marker, percentile) in styles.items():
                axis.plot(
                    x_values,
                    [float(row[field]) for row in selected],
                    color=colors[placement],
                    linestyle=line_style,
                    marker=marker,
                    linewidth=1.8,
                    label=f"{placement} {percentile}",
                )
        axis.set_title(OPERATION_TITLES[operation])
        axis.set_xlabel("Audited batch size")
        axis.set_ylabel("Latency (ms)")
        axis.set_xscale("log", base=2)
        axis.set_yscale("log")
        axis.grid(True, which="both", alpha=0.25)
        axis.legend(fontsize=8)

    figure.suptitle("HMF verification and tamper-localization latency (k=15)")
    figure.tight_layout()
    figure.savefig(path, dpi=180, bbox_inches="tight")
    plt.close(figure)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="benchmarks/results/latency_raw.csv", type=Path)
    parser.add_argument("--output-dir", default="benchmarks/results", type=Path)
    arguments = parser.parse_args()

    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    rows = summarize(read_samples(arguments.input))
    summary_path = arguments.output_dir / "latency_summary.csv"
    graph_path = arguments.output_dir / "latency_percentiles.png"
    write_summary(summary_path, rows)
    plot(graph_path, rows)
    print(f"summary: {summary_path}")
    print(f"graph:   {graph_path}")


if __name__ == "__main__":
    main()
