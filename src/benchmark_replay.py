"""Benchmark incremental replay throughput and per-flow alert latency.

Run:
    python -m src.benchmark_replay --limit 10000

The benchmark measures the existing offline replay path after the Parquet
frame has been loaded. It does not claim packet-line-rate performance.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from src import config
from src.kalman_engine import KalmanBank
from src.stream_replay import KALMAN_METRICS, ThreatScorer


def _numeric_sum(frame: pd.DataFrame, names: tuple[str, ...]) -> float:
    for name in names:
        if name in frame.columns:
            values = pd.to_numeric(frame[name], errors="coerce").fillna(0.0)
            return float(values.clip(lower=0.0).sum())
    return 0.0


def benchmark(limit: int | None = None, output: Path | None = None) -> dict:
    """Measure replay throughput and P50/P95 per-flow processing latency."""
    frame = pd.read_parquet(config.CLEAN_PARQUET)
    if limit is not None:
        frame = frame.head(limit)

    scorer = ThreatScorer()
    bank = KalmanBank(KALMAN_METRICS, log_metrics=["Rate"])
    latencies_ns: list[int] = []
    alerts = 0
    started = time.perf_counter_ns()

    for flow_id, row in enumerate(frame.to_dict(orient="records")):
        flow_started = time.perf_counter_ns()
        anomaly_score, _, anomaly_level = bank.update({
            metric: row.get(metric) for metric in KALMAN_METRICS
        })
        if scorer.score(flow_id, row, anomaly_score, anomaly_level) is not None:
            alerts += 1
        latencies_ns.append(time.perf_counter_ns() - flow_started)

    elapsed_ns = time.perf_counter_ns() - started
    elapsed_seconds = elapsed_ns / 1_000_000_000
    processed = len(frame)
    latency_ms = np.asarray(latencies_ns, dtype=np.float64) / 1_000_000
    total_bytes = _numeric_sum(frame, ("Tot size", "Tot sum", "Total Length of Fwd Packets"))

    result = {
        "rows_processed": processed,
        "alerts": alerts,
        "elapsed_seconds": elapsed_seconds,
        "flows_per_second": processed / elapsed_seconds if elapsed_seconds else 0.0,
        "estimated_mbps": (total_bytes * 8 / elapsed_seconds / 1_000_000)
        if elapsed_seconds else 0.0,
        "per_flow_latency_ms": {
            "p50": float(np.percentile(latency_ms, 50)) if processed else 0.0,
            "p95": float(np.percentile(latency_ms, 95)) if processed else 0.0,
            "p99": float(np.percentile(latency_ms, 99)) if processed else 0.0,
            "max": float(np.max(latency_ms)) if processed else 0.0,
        },
        "measurement_scope": "inference_and_kalman_after_parquet_load",
        "input": str(config.CLEAN_PARQUET),
    }
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        result["output"] = str(output)
    print(json.dumps(result, indent=2))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--output",
        type=Path,
        default=config.REPORTS_DIR / "replay_benchmark.json",
    )
    args = parser.parse_args()
    benchmark(args.limit, args.output)


if __name__ == "__main__":
    main()
