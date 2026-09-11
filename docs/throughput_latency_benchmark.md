# Throughput and Latency Benchmark

## Purpose

The SIH-145 problem statement requires the prototype to state and demonstrate
a traffic-processing rate and bounded alert latency. This benchmark measures
the existing incremental offline replay path using the cleaned Parquet flow
dataset.

The benchmark is intentionally honest about its scope:

- it measures flow inference and Kalman processing after the Parquet frame is
  loaded;
- it does not claim packet-line-rate, Npcap, disk-read, or network-interface
  performance;
- the estimated Mbps value is derived from the available byte-size feature and
  is not a wire-level measurement;
- per-flow latency includes Kalman update and XGBoost scoring;
- no traffic is generated and no network destination is contacted.

## Reproduction

From the repository root:

```text
python -m src.benchmark_replay --limit 10000
```

For the complete cleaned dataset:

```text
python -m src.benchmark_replay
```

The command prints JSON and writes:

```text
reports/replay_benchmark.json
```

## Recorded development-machine result

The first 10,000-row run on the Windows development machine produced:

| Measurement | Result |
|---|---:|
| Rows processed | 10,000 |
| Alerts | 30 |
| Replay throughput | 1,750.26 flows/sec |
| Estimated traffic rate | 3.58 Mbps |
| P50 per-flow latency | 0.4446 ms |
| P95 per-flow latency | 0.8721 ms |
| P99 per-flow latency | 1.8675 ms |
| Maximum per-flow latency | 134.2895 ms |

The maximum is an outlier and should not be confused with the P95 bounded
latency result. These values are specific to this machine, Python process,
model artifact, and 10,000-row input.

## Measurements

The report contains:

- `rows_processed`: number of flow rows processed;
- `flows_per_second`: incremental flow-processing throughput;
- `estimated_mbps`: estimated Mbps from the available size column;
- `elapsed_seconds`: measured processing duration;
- `per_flow_latency_ms.p50`: median flow-processing latency;
- `per_flow_latency_ms.p95`: P95 flow-processing latency;
- `per_flow_latency_ms.p99`: P99 flow-processing latency;
- `per_flow_latency_ms.max`: maximum observed flow-processing latency;
- `alerts`: number of generated standardized alerts.

P95 latency is the primary bounded-latency indicator. It should be reported
with the machine, Python version, model artifact, dataset limit, and whether
the result came from a warm or cold process.

## Interpretation

This result demonstrates the performance of the current replay/inference
implementation on the development machine. It is not a guarantee for a
production data diode, a specific NIC, or a different CPU.

The next performance phase should benchmark the live Npcap callback path
separately, because capture, flow reconstruction, expiration, and WebSocket
delivery add work that is not included in this offline measurement.
