# Live Callback Throughput and Latency Benchmark

## Purpose

This benchmark measures the actual live processing callback used by the
dashboard: `LiveSession.on_packet`. It includes live metadata extraction,
flow reconstruction, feature extraction, Kalman scoring, XGBoost inference,
and specialist evidence checks.

It does not send packets, probe hosts, decrypt payloads, or block traffic.

## Safe default: in-memory benchmark

Run from the repository root:

```text
python -m src.benchmark_live --packets 1000
```

This creates Scapy packet objects in memory and passes them directly to the
same callback used by Npcap. It measures processing overhead without touching
the network.

The first 1,000-packet development run measured **437.97 callback packets/sec**
with 1,000 active flows. All 1,000 synthetic flows were flagged by the
generic model; this is a synthetic feature-distribution artifact and is not a
detection-accuracy result.

## Optional authorized passive Npcap benchmark

Only run this on an interface and monitoring environment that you are
authorized to observe:

```text
python -m src.benchmark_live --interface "<Npcap interface>" --seconds 10
```

This mode only reads packets for the requested bounded duration. It does not
generate traffic. The result includes the observed packet count and callback
processing rate, but the rate depends on the traffic present during the
capture.

## Report fields

The command writes `reports/live_benchmark.json` containing:

- `packets_per_second`;
- elapsed seconds;
- active and processed flow counts;
- flagged-flow count;
- ignored packets;
- benchmark source and measurement scope.

The callback benchmark is a throughput measurement. Unlike the offline
benchmark, it does not currently record a per-packet latency percentile because
the callback is intentionally synchronized under the session lock and adding
per-packet timestamp storage would change the hot path. The offline benchmark
continues to provide P50/P95/P99 inference latency.

## Interpretation

Synthetic results demonstrate callback capacity under controlled packet
shapes, not real NIC capacity. Passive Npcap results demonstrate end-to-end
callback handling for the observed local traffic, but are not representative
of a saturated production link unless the capture is conducted under an
authorized controlled load.

Do not scan public websites or generate attack traffic for this benchmark.
