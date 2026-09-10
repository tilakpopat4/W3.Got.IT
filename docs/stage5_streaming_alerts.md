# Stage 5 — Streaming Replay, Scoring, and Alerts

## Purpose

Stage 5 connects the existing Kalman detector and hardened binary classifier
into a row-by-row replay pipeline. It is an alert-only component: it reads
the cleaned Parquet artifact and never sends traffic, probes a host, or calls
back into the monitored network.

## Files

- `src/stream_replay.py` — deterministic Parquet replay and inference
- `src/alert_schema.py` — Pydantic `ThreatAlert` contract
- `src/kalman_engine.py` — invalid measurements are ignored without poisoning state

## Processing flow

For each row:

1. Read the next cleaned feature record.
2. Update the link-level Kalman bank using `Rate`, `IAT`, and `syn_count`.
3. Run the hardened binary XGBoost model.
4. Discard benign predictions below the 0.5 malicious-probability threshold.
5. Emit a JSON Lines alert for malicious predictions.

The current dataset has no timestamp, source IP, destination IP, or stable flow
identifier. Therefore the replay uses deterministic row order and the row index
as `flow_id`. This is a documented limitation, not an assumption that the
dataset is a real ordered network stream.

## Alert contract

Each alert contains:

- UTC `timestamp`
- `flow_id`
- `threat_class`
- calibrated model probability field named `confidence`
- `severity`
- `anomaly_score`
- `anomaly_level`
- top model features and their values in `evidence`
- model artifact name

Example command:

```text
python -m src.stream_replay --limit 10000 --output reports/alerts.jsonl
```

The command prints `rows_processed`, alert count, elapsed seconds, and measured
rows per second. The throughput number is a local replay measurement, not a
claim about packet-line-rate performance.

## Validation

The Stage 3 audit previously found a false “NaN-safe” result because warmup
masked the corrupted state. Stage 5 fixes this at the producer: non-finite
measurements are ignored before Kalman state mutation. A focused runtime check
must verify that the score, state, covariance, and noise remain finite.

The focused Kalman runtime check passed. The 1,000-row replay smoke test could
not run in the repository `.venv`: NumPy failed to load its
`_bounded_integers` Windows DLL because an Application Control policy blocked
the extension. This is an environment/runner issue rather than a replay
exception; the project environment must be repaired before recording the
throughput benchmark.

## Remaining limitations

- No source/entity keying until source fields are available.
- No timestamp reconstruction.
- The binary model produces `malicious`, not DDoS versus botnet subclasses.
- No API, persistence, or dashboard yet.
- Additional datasets remain necessary for DGA/DNS tunnelling, encrypted
  malware metadata, scanning, and exfiltration coverage.
