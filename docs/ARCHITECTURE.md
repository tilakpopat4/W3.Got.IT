# Architecture — Hybrid Streaming Threat-Detection Pipeline

## One-line summary
One-way traffic → flow records (metadata only) → feature vectors → **Kalman residual** (is it abnormal, fast) → **classifier** (what threat) → **scoring** (confidence/severity/evidence) → standardized alert → dashboard.

## Why hybrid (Kalman + classifier)
- **Kalman (Stage 3)** = fast, streaming, bounded-latency "*something is wrong now*" trigger on numeric time-series. Not a classifier.
- **Classifier (Stage 4)** = labels *what* the threat is with a probability. Not real-time-adaptive by itself.
- Together: **speed + accuracy**, satisfying the streaming / read-only / metadata-only constraints.

## Stage map

```
[0] One-way traffic --> [1] Ingest/Flow --> [2] Feature Extraction
                                                 |
                        +------------------------+---------------+
                        v                                        v
              [3] KALMAN anomaly engine              (strings/metadata bypass)
                        |                                        |
                        +------------------------+---------------+
                                                 v
                                 [4] CLASSIFIER (XGBoost + anomaly)
                                                 v
                                 [5] SCORING --> standardized ALERT (JSON)
                                                 v
                                 [6] STORAGE + DASHBOARD (live/replay)
```

| Stage | Purpose | Framework/Tool | Status |
|---|---|---|---|
| 0 | one-way traffic source / replay | Python, pcap/parquet | replay implemented |
| 1 | ingest -> flow records | Scapy/PyShark/Zeek | IPv4 PCAP adapter implemented |
| 2 | feature extraction / cleaning | pandas, numpy | Parquet + PCAP flow adapter implemented |
| 3 | Kalman anomaly engine | numpy (custom) | done |
| 4 | classifier | xgboost, scikit-learn, imbalanced-learn | done |
| 5 | scoring + alert schema | pydantic + XGBoost inference | implemented for replay |
| 6 | storage + dashboard | SQLite, FastAPI, static dashboard | basic PCAP dashboard implemented |

## Prevention model (important)
This system is **passive / alert-only**. It cannot block (no return path). Reaction order:
**Detect (our system) -> Decide (SOC/SIEM/SOAR) -> Block (operator's inline firewall/IPS)**.
The firewall sits on the live production path, in parallel to our monitoring branch — never downstream of us.

## Offline architecture boundary

The saved-PCAP/Parquet path is a protected offline workflow:

```text
offline PCAP/Parquet -> offline flow/features/replay -> offline reports
```

Live acquisition is a separate adapter:

```text
Npcap interface -> live_capture.py -> dashboard status
```

Live work must not change offline parsers, replay ordering, offline model
artifacts, or offline report formats. Shared feature extraction and scoring
helpers may only be changed when their existing offline behavior is preserved
and a focused offline regression check is run. Live-only state, expiration,
capture health, and interface handling belong in the live adapter/dashboard
surface.

## Tech stack (final)
Python 3.10 · pandas/numpy/pyarrow · custom Kalman · scikit-learn + xgboost + imbalanced-learn · pydantic · SQLite · FastAPI + WebSocket · Streamlit · Plotly.
