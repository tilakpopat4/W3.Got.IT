# Stage 3 — Kalman Anomaly Engine

**Code:** `src/kalman_engine.py`
**Report:** `reports/stage3_kalman.txt`
**Role:** Fast, streaming "*something is wrong now*" trigger. NOT a classifier.

## Design
- A **bank of tiny 1-D adaptive Kalman filters**, one per (entity, metric). In the live pipeline each source IP gets its own filter set; on the static dataset we run one filter per metric.
- **Random-walk state model** per scalar signal `x`:
  - predict: `x_pred = x`, `P_pred = P + Q`
  - innovation: `y = z - x_pred`, `S = P_pred + R`
  - **anomaly score = |y| / sqrt(S)** (normalized innovation / residual)
  - update: `K = P_pred/S`, `x = x_pred + K·y`, `P = (1-K)·P_pred`
- **Adaptive R:** measurement-noise `R` tracks a rolling innovation variance (EWMA, α=0.05) → self-tuning; deviations stand out sharply.
- **Log-space** (`log1p`) for bursty counts like `Rate` → stabilises non-Gaussian variance, fewer false spikes.
- **Warmup** (20 samples) suppresses early scores so the filter learns "normal" first.
- **Thresholds:** soft = 3.0 (watch / low severity), hard = 6.0 (alert).

## Metrics tracked
`Rate` (log-space), `IAT`, `syn_count` — extensible to `out:in ratio`, `new-dst-port rate`, etc.

## Results
**Self-test on shuffled static rows (benign vs Mirai):**
- benign mean 0.98 (p95 2.43) · attack mean 1.18 (p95 2.44) · **separation only 0.20** → weak.

**Controlled ordered-stream burst test (from audit):**
- steady baseline max **1.71** → injected flood peak **45.6** → **hard alert fires**.

## Key insight
Kalman is a **time-series** detector — it needs *ordered, per-source* observations. On shuffled per-window rows there is no temporal signal, so it looks weak; on a real ordered stream it spikes hard and correctly. This is expected behaviour and is why the Stage 0–1 ordered replay is the next build.

## Verified properties (audit)
NaN-safe ✅ · warmup suppression ✅ · self-adapting ✅ · burst detection ✅.
