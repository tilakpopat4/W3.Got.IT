"""
Stage 3 - Kalman anomaly engine (real-time "something's wrong" trigger).

Design
------
* We use a bank of tiny 1-D constant-velocity-less (random-walk) Kalman filters,
  one per (entity, metric). For the parquet dataset we don't have a source-IP
  column, so we treat the stream as a single link and run one filter per metric;
  in the live pipeline the same class is keyed per source IP.

* Each filter tracks a scalar signal x_t (e.g. Rate). Model:
      predict:  x_pred = x        (random walk)      P_pred = P + Q
      innovation: y = z - x_pred                     S = P_pred + R
      normalized residual (anomaly score): z_score = |y| / sqrt(S)
      update:   K = P_pred / S ; x = x_pred + K*y ;  P = (1-K)*P_pred

* Q (process noise) = how fast normal behaviour may drift.
  R (measurement noise) = normal jitter of the signal.
  Both are adapted online from a rolling estimate of the innovation variance,
  which makes the filter self-tuning (robust + aggressive).

* Bursty counts are non-Gaussian, so signals can be tracked in log-space
  (log1p) to stabilise variance -> fewer false spikes.

Anomaly score per observation = max over tracked metrics of the normalized
residual. Two thresholds:
    soft (default 3.0)  -> "watch" (low severity)
    hard (default 6.0)  -> "alert"

Run a self-test:  python -m src.kalman_engine
"""
from __future__ import annotations
import numpy as np


class KalmanScalar:
    """A minimal adaptive 1-D Kalman filter returning a normalized residual."""

    def __init__(self, q: float = 1e-3, r: float = 1.0, log_space: bool = False,
                 adapt: bool = True, warmup: int = 20):
        self.x = None          # state estimate
        self.P = 1.0           # estimate covariance
        self.Q = q             # process noise
        self.R = r             # measurement noise
        self.log_space = log_space
        self.adapt = adapt
        self.warmup = warmup
        self.n = 0
        self._innov_var = None  # rolling innovation variance (for adaptation)

    def _tx(self, z: float) -> float:
        return np.log1p(max(z, 0.0)) if self.log_space else float(z)

    def update(self, z: float) -> float:
        """Feed one measurement; return normalized residual (anomaly score)."""
        if not np.isfinite(z):
            return 0.0
        z = self._tx(z)
        self.n += 1

        # initialise on first sample
        if self.x is None:
            self.x = z
            self.P = 1.0
            return 0.0

        # --- predict ---
        x_pred = self.x
        P_pred = self.P + self.Q

        # --- innovation ---
        y = z - x_pred
        S = P_pred + self.R
        score = abs(y) / np.sqrt(S) if S > 0 else 0.0

        # --- adapt R from rolling innovation variance ---
        if self.adapt:
            if self._innov_var is None:
                self._innov_var = y * y
            else:
                self._innov_var = 0.95 * self._innov_var + 0.05 * (y * y)
            # keep R near the observed innovation variance (floored)
            self.R = max(self._innov_var, 1e-6)

        # --- update ---
        K = P_pred / S if S > 0 else 0.0
        self.x = x_pred + K * y
        self.P = (1.0 - K) * P_pred

        # suppress scores during warmup so the filter can learn "normal"
        if self.n <= self.warmup:
            return 0.0
        return float(score)


class KalmanBank:
    """One KalmanScalar per metric (per entity in the live pipeline)."""

    def __init__(self, metrics, log_metrics=None, soft=3.0, hard=6.0):
        self.soft = soft
        self.hard = hard
        log_metrics = set(log_metrics or [])
        self.filters = {
            m: KalmanScalar(log_space=(m in log_metrics)) for m in metrics
        }

    def update(self, row: dict):
        """row: {metric: value}. Returns (max_score, per_metric_scores, level)."""
        scores = {}
        for m, filt in self.filters.items():
            if m in row and row[m] is not None:
                scores[m] = filt.update(float(row[m]))
        max_score = max(scores.values()) if scores else 0.0
        level = "alert" if max_score >= self.hard else ("watch" if max_score >= self.soft else "ok")
        return max_score, scores, level


# ----------------------------- self-test -----------------------------
def _self_test():
    import pandas as pd
    from src import config

    df = pd.read_parquet(config.CLEAN_PARQUET)
    metrics = [m for m in ["Rate", "IAT", "syn_count"] if m in df.columns]
    log_metrics = ["Rate"]  # bursty -> track in log space

    # Build a stream: 300 benign rows (learn normal) then benign vs Mirai test
    benign = df[df[config.LABEL_COL] == "Benign"]
    mirai = df[df[config.LABEL_COL] == "Mirai"]

    def stream_scores(warm_rows, test_rows):
        bank = KalmanBank(metrics, log_metrics=log_metrics)
        for _, r in warm_rows.iterrows():
            bank.update({m: r[m] for m in metrics})
        out = []
        for _, r in test_rows.iterrows():
            s, _, lvl = bank.update({m: r[m] for m in metrics})
            out.append((s, lvl))
        return out

    warm = benign.head(300)
    ben_test = benign.iloc[300:800]
    att_test = mirai.head(500)

    ben = stream_scores(warm, ben_test)
    att = stream_scores(warm, att_test)

    ben_scores = np.array([s for s, _ in ben])
    att_scores = np.array([s for s, _ in att])

    def frac_alert(scores, thr):
        return float((scores >= thr).mean())

    print("=== STAGE 3 KALMAN SELF-TEST (benign vs Mirai) ===")
    print(f"metrics tracked         : {metrics} (log: {log_metrics})")
    print(f"benign  mean score      : {ben_scores.mean():.3f}   p95: {np.percentile(ben_scores,95):.3f}")
    print(f"attack  mean score      : {att_scores.mean():.3f}   p95: {np.percentile(att_scores,95):.3f}")
    print(f"benign  %>=soft(3.0)    : {frac_alert(ben_scores,3.0)*100:5.1f}%   (false-positive proxy)")
    print(f"attack  %>=soft(3.0)    : {frac_alert(att_scores,3.0)*100:5.1f}%   (detection proxy)")
    print(f"benign  %>=hard(6.0)    : {frac_alert(ben_scores,6.0)*100:5.1f}%")
    print(f"attack  %>=hard(6.0)    : {frac_alert(att_scores,6.0)*100:5.1f}%")
    sep = att_scores.mean() - ben_scores.mean()
    print(f"separation (attack-benign mean) : {sep:.3f}")

    out = (
        "=== STAGE 3 KALMAN SELF-TEST (benign vs Mirai) ===\n"
        f"metrics: {metrics} log:{log_metrics}\n"
        f"benign mean={ben_scores.mean():.3f} p95={np.percentile(ben_scores,95):.3f}\n"
        f"attack mean={att_scores.mean():.3f} p95={np.percentile(att_scores,95):.3f}\n"
        f"benign %>=3.0={frac_alert(ben_scores,3.0)*100:.1f}% attack %>=3.0={frac_alert(att_scores,3.0)*100:.1f}%\n"
        f"benign %>=6.0={frac_alert(ben_scores,6.0)*100:.1f}% attack %>=6.0={frac_alert(att_scores,6.0)*100:.1f}%\n"
        f"separation={sep:.3f}\n"
    )
    (config.REPORTS_DIR / "stage3_kalman.txt").write_text(out)
    print(f"\n[done] report -> {config.REPORTS_DIR / 'stage3_kalman.txt'}")


if __name__ == "__main__":
    _self_test()
