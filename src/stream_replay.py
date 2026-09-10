"""Stage 5 - replay cleaned flow rows through anomaly and classifier inference.

The replay is deliberately read-only and incremental from the consumer's
perspective: each row is converted to an alert decision before the next row is
processed. The current Parquet file has no timestamp or source-IP columns, so
the replay uses row order and a single link-level Kalman bank. Live adapters
can replace ``iter_rows`` once source and timestamp fields are available.

Run:
    python -m src.stream_replay --limit 10000
"""
from __future__ import annotations

import argparse
import json
import time
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd
from xgboost import XGBClassifier

from src import config
from src.alert_schema import ThreatAlert
from src.kalman_engine import KalmanBank


MODEL_PATH = config.MODELS_DIR / "xgb_binary_hardened.json"
FEATURE_PATH = config.MODELS_DIR / "feature_cols.json"
KALMAN_METRICS = ["Rate", "IAT", "syn_count"]


def iter_rows(path: Path, limit: int | None = None) -> Iterator[tuple[int, dict]]:
    """Yield feature dictionaries in deterministic file order."""
    frame = pd.read_parquet(path)
    if limit is not None:
        frame = frame.head(limit)
    for flow_id, row in enumerate(frame.to_dict(orient="records")):
        yield flow_id, row


class ThreatScorer:
    """Load the hardened model and convert one feature row into an alert."""

    def __init__(self, model_path: Path = MODEL_PATH, feature_path: Path = FEATURE_PATH):
        self.model = XGBClassifier()
        self.model.load_model(str(model_path))
        self.feature_cols = json.loads(feature_path.read_text())
        self.importances = dict(zip(self.feature_cols, self.model.feature_importances_))

    @staticmethod
    def _number(value: object) -> float:
        number = float(value) if value is not None else 0.0
        return number if np.isfinite(number) else 0.0

    def score(self, flow_id: int, row: dict, anomaly_score: float, anomaly_level: str,
              timestamp: float | None = None) -> ThreatAlert | None:
        values = np.array([[self._number(row.get(name, 0.0)) for name in self.feature_cols]])
        probability = float(self.model.predict_proba(values)[0, 1])
        if probability < 0.5:
            return None

        evidence_names = sorted(self.feature_cols, key=self.importances.get, reverse=True)[:5]
        evidence = {
            "classifier_probability": probability,
            "top_features": {
                name: self._number(row.get(name, 0.0)) for name in evidence_names
            },
        }
        if anomaly_level != "ok":
            evidence["kalman_metrics"] = {"level": anomaly_level}

        kalman_component = 1.0 - math.exp(-max(float(anomaly_score), 0.0) / 3.0)
        confidence = min(1.0, 0.7 * probability + 0.3 * kalman_component)
        evidence["score_fusion"] = {
            "classifier_weight": 0.7,
            "kalman_weight": 0.3,
            "kalman_component": kalman_component,
            "fused_confidence": confidence,
            "volume_claim": "not_assessed_without_packet_aggregation",
        }
        severity = "critical" if confidence >= 0.9 and anomaly_level == "alert" else (
            "high" if probability >= 0.9 else "medium"
        )
        return ThreatAlert(
            timestamp=(
                datetime.fromtimestamp(timestamp, tz=timezone.utc)
                if timestamp is not None else datetime.now(timezone.utc)
            ),
            flow_id=str(flow_id),
            threat_class="malicious",
            confidence=confidence,
            severity=severity,
            anomaly_score=max(float(anomaly_score), 0.0),
            anomaly_level=anomaly_level,
            evidence=evidence,
            model=MODEL_PATH.name,
        )


def replay(limit: int | None = None, output: Path | None = None) -> dict:
    """Replay rows, optionally writing newline-delimited JSON alerts."""
    scorer = ThreatScorer()
    bank = KalmanBank(KALMAN_METRICS, log_metrics=["Rate"])
    alerts: list[ThreatAlert] = []
    started = time.perf_counter()
    processed = 0

    for flow_id, row in iter_rows(config.CLEAN_PARQUET, limit):
        processed += 1
        anomaly_score, _, anomaly_level = bank.update({
            metric: row.get(metric) for metric in KALMAN_METRICS
        })
        alert = scorer.score(flow_id, row, anomaly_score, anomaly_level)
        if alert is not None:
            alerts.append(alert)
    elapsed = time.perf_counter() - started
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("\n".join(alert.model_dump_json() for alert in alerts) + ("\n" if alerts else ""))

    result = {
        "rows_processed": processed,
        "alerts": len(alerts),
        "elapsed_seconds": elapsed,
        "rows_per_second": processed / elapsed if elapsed else 0.0,
        "output": str(output) if output else None,
    }
    print(json.dumps(result, indent=2))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--output", type=Path, default=config.REPORTS_DIR / "alerts.jsonl")
    args = parser.parse_args()
    replay(args.limit, args.output)


if __name__ == "__main__":
    main()
