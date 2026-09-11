"""Run the existing Kalman and classifier stages on PCAP-derived features."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from src.kalman_engine import KalmanBank
from src.stream_replay import ThreatScorer


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("features", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    scorer = ThreatScorer()
    bank = KalmanBank(["Rate", "IAT", "syn_count"], log_metrics=["Rate"])
    alerts = []
    processed = 0
    with args.features.open(encoding="utf-8") as stream:
        for line in stream:
            record = json.loads(line)
            features = record["features"]
            anomaly_score, _, anomaly_level = bank.update({
                metric: features.get(metric) for metric in ("Rate", "IAT", "syn_count")
            })
            alert = scorer.score(
                processed, features, anomaly_score, anomaly_level,
                timestamp=record.get("timestamp"),
            )
            if alert is not None:
                alert.flow_id = str(record["flow_id"])
                alert.evidence["source_ip"] = record.get("source_ip")
                alert.evidence["destination_ip"] = record.get("destination_ip")
                alerts.append(alert)
            processed += 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(item.model_dump_json() for item in alerts) + ("\n" if alerts else ""))
    print(json.dumps({
        "features": str(args.features),
        "flows_processed": processed,
        "alerts": len(alerts),
        "output": str(args.output),
    }, indent=2))


if __name__ == "__main__":
    main()
