"""Stage 5 score fusion and volumetric attack evidence."""
from __future__ import annotations

import math
from collections import defaultdict
from typing import Any


def _bounded_anomaly(score: float) -> float:
    return 1.0 - math.exp(-max(float(score), 0.0) / 3.0)


def enrich_flow_report(rows: list[dict[str, Any]], threshold: float) -> dict:
    """Add fused confidence, severity, and cautious DoS/DDoS evidence."""
    by_destination: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_destination[row["destination_ip"]].append(row)

    destination_summary = []
    for destination, destination_rows in by_destination.items():
        sources = {row["observed_source_ip"] for row in destination_rows}
        packets = sum(row["packets"] for row in destination_rows)
        bytes_total = sum(row["bytes"] for row in destination_rows)
        pps = sum(row["packets_per_second"] for row in destination_rows)
        if len(sources) >= 3 and packets >= 1000 and pps >= 1000:
            attack_type = "possible_ddos"
        elif len(sources) == 1 and packets >= 1000 and pps >= 1000:
            attack_type = "possible_dos"
        else:
            attack_type = "none"
        destination_summary.append({
            "destination_ip": destination,
            "source_ips": sorted(sources),
            "distinct_sources": len(sources),
            "flows": len(destination_rows),
            "packets": packets,
            "bytes": bytes_total,
            "packets_per_second": round(pps, 4),
            "attack_type": attack_type,
        })

    for row in rows:
        kalman_component = _bounded_anomaly(row["anomaly_score"])
        row["confidence"] = round(
            min(1.0, 0.7 * row["probability"] + 0.3 * kalman_component), 6
        )
        destination = next(
            item for item in destination_summary
            if item["destination_ip"] == row["destination_ip"]
        )
        row["destination_context"] = destination
        row["volumetric_evidence"] = {
            "packets": row["packets"],
            "bytes": row["bytes"],
            "packets_per_second": row["packets_per_second"],
            "distinct_sources_to_destination": destination["distinct_sources"],
            "dos_ddos_assessment": destination["attack_type"],
        }
        row["severity"] = (
            "high" if destination["attack_type"] != "none" and row["confidence"] >= 0.8
            else "medium" if row["flagged"] else "low"
        )
        if row["flagged"]:
            row["flag_reason"] = (
                f"Classifier probability {row['probability']:.3f} >= "
                f"threshold {threshold:.3f}; this flow has {row['packets']} packets "
                f"({row['bytes']} bytes), so volumetric assessment is "
                f"{destination['attack_type']}."
            )
        else:
            row["flag_reason"] = (
                f"Classifier probability {row['probability']:.3f} < "
                f"threshold {threshold:.3f}."
            )
    most_targeted = max(
        destination_summary,
        key=lambda item: (item["packets"], item["bytes"]),
        default=None,
    )
    return {
        "destinations": sorted(
            destination_summary, key=lambda item: item["packets"], reverse=True
        ),
        "most_targeted_destination": most_targeted,
        "dos_ddos_claim": (
            most_targeted["attack_type"] if most_targeted else "none"
        ),
    }
