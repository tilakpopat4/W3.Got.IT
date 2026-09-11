"""Stage 5 alert contract for passive threat detections."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class ThreatAlert(BaseModel):
    """Structured, alert-only output emitted by the replay or live pipeline."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    flow_id: str
    threat_class: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: str
    anomaly_score: float = Field(ge=0.0)
    anomaly_level: str
    evidence: dict[str, Any]
    model: str


def alert_from_row(row: dict[str, Any], model: str) -> ThreatAlert | None:
    """Convert an enriched flagged flow into the shared alert contract."""
    if not row.get("flagged"):
        return None
    return ThreatAlert(
        timestamp=datetime.fromtimestamp(
            float(row["timestamp"]), tz=timezone.utc
        ),
        flow_id=str(row["flow_id"]),
        threat_class=str(row.get("threat_class", "generic_malicious_flow")),
        confidence=float(row.get("confidence", row.get("probability", 0.0))),
        severity=str(row.get("severity", "medium")),
        anomaly_score=max(float(row.get("anomaly_score", 0.0)), 0.0),
        anomaly_level=str(row.get("anomaly_level", "ok")),
        evidence={
            "classifier_probability": float(row.get("probability", 0.0)),
            "threat_evidence": row.get("threat_evidence"),
            "volumetric_evidence": row.get("volumetric_evidence"),
            "flag_reason": row.get("flag_reason"),
        },
        model=model,
    )
