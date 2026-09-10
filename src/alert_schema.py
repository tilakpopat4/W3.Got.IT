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

