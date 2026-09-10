"""Passive live packet capture and incremental flow scoring."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from scapy.sendrecv import AsyncSniffer
from xgboost import XGBClassifier

from src.feature_extractor import flow_to_features
from src.flow_records import FlowRecord, _packet_metadata
from src.kalman_engine import KalmanBank
from src.stage5_scoring import enrich_flow_report


@dataclass
class LiveSession:
    model: XGBClassifier
    feature_cols: list[str]
    model_label: str
    threshold: float
    interface: str
    sniffer: AsyncSniffer | None = None
    started_at: float = field(default_factory=time.time)
    packet_count: int = 0
    flows: dict[tuple, FlowRecord] = field(default_factory=dict)
    decisions: dict[str, dict] = field(default_factory=dict)
    kalman: KalmanBank = field(default_factory=lambda: KalmanBank(
        ["Rate", "IAT", "syn_count"], log_metrics=["Rate"]
    ))
    lock: threading.Lock = field(default_factory=threading.Lock)
    error: str | None = None
    stopped: bool = False

    def on_packet(self, packet) -> None:
        metadata = _packet_metadata(packet)
        if metadata is None:
            return
        key, forward, size, flags, observed_key = metadata
        timestamp = float(packet.time)
        with self.lock:
            flow = self.flows.get(key)
            if flow is None:
                flow = FlowRecord(
                    flow_id=f"{key[0]}:{key[1]}-{key[2]}:{key[3]}/{key[4]}",
                    source_ip=key[0], source_port=key[1],
                    destination_ip=key[2], destination_port=key[3],
                    protocol=key[4], start_time=timestamp, end_time=timestamp,
                    observed_source_ip=observed_key[0],
                    observed_source_port=observed_key[1],
                    observed_destination_ip=observed_key[2],
                    observed_destination_port=observed_key[3],
                )
                self.flows[key] = flow
            flow.add(timestamp, size, forward, flags)
            self.packet_count += 1
            raw = flow.to_dict()
            features = flow_to_features(raw)
            values = np.array([[float(features.get(name, 0.0)) for name in self.feature_cols]])
            probability = float(self.model.predict_proba(values)[0, 1])
            anomaly_score, _, anomaly_level = self.kalman.update({
                metric: features.get(metric) for metric in ("Rate", "IAT", "syn_count")
            })
            self.decisions[flow.flow_id] = {
                "flow_id": flow.flow_id,
                "timestamp": raw["start_time"],
                "start_time_utc": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(raw["start_time"])
                ),
                "end_time_utc": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(raw["end_time"])
                ),
                "source_ip": raw["source_ip"],
                "source_port": raw["source_port"],
                "destination_ip": raw["destination_ip"],
                "destination_port": raw["destination_port"],
                "observed_source_ip": raw["observed_source_ip"],
                "observed_source_port": raw["observed_source_port"],
                "observed_destination_ip": raw["observed_destination_ip"],
                "observed_destination_port": raw["observed_destination_port"],
                "protocol": raw["protocol"],
                "packets": raw["packet_count"],
                "bytes": raw["byte_count"],
                "packets_per_second": round(
                    raw["packet_count"] / raw["duration"], 4
                ) if raw["duration"] > 0 else raw["packet_count"],
                "probability": round(probability, 6),
                "flagged": probability >= self.threshold,
                "anomaly_score": round(max(float(anomaly_score), 0.0), 6),
                "anomaly_level": anomaly_level,
                "kalman": {
                    "rate": round(float(features.get("Rate", 0.0)), 4),
                    "iat": round(float(features.get("IAT", 0.0)), 4),
                    "syn_count": round(float(features.get("syn_count", 0.0)), 4),
                },
                "top_features": {
                    name: round(float(features.get(name, 0.0)), 4)
                    for name in sorted(
                        self.feature_cols,
                        key=dict(zip(self.feature_cols, self.model.feature_importances_)).get,
                        reverse=True,
                    )[:5]
                },
                "flag_reason": (
                    f"XGBoost probability {probability:.3f} >= threshold {self.threshold:.3f}"
                    if probability >= self.threshold else
                    f"XGBoost probability {probability:.3f} < threshold {self.threshold:.3f}"
                ),
            }


class LiveCaptureManager:
    def __init__(self) -> None:
        self.session: LiveSession | None = None
        self.lock = threading.Lock()

    def start(
        self, interface: str, model: XGBClassifier, feature_cols: list[str],
        model_label: str, threshold: float,
    ) -> None:
        with self.lock:
            if self.session is not None and not self.session.stopped:
                raise RuntimeError("A live capture is already running")
            session = LiveSession(model, feature_cols, model_label, threshold, interface)
            try:
                session.sniffer = AsyncSniffer(
                    iface=interface, prn=session.on_packet, store=False
                )
                session.sniffer.start()
            except Exception as exc:
                session.error = str(exc)
                session.stopped = True
                raise RuntimeError(
                    f"Could not start capture on '{interface}'. Check Npcap, "
                    f"interface name, and administrator permissions: {exc}"
                ) from exc
            self.session = session

    def stop(self) -> None:
        with self.lock:
            if self.session is None or self.session.stopped:
                return
            if self.session.sniffer is not None:
                self.session.sniffer.stop()
            self.session.stopped = True

    def status(self) -> dict:
        with self.lock:
            session = self.session
            if session is None:
                return {"running": False, "flows": [], "packets": 0}
            with session.lock:
                flows = list(session.decisions.values())
                flows.sort(key=lambda item: item["timestamp"], reverse=True)
                flagged = sum(1 for item in flows if item["flagged"])
                attack_summary = enrich_flow_report(flows, session.threshold)
                elapsed = max(time.time() - session.started_at, 0.001)
                return {
                    "running": not session.stopped,
                    "interface": session.interface,
                    "model": session.model_label,
                    "algorithm": "XGBoost gradient-boosted trees (not Random Forest)",
                    "threshold": session.threshold,
                    "packets": session.packet_count,
                    "flows_processed": len(flows),
                    "flows_flagged": flagged,
                    "flag_rate": round(flagged / len(flows), 6) if flows else 0.0,
                    "packets_per_second": round(session.packet_count / elapsed, 2),
                    "read_only": True,
                    "payload_inspected": False,
                    "error": session.error,
                    "flows": flows[:500],
                    "attack_summary": attack_summary,
                }


LIVE_MANAGER = LiveCaptureManager()
