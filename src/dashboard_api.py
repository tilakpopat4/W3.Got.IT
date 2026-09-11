"""Basic read-only PCAP analysis API for the local dashboard."""
from __future__ import annotations

import json
import asyncio
import tempfile
import time
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path

import numpy as np
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, WebSocket
from starlette.websockets import WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from xgboost import XGBClassifier
from scapy.all import get_if_list
from scapy.arch.windows import get_windows_if_list

from src import config
from src.alert_schema import alert_from_row
from src.feature_extractor import flow_to_features
from src.flow_records import read_pcap
from src.kalman_engine import KalmanBank
from src.live_capture import LIVE_MANAGER
from src.live_calibration import summarize_probabilities
from src.stage5_scoring import enrich_flow_report


ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = ROOT / "dashboard"
MODEL_OPTIONS = {
    "generic": (config.MODELS_DIR / "xgb_binary_hardened.json",
                config.MODELS_DIR / "feature_cols.json",
                "Generic flow model"),
    "mythic_c2": (config.MODELS_DIR / "tqh_c2_xgb.json",
                  config.MODELS_DIR / "tqh_c2_feature_cols.json",
                  "TQH Mythic HTTP C2 model"),
}

app = FastAPI(title="SIH-145 Passive PCAP Dashboard")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def load_model(model_name: str) -> tuple[XGBClassifier, list[str], str]:
    paths = MODEL_OPTIONS.get(model_name)
    if paths is None:
        raise HTTPException(status_code=400, detail=f"Unknown model: {model_name}")
    model_path, feature_path, label = paths
    if not model_path.exists() or not feature_path.exists():
        raise HTTPException(status_code=503, detail=f"Model artifacts missing for {model_name}")
    model = XGBClassifier()
    model.load_model(str(model_path))
    return model, json.loads(feature_path.read_text(encoding="utf-8")), label


def analyze(
    path: Path, model_name: str, threshold: float, limit: int | None,
    display_name: str | None = None,
) -> dict:
    model, feature_cols, model_label = load_model(model_name)
    importances = dict(zip(feature_cols, model.feature_importances_))
    bank = KalmanBank(["Rate", "IAT", "syn_count"], log_metrics=["Rate"])
    started = time.perf_counter()
    rows: list[dict] = []
    for index, flow in enumerate(read_pcap(path, limit)):
        raw = flow.to_dict()
        features = flow_to_features(raw)
        values = np.array([[float(features.get(name, 0.0)) for name in feature_cols]])
        probability = float(model.predict_proba(values)[0, 1])
        anomaly_score, _, anomaly_level = bank.update({
            metric: features.get(metric) for metric in ("Rate", "IAT", "syn_count")
        })
        flagged = probability >= threshold
        top_features = sorted(feature_cols, key=importances.get, reverse=True)[:5]
        rows.append({
            "flow_id": raw["flow_id"],
            "timestamp": raw["start_time"],
            "start_time_utc": datetime.fromtimestamp(raw["start_time"], timezone.utc).isoformat(),
            "end_time_utc": datetime.fromtimestamp(raw["end_time"], timezone.utc).isoformat(),
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
            "duration": raw["duration"],
            "packets_per_second": round(raw["packet_count"] / raw["duration"], 4)
            if raw["duration"] > 0 else raw["packet_count"],
            "bytes_per_second": round(raw["byte_count"] / raw["duration"], 4)
            if raw["duration"] > 0 else raw["byte_count"],
            "probability": round(probability, 6),
            "flagged": flagged,
            "anomaly_score": round(max(float(anomaly_score), 0.0), 6),
            "anomaly_level": anomaly_level,
            "kalman": {
                "rate": round(float(features.get("Rate", 0.0)), 4),
                "iat": round(float(features.get("IAT", 0.0)), 4),
                "syn_count": round(float(features.get("syn_count", 0.0)), 4),
            },
            "top_features": {
                name: round(float(features.get(name, 0.0)), 4) for name in top_features
            },
            "flag_reason": (
                f"XGBoost probability {probability:.3f} >= threshold {threshold:.3f}"
                if flagged else f"XGBoost probability {probability:.3f} < threshold {threshold:.3f}"
            ),
        })
    elapsed = time.perf_counter() - started
    flagged_rows = [row for row in rows if row["flagged"]]
    attack_summary = enrich_flow_report(rows, threshold)
    alerts = [
        alert.model_dump(mode="json")
        for row in rows
        if (alert := alert_from_row(row, model_label)) is not None
    ]
    return {
        "file": display_name or path.name,
        "model": model_label,
        "algorithm": "XGBoost gradient-boosted trees (not Random Forest)",
        "model_name": model_name,
        "threshold": threshold,
        "flows_processed": len(rows),
        "flows_flagged": len(flagged_rows),
        "flag_rate": round(len(flagged_rows) / len(rows), 6) if rows else 0.0,
        "elapsed_seconds": round(elapsed, 4),
        "flows_per_second": round(len(rows) / elapsed, 2) if elapsed else 0.0,
        "read_only": True,
        "payload_inspected": False,
        "flows": rows,
        "alerts": alerts,
        "attack_summary": attack_summary,
    }


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/api/analyze")
async def analyze_upload(
    file: UploadFile = File(...),
    model: str = Form("generic"),
    threshold: float = Form(0.5),
    limit: int = Form(10000),
) -> dict:
    if not file.filename or not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Upload a .pcap or .pcapng file")
    if not 0.0 <= threshold <= 1.0:
        raise HTTPException(status_code=400, detail="Threshold must be between 0 and 1")
    if limit < 1 or limit > 100000:
        raise HTTPException(status_code=400, detail="Flow limit must be between 1 and 100000")
    suffix = Path(file.filename).suffix.lower()
    with tempfile.NamedTemporaryFile(prefix="sih145_", suffix=suffix, delete=False) as temporary:
        temporary.write(await file.read())
        temporary_path = Path(temporary.name)
    try:
        return analyze(temporary_path, model, threshold, limit, file.filename)
    finally:
        temporary_path.unlink(missing_ok=True)


@app.post("/api/live/start")
def start_live(
    interface: str = Form(...),
    model: str = Form("generic"),
    threshold: float = Form(0.5),
    target_ips: str = Form(""),
) -> dict:
    if not interface.strip():
        raise HTTPException(status_code=400, detail="Capture interface is required")
    if not 0.0 <= threshold <= 1.0:
        raise HTTPException(status_code=400, detail="Threshold must be between 0 and 1")
    parsed_targets: set[str] = set()
    for value in target_ips.split(","):
        value = value.strip()
        if not value:
            continue
        try:
            parsed_targets.add(str(ip_address(value)))
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid target IP address: {value}",
            ) from exc
    loaded_model, feature_cols, model_label = load_model(model)
    try:
        LIVE_MANAGER.start(
            interface.strip(), loaded_model, feature_cols, model_label, threshold,
            frozenset(parsed_targets),
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return LIVE_MANAGER.status()


@app.post("/api/live/stop")
def stop_live() -> dict:
    LIVE_MANAGER.stop()
    return LIVE_MANAGER.status()


@app.get("/api/live/calibration")
def live_calibration() -> dict:
    """Summarize live probabilities as a benign-session calibration aid."""
    status = LIVE_MANAGER.status()
    return {
        "capture": {
            "running": status.get("running", False),
            "packets": status.get("packets", 0),
            "packets_analyzed": status.get("packets_analyzed", 0),
            "target_ips": status.get("target_ips", []),
            "model": status.get("model"),
            "threshold": status.get("threshold"),
        },
        "calibration": summarize_probabilities(status.get("flows", [])),
    }


@app.get("/api/live/status")
def live_status() -> dict:
    return LIVE_MANAGER.status()


@app.websocket("/ws/live-alerts")
async def live_alerts(websocket: WebSocket) -> None:
    """Stream new live alerts and periodic status snapshots to one client."""
    await websocket.accept()
    sent_alert_ids: set[str] = set()
    try:
        while True:
            status = LIVE_MANAGER.status()
            new_alerts = [
                alert for alert in status.get("alerts", [])
                if alert["flow_id"] not in sent_alert_ids
            ]
            if new_alerts:
                sent_alert_ids.update(alert["flow_id"] for alert in new_alerts)
                await websocket.send_json({
                    "type": "alerts",
                    "alerts": new_alerts,
                })
            await websocket.send_json({
                "type": "status",
                "status": status,
            })
            await asyncio.sleep(0.25)
    except WebSocketDisconnect:
        return


@app.get("/api/live/interfaces")
def live_interfaces() -> dict:
    """Return friendly Windows adapter names with their raw Npcap values."""
    raw_interfaces = get_if_list()
    windows_interfaces = get_windows_if_list()
    by_guid = {
        str(item.get("guid", "")).strip("{}").lower(): item
        for item in windows_interfaces
        if item.get("guid")
    }
    interfaces = []
    for raw_name in raw_interfaces:
        guid = raw_name.removeprefix(r"\Device\NPF_{").removesuffix("}")
        details = by_guid.get(guid.lower(), {})
        description = details.get("description") or details.get("name") or "Npcap interface"
        interfaces.append({
            "value": raw_name,
            "name": details.get("name") or description,
            "description": description,
            "status": details.get("status") or "unknown",
            "is_loopback": raw_name.endswith("NPF_Loopback"),
        })
    return {"interfaces": interfaces}
