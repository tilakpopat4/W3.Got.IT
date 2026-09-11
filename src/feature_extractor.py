"""Stage 2 - convert Stage 1 flow records into numeric model features."""
from __future__ import annotations

import math
from statistics import mean, pvariance
from typing import Iterable


MODEL_FEATURES = [
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ece_flag_number",
    "cwr_flag_number", "ack_count", "syn_count", "fin_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SSH", "TCP", "UDP", "DHCP", "ARP",
    "ICMP", "IGMP", "IPv", "LLC", "Tot sum", "Min", "Max", "AVG", "Std",
    "Tot size", "IAT", "Number", "Variance",
]


def _safe_rate(value: float, duration: float) -> float:
    return value / duration if duration > 0 else 0.0


def flow_to_features(flow: dict) -> dict:
    """Build a deterministic numeric vector without reading packet payloads."""
    sizes = [float(value) for value in flow.get("packet_sizes", [])]
    iats = [float(value) for value in flow.get("inter_arrival_times", [])]
    duration = max(float(flow.get("duration", 0.0)), 0.0)
    protocol = str(flow.get("protocol", ""))
    packet_count = int(flow.get("packet_count", len(sizes)))
    byte_count = float(flow.get("byte_count", sum(sizes)))
    avg_size = mean(sizes) if sizes else 0.0
    variance = pvariance(sizes) if len(sizes) > 1 else 0.0
    iat_mean = mean(iats) if iats else 0.0
    iat_variance = pvariance(iats) if len(iats) > 1 else 0.0
    features = {name: 0.0 for name in MODEL_FEATURES}
    features.update({
        "Protocol Type": {"TCP": 6, "UDP": 17, "ICMP": 1}.get(protocol, 0),
        "Rate": _safe_rate(packet_count, duration),
        "Header_Length": avg_size,
        "fin_flag_number": float(flow.get("fin_count", 0) > 0),
        "syn_flag_number": float(flow.get("syn_count", 0) > 0),
        "rst_flag_number": float(flow.get("rst_count", 0) > 0),
        "ack_flag_number": float(flow.get("ack_count", 0) > 0),
        "ack_count": float(flow.get("ack_count", 0)),
        "syn_count": float(flow.get("syn_count", 0)),
        "fin_count": float(flow.get("fin_count", 0)),
        "rst_count": float(flow.get("rst_count", 0)),
        "TCP": float(protocol == "TCP"),
        "UDP": float(protocol == "UDP"),
        "ICMP": float(protocol == "ICMP"),
        "HTTP": float(flow.get("destination_port") in (80, 8080) or flow.get("source_port") in (80, 8080)),
        "HTTPS": float(flow.get("destination_port") == 443 or flow.get("source_port") == 443),
        "DNS": float(flow.get("destination_port") in (53, 853) or flow.get("source_port") in (53, 853)),
        "Tot sum": byte_count,
        "Tot size": byte_count,
        "Min": min(sizes) if sizes else 0.0,
        "Max": max(sizes) if sizes else 0.0,
        "AVG": avg_size,
        "Std": math.sqrt(variance),
        "Variance": variance,
        "IAT": iat_mean,
        "Number": float(packet_count),
    })
    return features


def extract_features(flows: Iterable[dict]) -> list[dict]:
    """Convert flow dictionaries while preserving identity metadata."""
    output = []
    for flow in flows:
        features = flow_to_features(flow)
        output.append({
            "flow_id": flow.get("flow_id"),
            "timestamp": flow.get("start_time"),
            "source_ip": flow.get("source_ip"),
            "destination_ip": flow.get("destination_ip"),
            "source_port": flow.get("source_port"),
            "destination_port": flow.get("destination_port"),
            "protocol": flow.get("protocol"),
            "features": features,
        })
    return output
