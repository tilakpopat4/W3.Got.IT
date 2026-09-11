"""Benchmark the live packet callback without sending network traffic.

Default mode benchmarks the exact LiveSession.on_packet callback with
in-memory Scapy packets. Optional ``--interface`` mode passively captures for
a bounded duration and does not transmit packets.

Examples:
    python -m src.benchmark_live --packets 1000
    python -m src.benchmark_live --interface "<Npcap interface>" --seconds 10
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import AsyncSniffer
from xgboost import XGBClassifier

from src import config
from src.live_capture import LiveSession


def _session() -> LiveSession:
    model = XGBClassifier()
    model.load_model(str(config.MODELS_DIR / "xgb_binary_hardened.json"))
    feature_cols = json.loads(
        (config.MODELS_DIR / "feature_cols.json").read_text(encoding="utf-8")
    )
    return LiveSession(
        model=model,
        feature_cols=feature_cols,
        model_label="Generic flow model",
        threshold=0.5,
        interface="benchmark",
    )


def _synthetic_packets(count: int) -> list:
    packets = []
    for index in range(count):
        source = f"10.250.{index // 250}.{(index % 250) + 1}"
        destination = "192.0.2.10"
        packet = IP(src=source, dst=destination) / TCP(
            sport=40000 + (index % 1000), dport=443, flags="A"
        ) / Raw(load=b"benchmark")
        packet.time = 1_700_000_000.0 + index * 0.001
        packets.append(packet)
    return packets


def _result(session: LiveSession, elapsed_ns: int, callbacks: int) -> dict:
    elapsed_seconds = elapsed_ns / 1_000_000_000
    return {
        "callbacks": callbacks,
        "elapsed_seconds": elapsed_seconds,
        "packets_per_second": callbacks / elapsed_seconds
        if elapsed_seconds else 0.0,
        "active_flows": len(session.flows),
        "flows_processed": len(session.decisions),
        "flows_flagged": sum(
            1 for decision in session.decisions.values()
            if decision.get("flagged")
        ),
        "packets_ignored_by_filter": session.ignored_packet_count,
        "measurement_scope": "live_session_on_packet_callback",
    }


def benchmark_synthetic(count: int) -> dict:
    session = _session()
    packets = _synthetic_packets(count)
    started = time.perf_counter_ns()
    for packet in packets:
        session.on_packet(packet)
    result = _result(session, time.perf_counter_ns() - started, count)
    result["source"] = "in_memory_scapy_packets"
    return result


def benchmark_passive(interface: str, seconds: float) -> dict:
    if seconds <= 0:
        raise ValueError("seconds must be greater than zero")
    session = _session()
    started = time.perf_counter_ns()
    sniffer = AsyncSniffer(iface=interface, prn=session.on_packet, store=False)
    sniffer.start()
    try:
        time.sleep(seconds)
    finally:
        sniffer.stop()
    result = _result(session, time.perf_counter_ns() - started, session.packet_count)
    result["source"] = "passive_npcap_interface"
    result["interface"] = interface
    result["capture_seconds"] = seconds
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", type=int, default=1000)
    parser.add_argument("--interface", type=str, default=None)
    parser.add_argument("--seconds", type=float, default=10.0)
    parser.add_argument(
        "--output", type=Path, default=config.REPORTS_DIR / "live_benchmark.json"
    )
    args = parser.parse_args()
    if args.packets <= 0:
        raise ValueError("packets must be greater than zero")
    result = (
        benchmark_passive(args.interface, args.seconds)
        if args.interface
        else benchmark_synthetic(args.packets)
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
