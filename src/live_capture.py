"""Passive live packet capture and incremental flow scoring."""
from __future__ import annotations

import threading
import time
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from ipaddress import ip_address

import numpy as np
from scapy.sendrecv import AsyncSniffer
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from xgboost import XGBClassifier

from src.feature_extractor import flow_to_features
from src.flow_records import FlowRecord
from src.kalman_engine import KalmanBank
from src.alert_schema import alert_from_row
from src.stage5_scoring import enrich_flow_report


def _live_packet_metadata(packet) -> tuple[tuple, bool, int, int, tuple] | None:
    """Extract IPv4/IPv6 transport metadata for live capture only."""
    if IPv6 in packet:
        network = packet[IPv6]
        address_version = 6
    elif IP in packet:
        network = packet[IP]
        address_version = 4
    else:
        return None

    if TCP in packet:
        transport, protocol = packet[TCP], "TCP"
        source_port, destination_port = int(transport.sport), int(transport.dport)
        flags = int(transport.flags)
    elif UDP in packet:
        transport, protocol = packet[UDP], "UDP"
        source_port, destination_port = int(transport.sport), int(transport.dport)
        flags = 0
    elif (address_version == 4 and ICMP in packet) or (
        address_version == 6
        and (ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet)
    ):
        source_port = destination_port = 0
        protocol, flags = "ICMP", 0
    else:
        source_port = destination_port = 0
        protocol = f"IPv{address_version}:{network.nh if address_version == 6 else network.proto}"
        flags = 0

    forward_key = (
        network.src, source_port, network.dst, destination_port, protocol
    )
    reverse_key = (
        network.dst, destination_port, network.src, source_port, protocol
    )
    canonical = min(forward_key, reverse_key)
    return canonical, forward_key == canonical, len(packet), flags, forward_key


@dataclass
class LiveSession:
    model: XGBClassifier
    feature_cols: list[str]
    model_label: str
    threshold: float
    interface: str
    target_ips: frozenset[str] = frozenset()
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
    idle_timeout_seconds: float = 60.0
    max_flows: int = 5000
    expired_flows: int = 0
    evicted_flows: int = 0
    last_packet_at: float | None = None
    ignored_packet_count: int = 0
    scan_window_seconds: float = 30.0
    scan_attempts: dict[str, deque[tuple[float, str, int]]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    dns_evidence: dict[str, dict] = field(default_factory=dict)

    @staticmethod
    def _dns_query_evidence(packet) -> dict | None:
        """Classify suspicious DNS query metadata without reading payload data."""
        if DNS not in packet or DNSQR not in packet or int(packet[DNS].qr) != 0:
            return None
        raw_name = bytes(packet[DNSQR].qname).rstrip(b".\x00")
        try:
            name = raw_name.decode("ascii").lower()
        except UnicodeDecodeError:
            return None
        labels = [label for label in name.split(".") if label]
        if not labels:
            return None
        longest_label = max(map(len, labels))
        total_length = len(name)
        character_counts = {char: name.count(char) for char in set(name)}
        entropy = -sum(
            (count / total_length) * math.log2(count / total_length)
            for count in character_counts.values()
        ) if total_length else 0.0
        alphanumeric = sum(char.isalnum() for char in name)
        digit_ratio = sum(char.isdigit() for char in name) / max(alphanumeric, 1)
        dga = (
            longest_label >= 20
            and entropy >= 3.5
            and digit_ratio >= 0.15
        )
        tunneling = longest_label >= 40 or total_length >= 100
        if not dga and not tunneling:
            return None
        return {
            "threat_class": "dns_tunneling" if tunneling else "dga_dns",
            "query_length": total_length,
            "longest_label": longest_label,
            "label_count": len(labels),
            "entropy_bits_per_character": round(entropy, 4),
            "digit_ratio": round(digit_ratio, 4),
            "query_name_metadata": {
                "name_omitted": True,
            },
        }

    def _port_scan_evidence(
        self, timestamp: float, observed_key: tuple, protocol: str, flags: int,
    ) -> dict | None:
        """Return evidence when one source fans out across many endpoints."""
        source_ip, _, destination_ip, destination_port, _ = observed_key
        if protocol == "TCP" and not flags & 0x02:
            return None
        if protocol not in {"TCP", "UDP"}:
            return None

        attempts = self.scan_attempts[source_ip]
        cutoff = timestamp - self.scan_window_seconds
        while attempts and attempts[0][0] < cutoff:
            attempts.popleft()
        attempts.append((timestamp, destination_ip, destination_port))
        unique_hosts = {item[1] for item in attempts}
        unique_ports = {item[2] for item in attempts}
        if len(unique_hosts) < 5 and len(unique_ports) < 20:
            return None
        return {
            "source_ip": source_ip,
            "unique_destination_hosts": len(unique_hosts),
            "unique_destination_ports": len(unique_ports),
            "attempts": len(attempts),
            "window_seconds": self.scan_window_seconds,
            "protocol": protocol,
        }

    @staticmethod
    def _protocol_attack_evidence(flow: FlowRecord) -> dict | None:
        """Identify high-rate SYN imbalance or UDP flood metadata."""
        duration = max(flow.end_time - flow.start_time, 0.001)
        packets_per_second = flow.packet_count / duration
        if (
            flow.protocol == "TCP"
            and flow.syn_count >= 20
            and flow.ack_count <= max(1, flow.syn_count // 10)
            and packets_per_second >= 100
        ):
            return {
                "threat_class": "syn_flood",
                "syn_count": flow.syn_count,
                "ack_count": flow.ack_count,
                "packets_per_second": round(packets_per_second, 4),
                "syn_ack_ratio": round(
                    flow.syn_count / max(flow.ack_count, 1), 4
                ),
            }
        if (
            flow.protocol == "UDP"
            and flow.packet_count >= 1000
            and packets_per_second >= 1000
        ):
            return {
                "threat_class": "udp_flood",
                "packets": flow.packet_count,
                "bytes": flow.byte_count,
                "packets_per_second": round(packets_per_second, 4),
            }
        return None

    @staticmethod
    def _beacon_evidence(flow: FlowRecord) -> dict | None:
        """Identify repeated, low-jitter flow timing consistent with beaconing."""
        intervals = [
            value for value in flow.inter_arrival_times
            if value > 0.0
        ]
        if len(intervals) < 6:
            return None
        mean_interval = sum(intervals) / len(intervals)
        if not 0.5 <= mean_interval <= 60.0:
            return None
        variance = sum(
            (value - mean_interval) ** 2 for value in intervals
        ) / len(intervals)
        coefficient_of_variation = variance ** 0.5 / mean_interval
        if coefficient_of_variation > 0.15:
            return None
        return {
            "threat_class": "c2_beacon",
            "samples": len(intervals),
            "mean_interval_seconds": round(mean_interval, 4),
            "jitter_seconds": round(variance ** 0.5, 4),
            "coefficient_of_variation": round(coefficient_of_variation, 4),
        }

    @staticmethod
    def _encrypted_transport_evidence(flow: FlowRecord) -> dict | None:
        """Identify unusual high-rate metadata on common TLS/QUIC ports."""
        if flow.protocol not in {"TCP", "UDP"}:
            return None
        if flow.source_port != 443 and flow.destination_port != 443:
            return None
        duration = max(flow.end_time - flow.start_time, 0.001)
        packets_per_second = flow.packet_count / duration
        bytes_per_second = flow.byte_count / duration
        if flow.protocol == "TCP":
            anomalous = flow.packet_count >= 80 and packets_per_second >= 200
            transport = "TLS"
        else:
            anomalous = flow.packet_count >= 100 and packets_per_second >= 250
            transport = "QUIC"
        if not anomalous:
            return None
        return {
            "threat_class": "encrypted_transport_anomaly",
            "transport": transport,
            "packets": flow.packet_count,
            "bytes": flow.byte_count,
            "packets_per_second": round(packets_per_second, 4),
            "bytes_per_second": round(bytes_per_second, 4),
            "payload_inspected": False,
        }

    @staticmethod
    def _exfiltration_evidence(flow: FlowRecord) -> dict | None:
        """Identify large, strongly one-way outbound flow metadata."""
        if flow.protocol not in {"TCP", "UDP"} or flow.packet_count < 20:
            return None
        if (
            flow.observed_source_ip == flow.source_ip
            and flow.observed_source_port == flow.source_port
        ):
            outbound_bytes = flow.forward_bytes
        else:
            outbound_bytes = flow.reverse_bytes
        outbound_ratio = outbound_bytes / max(flow.byte_count, 1)
        duration = max(flow.end_time - flow.start_time, 0.001)
        bytes_per_second = flow.byte_count / duration
        if outbound_bytes < 1_000_000 or outbound_ratio < 0.85:
            return None
        return {
            "threat_class": "possible_exfiltration",
            "outbound_bytes": outbound_bytes,
            "total_bytes": flow.byte_count,
            "outbound_ratio": round(outbound_ratio, 4),
            "bytes_per_second": round(bytes_per_second, 4),
            "packets": flow.packet_count,
            "payload_inspected": False,
        }

    def _expire_flows(self, now: float) -> None:
        cutoff = now - self.idle_timeout_seconds
        expired = [
            key for key, flow in self.flows.items()
            if flow.end_time < cutoff
        ]
        for key in expired:
            flow = self.flows.pop(key)
            self.decisions.pop(flow.flow_id, None)
            self.dns_evidence.pop(flow.flow_id, None)
        self.expired_flows += len(expired)

        if len(self.flows) <= self.max_flows:
            return
        oldest = sorted(self.flows.items(), key=lambda item: item[1].end_time)
        for key, flow in oldest[:len(self.flows) - self.max_flows]:
            self.flows.pop(key, None)
            self.decisions.pop(flow.flow_id, None)
            self.dns_evidence.pop(flow.flow_id, None)
            self.evicted_flows += 1

    def on_packet(self, packet) -> None:
        metadata = _live_packet_metadata(packet)
        if metadata is None:
            return
        key, forward, size, flags, observed_key = metadata
        protocol = observed_key[4]
        timestamp = float(packet.time)
        with self.lock:
            self.packet_count += 1
            self.last_packet_at = timestamp
            if self.target_ips and not (
                observed_key[0] in self.target_ips
                or observed_key[2] in self.target_ips
            ):
                self.ignored_packet_count += 1
                return
            self._expire_flows(timestamp)
            scan_evidence = self._port_scan_evidence(
                timestamp, observed_key, protocol, flags,
            )
            current_dns_evidence = self._dns_query_evidence(packet)
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
            raw = flow.to_dict()
            protocol_evidence = self._protocol_attack_evidence(flow)
            beacon_evidence = self._beacon_evidence(flow)
            encrypted_evidence = self._encrypted_transport_evidence(flow)
            exfiltration_evidence = self._exfiltration_evidence(flow)
            if current_dns_evidence is not None:
                self.dns_evidence[flow.flow_id] = current_dns_evidence
            dns_evidence = self.dns_evidence.get(flow.flow_id)
            features = flow_to_features(raw)
            values = np.array([[float(features.get(name, 0.0)) for name in self.feature_cols]])
            probability = float(self.model.predict_proba(values)[0, 1])
            anomaly_score, _, anomaly_level = self.kalman.update({
                metric: features.get(metric) for metric in ("Rate", "IAT", "syn_count")
            })
            classifier_flagged = probability >= self.threshold
            port_scan_flagged = scan_evidence is not None
            protocol_flagged = protocol_evidence is not None
            dns_flagged = dns_evidence is not None
            beacon_flagged = beacon_evidence is not None
            encrypted_flagged = encrypted_evidence is not None
            exfiltration_flagged = exfiltration_evidence is not None
            specialist_evidence = (
                dns_evidence or beacon_evidence or encrypted_evidence
                or exfiltration_evidence
                or protocol_evidence or scan_evidence
            )
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
                "flagged": (
                    classifier_flagged
                    or port_scan_flagged
                    or protocol_flagged
                    or dns_flagged
                    or beacon_flagged
                    or encrypted_flagged
                    or exfiltration_flagged
                ),
                "classifier_flagged": classifier_flagged,
                "threat_class": (
                    dns_evidence["threat_class"] if dns_flagged
                    else beacon_evidence["threat_class"] if beacon_flagged
                    else encrypted_evidence["threat_class"] if encrypted_flagged
                    else exfiltration_evidence["threat_class"] if exfiltration_flagged
                    else protocol_evidence["threat_class"] if protocol_flagged
                    else "port_scan" if port_scan_flagged
                    else "generic_malicious_flow"
                ),
                "threat_evidence": specialist_evidence,
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
                    f"{dns_evidence['threat_class']} evidence: "
                    f"query length {dns_evidence['query_length']} characters"
                    if dns_flagged else
                    f"c2_beacon evidence: interval CV "
                    f"{beacon_evidence['coefficient_of_variation']:.3f}"
                    if beacon_flagged else
                    f"{encrypted_evidence['threat_class']} evidence: "
                    f"{encrypted_evidence['transport']} at "
                    f"{encrypted_evidence['packets_per_second']:.2f} packets/sec"
                    if encrypted_flagged else
                    f"possible_exfiltration evidence: "
                    f"{exfiltration_evidence['outbound_bytes']} outbound bytes "
                    f"({exfiltration_evidence['outbound_ratio']:.1%} of flow)"
                    if exfiltration_flagged else
                    f"{protocol_evidence['threat_class']} evidence: "
                    f"{protocol_evidence.get('packets_per_second', 0):.2f} packets/sec"
                    if protocol_flagged else
                    f"Port-scan evidence: {scan_evidence['unique_destination_ports']} "
                    f"destination ports across {scan_evidence['unique_destination_hosts']} "
                    f"hosts in {scan_evidence['window_seconds']:.0f}s"
                    if port_scan_flagged else
                    f"XGBoost probability {probability:.3f} >= threshold {self.threshold:.3f}"
                    if classifier_flagged else
                    f"XGBoost probability {probability:.3f} < threshold {self.threshold:.3f}"
                ),
            }


class LiveCaptureManager:
    def __init__(self) -> None:
        self.session: LiveSession | None = None
        self.lock = threading.Lock()

    def start(
        self, interface: str, model: XGBClassifier, feature_cols: list[str],
        model_label: str, threshold: float, target_ips: frozenset[str] = frozenset(),
    ) -> None:
        with self.lock:
            if self.session is not None and not self.session.stopped:
                raise RuntimeError("A live capture is already running")
            session = LiveSession(
                model, feature_cols, model_label, threshold, interface,
                target_ips=target_ips,
            )
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
                return {"running": False, "flows": [], "alerts": [], "packets": 0}
            with session.lock:
                session._expire_flows(time.time())
                flows = list(session.decisions.values())
                flows.sort(key=lambda item: item["timestamp"], reverse=True)
                flagged = sum(1 for item in flows if item["flagged"])
                attack_summary = enrich_flow_report(flows, session.threshold)
                alerts = [
                    alert.model_dump(mode="json")
                    for row in flows
                    if (alert := alert_from_row(row, session.model_label)) is not None
                ]
                elapsed = max(time.time() - session.started_at, 0.001)
                return {
                    "running": not session.stopped,
                    "interface": session.interface,
                    "model": session.model_label,
                    "algorithm": "XGBoost gradient-boosted trees (not Random Forest)",
                    "threshold": session.threshold,
                    "target_ips": sorted(session.target_ips),
                    "packets": session.packet_count,
                    "packets_analyzed": session.packet_count - session.ignored_packet_count,
                    "packets_ignored_by_filter": session.ignored_packet_count,
                    "capture_started_at": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(session.started_at)
                    ),
                    "last_packet_at": (
                        time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ",
                            time.gmtime(session.last_packet_at),
                        )
                        if session.last_packet_at is not None else None
                    ),
                    "idle_timeout_seconds": session.idle_timeout_seconds,
                    "active_flows": len(session.flows),
                    "expired_flows": session.expired_flows,
                    "evicted_flows": session.evicted_flows,
                    "flows_processed": len(flows),
                    "flows_flagged": flagged,
                    "flag_rate": round(flagged / len(flows), 6) if flows else 0.0,
                    "packets_per_second": round(session.packet_count / elapsed, 2),
                    "read_only": True,
                    "payload_inspected": False,
                    "error": session.error,
                    "flows": flows[:500],
                    "alerts": alerts[:500],
                    "attack_summary": attack_summary,
                }


LIVE_MANAGER = LiveCaptureManager()
