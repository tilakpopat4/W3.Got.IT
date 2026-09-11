"""Stage 1 - read-only PCAP packet aggregation into metadata flow records."""
from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.utils import PcapReader


@dataclass
class FlowRecord:
    """Bidirectional metadata summary for one canonical 5-tuple."""

    flow_id: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    start_time: float
    end_time: float
    observed_source_ip: str | None = None
    observed_source_port: int | None = None
    observed_destination_ip: str | None = None
    observed_destination_port: int | None = None
    packet_count: int = 0
    byte_count: int = 0
    forward_packets: int = 0
    reverse_packets: int = 0
    forward_bytes: int = 0
    reverse_bytes: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    packet_sizes: list[int] = field(default_factory=list)
    inter_arrival_times: list[float] = field(default_factory=list)
    _last_seen: float | None = field(default=None, repr=False)

    def add(self, timestamp: float, size: int, forward: bool, flags: int = 0) -> None:
        if self._last_seen is not None:
            self.inter_arrival_times.append(max(timestamp - self._last_seen, 0.0))
        self._last_seen = timestamp
        self.end_time = max(self.end_time, timestamp)
        self.packet_count += 1
        self.byte_count += size
        self.packet_sizes.append(size)
        if forward:
            self.forward_packets += 1
            self.forward_bytes += size
        else:
            self.reverse_packets += 1
            self.reverse_bytes += size
        self.syn_count += int(bool(flags & 0x02))
        self.ack_count += int(bool(flags & 0x10))
        self.fin_count += int(bool(flags & 0x01))
        self.rst_count += int(bool(flags & 0x04))

    def to_dict(self) -> dict:
        result = asdict(self)
        result.pop("_last_seen", None)
        result["duration"] = max(self.end_time - self.start_time, 0.0)
        return result


def _packet_metadata(packet) -> tuple[tuple, bool, int, int, tuple] | None:
    if IP not in packet:
        return None
    ip = packet[IP]
    if TCP in packet:
        transport, protocol = packet[TCP], "TCP"
        source_port, destination_port = int(transport.sport), int(transport.dport)
        flags = int(transport.flags)
    elif UDP in packet:
        transport, protocol = packet[UDP], "UDP"
        source_port, destination_port = int(transport.sport), int(transport.dport)
        flags = 0
    elif ICMP in packet:
        source_port = destination_port = 0
        protocol, flags = "ICMP", 0
    else:
        source_port = destination_port = 0
        protocol, flags = str(ip.proto), 0

    forward_key = (ip.src, source_port, ip.dst, destination_port, protocol)
    reverse_key = (ip.dst, destination_port, ip.src, source_port, protocol)
    canonical = min(forward_key, reverse_key)
    return canonical, forward_key == canonical, len(packet), flags, forward_key


def read_pcap(path: Path, limit: int | None = None) -> Iterator[FlowRecord]:
    """Read a PCAP without transmitting or modifying packets."""
    flows: dict[tuple, FlowRecord] = {}
    packet_count = 0
    with PcapReader(str(path)) as reader:
        for packet in reader:
            if limit is not None and packet_count >= limit:
                break
            metadata = _packet_metadata(packet)
            if metadata is None:
                continue
            key, forward, size, flags, observed_key = metadata
            timestamp = float(packet.time)
            flow = flows.get(key)
            if flow is None:
                flow = FlowRecord(
                    flow_id=f"{key[0]}:{key[1]}-{key[2]}:{key[3]}/{key[4]}",
                    source_ip=key[0],
                    source_port=key[1],
                    destination_ip=key[2],
                    destination_port=key[3],
                    protocol=key[4],
                    start_time=timestamp,
                    end_time=timestamp,
                    observed_source_ip=observed_key[0],
                    observed_source_port=observed_key[1],
                    observed_destination_ip=observed_key[2],
                    observed_destination_port=observed_key[3],
                )
                flows[key] = flow
            flow.add(timestamp, size, forward, flags)
            packet_count += 1
    yield from sorted(flows.values(), key=lambda item: item.start_time)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    started = time.perf_counter()
    records = list(read_pcap(args.pcap, args.limit))
    payload = "\n".join(json.dumps(record.to_dict()) for record in records)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + ("\n" if payload else ""))
    elapsed = time.perf_counter() - started
    print(json.dumps({
        "pcap": str(args.pcap),
        "flows": len(records),
        "elapsed_seconds": elapsed,
        "flows_per_second": len(records) / elapsed if elapsed else 0.0,
        "output": str(args.output) if args.output else None,
    }, indent=2))


if __name__ == "__main__":
    main()
