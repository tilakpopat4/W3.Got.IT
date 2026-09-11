# Stage 1 — PCAP to Flow Records

## Purpose

This stage reads passive PCAP files and converts packets into bidirectional
metadata-only flow records. It never sends packets, completes handshakes,
queries endpoints, or inspects decrypted payloads.

## Implementation

`src/flow_records.py` uses Scapy's `PcapReader` and supports:

- IPv4 TCP
- IPv4 UDP
- IPv4 ICMP
- Other IPv4 protocols as numeric protocol names

Flows are grouped by a canonical bidirectional 5-tuple:

```text
(source IP, source port, destination IP, destination port, protocol)
```

The canonical ordering makes packets in both directions belong to one flow.
The record retains forward/reverse packet and byte counts based on the first
canonical endpoint.

## Output fields

- Flow identity and 5-tuple
- Start/end timestamps and duration
- Total, forward, and reverse packet/byte counts
- TCP SYN/ACK/FIN/RST counts
- Packet sizes
- Inter-arrival times

No payload bytes are written to the output.

## Usage

```text
python -m src.flow_records C:\path\capture.pcap --limit 10000 --output reports\flows.jsonl
```

The command reports flow count, elapsed time, and measured flows per second.
`--limit` limits packets read, not output flows.

## Current limitations

- This first adapter supports IPv4 only.
- It aggregates a finite PCAP in memory before yielding sorted flows.
- TCP/UDP application metadata, DNS strings, TLS fingerprints, and IPv6 are
  not extracted yet.
- A production stream adapter still needs idle-flow expiry and bounded memory.

These are deliberate follow-up stages; the current output schema is the
contract for feature extraction.
