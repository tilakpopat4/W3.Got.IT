# Live SYN-flood and protocol-specific DDoS evidence

The live adapter now adds passive protocol evidence without sending packets or
inspecting payloads.

## Rules

- `syn_flood`: TCP flow with at least 20 SYN packets, at most 10% as many ACK
  packets (with a minimum allowance of one ACK), and at least 100 packets/sec.
- `udp_flood`: UDP flow with at least 1,000 packets and at least 1,000
  packets/sec.

The existing destination aggregation still determines whether the broader
event is `possible_dos` or `possible_ddos`. These protocol labels explain the
flow-level evidence; they do not replace destination-level corroboration.

## Evidence

Each specialist decision includes `threat_class` and `threat_evidence`.
SYN evidence reports SYN count, ACK count, SYN/ACK ratio, and packet rate.
UDP evidence reports packet count, bytes, and packet rate.

Thresholds are conservative prototype values and require validation against
authorized lab captures before operational use.

## Boundary

This is live-only state in `src/live_capture.py`. Offline PCAP/Parquet
parsing, replay, model artifacts, and reports are unchanged.
