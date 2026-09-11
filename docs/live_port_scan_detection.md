# Live port-scan detection

## Purpose

This build adds a live-only reconnaissance detector for the SIH requirement
covering port scanning. It uses only observed flow metadata and does not send
probes or inspect payloads.

## Rule

For each observed source address, the live adapter keeps a bounded rolling
30-second window of TCP SYN or UDP destination attempts. A flow receives a
`port_scan` threat classification when the source reaches either:

- 20 unique destination ports, or
- 5 unique destination hosts

The alert evidence includes the source, unique host count, unique port count,
attempt count, protocol, and window duration.

This is a conservative prototype heuristic, not proof of malicious intent.
Legitimate vulnerability scanners and service discovery can produce the same
pattern and require operator review.

## Alert behavior

Port-scan evidence sets the flow's `flagged` value even when the generic
classifier probability is below its threshold. The decision also includes:

```json
{
  "threat_class": "port_scan",
  "threat_evidence": {
    "unique_destination_hosts": 1,
    "unique_destination_ports": 20,
    "attempts": 20,
    "window_seconds": 30.0,
    "protocol": "TCP"
  }
}
```

Generic classifier flags remain distinguishable through
`classifier_flagged`. The live dashboard can therefore explain whether a
decision came from the generic model or the port-scan rule.

## Architecture boundary

The detector is isolated to live Npcap state in `src/live_capture.py`.
Offline PCAP parsing, Parquet replay, model artifacts, and existing report
formats are unchanged.
