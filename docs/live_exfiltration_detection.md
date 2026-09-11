# Live directional exfiltration evidence

The live adapter now identifies large, strongly one-way outbound flow
metadata as possible exfiltration.

## Evidence rule

A TCP or UDP flow must contain at least 20 packets, at least 1,000,000
outbound bytes, and outbound bytes must be at least 85% of the total flow.
The evidence reports outbound bytes, total bytes, outbound ratio, byte rate,
and packet count. Payloads and file contents are not inspected.

## Interpretation

This is a cautious lead, not proof of data theft. Backups, uploads, cloud
synchronization, video calls, and legitimate data transfers can match the
rule. Destination reputation, user context, and additional labeled captures
are needed before an operational decision.

## Boundary

The detector is live-only and alert-only. It does not block or modify
traffic, and offline PCAP/Parquet parsing and model artifacts are unchanged.
