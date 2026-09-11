# Live TLS/QUIC metadata anomaly evidence

The live adapter now identifies unusual high-rate flows on common encrypted
transport ports without decrypting or inspecting payloads.

## Evidence rules

- TCP port 443 (`TLS`): at least 80 packets and at least 200 packets/sec.
- UDP port 443 (`QUIC`): at least 100 packets and at least 250 packets/sec.

Evidence reports protocol family, packet/byte totals, rates, and confirms that
payloads were not inspected. These thresholds are conservative prototype
heuristics, not a TLS/QUIC malware classifier.

## Limitations

Port 443 is only a transport hint. Encrypted traffic can be benign, and
malware can use other ports or encrypted protocols. JA3/JA4 fingerprints,
SNI, and payload contents are intentionally not collected.

## Boundary

This detector is live-only and alert-only. It does not decrypt, block, or
modify traffic, and it does not change offline PCAP/Parquet behavior.
