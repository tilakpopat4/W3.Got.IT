# Stage 2 — PCAP Flow Feature Extraction

## Purpose

This stage connects Stage 1 flow records to the existing numeric model
interface. It converts metadata-only flow summaries into a stable feature
vector while preserving flow identity for later alerts.

## Implemented features

- Packet and byte rate
- Packet count and total size
- Minimum, maximum, mean, standard deviation, and variance of packet sizes
- Mean and variance of inter-arrival times
- TCP SYN/ACK/FIN/RST counts and indicators
- TCP/UDP/ICMP protocol indicators
- HTTP/HTTPS/DNS port indicators
- Protocol type
- Flow identity and timestamps

Features not present in a PCAP flow record are represented as zero and remain
explicitly unsupported: DNS domain entropy, TLS fingerprints, source/destination
fan-out, and direction-aware time-window aggregates require additional stages.

## Usage

```text
python -m src.pcap_pipeline C:\path\capture.pcap --limit 5000 --output reports\pcap_features.jsonl
```

The output format is:

```json
{
  "flow_id": "...",
  "timestamp": 1783206284.155,
  "source_ip": "...",
  "destination_ip": "...",
  "features": {"Rate": 6710.0, "TCP": 1.0}
}
```

This is the integration contract for the Kalman and classifier stages.

## Connected detection command

After producing features, run the existing Stage 3 and Stage 4 components:

```text
python -m src.pcap_detect reports\stage2_sample_features.jsonl --output reports\stage5_pcap_alerts.jsonl
```

This applies the link-level Kalman bank and hardened binary classifier to
every PCAP-derived feature record. The current classifier labels predictions
as broad `malicious`; threat-specific DDoS/C2 labels require a multiclass model
trained on matching labels.
