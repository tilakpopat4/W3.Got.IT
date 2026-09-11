# Live DNS/DGA and tunneling metadata detection

The live adapter now checks DNS query metadata without retaining or inspecting
the query name as an alert payload.

## Evidence rules

- `dga_dns`: longest label at least 20 characters, entropy at least 3.5
  bits/character, and digit ratio at least 15%.
- `dns_tunneling`: longest label at least 40 characters or total query name
  length at least 100 characters.

The detector records lengths, label count, entropy, and digit ratio; the full
query name is omitted. Ordinary short DNS names do
not produce specialist evidence.

## Limitations

These are explainable metadata heuristics, not a trained DNS classifier.
Encrypted DNS (DoH/DoT) and DNS responses without visible queries are not
covered. Thresholds must be evaluated against labeled benign and malicious DNS
captures before operational use.

## Boundary and safety

The implementation is live-only and alert-only. It does not send DNS queries,
modify traffic, decrypt TLS, or change the offline PCAP/Parquet parser.
