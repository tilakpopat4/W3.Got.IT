# Stage 7 — Capture-Level Mythic HTTP C2 Training

## Dataset and label extraction

The supplied `TQH-C2_labels.zip` contains Zeek-style `labeled.jsonl` records
for the C-profile captures. The corresponding PCAPs are in
`TQH-C2_pcap_C_mythic_http.zip`, now extracted under the local dataset
directory.

Labels are joined to PCAP-derived flows using the canonical bidirectional
5-tuple:

```text
(source IP, source port, destination IP, destination port, protocol)
```

Only these labels are used:

- `malicious_c2` → positive class
- `benign`, `benign_external` → negative class

`unknown` and `malicious_recon` are excluded rather than silently assigning
them to the C2 class.

## Pipeline

```text
PCAP
  -> Scapy packet reader
  -> bidirectional flow records
  -> numeric flow features
  -> capture-level train/test split
  -> XGBoost Mythic C2 classifier
```

The model uses only features derived from PCAP metadata. Labels and capture
metadata are not used as model features.

## Evaluation design

`GroupShuffleSplit` holds out complete capture files. Flows from one capture
cannot appear in both train and test. This is more realistic than a random
flow split and prevents within-capture leakage.

The report includes accuracy, precision, recall, F1, ROC-AUC, and confusion
matrix, along with the exact train/test capture IDs.

## Outputs

- `data/tqh_c2_flow_features.csv`
- `models/tqh_c2_xgb.json`
- `models/tqh_c2_feature_cols.json`
- `reports/tqh_c2_metrics.txt`

## Limitations

The first model uses flow statistics only. It does not yet use Zeek HTTP
fields, JA3/JA4, DNS strings, or periodicity windows. Those can be added as
metadata-only features in later stages without decrypting payloads.
