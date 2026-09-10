# Stage 6 — Domain/DGA Metadata Classifier

## Dataset choice

The supplied directory contains:

- `6508640.zip` — labeled `domain,class` train/test data
- `TQH-C2_pcap_C_mythic_http.zip` — PCAP captures
- `TQH-C2_scripts.zip` — capture/orchestration scripts

The labeled CSV archive was selected for this stage because it can be trained
and evaluated directly. The PCAP archive is not mixed into this model: it
requires a separate packet-to-flow/metadata extraction step and has no labels
that can be safely mapped to the domain classes.

The archive contains 2,482,810 training rows and 620,703 test rows with three
labels (`0`, `1`, `2`). The exact semantic names of these labels are not
assumed because the archive only supplies numeric class IDs.

## Model

`src/train_domain_classifier.py` uses:

- Character n-gram hashing (2-5 grams, 262,144 dimensions)
- `SGDClassifier(loss="log_loss")`
- Incremental `partial_fit` batches of 25,000 rows
- Inverse-frequency class weights

This is a separate domain/DGA metadata model. It is not compatible with the
numeric flow model in `models/xgb_binary_hardened.json`.

## Reproduction

```text
python -m src.train_domain_classifier
```

Outputs:

- `models/dga_domain_sgd.joblib`
- `models/dga_domain_label_map.json`
- `reports/dga_domain_metrics.txt`

The report records accuracy, macro F1, weighted F1, class-level metrics, and
measured training/evaluation throughput.

## Measured result

The full run completed in 65.51 seconds at 47,373.92 rows/second across
training and test processing:

| Metric | Result |
|---|---:|
| Accuracy | **0.9293** |
| Macro F1 | **0.7886** |
| Weighted F1 | **0.9298** |

Per-class F1 was 0.9146 for class `0`, 0.9409 for class `1`, and 0.5102 for
the very small class `2` (1,559 test rows). Accuracy alone therefore
overstates performance on the minority class; macro F1 is the more cautious
summary.

## Scope and limitation

This stage detects the statistical domain patterns represented by the supplied
labels. It does not prove DNS tunnelling detection, because the archive has no
query sequence, query length over time, record type, source, destination, or
flow context. Those require DNS-flow features and a separately labeled dataset.
