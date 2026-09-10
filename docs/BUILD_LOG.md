# Build Log

Chronological record of everything built, run, and measured. Newest entries at the bottom.
All metrics below are actual measured results, not estimates.

---

## Entry 1 — Environment & data inspection
**What:** Inspected the source dataset `C:\Users\himanshu\Downloads\CN\pcap.parquet`.
**Files:** `scripts/inspect_pcap.py`, `scripts/pcap_report.txt`
**Findings:**
- 455,641 rows × 42 columns (pre-extracted flow features, CICIoT-style — NOT raw pcap).
- Label column `MalwareFamily`: Mirai 319,808 · Benign 82,622 · Unknown 31,531 · DarkNexus 9,938 · Gafgyt 7,666 · Generic 4,076.
- Data quality issues: `Rate` has +inf values; `Std`/`Variance` have 483 nulls; `Arch`/`SMTP`/`IRC` are dead/constant columns.
- Environment: Python 3.10; installed `pyarrow`, `xgboost` 3.2.0, `scikit-learn` 1.7.2, `imbalanced-learn` 0.14.2.

---

## Entry 2 — Project scaffold
**What:** Created project structure and dependency list.
**Files:** `requirements.txt`, `src/__init__.py`, `src/config.py`
**Notes:** `config.py` centralises paths, label column, drop-columns, Kalman feature list, random seed.

---

## Entry 3 — Stage 2: data cleaning
**What:** Cleaned the raw parquet into a model-ready dataset.
**Files:** `src/data_clean.py` → outputs `data/pcap_clean.parquet`, `data/label_map.json`
**Doc:** [stage2_features.md](stage2_features.md)
**Actions & results:**
- Dropped dead/id columns: `Arch, SMTP, IRC, Hash`.
- Capped `Rate` at p99.9 = 26,955.68 (451 rows).
- Imputed 1,449 NaN cells with 0 across 37 numeric columns.
- Encoded labels: `{Benign:0, DarkNexus:1, Gafgyt:2, Generic:3, Mirai:4, Unknown:5}`.
- Output: **455,641 rows × 39 cols**, no NaN/inf remaining.

---

## Entry 4 — Stage 4: first classifier (6-class)
**What:** Trained the initial XGBoost multi-class model on `MalwareFamily`.
**Files:** `src/train_classifier.py` → `models/xgb_threat.json`, `reports/stage4_metrics.txt`
**Doc:** [stage4_classifier.md](stage4_classifier.md)
**Result:** accuracy **0.49**, weighted F1 **0.57**.
**Diagnosis:** balanced sample-weights sacrificed the Mirai majority; `Unknown` is a garbage label; single feature `TCP` dominated. Benign detection was already strong (0.92–0.99).

---

## Entry 5 — Stage 4: improved variants
**What:** Two better formulations of the classification problem.
**Files:** `src/train_variants.py` → `models/xgb_binary.json`, `models/xgb_multiclass_clean.json`, `reports/stage4_variants.txt`
**Doc:** [stage4_classifier.md](stage4_classifier.md)
**Results:**
| Variant | Accuracy | F1 (weighted) |
|---|---|---|
| Original 6-class | 0.4927 | 0.5689 |
| **A: Binary (Benign vs Malicious)** | **0.9839** | **0.9841** (ROC-AUC 0.9986) |
| **B: Multiclass (Benign/Mirai/Botnet)** | **0.9201** | **0.9170** |
**Notes:** dropped `Unknown`, merged DarkNexus/Gafgyt/Generic → `Botnet`, used SMOTE instead of full balancing.

---

## Entry 6 — Stage 3: Kalman anomaly engine
**What:** Built the streaming anomaly-detection layer.
**Files:** `src/kalman_engine.py` → `reports/stage3_kalman.txt`
**Doc:** [stage3_kalman.md](stage3_kalman.md)
**Design:** adaptive 1-D Kalman filter bank (one per metric/entity), normalized-innovation anomaly score, soft(3.0)/hard(6.0) thresholds, log-space for bursty `Rate`, warmup period.
**Result (shuffled static rows):** benign mean 0.98 vs Mirai mean 1.18 — **weak separation (0.20)**.
**Key insight:** Kalman needs a *time-ordered* per-source stream; on shuffled per-window rows there is no temporal signal. This is expected and motivates the Stage 0–1 replay.

---

## Entry 7 — Audit of both models
**What:** Full correctness + robustness audit.
**Files:** `src/audit_models.py` → `reports/audit.txt`
**Results:**
- Data: 0 NaN, 0 inf, no constant cols, **337 duplicate rows** (leakage risk).
- Stage 4 binary **5-fold CV F1 = 0.9906 (std 0.0005)**, AUC 0.9983 → stable, not a lucky split.
- Leakage warning: `TCP` feature importance = **0.90** (single-feature dominance).
- Stage 3 controlled burst test: baseline **1.71** → burst **45.6** → **hard alert fires**. NaN-safe, warmup OK. Confirms the engine works on ordered streams.

---

## Entry 8 — Stage 4: hardening
**What:** Fixed the two audit issues and proved robustness.
**Files:** `src/harden_classifier.py` → `models/xgb_binary_hardened.json`, `reports/stage4_hardened.txt`
**Doc:** [stage4_classifier.md](stage4_classifier.md)
**Actions & results:**
- Dropped 337 duplicate rows (455,641 → 455,304).
- Regularized (colsample_bynode 0.6, reg_lambda 2.0, min_child_weight 5) → `TCP` importance 0.90 → **0.55** (spread to syn_count, Header_Length, syn_flag_number).
- Hardened model: acc **0.983**, F1 **0.990**, AUC **0.999** (precision 0.999 / recall 0.981).
- **Robustness proof:** trained WITHOUT `TCP` → F1 still **0.990** (zero drop). Not a single-feature trick.

---

## Entry 9 — Stage 5: replay inference and standardized alerts
**What:** Connected the hardened binary model and Kalman bank into a documented
row-by-row replay pipeline.
**Files:** `src/stream_replay.py`, `src/alert_schema.py`,
`docs/stage5_streaming_alerts.md`
**Behavior:**
- Reads the cleaned Parquet data in deterministic row order.
- Updates the link-level Kalman bank for `Rate`, `IAT`, and `syn_count`.
- Loads `models/xgb_binary_hardened.json` for per-row inference.
- Emits Pydantic-validated JSON Lines alerts with confidence, severity,
  anomaly score, and top-feature evidence.
- Prints measured rows/sec and elapsed time.
**Known boundary:** the current Parquet artifact has no timestamp, source IP, or
flow ID, so row index is used as a replay identifier. This is a replay adapter,
not yet a packet/NetFlow ingest service.

## Entry 10 — Stage 3 correctness fix
**What:** Fixed invalid Kalman measurements poisoning the filter state.
**File:** `src/kalman_engine.py`
**Behavior:** non-finite measurements are ignored before state mutation. This
replaces the earlier audit claim that was only masked by the warmup period.

---

## Entry 11 — Stage 5 validation status
**What:** Ran syntax checks, Pylance diagnostics, a focused Kalman runtime
check, and a 1,000-row replay smoke test.
**Results:**
- New Stage 5 Python files have no syntax errors or Pylance errors.
- Invalid-measurement regression check passed; score and filter state remain
  finite.
- Replay smoke test is currently blocked by the local `.venv`: NumPy's
  `_bounded_integers` DLL is blocked by Windows Application Control before
  Parquet/model loading begins.
**Next action:** repair or select a permitted Python environment, then rerun
the replay to record measured throughput and alert counts.

---

---

## Entry 12 — Stage 6: supplied domain dataset
**What:** Added a separate streaming domain/DGA-style classifier for the
`6508640.zip` labeled CSV archive supplied by the user.
**Files:** `src/train_domain_classifier.py`,
`docs/stage6_domain_classifier.md`
**Dataset:** 2,482,810 training rows and 620,703 test rows, three numeric
classes, `domain,class` schema.
**Model:** character 2-5 grams hashed into 262,144 dimensions and incremental
log-loss SGD training with inverse-frequency class weights.
**Outputs:** `models/dga_domain_sgd.joblib`,
`models/dga_domain_label_map.json`, and
`reports/dga_domain_metrics.txt`.
**Measured result:** accuracy **0.9293**, macro F1 **0.7886**, weighted F1
**0.9298** on the provided test split; class-2 F1 was **0.5102** because only
1,559 test examples belong to that class. Training/evaluation throughput was
47,373.92 rows/sec.
**Important boundary:** this model is separate from the existing flow model;
the supplied domain labels do not justify claiming DNS tunnelling or assigning
semantic class names without metadata.

---

## Entry 13 — Stage 1: PCAP to flow records
**What:** Added a read-only Scapy PCAP adapter that aggregates IPv4 packets
into bidirectional metadata-only flow records.
**Files:** `src/flow_records.py`, `docs/stage1_flow_records.md`,
`requirements.txt`
**Output:** JSON Lines records containing 5-tuple identity, timestamps,
duration, packet/byte counts per direction, TCP flag counts, packet sizes, and
inter-arrival times.
**Security boundary:** no packets are transmitted and no payload bytes are
written.
**Known limitations:** first version supports IPv4 and finite-PCAP
aggregation; idle expiry, IPv6, DNS metadata, and TLS fingerprints remain
follow-up work.

**Validation:** extracted one supplied 3.47 MB Mythic HTTP PCAP and processed
the first 5,000 packets. The adapter emitted **235 flow records** in **0.5582
seconds** at **421.0 flows/sec**. The flow schema smoke test passed for
bidirectional packet counts, byte counts, TCP flags, and IAT values.

---

## Entry 14 — Stage 2: PCAP flow feature extraction
**What:** Connected Stage 1 flow records to a numeric feature-vector contract.
**Files:** `src/feature_extractor.py`, `src/pcap_pipeline.py`,
`docs/stage2_pcap_features.md`
**Behavior:** computes rate, size, IAT, TCP flag, protocol, and common-port
features while preserving flow identity and timestamps. Unsupported DNS/TLS
and cross-flow features remain explicit follow-up work.
**Pipeline command:** `python -m src.pcap_pipeline <pcap> --output <jsonl>`.

**Detection wiring:** `src/pcap_detect.py` now feeds the generated feature
records into the existing Stage 3 Kalman bank and Stage 4 hardened classifier,
emitting Stage 5 JSON alerts.
**Validation:** the connected run processed **235 flows** and emitted **235
alerts** into `reports/stage5_pcap_alerts.jsonl`. This is an integration smoke
test only: the hardened model was trained on a different labeled flow dataset,
so this alert count is not a PCAP accuracy measurement and indicates dataset
shift that must be addressed with capture-specific labels.

---

## Entry 15 — Stage 7: capture-level Mythic C2 classifier
**What:** Joined the supplied TQH C-profile labels to corresponding PCAP flows
using canonical 5-tuples, extracted numeric features, and trained a dedicated
`malicious_c2` versus benign XGBoost model.
**Files:** `src/train_tqh_c2.py`,
`docs/stage7_tqh_c2_training.md`
**Evaluation:** complete PCAP captures are grouped into train/test sets using
`GroupShuffleSplit`; no flow from a held-out capture enters training.
**Labels:** `malicious_c2` positive; `benign` and `benign_external` negative;
`unknown` and `malicious_recon` excluded.
**Outputs:** capture-level metrics, model, feature list, and CSV features.

---

## Entry 17 — Stage 8 live capture mode
**What:** Connected the dashboard to Scapy `AsyncSniffer` for read-only live
packet observation. Added start/stop controls, one-second status polling,
interface discovery, and live flow/model counters.
**Files:** `src/live_capture.py`, `src/dashboard_api.py`,
`dashboard/index.html`, `dashboard/app.js`, `dashboard/styles.css`,
`docs/stage8_basic_dashboard.md`
**Windows requirement:** Npcap and sufficient capture permission are required.
Wireshark is optional; `tshark` is not required by the dashboard.

## Documentation rule
Every future build step appends a numbered entry here, plus a dedicated stage doc where relevant.

---

## Entry 18 — flow identity and flag explainability
**What:** Corrected dashboard terminology for bidirectional canonical flows and
preserved the first observed packet direction. Added UTC timeline fields,
packet/byte rates, Kalman input values, top model features, and an explicit
probability-versus-threshold reason for every decision.
**Important clarification:** the classifier is XGBoost gradient-boosted trees,
not Random Forest. A generic `malicious` flag is not a DDoS claim; DDoS needs
aggregation across many sources targeting one destination.

---

## Entry 19 — Stage 5 score fusion and volumetric evidence
**What:** Added fused confidence, severity, explicit packet/byte evidence, and
destination-level DoS/DDoS assessment. A classifier flag is kept separate from
the volumetric attack claim; small flows such as 3 packets are not labeled
DDoS.

---

## Entry 20 — dashboard investigation filters
**What:** Added flow-report filters for free-text search across all fields,
packet count, byte count, classifier probability, flag status, severity, and
Kalman anomaly level. Added in-dashboard explanations for the generic model,
Mythic model, and live interface behavior.

---

## Entry 16 — Stage 8: basic manual PCAP dashboard
**What:** Added a local FastAPI dashboard for uploading a PCAP and viewing
flow-level model decisions.
**Files:** `src/dashboard_api.py`, `dashboard/index.html`,
`dashboard/app.js`, `dashboard/styles.css`,
`docs/stage8_basic_dashboard.md`
**Pipeline:** PCAP -> flow records -> numeric features -> Kalman -> selected
XGBoost model -> per-flow report.
**Models:** Generic hardened model and capture-trained Mythic C2 model are
selectable. The dashboard is alert-only and does not inspect payloads.

---

## Entry 21 — scoring meaning and coverage guide
**What:** Added an in-dashboard explanation of classifier thresholding, Kalman
anomaly scoring, confidence fusion, severity, and cautious DoS/DDoS evidence.
The dashboard distinguishes implemented generic/Mythic/volume scoring from
planned SYN-flood, port-scan, DNS/DGA, beaconing, TLS/QUIC, exfiltration,
JSONL replay, and WebSocket features.
