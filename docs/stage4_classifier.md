# Stage 4 — Threat Classifier

**Code:** `src/train_classifier.py`, `src/train_variants.py`, `src/harden_classifier.py`, `src/audit_models.py`
**Reports:** `reports/stage4_metrics.txt`, `reports/stage4_variants.txt`, `reports/stage4_hardened.txt`, `reports/audit.txt`
**Role:** Labels *what* the threat is, with a probability. Pairs with Stage 3.

## Model
XGBoost gradient-boosted trees. Chosen for fast inference, strong tabular performance, and **explainability** (feature importances → evidence for alerts).

## Evolution & results

### v1 — 6-class (`models/xgb_threat.json`)
accuracy **0.49**, weighted F1 **0.57**. Failed because: full `balanced` weights sacrificed Mirai; `Unknown` is a garbage label; single feature dominated.

### v2 — variants (`models/xgb_binary.json`, `models/xgb_multiclass_clean.json`)
| Variant | Accuracy | F1 (weighted) |
|---|---|---|
| Binary (Benign vs Malicious) | **0.9839** | **0.9841** (AUC 0.9986) |
| Multiclass (Benign/Mirai/Botnet) | 0.9201 | 0.9170 |
Fixes: dropped `Unknown`, merged small botnet families → `Botnet`, SMOTE instead of full balancing.

### Audit (`reports/audit.txt`)
- 5-fold CV (binary): **F1 0.9906, std 0.0005**, AUC 0.9983 → stable.
- Found: 337 duplicate rows (leakage risk); `TCP` importance 0.90 (single-feature dominance).

### v3 — hardened (`models/xgb_binary_hardened.json`) ⭐ use this
- Dropped duplicates (455,641 → 455,304).
- Regularized: `colsample_bynode=0.6, reg_lambda=2.0, min_child_weight=5` → `TCP` importance 0.90 → **0.55**.
- Metrics: acc **0.983**, F1 **0.990**, AUC **0.999** (precision 0.999 / recall 0.981).
- **Robustness proof:** retrained WITHOUT `TCP` → F1 still **0.990** (zero drop). Not a single-feature trick.

## Threat coverage
Trained on botnet families (Mirai/Gafgyt/DarkNexus/Generic) + Benign → covers **DDoS + botnet** strongly. DGA, encrypted-malware, port-scan, exfiltration need additional datasets (see [datasets.md](datasets.md)).

## Current best artifacts
- Model: `models/xgb_binary_hardened.json`
- Feature list: `models/feature_cols.json`
- Multiclass label map: `models/multiclass_label_map.json`
