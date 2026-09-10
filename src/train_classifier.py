"""
Stage 4 - multi-class threat classifier (XGBoost) on the cleaned pcap dataset.

- Loads data/pcap_clean.parquet
- Splits train/test (stratified)
- Handles class imbalance via per-sample weights (inverse class frequency)
- Trains XGBoost multi-class classifier
- Reports accuracy, precision, recall, F1 (macro + weighted) and confusion matrix
- Saves model -> models/xgb_threat.json and a text report -> reports/stage4_metrics.txt

Run:  python -m src.train_classifier
"""
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
)
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from src import config


def main():
    df = pd.read_parquet(config.CLEAN_PARQUET)
    label_map = json.loads((config.DATA_DIR / "label_map.json").read_text())
    inv_map = {v: k for k, v in label_map.items()}

    feature_cols = [
        c for c in df.columns
        if c not in (config.LABEL_COL, "label") and pd.api.types.is_numeric_dtype(df[c])
    ]
    X = df[feature_cols].values
    y = df["label"].values
    print(f"[data] X={X.shape} y_classes={sorted(set(y))} features={len(feature_cols)}")

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=config.TEST_SIZE, random_state=config.RANDOM_STATE, stratify=y
    )

    # Inverse-frequency sample weights to counter imbalance (Mirai dominates)
    sample_w = compute_sample_weight(class_weight="balanced", y=y_tr)

    clf = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.15,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="multi:softprob",
        num_class=len(label_map),
        tree_method="hist",
        eval_metric="mlogloss",
        n_jobs=-1,
        random_state=config.RANDOM_STATE,
    )
    print("[train] fitting XGBoost...")
    clf.fit(X_tr, y_tr, sample_weight=sample_w)

    y_pred = clf.predict(X_te)

    acc = accuracy_score(y_te, y_pred)
    p_m, r_m, f_m, _ = precision_recall_fscore_support(y_te, y_pred, average="macro", zero_division=0)
    p_w, r_w, f_w, _ = precision_recall_fscore_support(y_te, y_pred, average="weighted", zero_division=0)

    target_names = [inv_map[i] for i in sorted(inv_map)]
    report = classification_report(y_te, y_pred, target_names=target_names, zero_division=0)
    cm = confusion_matrix(y_te, y_pred)

    # Top feature importances
    importances = clf.feature_importances_
    top = sorted(zip(feature_cols, importances), key=lambda t: t[1], reverse=True)[:12]

    lines = []
    lines.append("=== STAGE 4 CLASSIFIER (XGBoost) — TEST METRICS ===")
    lines.append(f"accuracy            : {acc:.4f}")
    lines.append(f"precision (macro)   : {p_m:.4f}   (weighted): {p_w:.4f}")
    lines.append(f"recall    (macro)   : {r_m:.4f}   (weighted): {r_w:.4f}")
    lines.append(f"f1-score  (macro)   : {f_m:.4f}   (weighted): {f_w:.4f}")
    lines.append("\n--- per-class report ---")
    lines.append(report)
    lines.append("--- confusion matrix (rows=true, cols=pred) ---")
    lines.append("labels: " + ", ".join(f"{i}={n}" for i, n in enumerate(target_names)))
    lines.append(np.array2string(cm))
    lines.append("\n--- top feature importances ---")
    for name, imp in top:
        lines.append(f"{name:20s} {imp:.4f}")
    out = "\n".join(lines)

    print("\n" + out)

    clf.save_model(str(config.MODELS_DIR / "xgb_threat.json"))
    (config.REPORTS_DIR / "stage4_metrics.txt").write_text(out)
    (config.MODELS_DIR / "feature_cols.json").write_text(json.dumps(feature_cols, indent=2))
    print(f"\n[done] model -> {config.MODELS_DIR / 'xgb_threat.json'}")
    print(f"[done] report -> {config.REPORTS_DIR / 'stage4_metrics.txt'}")


if __name__ == "__main__":
    main()
