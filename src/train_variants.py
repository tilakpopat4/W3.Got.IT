"""
Stage 4 improved training - two variants + comparison.

Variant A: BINARY  Benign vs Malicious
Variant B: MULTICLASS (cleaned) - drop 'Unknown', merge DarkNexus/Gafgyt/Generic -> 'Botnet',
           keep Mirai and Benign.  Classes: Benign / Mirai / Botnet

Both use SMOTE (train split only) instead of full 'balanced' weights, so the
majority class (Mirai) is not sacrificed. Reports accuracy/precision/recall/F1
and confusion matrix, and writes a combined comparison table.

Run:  python -m src.train_variants
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
    roc_auc_score,
)
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier

from src import config

BENIGN = "Benign"
BOTNET_MERGE = {"DarkNexus", "Gafgyt", "Generic"}
DROP = {"Unknown"}


def load():
    df = pd.read_parquet(config.CLEAN_PARQUET)
    feature_cols = [
        c for c in df.columns
        if c not in (config.LABEL_COL, "label") and pd.api.types.is_numeric_dtype(df[c])
    ]
    return df, feature_cols


def make_model(num_class):
    return XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.15,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="binary:logistic" if num_class == 2 else "multi:softprob",
        num_class=None if num_class == 2 else num_class,
        tree_method="hist",
        eval_metric="logloss" if num_class == 2 else "mlogloss",
        n_jobs=-1,
        random_state=config.RANDOM_STATE,
    )


def evaluate(name, y_te, y_pred, target_names, proba=None):
    acc = accuracy_score(y_te, y_pred)
    p_m, r_m, f_m, _ = precision_recall_fscore_support(y_te, y_pred, average="macro", zero_division=0)
    p_w, r_w, f_w, _ = precision_recall_fscore_support(y_te, y_pred, average="weighted", zero_division=0)
    lines = [f"=== {name} ===",
             f"accuracy          : {acc:.4f}",
             f"precision (macro) : {p_m:.4f}   (weighted): {p_w:.4f}",
             f"recall    (macro) : {r_m:.4f}   (weighted): {r_w:.4f}",
             f"f1-score  (macro) : {f_m:.4f}   (weighted): {f_w:.4f}"]
    if proba is not None and len(target_names) == 2:
        try:
            lines.append(f"roc-auc           : {roc_auc_score(y_te, proba):.4f}")
        except Exception:
            pass
    lines.append("\n--- per-class ---")
    lines.append(classification_report(y_te, y_pred, target_names=target_names, zero_division=0))
    lines.append("--- confusion matrix (rows=true, cols=pred) ---")
    lines.append("labels: " + ", ".join(f"{i}={n}" for i, n in enumerate(target_names)))
    lines.append(np.array2string(confusion_matrix(y_te, y_pred)))
    return acc, f_w, "\n".join(lines)


def run_binary(df, feature_cols):
    y = (df[config.LABEL_COL] != BENIGN).astype(int)  # 1 = malicious
    X = df[feature_cols].values
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=config.TEST_SIZE, random_state=config.RANDOM_STATE, stratify=y)
    X_tr, y_tr = SMOTE(random_state=config.RANDOM_STATE).fit_resample(X_tr, y_tr)
    clf = make_model(2)
    clf.fit(X_tr, y_tr)
    proba = clf.predict_proba(X_te)[:, 1]
    y_pred = (proba >= 0.5).astype(int)
    clf.save_model(str(config.MODELS_DIR / "xgb_binary.json"))
    return evaluate("VARIANT A - BINARY (Benign vs Malicious)", y_te, y_pred,
                    ["Benign", "Malicious"], proba)


def run_multiclass(df, feature_cols):
    d = df[~df[config.LABEL_COL].isin(DROP)].copy()

    def remap(x):
        if x in BOTNET_MERGE:
            return "Botnet"
        return x
    d["cls"] = d[config.LABEL_COL].map(remap)
    classes = sorted(d["cls"].unique())
    cmap = {c: i for i, c in enumerate(classes)}
    y = d["cls"].map(cmap).values
    X = d[feature_cols].values
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=config.TEST_SIZE, random_state=config.RANDOM_STATE, stratify=y)
    X_tr, y_tr = SMOTE(random_state=config.RANDOM_STATE).fit_resample(X_tr, y_tr)
    clf = make_model(len(classes))
    clf.fit(X_tr, y_tr)
    y_pred = clf.predict(X_te)
    clf.save_model(str(config.MODELS_DIR / "xgb_multiclass_clean.json"))
    (config.MODELS_DIR / "multiclass_label_map.json").write_text(json.dumps(cmap, indent=2))
    return evaluate(f"VARIANT B - MULTICLASS (classes={classes})", y_te, y_pred, classes)


def main():
    df, feature_cols = load()

    accA, fA, repA = run_binary(df, feature_cols)
    accB, fB, repB = run_multiclass(df, feature_cols)

    summary = [
        "################  STAGE 4 - VARIANT COMPARISON  ################\n",
        repA, "\n", repB, "\n",
        "================  SUMMARY TABLE  ================",
        f"{'variant':40s} {'accuracy':>10s} {'f1(weighted)':>14s}",
        f"{'Original 6-class (balanced weights)':40s} {0.4927:>10.4f} {0.5689:>14.4f}",
        f"{'A: Binary Benign-vs-Malicious':40s} {accA:>10.4f} {fA:>14.4f}",
        f"{'B: Multiclass clean (Benign/Mirai/Botnet)':40s} {accB:>10.4f} {fB:>14.4f}",
    ]
    out = "\n".join(summary)
    print(out)
    (config.REPORTS_DIR / "stage4_variants.txt").write_text(out)
    print(f"\n[done] -> {config.REPORTS_DIR / 'stage4_variants.txt'}")


if __name__ == "__main__":
    main()
