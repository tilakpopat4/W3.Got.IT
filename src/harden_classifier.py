"""
Stage 4 hardening:
1. Drop exact duplicate rows (leakage risk found in audit: 337 dupes).
2. Regularize XGBoost (colsample_bynode, reg_lambda, min_child_weight) to
   spread importance across features instead of relying on 'TCP' (90%).
3. Train a robustness variant WITHOUT 'TCP' to prove the model is not a
   single-feature trick, and compare.

Writes reports/stage4_hardened.txt

Run:  python -m src.harden_classifier
"""
from __future__ import annotations
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, precision_recall_fscore_support
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier

from src import config

OUT = []


def log(m=""):
    print(m)
    OUT.append(str(m))


def make_clf():
    # colsample_bynode + regularization spread feature usage -> less dominance
    return XGBClassifier(
        n_estimators=400, max_depth=6, learning_rate=0.1,
        subsample=0.9, colsample_bytree=0.8, colsample_bynode=0.6,
        reg_lambda=2.0, min_child_weight=5,
        objective="binary:logistic", eval_metric="logloss",
        tree_method="hist", n_jobs=-1, random_state=config.RANDOM_STATE,
    )


def train_eval(X, y, feature_cols, tag):
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=config.TEST_SIZE, random_state=config.RANDOM_STATE, stratify=y)
    Xtr, ytr = SMOTE(random_state=config.RANDOM_STATE).fit_resample(Xtr, ytr)
    clf = make_clf()
    clf.fit(Xtr, ytr)
    proba = clf.predict_proba(Xte)[:, 1]
    pred = (proba >= 0.5).astype(int)
    acc = accuracy_score(yte, pred)
    f1 = f1_score(yte, pred)
    auc = roc_auc_score(yte, proba)
    p, r, _, _ = precision_recall_fscore_support(yte, pred, average="binary", zero_division=0)
    log(f"[{tag}] acc={acc:.4f} f1={f1:.4f} auc={auc:.4f} precision={p:.4f} recall={r:.4f}")
    imp = sorted(zip(feature_cols, clf.feature_importances_), key=lambda t: t[1], reverse=True)[:8]
    log(f"[{tag}] top features: " + ", ".join(f"{n}={v:.2f}" for n, v in imp))
    return clf, acc, f1, auc


def main():
    df = pd.read_parquet(config.CLEAN_PARQUET)
    feats_all = [c for c in df.columns
                 if c not in (config.LABEL_COL, "label")
                 and pd.api.types.is_numeric_dtype(df[c])]

    log("################  STAGE 4 HARDENING  ################")
    log(f"rows before dedup : {len(df)}")
    df = df.drop_duplicates(subset=feats_all).reset_index(drop=True)
    log(f"rows after  dedup : {len(df)}")

    y = (df[config.LABEL_COL] != "Benign").astype(int).values

    log("\n--- A) hardened model (all features, regularized) ---")
    Xa = df[feats_all].values
    clfA, accA, f1A, aucA = train_eval(Xa, y, feats_all, "ALL")
    clfA.save_model(str(config.MODELS_DIR / "xgb_binary_hardened.json"))

    log("\n--- B) robustness check: WITHOUT 'TCP' feature ---")
    feats_noTCP = [c for c in feats_all if c != "TCP"]
    Xb = df[feats_noTCP].values
    _, accB, f1B, aucB = train_eval(Xb, y, feats_noTCP, "NO_TCP")

    log("\n=== VERDICT ===")
    log(f"with TCP    : acc={accA:.4f} f1={f1A:.4f} auc={aucA:.4f}")
    log(f"without TCP : acc={accB:.4f} f1={f1B:.4f} auc={aucB:.4f}")
    drop = f1A - f1B
    if f1B >= 0.90:
        log(f"robustness  : STRONG - keeps f1={f1B:.3f} even without TCP (only {drop:.3f} drop). Not a single-feature trick.")
    elif f1B >= 0.80:
        log(f"robustness  : OK - f1 drops to {f1B:.3f} without TCP (-{drop:.3f}).")
    else:
        log(f"robustness  : WEAK - f1 collapses to {f1B:.3f} without TCP (-{drop:.3f}); over-relies on one feature.")

    (config.REPORTS_DIR / "stage4_hardened.txt").write_text("\n".join(OUT))
    log(f"\n[done] -> {config.REPORTS_DIR / 'stage4_hardened.txt'}")


if __name__ == "__main__":
    main()
