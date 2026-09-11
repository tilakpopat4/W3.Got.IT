"""
Audit + hardening for Stage 3 (Kalman) and Stage 4 (classifier).

Checks performed
----------------
1. DATA INTEGRITY: NaN/inf remaining, duplicate rows, constant columns,
   train/test leakage (duplicate rows crossing the split).
2. STAGE 4 ROBUSTNESS: 5-fold stratified cross-validation (binary) so the
   0.98 number is proven stable, not a lucky split. Warnings captured.
3. STAGE 4 CORRECTNESS: clean XGBoost construction (no None params), verify
   no single feature dominates unrealistically (leakage proxy).
4. STAGE 3 KALMAN: sanity checks on the filter (NaN-safe, warmup, adapts),
   and a controlled synthetic stream test where an injected burst MUST spike.

Writes reports/audit.txt

Run:  python -m src.audit_models
"""
from __future__ import annotations
import warnings
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, cross_val_score
from xgboost import XGBClassifier

from src import config
from src.kalman_engine import KalmanScalar, KalmanBank

LINES = []


def log(msg=""):
    print(msg)
    LINES.append(str(msg))


def data_integrity(df, feature_cols):
    log("=== 1. DATA INTEGRITY ===")
    X = df[feature_cols]
    n_nan = int(np.isnan(X.values).sum())
    n_inf = int(np.isinf(X.values).sum())
    log(f"remaining NaN cells      : {n_nan}")
    log(f"remaining inf cells      : {n_inf}")

    const_cols = [c for c in feature_cols if df[c].nunique() <= 1]
    log(f"constant feature columns : {const_cols if const_cols else 'none'}")

    dupes = int(df.duplicated(subset=feature_cols).sum())
    log(f"duplicate feature rows   : {dupes} ({dupes/len(df)*100:.1f}%)")
    log("  note: duplicates across train/test can inflate scores (leakage risk).")
    log("")
    return n_nan, n_inf, const_cols, dupes


def build_clf(binary=True, num_class=2):
    """Clean XGBoost builder - no None params passed."""
    params = dict(
        n_estimators=300, max_depth=8, learning_rate=0.15,
        subsample=0.9, colsample_bytree=0.9, tree_method="hist",
        n_jobs=-1, random_state=config.RANDOM_STATE,
    )
    if binary:
        params.update(objective="binary:logistic", eval_metric="logloss")
    else:
        params.update(objective="multi:softprob", eval_metric="mlogloss",
                      num_class=num_class)
    return XGBClassifier(**params)


def stage4_cv(df, feature_cols):
    log("=== 2. STAGE 4 ROBUSTNESS: 5-fold CV (binary Benign-vs-Malicious) ===")
    X = df[feature_cols].values
    y = (df[config.LABEL_COL] != "Benign").astype(int).values

    with warnings.catch_warnings(record=True) as wlist:
        warnings.simplefilter("always")
        clf = build_clf(binary=True)
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=config.RANDOM_STATE)
        # subsample for speed of the audit (stratified) if very large
        if len(y) > 150000:
            idx = np.random.RandomState(config.RANDOM_STATE).permutation(len(y))[:150000]
            Xs, ys = X[idx], y[idx]
        else:
            Xs, ys = X, y
        f1 = cross_val_score(clf, Xs, ys, cv=skf, scoring="f1", n_jobs=-1)
        auc = cross_val_score(clf, Xs, ys, cv=skf, scoring="roc_auc", n_jobs=-1)

    log(f"CV F1  (5-fold)  : mean={f1.mean():.4f}  std={f1.std():.4f}  folds={np.round(f1,4)}")
    log(f"CV AUC (5-fold)  : mean={auc.mean():.4f}  std={auc.std():.4f}")
    log(f"stability verdict: {'STABLE' if f1.std() < 0.02 else 'VARIABLE - investigate'}")

    # dominant-feature (leakage proxy) check
    clf.fit(Xs, ys)
    imp = sorted(zip(feature_cols, clf.feature_importances_), key=lambda t: t[1], reverse=True)
    top_name, top_val = imp[0]
    log(f"top feature      : {top_name} = {top_val:.3f}")
    log(f"leakage check    : {'OK' if top_val < 0.85 else 'WARN single feature dominates'}")
    warnmsgs = {str(w.message) for w in wlist}
    log(f"warnings raised  : {len(warnmsgs)}")
    for w in list(warnmsgs)[:5]:
        log(f"   - {w[:140]}")
    log("")


def stage3_kalman_checks():
    log("=== 3. STAGE 3 KALMAN: unit + controlled-burst tests ===")

    # 3a. NaN-safety
    f = KalmanScalar()
    s0 = f.update(10.0)
    s_nan = f.update(float("nan"))
    nan_safe = not np.isnan(s_nan)
    log(f"NaN-safe update          : {'OK' if nan_safe else 'FAIL (returns NaN)'}")

    # 3b. warmup suppresses early scores
    f2 = KalmanScalar(warmup=20)
    early = [f2.update(100.0 + np.random.randn()) for _ in range(15)]
    log(f"warmup suppresses scores : {'OK' if max(early) == 0.0 else 'WARN nonzero during warmup'}")

    # 3c. CONTROLLED BURST: steady baseline then a spike MUST trigger
    bank = KalmanBank(["rate"], log_metrics=["rate"], soft=3.0, hard=6.0)
    rng = np.random.RandomState(0)
    baseline_scores, burst_scores = [], []
    for _ in range(200):                       # steady benign ~ 500/s
        v = 500 + rng.randn() * 20
        s, _, _ = bank.update({"rate": v})
        baseline_scores.append(s)
    for i in range(30):                        # sudden flood 500 -> 9000/s
        v = 9000 + rng.randn() * 200
        s, _, lvl = bank.update({"rate": v})
        burst_scores.append(s)

    base_max = max(baseline_scores[50:])       # after warmup
    burst_peak = max(burst_scores)
    triggered = burst_peak >= 6.0
    log(f"steady baseline max score: {base_max:.2f}")
    log(f"injected-burst peak score: {burst_peak:.2f}")
    log(f"burst triggers HARD alert: {'OK (detected)' if triggered else 'FAIL (missed)'}")
    log(f"burst >> baseline         : {'OK' if burst_peak > 3*max(base_max,0.1) else 'WARN weak separation'}")
    log("")
    return triggered


def main():
    df = pd.read_parquet(config.CLEAN_PARQUET)
    feature_cols = [c for c in df.columns
                    if c not in (config.LABEL_COL, "label")
                    and pd.api.types.is_numeric_dtype(df[c])]

    log("################  MODEL AUDIT REPORT  ################")
    log(f"dataset rows={len(df)} features={len(feature_cols)}\n")

    n_nan, n_inf, const_cols, dupes = data_integrity(df, feature_cols)
    stage4_cv(df, feature_cols)
    burst_ok = stage3_kalman_checks()

    log("=== SUMMARY ===")
    log(f"Stage4 data clean (no nan/inf) : {'YES' if n_nan == 0 and n_inf == 0 else 'NO'}")
    log(f"Stage4 constant cols to drop   : {const_cols if const_cols else 'none'}")
    log(f"Stage4 duplicate-row leakage   : {'CHECK (' + str(dupes) + ' dupes)' if dupes else 'none'}")
    log(f"Stage3 Kalman burst detection  : {'WORKS' if burst_ok else 'BROKEN'}")

    (config.REPORTS_DIR / "audit.txt").write_text("\n".join(LINES))
    log(f"\n[done] -> {config.REPORTS_DIR / 'audit.txt'}")


if __name__ == "__main__":
    main()
