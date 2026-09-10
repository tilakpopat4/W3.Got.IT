"""
Stage 1-2 data preparation for pcap.parquet.

Fixes discovered during inspection:
- `Rate` contains +inf values (division artifacts) -> cap to a finite percentile.
- `Std` and `Variance` have ~483 NaNs -> impute with 0 (single-packet windows).
- Drop dead/constant/identifier columns: Arch (all x86), SMTP (all 0), IRC (all 0), Hash (id).
- Encode MalwareFamily labels -> integer classes (label_map.json saved).
- Produce a clean parquet ready for training.

Run:  python -m src.data_clean
"""
import json
import numpy as np
import pandas as pd

from src import config


def load_raw() -> pd.DataFrame:
    print(f"[load] reading {config.RAW_PARQUET}")
    df = pd.read_parquet(config.RAW_PARQUET)
    print(f"[load] shape={df.shape}")
    return df


def clean(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    # 1) Drop dead / identifier columns (keep only those present)
    drop = [c for c in config.DROP_COLS if c in df.columns]
    df = df.drop(columns=drop)
    print(f"[clean] dropped columns: {drop}")

    # 2) Replace +/-inf with NaN so we can handle uniformly
    df = df.replace([np.inf, -np.inf], np.nan)

    # 3) Cap 'Rate' outliers at the 99.9th percentile (robust to floods)
    if "Rate" in df.columns:
        cap = df["Rate"].quantile(0.999)
        n_over = (df["Rate"] > cap).sum()
        df["Rate"] = df["Rate"].clip(upper=cap)
        print(f"[clean] capped 'Rate' at p99.9={cap:.2f} ({n_over} rows)")

    # 4) Impute remaining NaNs in numeric feature columns with 0
    label = config.LABEL_COL
    num_cols = [c for c in df.columns if c != label and pd.api.types.is_numeric_dtype(df[c])]
    n_nan = int(df[num_cols].isna().sum().sum())
    df[num_cols] = df[num_cols].fillna(0)
    print(f"[clean] imputed {n_nan} NaN cells with 0 across {len(num_cols)} numeric cols")

    return df


def encode_labels(df: pd.DataFrame):
    label = config.LABEL_COL
    classes = sorted(df[label].astype(str).unique())
    label_map = {name: i for i, name in enumerate(classes)}
    df["label"] = df[label].astype(str).map(label_map)
    print(f"[encode] label_map={label_map}")
    return df, label_map


def main():
    df = load_raw()
    df = clean(df)
    df, label_map = encode_labels(df)

    # Save cleaned dataset + label map
    df.to_parquet(config.CLEAN_PARQUET, index=False)
    (config.DATA_DIR / "label_map.json").write_text(json.dumps(label_map, indent=2))

    print(f"\n[done] clean dataset -> {config.CLEAN_PARQUET}")
    print(f"[done] rows={len(df)} cols={df.shape[1]}")
    print("[done] class distribution:")
    print(df[config.LABEL_COL].value_counts().to_string())


if __name__ == "__main__":
    main()
