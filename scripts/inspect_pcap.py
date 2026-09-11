import pandas as pd

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 200)

path = r"C:\Users\himanshu\Downloads\CN\pcap.parquet"
df = pd.read_parquet(path)

print("=== SHAPE ===")
print("rows:", len(df), "cols:", len(df.columns))

print("\n=== COLUMNS + DTYPES ===")
for c in df.columns:
    print(f"{c:30s} {str(df[c].dtype):12s} nulls={df[c].isna().sum()}")

print("\n=== HEAD (5 rows) ===")
print(df.head(5).to_string())

print("\n=== PER-COLUMN QUICK SUMMARY ===")
for c in df.columns:
    nun = df[c].nunique(dropna=True)
    print(f"\n--- {c} | unique={nun} ---")
    if nun <= 15:
        print(df[c].value_counts(dropna=False).head(15).to_string())
    else:
        try:
            print(df[c].describe().to_string())
        except Exception:
            print(df[c].astype(str).value_counts().head(5).to_string())
