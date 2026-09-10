"""Central config: paths and constants for the SIH-145 threat-detection pipeline."""
from pathlib import Path

# Source dataset (labeled flow features, CICIoT-style)
RAW_PARQUET = r"C:\Users\himanshu\Downloads\CN\pcap.parquet"

# Project directories
ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
MODELS_DIR = ROOT / "models"
REPORTS_DIR = ROOT / "reports"

for _d in (DATA_DIR, MODELS_DIR, REPORTS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# Cleaned dataset outputs
CLEAN_PARQUET = DATA_DIR / "pcap_clean.parquet"
LABEL_COL = "MalwareFamily"

# Columns to drop: dead/constant or identifier columns
DROP_COLS = ["Arch", "SMTP", "IRC", "Hash"]

# Kalman-relevant time-series/statistical signals
KALMAN_FEATURES = ["Rate", "IAT", "syn_count", "Tot size", "Variance"]

RANDOM_STATE = 42
TEST_SIZE = 0.2
