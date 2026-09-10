"""Build and evaluate a capture-level Mythic HTTP C2 flow classifier."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

from src.feature_extractor import MODEL_FEATURES, flow_to_features
from src.flow_records import read_pcap


POSITIVE = "malicious_c2"
NEGATIVE = {"benign", "benign_external"}
DEFAULT_PCAP_DIR = Path(r"C:\Users\himanshu\Downloads\dataset\TQH-C2_pcap_extracted")
DEFAULT_LABEL_DIR = Path(r"C:\Users\himanshu\Downloads\dataset\TQH-C2_labels_extracted\C")
REPORT_PATH = Path("reports/tqh_c2_metrics.txt")
MODEL_PATH = Path("models/tqh_c2_xgb.json")
FEATURE_PATH = Path("models/tqh_c2_feature_cols.json")
PCAP_CAPTURE_MAP = {
    "C_0804": "C_i30_j0",
    "C_1509": "C_i30_j30",
    "C_1541": "C_i30_j70",
    "C_1615": "C_i300_j0",
    "C_1817": "C_i300_j30",
    "C_2020": "C_i300_j70",
    "C_2223": "C_i1800_j0",
    "C_1026": "C_i1800_j30",
    "C_2228": "C_i1800_j70",
    "C_1031": "C_i3600_j0",
    "C_1034": "C_i3600_j30",
    "C_1036": "C_i3600_j70",
}


def tuple_key(source: str, source_port: int, destination: str, destination_port: int, protocol: str) -> tuple:
    left = (str(source), int(source_port), str(destination), int(destination_port), protocol.upper())
    right = (left[2], left[3], left[0], left[1], left[4])
    return min(left, right)


def load_labels(path: Path) -> dict[tuple, str]:
    labels: dict[tuple, str] = {}
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            item = json.loads(line)
            label = item.get("label")
            if label in NEGATIVE or label == POSITIVE:
                labels[tuple_key(
                    item["orig_h"], item["orig_p"], item["resp_h"], item["resp_p"], item["proto"]
                )] = label
    return labels


def capture_id_from_pcap(path: Path) -> str:
    try:
        return PCAP_CAPTURE_MAP[path.stem]
    except KeyError as exc:
        raise ValueError(f"Unknown TQH PCAP filename: {path.name}") from exc


def build_dataset(pcap_dir: Path, label_dir: Path) -> pd.DataFrame:
    rows: list[dict] = []
    for pcap_path in sorted(pcap_dir.rglob("C_*.pcap")):
        capture_id = capture_id_from_pcap(pcap_path)
        label_path = label_dir / capture_id / "labeled.jsonl"
        if not label_path.exists():
            raise FileNotFoundError(f"No labels found for {capture_id}")
        labels = load_labels(label_path)
        matched = 0
        for flow in read_pcap(pcap_path):
            key = tuple_key(
                flow.source_ip, flow.source_port, flow.destination_ip,
                flow.destination_port, flow.protocol
            )
            label = labels.get(key)
            if label is None:
                continue
            matched += 1
            rows.append({
                "capture_id": capture_id,
                "label": int(label == POSITIVE),
                "label_name": label,
                **flow_to_features(flow.to_dict()),
            })
        print(f"[capture] {capture_id}: matched={matched} labels={len(labels)}")
    if not rows:
        raise RuntimeError("No PCAP flows matched the supplied labels")
    return pd.DataFrame(rows)


def train_and_report(data: pd.DataFrame, report_path: Path, model_path: Path) -> None:
    groups = data["capture_id"].to_numpy()
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    train_idx, test_idx = next(splitter.split(data, data["label"], groups))
    feature_cols = [name for name in MODEL_FEATURES if name in data.columns]
    x_train, x_test = data.iloc[train_idx][feature_cols], data.iloc[test_idx][feature_cols]
    y_train, y_test = data.iloc[train_idx]["label"], data.iloc[test_idx]["label"]
    model = XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.08, subsample=0.9,
        colsample_bytree=0.85, reg_lambda=2.0, min_child_weight=5,
        objective="binary:logistic", eval_metric="logloss", tree_method="hist",
        n_jobs=-1, random_state=42,
    )
    model.fit(x_train, y_train)
    probability = model.predict_proba(x_test)[:, 1]
    prediction = (probability >= 0.5).astype(int)
    train_captures = sorted(data.iloc[train_idx]["capture_id"].unique())
    test_captures = sorted(data.iloc[test_idx]["capture_id"].unique())
    output = (
        "=== TQH MYTHIC HTTP C2 CLASSIFIER ===\n"
        f"rows_total       : {len(data)}\n"
        f"rows_train       : {len(train_idx)}\n"
        f"rows_test        : {len(test_idx)}\n"
        f"train_captures   : {train_captures}\n"
        f"test_captures    : {test_captures}\n"
        f"matched_labels   : {data['label_name'].value_counts().to_dict()}\n"
        f"accuracy         : {accuracy_score(y_test, prediction):.4f}\n"
        f"precision        : {precision_score(y_test, prediction, zero_division=0):.4f}\n"
        f"recall           : {recall_score(y_test, prediction, zero_division=0):.4f}\n"
        f"f1               : {f1_score(y_test, prediction, zero_division=0):.4f}\n"
        f"roc_auc          : {roc_auc_score(y_test, probability):.4f}\n\n"
        "--- classification report ---\n"
        f"{classification_report(y_test, prediction, target_names=['benign', 'malicious_c2'], zero_division=0)}"
        "--- confusion matrix (rows=true, cols=pred) ---\n"
        f"{confusion_matrix(y_test, prediction)}\n"
    )
    print(output)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    model.save_model(str(model_path))
    FEATURE_PATH.write_text(json.dumps(feature_cols, indent=2))
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(output)
    data.to_csv("data/tqh_c2_flow_features.csv", index=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap-dir", type=Path, default=DEFAULT_PCAP_DIR)
    parser.add_argument("--label-dir", type=Path, default=DEFAULT_LABEL_DIR)
    parser.add_argument("--report", type=Path, default=REPORT_PATH)
    parser.add_argument("--model", type=Path, default=MODEL_PATH)
    args = parser.parse_args()
    data = build_dataset(args.pcap_dir, args.label_dir)
    train_and_report(data, args.report, args.model)


if __name__ == "__main__":
    main()
