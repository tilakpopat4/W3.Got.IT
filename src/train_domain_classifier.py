"""Train a streaming domain/DGA classifier from the supplied gzip CSV files.

The domain dataset is intentionally a separate model from the numeric flow
classifier: it has only ``domain,class`` columns and cannot be concatenated
with the Parquet flow features without inventing unsupported values.

Run:
    python -m src.train_domain_classifier
"""
from __future__ import annotations

import csv
import gzip
import json
import time
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score

from src import config


DATA_DIR = Path(r"C:\Users\himanshu\Downloads\dataset\6508640_extracted")
TRAIN_PATH = DATA_DIR / "train_combined_multiclass.csv.gz"
TEST_PATH = DATA_DIR / "test_combined_multiclass.csv.gz"
MODEL_PATH = config.MODELS_DIR / "dga_domain_sgd.joblib"
REPORT_PATH = config.REPORTS_DIR / "dga_domain_metrics.txt"
LABEL_PATH = config.MODELS_DIR / "dga_domain_label_map.json"
BATCH_SIZE = 25_000


def rows(path: Path, batch_size: int = BATCH_SIZE):
    with gzip.open(path, "rt", newline="", encoding="utf-8") as stream:
        reader = csv.reader(stream)
        next(reader)
        batch_domains: list[str] = []
        batch_labels: list[int] = []
        for domain, label in reader:
            batch_domains.append(domain)
            batch_labels.append(int(label))
            if len(batch_domains) == batch_size:
                yield batch_domains, np.asarray(batch_labels, dtype=np.int64)
                batch_domains, batch_labels = [], []
        if batch_domains:
            yield batch_domains, np.asarray(batch_labels, dtype=np.int64)


def count_labels(path: Path) -> Counter[int]:
    counts: Counter[int] = Counter()
    for _, labels in rows(path):
        counts.update(labels.tolist())
    return counts


def main() -> None:
    started = time.perf_counter()
    train_counts = count_labels(TRAIN_PATH)
    classes = np.asarray(sorted(train_counts), dtype=np.int64)
    total = sum(train_counts.values())
    class_weights = {
        label: total / (len(classes) * train_counts[label]) for label in classes
    }
    vectorizer = HashingVectorizer(
        analyzer="char",
        ngram_range=(2, 5),
        n_features=2**18,
        lowercase=True,
        alternate_sign=False,
        norm="l2",
    )
    classifier = SGDClassifier(
        loss="log_loss",
        alpha=1e-5,
        max_iter=1,
        learning_rate="optimal",
        random_state=config.RANDOM_STATE,
        class_weight=class_weights,
    )

    batches = 0
    for domains, labels in rows(TRAIN_PATH):
        classifier.partial_fit(vectorizer.transform(domains), labels, classes=classes)
        batches += 1
        if batches == 1:
            classes = None

    true: list[int] = []
    predicted: list[int] = []
    for domains, labels in rows(TEST_PATH):
        pred = classifier.predict(vectorizer.transform(domains))
        true.extend(labels.tolist())
        predicted.extend(pred.tolist())

    accuracy = accuracy_score(true, predicted)
    macro_f1 = f1_score(true, predicted, average="macro", zero_division=0)
    weighted_f1 = f1_score(true, predicted, average="weighted", zero_division=0)
    report = classification_report(true, predicted, digits=4, zero_division=0)
    elapsed = time.perf_counter() - started
    test_rows = len(true)
    output = (
        "=== DOMAIN/DGA CLASSIFIER ===\n"
        f"train_file       : {TRAIN_PATH}\n"
        f"test_file        : {TEST_PATH}\n"
        f"train_rows       : {total}\n"
        f"test_rows        : {test_rows}\n"
        f"train_classes    : {dict(sorted(train_counts.items()))}\n"
        f"batches          : {batches}\n"
        f"features         : char ngrams 2-5, hashing dimension 262144\n"
        f"accuracy         : {accuracy:.4f}\n"
        f"macro_f1         : {macro_f1:.4f}\n"
        f"weighted_f1      : {weighted_f1:.4f}\n"
        f"elapsed_seconds  : {elapsed:.2f}\n"
        f"rows_per_second  : {(total + test_rows) / elapsed:.2f}\n\n"
        "--- per-class report ---\n"
        f"{report}"
    )
    print(output)
    joblib.dump({"vectorizer": vectorizer, "classifier": classifier}, MODEL_PATH)
    LABEL_PATH.write_text(json.dumps({str(label): int(label) for label in sorted(train_counts)}, indent=2))
    REPORT_PATH.write_text(output)
    print(f"[done] model -> {MODEL_PATH}")
    print(f"[done] report -> {REPORT_PATH}")


if __name__ == "__main__":
    main()
