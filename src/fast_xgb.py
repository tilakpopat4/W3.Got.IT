"""Lightweight pure-Python/NumPy XGBoost JSON model evaluator for serverless runtimes.

Eliminates the heavy native C++ libxgboost binary (~250MB) dependency on Vercel/Lambda.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
import numpy as np


class FastXGBPredictor:
    """Evaluates XGBoost decision tree ensembles directly from JSON model dumps."""

    def __init__(self, json_path: str | Path, feature_cols: list[str] | None = None):
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        learner = data["learner"]
        gbtree = learner["gradient_booster"]["model"]
        self.trees = gbtree["trees"]
        param = learner["learner_model_param"]
        raw_bs = str(param.get("base_score", "0.5")).strip("[]")
        bs = float(raw_bs)
        self.base_margin = math.log(bs / (1.0 - bs)) if 0 < bs < 1 else 0.0
        self.feature_cols = feature_cols or []

        feature_gain: dict[int, float] = {}
        for tree in self.trees:
            split_indices = tree["split_indices"]
            gains = tree.get("gains", [0.0] * len(split_indices))
            lefts = tree["left_children"]
            for node in range(len(lefts)):
                if lefts[node] != -1:
                    feat_idx = split_indices[node]
                    feature_gain[feat_idx] = feature_gain.get(feat_idx, 0.0) + gains[node]
        self.feature_gain = feature_gain

    def predict_proba(self, feature_vector: np.ndarray) -> np.ndarray:
        raw_sum = self.base_margin
        vec = feature_vector[0] if feature_vector.ndim == 2 else feature_vector
        for tree in self.trees:
            node = 0
            lefts = tree["left_children"]
            rights = tree["right_children"]
            split_indices = tree["split_indices"]
            split_conditions = tree["split_conditions"]
            default_left = tree["default_left"]

            while lefts[node] != -1:
                feat_idx = split_indices[node]
                feat_val = vec[feat_idx]
                thresh = split_conditions[node]
                if np.isnan(feat_val):
                    node = lefts[node] if default_left[node] else rights[node]
                elif feat_val < thresh:
                    node = lefts[node]
                else:
                    node = rights[node]
            raw_sum += split_conditions[node]
        prob = 1.0 / (1.0 + math.exp(-raw_sum))
        return np.array([[1.0 - prob, prob]])

    @property
    def feature_importances_(self) -> np.ndarray:
        num_cols = len(self.feature_cols) if self.feature_cols else (max(self.feature_gain.keys(), default=0) + 1)
        arr = np.zeros(num_cols)
        tot = sum(self.feature_gain.values()) or 1.0
        for k, v in self.feature_gain.items():
            if k < num_cols:
                arr[k] = v / tot
        return arr
