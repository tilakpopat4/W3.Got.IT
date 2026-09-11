"""Live-only calibration summaries for benign traffic captures."""
from __future__ import annotations

from collections.abc import Iterable

import numpy as np


DEFAULT_THRESHOLDS = (0.50, 0.75, 0.90, 0.95, 0.99)


def summarize_probabilities(
    flows: Iterable[dict],
    thresholds: tuple[float, ...] = DEFAULT_THRESHOLDS,
) -> dict:
    """Summarize classifier probabilities from a capture known to be benign."""
    probabilities = np.asarray(
        [float(flow["probability"]) for flow in flows],
        dtype=float,
    )
    probabilities = probabilities[np.isfinite(probabilities)]
    probabilities.sort()
    count = int(probabilities.size)
    if not count:
        return {
            "flows": 0,
            "probability_quantiles": {},
            "thresholds": {},
            "warning": "No scored flows are available for calibration.",
        }

    quantiles = {
        label: round(float(np.quantile(probabilities, value)), 6)
        for label, value in (
            ("p50", 0.50),
            ("p90", 0.90),
            ("p95", 0.95),
            ("p99", 0.99),
            ("max", 1.00),
        )
    }
    threshold_results = {
        f"{threshold:.2f}": {
            "flagged_flows": int(np.count_nonzero(probabilities >= threshold)),
            "false_positive_rate": round(
                float(np.count_nonzero(probabilities >= threshold) / count), 6
            ),
        }
        for threshold in thresholds
    }
    return {
        "flows": count,
        "probability_quantiles": quantiles,
        "thresholds": threshold_results,
        "warning": (
            "Use only a capture containing known-benign activity. "
            "These measurements do not prove threat-detection accuracy."
        ),
    }
