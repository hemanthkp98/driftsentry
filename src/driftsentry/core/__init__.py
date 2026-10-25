"""Core engine — models, scanner, differ, configuration, and baseline."""

from driftsentry.core.baseline import (
    DEFAULT_BASELINE_FILENAME,
    BaselineEntry,
    BaselineFilterResult,
    DriftBaseline,
    compute_drift_fingerprint,
    filter_against_baseline,
    fingerprint_from_drift_item,
    load_baseline,
    save_baseline,
)

__all__ = [
    "DEFAULT_BASELINE_FILENAME",
    "BaselineEntry",
    "BaselineFilterResult",
    "DriftBaseline",
    "compute_drift_fingerprint",
    "filter_against_baseline",
    "fingerprint_from_drift_item",
    "load_baseline",
    "save_baseline",
]
