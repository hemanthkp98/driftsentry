"""Drift baseline and acknowledged-drift ledger.

Provides persistent drift suppression via deterministic SHA-256 fingerprinting.
Enables infrastructure teams to acknowledge known drift states (such as emergency
hotfixes or approved manual overrides) so they do not produce alert fatigue in
subsequent scans or CI/CD pipelines.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from driftsentry.core.models import (
    AttributeDiff,
    DriftItem,
    DriftResult,
    DriftType,
)

logger = logging.getLogger(__name__)

DEFAULT_BASELINE_FILENAME = ".driftsentry-baseline.json"


def canonical_json_dumps(obj: Any) -> str:
    """Serialize an object to a deterministic canonical JSON string.

    Dictionary keys are sorted recursively and stable delimiters are used.
    Non-serializable types fall back to string representations.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def compute_drift_fingerprint(
    resource_address: str,
    drift_type: DriftType,
    attribute_path: str | None,
    actual_value: Any,
) -> str:
    """Generate a deterministic SHA-256 fingerprint for a specific drift state.

    Args:
        resource_address: Resource address in IaC (e.g. 'aws_security_group.web').
        drift_type: Type of drift (changed, deleted, unmanaged).
        attribute_path: Attribute path in dot-notation (None for deleted/unmanaged).
        actual_value: Actual live cloud value at the time of observation.

    Returns:
        Hex-encoded SHA-256 hash string.
    """
    norm_address = resource_address.strip().lower()
    norm_drift_type = drift_type.value.strip().lower()
    norm_attr_path = (attribute_path or "").strip()
    norm_value_str = canonical_json_dumps(actual_value)

    payload = f"{norm_address}|{norm_drift_type}|{norm_attr_path}|{norm_value_str}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def fingerprint_from_drift_item(
    item: DriftItem,
    attribute_diff: AttributeDiff | None = None,
) -> str:
    """Extract attributes from a DriftItem and compute its deterministic fingerprint.

    Args:
        item: The detected DriftItem.
        attribute_diff: Specific attribute difference if item drift_type is CHANGED.

    Returns:
        Hex-encoded SHA-256 hash string.
    """
    attr_path = attribute_diff.path if attribute_diff is not None else None
    actual_val: Any = None
    if attribute_diff is not None:
        actual_val = attribute_diff.actual_value
    elif item.drift_type == DriftType.UNMANAGED and item.cloud_resource:
        actual_val = item.cloud_resource.attributes

    return compute_drift_fingerprint(
        resource_address=item.resource_address,
        drift_type=item.drift_type,
        attribute_path=attr_path,
        actual_value=actual_val,
    )


class BaselineEntry(BaseModel):
    """Represents an individual acknowledged drift item."""

    resource_address: str = Field(description="Resource address, e.g. 'aws_security_group.web'")
    resource_type: str = Field(description="Resource type, e.g. 'aws_security_group'")
    resource_id: str | None = Field(default=None, description="Cloud resource ID")
    drift_type: DriftType = Field(description="Type of drift detected")
    attribute_path: str | None = Field(
        default=None,
        description="Path of the drifted attribute (None for deleted/unmanaged)",
    )
    fingerprint: str = Field(description="SHA-256 hex digest uniquely identifying this drift state")
    acknowledged_at: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC),
        description="UTC timestamp when entry was recorded",
    )
    acknowledged_by: str | None = Field(
        default=None,
        description="Identity or user who acknowledged the drift",
    )
    reason: str | None = Field(
        default=None,
        description="Human-readable note or ticket reference",
    )
    last_known_value: Any = Field(
        default=None,
        description="Value in cloud at time of acknowledgment",
    )


class DriftBaseline(BaseModel):
    """Container for acknowledged drift baseline entries."""

    version: int = Field(default=1, description="Schema version")
    created_at: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC),
        description="When the baseline was first created",
    )
    updated_at: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC),
        description="When the baseline was last modified",
    )
    entries: list[BaselineEntry] = Field(
        default_factory=list,
        description="Collection of acknowledged baseline entries",
    )

    def find_entry(
        self, resource_address: str, attribute_path: str | None = None
    ) -> BaselineEntry | None:
        """Find a baseline entry by resource address and optional attribute path."""
        norm_address = resource_address.strip().lower()
        norm_path = (attribute_path or "").strip()
        for entry in self.entries:
            if (
                entry.resource_address.strip().lower() == norm_address
                and (entry.attribute_path or "").strip() == norm_path
            ):
                return entry
        return None

    def add_or_update_entry(self, entry: BaselineEntry) -> None:
        """Add a new baseline entry or replace an existing entry for the same address/path."""
        norm_address = entry.resource_address.strip().lower()
        norm_path = (entry.attribute_path or "").strip()
        for i, existing in enumerate(self.entries):
            if (
                existing.resource_address.strip().lower() == norm_address
                and (existing.attribute_path or "").strip() == norm_path
            ):
                self.entries[i] = entry
                self.updated_at = datetime.datetime.now(datetime.UTC)
                return
        self.entries.append(entry)
        self.updated_at = datetime.datetime.now(datetime.UTC)

    def remove_entry(self, resource_address: str, attribute_path: str | None = None) -> bool:
        """Remove a baseline entry by resource address and optional attribute path."""
        norm_address = resource_address.strip().lower()
        norm_path = (attribute_path or "").strip()
        for i, existing in enumerate(self.entries):
            if (
                existing.resource_address.strip().lower() == norm_address
                and (existing.attribute_path or "").strip() == norm_path
            ):
                del self.entries[i]
                self.updated_at = datetime.datetime.now(datetime.UTC)
                return True
        return False


def load_baseline(path: Path | str | None = None) -> DriftBaseline | None:
    """Load and parse DriftBaseline from a JSON file.

    Args:
        path: Custom path to baseline JSON file, or None for default.

    Returns:
        Parsed DriftBaseline instance, or None if file does not exist or fails validation.
    """
    baseline_path = Path(path) if path else (Path.cwd() / DEFAULT_BASELINE_FILENAME)
    if not baseline_path.exists():
        return None

    try:
        content = baseline_path.read_text(encoding="utf-8")
        return DriftBaseline.model_validate_json(content)
    except Exception as e:
        logger.warning(f"Failed to load drift baseline from {baseline_path}: {e}")
        return None


def save_baseline(baseline: DriftBaseline, path: Path | str | None = None) -> Path:
    """Save DriftBaseline to a JSON file.

    Args:
        baseline: The DriftBaseline to write.
        path: Custom destination path, or None for default.

    Returns:
        Resolved Path where the baseline was saved.
    """
    baseline_path = Path(path) if path else (Path.cwd() / DEFAULT_BASELINE_FILENAME)
    baseline.updated_at = datetime.datetime.now(datetime.UTC)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(
        baseline.model_dump_json(indent=2),
        encoding="utf-8",
    )
    return baseline_path


class BaselineFilterResult(BaseModel):
    """Breakdown of drift filtering results against a baseline."""

    active_items: list[DriftItem] = Field(
        default_factory=list,
        description="Items with no baseline match (net-new drift)",
    )
    acknowledged_items: list[DriftItem] = Field(
        default_factory=list,
        description="Items whose fingerprints match a baseline entry exactly",
    )
    regression_items: list[DriftItem] = Field(
        default_factory=list,
        description="Items matching baseline address/attribute whose fingerprint differs (re-drifted)",
    )

    @property
    def total_active(self) -> int:
        """Count of active unacknowledged and regressed items requiring attention."""
        return len(self.active_items) + len(self.regression_items)

    @property
    def total_acknowledged(self) -> int:
        """Count of fully acknowledged items suppressed by baseline."""
        return len(self.acknowledged_items)


def filter_against_baseline(
    result: DriftResult,
    baseline: DriftBaseline,
) -> tuple[DriftResult, BaselineFilterResult]:
    """Filter a DriftResult against a DriftBaseline.

    Separates detected drift items into:
    - Active: Unacknowledged, novel drift items
    - Acknowledged: Items matching the baseline fingerprint exactly
    - Regression: Items matching address/attribute in baseline whose fingerprint differs

    Args:
        result: The original DriftResult from scanning.
        baseline: The DriftBaseline ledger to filter against.

    Returns:
        A tuple of (filtered_drift_result, filter_breakdown), where
        filtered_drift_result contains only active and regression items.
    """
    active_items: list[DriftItem] = []
    acknowledged_items: list[DriftItem] = []
    regression_items: list[DriftItem] = []

    for item in result.drift_items:
        if item.drift_type == DriftType.CHANGED and item.attribute_diffs:
            item_acknowledged_diffs: list[AttributeDiff] = []
            item_regression_diffs: list[AttributeDiff] = []
            item_active_diffs: list[AttributeDiff] = []

            for diff in item.attribute_diffs:
                entry = baseline.find_entry(item.resource_address, diff.path)
                if entry is None:
                    item_active_diffs.append(diff)
                else:
                    current_fp = compute_drift_fingerprint(
                        item.resource_address,
                        item.drift_type,
                        diff.path,
                        diff.actual_value,
                    )
                    if current_fp == entry.fingerprint:
                        item_acknowledged_diffs.append(diff)
                    else:
                        item_regression_diffs.append(diff)

            if item_regression_diffs:
                # Any regression makes the resource a regression item
                reg_item = item.model_copy(
                    update={"attribute_diffs": item_regression_diffs + item_active_diffs}
                )
                regression_items.append(reg_item)
                if item_acknowledged_diffs:
                    ack_item = item.model_copy(update={"attribute_diffs": item_acknowledged_diffs})
                    acknowledged_items.append(ack_item)
            elif item_active_diffs:
                # Active/unacknowledged diffs present
                act_item = item.model_copy(update={"attribute_diffs": item_active_diffs})
                active_items.append(act_item)
                if item_acknowledged_diffs:
                    ack_item = item.model_copy(update={"attribute_diffs": item_acknowledged_diffs})
                    acknowledged_items.append(ack_item)
            else:
                # All diffs matched baseline fingerprints
                acknowledged_items.append(item)
        else:
            # DELETED or UNMANAGED resource
            entry = baseline.find_entry(item.resource_address, None)
            if entry is None:
                active_items.append(item)
            else:
                actual_val: Any = None
                if item.drift_type == DriftType.UNMANAGED and item.cloud_resource:
                    actual_val = item.cloud_resource.attributes

                current_fp = compute_drift_fingerprint(
                    item.resource_address,
                    item.drift_type,
                    None,
                    actual_val,
                )
                if current_fp == entry.fingerprint:
                    acknowledged_items.append(item)
                else:
                    regression_items.append(item)

    filter_breakdown = BaselineFilterResult(
        active_items=active_items,
        acknowledged_items=acknowledged_items,
        regression_items=regression_items,
    )

    filtered_items = active_items + regression_items
    filtered_result = result.model_copy(update={"drift_items": filtered_items})

    return filtered_result, filter_breakdown
