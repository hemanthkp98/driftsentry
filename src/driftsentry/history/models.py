"""Pydantic models for the drift history store.

Defines the normalized, queryable records persisted by `DriftStore`:
a per-scan summary (`ScanSnapshot`) and per-resource drift records
(`DriftItemSnapshot`) linked to a scan.
"""

from __future__ import annotations

import datetime
import enum

from pydantic import BaseModel, Field

from driftsentry.core.models import DriftSeverity, DriftType


class ScanSnapshot(BaseModel):
    """A lightweight summary of a `DriftResult`, persisted as one history row."""

    scan_id: str = Field(description="Unique identifier for this scan run")
    timestamp: datetime.datetime = Field(description="When the scan was performed")
    total_resources: int = Field(default=0, description="Total managed resources in state")
    total_drifted: int = Field(default=0, description="Total number of drifted resources")
    changed_count: int = Field(default=0, description="Count of resources with attribute changes")
    deleted_count: int = Field(default=0, description="Count of resources deleted from the cloud")
    unmanaged_count: int = Field(default=0, description="Count of unmanaged (shadow IT) resources")
    critical_count: int = Field(default=0, description="Count of critical-severity drift items")
    duration_seconds: float = Field(default=0.0, description="Scan duration in seconds")
    state_source: str = Field(default="", description="State file path or backend location")
    regions: list[str] = Field(default_factory=list, description="All cloud regions scanned")
    accounts: list[str] = Field(
        default_factory=list, description="All cloud account IDs/aliases scanned"
    )
    errors_count: int = Field(
        default=0, description="Number of non-fatal errors encountered during the scan"
    )


class DriftItemSnapshot(BaseModel):
    """A per-resource drift record linked to a scan."""

    scan_id: str = Field(description="ID of the scan this drift item belongs to")
    resource_address: str = Field(description="Terraform address, e.g. 'aws_instance.web'")
    resource_type: str = Field(description="Resource type, e.g. 'aws_instance'")
    resource_id: str | None = Field(default=None, description="Cloud resource ID")
    drift_type: str = Field(description="Type of drift detected")
    severity: str = Field(description="Severity level")
    account_id: str | None = Field(default=None, description="AWS account ID")
    region: str | None = Field(default=None, description="Cloud region")
    attribution_principal: str | None = Field(
        default=None, description="IAM principal who made the change"
    )
    attribution_event_time: datetime.datetime | None = Field(
        default=None, description="When the change was made"
    )


class DriftDelta(enum.StrEnum):
    """Classification of how a drift item changed compared to a previous scan."""

    NEW = "new"
    RECURRING = "recurring"
    RESOLVED = "resolved"
    REGRESSION = "regression"
    WORSENED = "worsened"


class DriftDeltaItem(BaseModel):
    """A drift item classified against a previous scan."""

    resource_address: str = Field(description="Terraform address, e.g. 'aws_instance.web'")
    resource_type: str = Field(description="Resource type, e.g. 'aws_instance'")
    drift_type: DriftType = Field(description="Current drift type")
    severity: DriftSeverity = Field(description="Current severity level")
    delta: DriftDelta = Field(description="How this drift compares to the previous scan")
    previous_severity: DriftSeverity | None = Field(
        default=None, description="Previous severity level (for WORSENED)"
    )
    previous_drift_type: DriftType | None = Field(default=None, description="Previous drift type")
    first_seen_scan_id: str | None = Field(
        default=None, description="Earliest scan where this resource appeared drifted"
    )
    consecutive_scans: int = Field(
        default=1, description="Number of consecutive scans this resource has been drifted"
    )


class RegressionReport(BaseModel):
    """Result of comparing a current scan against a previous scan."""

    current_scan_id: str = Field(description="ID of the current scan")
    comparison_scan_id: str | None = Field(
        default=None, description="ID of the previous scan used for comparison"
    )
    timestamp: datetime.datetime = Field(
        default_factory=datetime.datetime.now, description="When the comparison was run"
    )
    items: list[DriftDeltaItem] = Field(
        default_factory=list, description="All classified drift items"
    )

    @property
    def new_count(self) -> int:
        return sum(1 for item in self.items if item.delta == DriftDelta.NEW)

    @property
    def recurring_count(self) -> int:
        return sum(1 for item in self.items if item.delta == DriftDelta.RECURRING)

    @property
    def resolved_count(self) -> int:
        return sum(1 for item in self.items if item.delta == DriftDelta.RESOLVED)

    @property
    def regression_count(self) -> int:
        return sum(1 for item in self.items if item.delta == DriftDelta.REGRESSION)

    @property
    def worsened_count(self) -> int:
        return sum(1 for item in self.items if item.delta == DriftDelta.WORSENED)

    @property
    def is_first_scan(self) -> bool:
        return self.comparison_scan_id is None
