"""Pydantic models for the drift history store.

Defines the normalized, queryable records persisted by `DriftStore`:
a per-scan summary (`ScanSnapshot`) and per-resource drift records
(`DriftItemSnapshot`) linked back to their scan.
"""

from __future__ import annotations

import datetime

from pydantic import BaseModel, Field

from driftsentry.core.models import DriftSeverity, DriftType


class ScanSnapshot(BaseModel):
    """A lightweight summary of a `DriftResult`, persisted as one history row per scan."""

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
    """A per-resource drift record linked to a scan snapshot."""

    scan_id: str = Field(description="Scan run this drift item belongs to")
    resource_address: str = Field(description="Terraform address, e.g. 'aws_instance.web'")
    resource_type: str = Field(description="Resource type, e.g. 'aws_instance'")
    resource_id: str | None = Field(default=None, description="Cloud resource ID")
    drift_type: DriftType = Field(description="Type of drift detected")
    severity: DriftSeverity = Field(description="Severity level")
    account_id: str | None = Field(default=None, description="AWS account ID")
    region: str | None = Field(default=None, description="Cloud region")
    attribution_principal: str | None = Field(
        default=None, description="IAM principal who made the change, if attributed"
    )
    attribution_event_time: datetime.datetime | None = Field(
        default=None, description="When the attributed change was made"
    )
