"""Data models for cloud resource discovery in DriftSentry."""

from __future__ import annotations

from pydantic import BaseModel, Field

from driftsentry.core.models import CloudResource


class DiscoveryResult(BaseModel):
    """Result of scanning live cloud infrastructure without IaC state."""

    scan_id: str = Field(description="Unique identifier for this discovery run")
    provider: str = Field(default="aws", description="Cloud provider name")
    regions: list[str] = Field(default_factory=list, description="Cloud regions scanned")
    accounts: list[str] = Field(default_factory=list, description="Account IDs or aliases scanned")
    total_resources: int = Field(default=0, description="Total count of discovered cloud resources")
    resources_by_type: dict[str, list[CloudResource]] = Field(
        default_factory=dict,
        description="Map of Terraform resource type to list of discovered resources",
    )
    duration_seconds: float = Field(
        default=0.0, description="Total time taken for discovery in seconds"
    )
    errors: list[str] = Field(
        default_factory=list, description="Any errors encountered during scanning"
    )

    @property
    def all_resources(self) -> list[CloudResource]:
        """Flatten all resources into a single list."""
        flattened: list[CloudResource] = []
        for resources in self.resources_by_type.values():
            flattened.extend(resources)
        return flattened
