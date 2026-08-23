"""Core data models for DriftSentry.

Defines the domain objects used throughout the application: drift results,
drift items, resource state representations, and severity/type enums.
"""

from __future__ import annotations

import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DriftType(StrEnum):
    """Classification of how a resource has drifted."""

    CHANGED = "changed"
    """Resource exists in state and cloud but attributes differ."""

    DELETED = "deleted"
    """Resource exists in state but has been deleted from the cloud."""

    UNMANAGED = "unmanaged"
    """Resource exists in the cloud but is not tracked in any state file."""


class DriftSeverity(StrEnum):
    """Severity level of a drift item, used for prioritization and policy evaluation."""

    CRITICAL = "critical"
    """Security-impacting drift (e.g., security group rules, IAM policies, public access)."""

    HIGH = "high"
    """Configuration drift that could cause outages or data loss."""

    MEDIUM = "medium"
    """Drift that deviates from desired state but has limited blast radius."""

    LOW = "low"
    """Cosmetic drift (tags, descriptions) with no operational impact."""

    INFO = "info"
    """Informational — expected drift or auto-generated attributes."""


class RemediationMode(StrEnum):
    """How drift should be remediated."""

    IMPORT = "import"
    """Generate `terraform import` commands to bring unmanaged resources under management."""

    REVERT = "revert"
    """Generate a plan to revert the cloud resource back to the desired state in code."""

    BOTH = "both"
    """Generate both import and revert artifacts, letting the user choose."""


class IaCTool(StrEnum):
    """Supported Infrastructure-as-Code tools."""

    TERRAFORM = "terraform"
    OPENTOFU = "opentofu"


class StateBackendType(StrEnum):
    """Supported Terraform/OpenTofu state backends."""

    LOCAL = "local"
    S3 = "s3"


# ─── Resource State ─────────────────────────────────────────────


class ResourceState(BaseModel):
    """Represents a single resource as recorded in the Terraform/OpenTofu state file."""

    address: str = Field(description="Full resource address, e.g. 'aws_instance.web'")
    resource_type: str = Field(description="Resource type, e.g. 'aws_instance'")
    resource_name: str = Field(description="Resource name in HCL, e.g. 'web'")
    provider: str = Field(description="Provider name, e.g. 'registry.terraform.io/hashicorp/aws'")
    mode: str = Field(default="managed", description="'managed' or 'data'")
    module: str | None = Field(default=None, description="Module path, e.g. 'module.vpc'")
    resource_id: str | None = Field(default=None, description="Cloud resource ID")
    attributes: dict[str, Any] = Field(default_factory=dict, description="Resource attributes")
    sensitive_attributes: list[str] = Field(
        default_factory=list,
        description="List of attribute paths that are sensitive",
    )
    dependencies: list[str] = Field(
        default_factory=list,
        description="Resources this resource depends on",
    )


# ─── Cloud Resource ─────────────────────────────────────────────


class CloudResource(BaseModel):
    """Represents a resource as it actually exists in the cloud provider."""

    resource_id: str = Field(description="Cloud-native resource ID (e.g., instance ID, ARN)")
    resource_type: str = Field(description="Terraform resource type, e.g. 'aws_instance'")
    arn: str | None = Field(default=None, description="AWS ARN if applicable")
    region: str | None = Field(default=None, description="Cloud region")
    attributes: dict[str, Any] = Field(default_factory=dict, description="Resource attributes")
    tags: dict[str, str] = Field(default_factory=dict, description="Resource tags")


# ─── Drift Attribution ──────────────────────────────────────────


class DriftAttribution(BaseModel):
    """Who or what caused the drift, derived from cloud audit logs."""

    principal: str | None = Field(
        default=None,
        description="IAM principal who made the change (ARN, email, or role name)",
    )
    event_name: str | None = Field(
        default=None,
        description="API call that caused the drift, e.g. 'ModifySecurityGroupRules'",
    )
    event_time: datetime.datetime | None = Field(
        default=None,
        description="When the change was made",
    )
    source_ip: str | None = Field(
        default=None,
        description="Source IP of the change",
    )
    user_agent: str | None = Field(
        default=None,
        description="User agent (e.g., 'console.amazonaws.com', 'aws-cli')",
    )
    is_console_change: bool = Field(
        default=False,
        description="Whether the change was made via the cloud console (ClickOps)",
    )


# ─── Attribute Diff ─────────────────────────────────────────────


class AttributeDiff(BaseModel):
    """A single attribute-level difference between desired and actual state."""

    path: str = Field(
        description="Dot-notation path to the attribute, e.g. 'ingress.0.cidr_blocks'"
    )
    desired_value: Any = Field(default=None, description="Value in Terraform state (desired)")
    actual_value: Any = Field(default=None, description="Value in the cloud (actual)")
    is_sensitive: bool = Field(default=False, description="Whether this attribute is sensitive")


# ─── Drift Item ──────────────────────────────────────────────────


class DriftItem(BaseModel):
    """A single drifted resource with full context."""

    resource_address: str = Field(
        description="Terraform address, e.g. 'module.vpc.aws_security_group.web'"
    )
    resource_type: str = Field(description="Resource type, e.g. 'aws_security_group'")
    resource_id: str | None = Field(default=None, description="Cloud resource ID")
    drift_type: DriftType = Field(description="Type of drift detected")
    severity: DriftSeverity = Field(default=DriftSeverity.MEDIUM, description="Severity level")
    attribute_diffs: list[AttributeDiff] = Field(
        default_factory=list,
        description="List of attribute-level differences (empty for DELETED/UNMANAGED)",
    )
    attribution: DriftAttribution | None = Field(
        default=None,
        description="Who caused this drift (populated if attribution is enabled)",
    )
    state_resource: ResourceState | None = Field(
        default=None,
        description="The resource as recorded in state (None for UNMANAGED)",
    )
    cloud_resource: CloudResource | None = Field(
        default=None,
        description="The resource as it exists in the cloud (None for DELETED)",
    )


# ─── Drift Result ───────────────────────────────────────────────


class DriftResult(BaseModel):
    """Complete result of a drift scan — the top-level output object."""

    scan_id: str = Field(description="Unique identifier for this scan run")
    timestamp: datetime.datetime = Field(
        default_factory=datetime.datetime.now,
        description="When the scan was performed",
    )
    iac_tool: IaCTool = Field(default=IaCTool.TERRAFORM, description="IaC tool used")
    provider: str = Field(description="Cloud provider, e.g. 'aws'")
    region: str | None = Field(default=None, description="Cloud region scanned")
    state_backend: StateBackendType = Field(description="State backend type used")
    state_source: str = Field(description="State file path or backend location")

    total_resources: int = Field(default=0, description="Total managed resources in state")
    total_cloud_resources: int = Field(default=0, description="Total cloud resources found")

    drift_items: list[DriftItem] = Field(
        default_factory=list,
        description="All detected drift items",
    )

    duration_seconds: float = Field(default=0.0, description="Scan duration in seconds")
    errors: list[str] = Field(
        default_factory=list,
        description="Non-fatal errors encountered during the scan",
    )

    @property
    def total_drifted(self) -> int:
        """Total number of drifted resources."""
        return len(self.drift_items)

    @property
    def changed_count(self) -> int:
        """Count of resources with attribute changes."""
        return sum(1 for d in self.drift_items if d.drift_type == DriftType.CHANGED)

    @property
    def deleted_count(self) -> int:
        """Count of resources deleted from the cloud."""
        return sum(1 for d in self.drift_items if d.drift_type == DriftType.DELETED)

    @property
    def unmanaged_count(self) -> int:
        """Count of unmanaged (shadow IT) resources."""
        return sum(1 for d in self.drift_items if d.drift_type == DriftType.UNMANAGED)

    @property
    def critical_count(self) -> int:
        """Count of critical-severity drift items."""
        return sum(1 for d in self.drift_items if d.severity == DriftSeverity.CRITICAL)

    @property
    def has_drift(self) -> bool:
        """Whether any drift was detected."""
        return len(self.drift_items) > 0

    def items_by_severity(self, severity: DriftSeverity) -> list[DriftItem]:
        """Filter drift items by severity."""
        return [d for d in self.drift_items if d.severity == severity]

    def items_by_type(self, drift_type: DriftType) -> list[DriftItem]:
        """Filter drift items by drift type."""
        return [d for d in self.drift_items if d.drift_type == drift_type]


# ─── AI Remediation Models ──────────────────────────────────────


class AIHCLResult(BaseModel):
    """LLM-generated HCL code for an unmanaged resource."""

    resource_address: str = Field(
        description="Terraform address, e.g. 'aws_security_group.shadow_sg'"
    )
    resource_type: str = Field(description="Resource type, e.g. 'aws_security_group'")
    resource_id: str = Field(description="Cloud resource ID")
    suggested_name: str = Field(description="Suggested HCL resource identifier name")
    hcl_code: str = Field(description="Idiomatic, production-quality HCL resource block")
    explanation: str = Field(default="", description="Why this HCL structure was chosen")
    import_command: str = Field(default="", description="Corresponding import command")


class AIRootCause(BaseModel):
    """LLM-generated root-cause narrative for a changed or deleted resource."""

    resource_address: str = Field(description="Terraform address of the drifted resource")
    resource_type: str = Field(description="Resource type")
    resource_id: str | None = Field(default=None, description="Cloud resource ID if available")
    narrative: str = Field(description="Human-readable root cause explanation")
    risk_assessment: str = Field(default="", description="Security and operational risk analysis")
    recommended_action: str = Field(
        default="investigate",
        description="Recommended action: 'revert', 'accept', or 'investigate'",
    )


class AIRemediationResult(BaseModel):
    """Complete AI-enhanced remediation output."""

    hcl_results: list[AIHCLResult] = Field(
        default_factory=list,
        description="LLM-generated HCL results for unmanaged resources",
    )
    root_causes: list[AIRootCause] = Field(
        default_factory=list,
        description="Root cause narratives and risk assessments for changed/deleted resources",
    )
    provider_used: str = Field(default="", description="LLM provider name ('claude' or 'gemini')")
    model_used: str = Field(default="", description="Specific model identifier used")
    total_tokens: int = Field(default=0, description="Approximate tokens used")
