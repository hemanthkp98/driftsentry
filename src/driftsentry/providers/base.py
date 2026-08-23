"""Abstract base class for cloud providers.

Each cloud provider (AWS, GCP, Azure) implements this interface to
enumerate and describe live infrastructure resources.
"""

from __future__ import annotations

import abc
from typing import Any

from driftsentry.core.models import CloudResource


class CloudProvider(abc.ABC):
    """Interface for cloud provider adapters.

    Implementations must be able to:
    1. List all resources of a given Terraform type in the cloud account
    2. Get a specific resource by its cloud ID
    3. Map between Terraform attribute names and cloud API response fields
    """

    @abc.abstractmethod
    def list_resources(self, resource_type: str) -> list[CloudResource]:
        """List all resources of a given Terraform type in the cloud.

        Args:
            resource_type: Terraform resource type, e.g. 'aws_instance'.

        Returns:
            List of CloudResource objects found in the cloud.
        """
        ...

    @abc.abstractmethod
    def get_resource(self, resource_type: str, resource_id: str) -> CloudResource | None:
        """Get a specific cloud resource by its ID.

        Args:
            resource_type: Terraform resource type.
            resource_id: Cloud-native resource ID.

        Returns:
            CloudResource if found, None otherwise.
        """
        ...

    @abc.abstractmethod
    def supported_resource_types(self) -> list[str]:
        """Return the list of Terraform resource types this provider can scan."""
        ...

    @abc.abstractmethod
    def normalize_attributes(
        self, resource_type: str, cloud_attrs: dict[str, Any]
    ) -> dict[str, Any]:
        """Normalize cloud API attributes to match Terraform state attribute names.

        This is critical for accurate diff comparison — cloud APIs return
        different field names and structures than what Terraform stores.

        Args:
            resource_type: Terraform resource type.
            cloud_attrs: Raw attributes from the cloud API.

        Returns:
            Attributes dict with keys matching Terraform state format.
        """
        ...

    @property
    @abc.abstractmethod
    def provider_name(self) -> str:
        """Short name for this provider, e.g. 'aws', 'gcp', 'azure'."""
        ...


class ResourceScanner(abc.ABC):
    """Interface for per-resource-type scanners within a provider.

    Each AWS resource type (EC2, S3, IAM, etc.) gets its own scanner
    that knows how to list, get, and normalize that resource type.
    """

    def __init__(self, session: Any, region: str) -> None:
        """Initialize the scanner with a cloud provider session and region."""
        self.session = session
        self.region = region

    @abc.abstractmethod
    def list_all(self) -> list[CloudResource]:
        """List all resources of this type."""
        ...

    @abc.abstractmethod
    def get_by_id(self, resource_id: str) -> CloudResource | None:
        """Get a resource by its cloud ID."""
        ...

    @abc.abstractmethod
    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize raw API response to Terraform attribute format."""
        ...

    @property
    @abc.abstractmethod
    def resource_types(self) -> list[str]:
        """Terraform resource types this scanner handles."""
        ...


# ─── Scanner Registry & Plugin System ───────────────────────────

_SCANNER_REGISTRY: dict[str, list[type[ResourceScanner]]] = {}


def register_scanner(provider: str = "aws") -> Any:
    """Decorator to register a ResourceScanner class for a cloud provider.

    Usage:
        @register_scanner("aws")
        class CustomScanner(ResourceScanner):
            ...
    """

    def decorator(cls: type[ResourceScanner]) -> type[ResourceScanner]:
        if provider not in _SCANNER_REGISTRY:
            _SCANNER_REGISTRY[provider] = []
        if cls not in _SCANNER_REGISTRY[provider]:
            _SCANNER_REGISTRY[provider].append(cls)
        return cls

    return decorator


def get_registered_scanners(provider: str = "aws") -> list[type[ResourceScanner]]:
    """Return all scanner classes registered for a given cloud provider."""
    return list(_SCANNER_REGISTRY.get(provider, []))


# ─── Declarative Resource Specifications ────────────────────────

from pydantic import BaseModel, Field  # noqa: E402


class DiscoverySpec(BaseModel):
    """Specification for discovering live resources via cloud API."""

    list_operation: str = Field(description="Boto3 operation to list resources, e.g. 'list_queues'")
    result_path: str = Field(
        default="@",
        description="JMESPath expression to extract items from list response, e.g. 'QueueUrls[]' or 'TableNames[]'",
    )
    id_field: str = Field(
        default="@",
        description="JMESPath expression to extract resource ID from listed item (or '@' for string items)",
    )
    describe_operation: str | None = Field(
        default=None,
        description="Optional Boto3 operation to fetch full resource details, e.g. 'get_queue_attributes'",
    )
    describe_params: dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters for describe_operation, with placeholders like '{id}' or '{name}'",
    )
    attributes_path: str | None = Field(
        default=None,
        description="Optional JMESPath to extract attributes dictionary from describe response",
    )
    paginator_operation: str | None = Field(
        default=None,
        description="Operation name if Boto3 paginator differs from list_operation",
    )


class DeclarativeResourceSpec(BaseModel):
    """Schema for defining an AWS resource scanner declaratively via YAML."""

    terraform_type: str = Field(description="Terraform resource type, e.g. 'aws_sqs_queue'")
    service: str = Field(description="Boto3 service client name, e.g. 'sqs', 'sns', 'dynamodb'")
    description: str = Field(default="", description="Human-readable description")
    discovery: DiscoverySpec = Field(description="Discovery and describe API configuration")
    id_prefix_hints: list[str] = Field(
        default_factory=list,
        description="Optional ID prefixes to assist get_by_id detection",
    )
    attributes: dict[str, str] = Field(
        default_factory=dict,
        description="Mapping of Terraform attribute names to JMESPath / response field names",
    )
    security_critical: list[str] = Field(
        default_factory=list,
        description="Attributes flagged as security-critical for severity classification",
    )
    noise_attributes: list[str] = Field(
        default_factory=list,
        description="Noisy or auto-generated attributes to ignore in diff comparison",
    )
    cloudtrail_events: list[str] = Field(
        default_factory=list,
        description="CloudTrail API event names that modify this resource type",
    )
