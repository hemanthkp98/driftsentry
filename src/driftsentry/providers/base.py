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
