"""Unit tests for the DriftScanner orchestrator."""

from __future__ import annotations

from typing import Any

from driftsentry.core.config import DriftSentryConfig
from driftsentry.core.models import (
    CloudResource,
    DriftType,
    ResourceState,
    StateBackendType,
)
from driftsentry.core.scanner import DriftScanner
from driftsentry.providers.base import CloudProvider
from driftsentry.state.base import StateReader


class MockStateReader(StateReader):
    def __init__(self, resources: list[ResourceState]) -> None:
        self._resources = resources

    def read_state(self) -> list[ResourceState]:
        return self._resources

    def get_raw_state(self) -> dict[str, Any]:
        return {}

    @property
    def source_description(self) -> str:
        return "mock://state"


class MockCloudProvider(CloudProvider):
    def __init__(self, resources_by_type: dict[str, list[CloudResource]]) -> None:
        self._resources = resources_by_type

    def list_resources(self, resource_type: str) -> list[CloudResource]:
        return self._resources.get(resource_type, [])

    def get_resource(self, resource_type: str, resource_id: str) -> CloudResource | None:
        for r in self._resources.get(resource_type, []):
            if r.resource_id == resource_id:
                return r
        return None

    def supported_resource_types(self) -> list[str]:
        return list(self._resources.keys())

    def normalize_attributes(
        self, resource_type: str, cloud_attrs: dict[str, Any]
    ) -> dict[str, Any]:
        return cloud_attrs

    @property
    def provider_name(self) -> str:
        return "mock-aws"


def test_scanner_end_to_end_drift_scenarios(
    mock_ec2_resource: ResourceState, mock_cloud_ec2: CloudResource
) -> None:
    # Set up scenario:
    # 1. EC2 instance exists in both, but instance_type changed (CHANGED)
    # 2. S3 bucket exists in state but NOT in cloud (DELETED)
    # 3. Security Group exists in cloud but NOT in state (UNMANAGED)

    changed_ec2_cloud = mock_cloud_ec2.model_copy(deep=True)
    changed_ec2_cloud.attributes["instance_type"] = "t3.2xlarge"

    s3_state = ResourceState(
        address="aws_s3_bucket.logs",
        resource_type="aws_s3_bucket",
        resource_name="logs",
        provider='provider["registry.terraform.io/hashicorp/aws"]',
        resource_id="my-app-logs",
        attributes={"id": "my-app-logs", "bucket": "my-app-logs"},
    )

    unmanaged_sg = CloudResource(
        resource_id="sg-99999",
        resource_type="aws_security_group",
        attributes={"id": "sg-99999", "name": "shadow-sg"},
    )

    state_reader = MockStateReader([mock_ec2_resource, s3_state])
    cloud_provider = MockCloudProvider(
        {
            "aws_instance": [changed_ec2_cloud],
            "aws_s3_bucket": [],  # Empty -> s3_state is DELETED
            "aws_security_group": [unmanaged_sg],  # Not in state -> UNMANAGED
        }
    )

    config = DriftSentryConfig()
    config.state.backend = StateBackendType.LOCAL
    config.attribution.enabled = False

    scanner = DriftScanner(config, state_reader, cloud_provider)
    result = scanner.scan(show_progress=False)

    assert result.has_drift
    assert result.total_resources == 2
    assert result.total_cloud_resources == 2
    assert result.total_drifted == 3

    assert result.changed_count == 1
    assert result.deleted_count == 1
    assert result.unmanaged_count == 1

    # Check drift items
    types = {item.drift_type for item in result.drift_items}
    assert types == {DriftType.CHANGED, DriftType.DELETED, DriftType.UNMANAGED}


def test_scanner_clean_no_drift(
    mock_ec2_resource: ResourceState, mock_cloud_ec2: CloudResource
) -> None:
    state_reader = MockStateReader([mock_ec2_resource])
    cloud_provider = MockCloudProvider(
        {
            "aws_instance": [mock_cloud_ec2],
        }
    )

    config = DriftSentryConfig()
    config.attribution.enabled = False

    scanner = DriftScanner(config, state_reader, cloud_provider)
    result = scanner.scan(show_progress=False)

    assert not result.has_drift
    assert result.total_drifted == 0
    assert result.total_resources == 1


def test_scanner_does_not_mark_failed_cloud_scan_as_deleted(
    mock_ec2_resource: ResourceState,
) -> None:
    class FailingCloudProvider(MockCloudProvider):
        def list_resources(self, resource_type: str) -> list[CloudResource]:
            raise RuntimeError("AWS unavailable")

    config = DriftSentryConfig()
    config.attribution.enabled = False
    scanner = DriftScanner(
        config,
        MockStateReader([mock_ec2_resource]),
        FailingCloudProvider({"aws_instance": []}),
    )

    result = scanner.scan(show_progress=False)

    assert result.deleted_count == 0
    assert result.errors == ["Error scanning aws_instance: AWS unavailable"]
