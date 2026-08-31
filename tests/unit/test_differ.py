"""Unit tests for the diff engine (DriftDiffer)."""

from __future__ import annotations

import copy

from driftsentry.core.differ import DriftDiffer
from driftsentry.core.models import (
    CloudResource,
    DriftSeverity,
    DriftType,
    ResourceState,
)


def test_differ_no_drift(mock_ec2_resource: ResourceState, mock_cloud_ec2: CloudResource) -> None:
    differ = DriftDiffer()
    item = differ.diff_resource(mock_ec2_resource, mock_cloud_ec2)
    assert item is None


def test_differ_detects_changed_attribute(
    mock_ec2_resource: ResourceState, mock_cloud_ec2: CloudResource
) -> None:
    differ = DriftDiffer()

    # Modify instance_type in cloud
    changed_cloud = copy.deepcopy(mock_cloud_ec2)
    changed_cloud.attributes["instance_type"] = "t3.large"

    item = differ.diff_resource(mock_ec2_resource, changed_cloud)
    assert item is not None
    assert item.drift_type == DriftType.CHANGED
    assert item.resource_address == "aws_instance.web"
    assert len(item.attribute_diffs) == 1

    diff = item.attribute_diffs[0]
    assert diff.path == "instance_type"
    assert diff.desired_value == "t3.micro"
    assert diff.actual_value == "t3.large"


def test_differ_detects_security_critical_drift() -> None:
    differ = DriftDiffer()

    state_sg = ResourceState(
        address="aws_security_group.web",
        resource_type="aws_security_group",
        resource_name="web",
        provider='provider["registry.terraform.io/hashicorp/aws"]',
        resource_id="sg-12345",
        attributes={
            "id": "sg-12345",
            "name": "web-sg",
            "ingress": [
                {
                    "from_port": 443,
                    "to_port": 443,
                    "protocol": "tcp",
                    "cidr_blocks": ["10.0.0.0/8"],
                }
            ],
        },
    )

    # Ingress rule modified in cloud to open to 0.0.0.0/0
    cloud_sg = CloudResource(
        resource_id="sg-12345",
        resource_type="aws_security_group",
        attributes={
            "id": "sg-12345",
            "name": "web-sg",
            "ingress": [
                {
                    "from_port": 443,
                    "to_port": 443,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                }
            ],
        },
    )

    item = differ.diff_resource(state_sg, cloud_sg)
    assert item is not None
    assert item.drift_type == DriftType.CHANGED
    assert item.severity == DriftSeverity.CRITICAL


def test_differ_detect_deleted(mock_ec2_resource: ResourceState) -> None:
    differ = DriftDiffer()
    item = differ.detect_deleted(mock_ec2_resource)

    assert item.drift_type == DriftType.DELETED
    assert item.severity == DriftSeverity.HIGH
    assert item.resource_address == "aws_instance.web"
    assert item.state_resource is not None


def test_differ_detect_unmanaged(mock_cloud_ec2: CloudResource) -> None:
    differ = DriftDiffer()
    item = differ.detect_unmanaged(mock_cloud_ec2)

    assert item.drift_type == DriftType.UNMANAGED
    assert item.resource_id == "i-0abc123def456789"
    assert "[unmanaged]" in item.resource_address
    assert item.cloud_resource is not None


def test_differ_ignores_noise_attributes(
    mock_ec2_resource: ResourceState, mock_cloud_ec2: CloudResource
) -> None:
    differ = DriftDiffer()

    # Cloud has extra noise tags/timestamps
    noisy_cloud = copy.deepcopy(mock_cloud_ec2)
    noisy_cloud.attributes["tags_all"] = {"Extra": "Tag"}
    noisy_cloud.attributes["arn"] = "arn:aws:ec2:us-east-1:123:instance/i-123"

    item = differ.diff_resource(mock_ec2_resource, noisy_cloud)
    assert item is None


def test_differ_redacts_sensitive_values() -> None:
    differ = DriftDiffer()
    state = ResourceState(
        address="aws_db_instance.prod",
        resource_type="aws_db_instance",
        resource_name="prod",
        provider="aws",
        resource_id="db-123",
        attributes={"id": "db-123", "password": "old-secret"},
        sensitive_attributes=["password"],
    )
    cloud = CloudResource(
        resource_id="db-123",
        resource_type="aws_db_instance",
        attributes={"id": "db-123", "password": "new-secret"},
    )

    item = differ.diff_resource(state, cloud)

    assert item is not None
    assert item.attribute_diffs[0].is_sensitive
    assert item.attribute_diffs[0].desired_value == "[REDACTED]"
    assert item.attribute_diffs[0].actual_value == "[REDACTED]"
