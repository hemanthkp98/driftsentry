"""Unit tests for EBS, Snapshots, AMIs, RDS clusters, and EFS scanners."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from driftsentry.providers.aws.catalog import ResourceCatalog
from driftsentry.providers.aws.declarative import GenericAWSDeclarativeScanner
from driftsentry.providers.aws.resources.ebs import EBSScanner
from driftsentry.providers.aws.resources.rds import RDSScanner


@pytest.fixture
def mock_session() -> MagicMock:
    session = MagicMock()
    return session


def test_ebs_scanner_supported_types(mock_session: MagicMock) -> None:
    scanner = EBSScanner(mock_session, "us-east-1")
    assert sorted(scanner.resource_types) == ["aws_ami", "aws_ebs_snapshot", "aws_ebs_volume"]


def test_ebs_volume_listing_and_get(mock_session: MagicMock) -> None:
    mock_ec2 = MagicMock()
    mock_session.client.return_value = mock_ec2

    sample_vol = {
        "VolumeId": "vol-0123456789abcdef0",
        "AvailabilityZone": "us-east-1a",
        "Size": 100,
        "VolumeType": "gp3",
        "Iops": 3000,
        "Throughput": 125,
        "Encrypted": True,
        "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/sample-key",
        "Tags": [{"Key": "Name", "Value": "data-vol"}],
    }

    paginator = MagicMock()
    paginator.paginate.return_value = [{"Volumes": [sample_vol]}]
    mock_ec2.get_paginator.return_value = paginator

    scanner = EBSScanner(mock_session, "us-east-1")
    volumes = scanner._list_volumes()
    assert len(volumes) == 1
    vol = volumes[0]
    assert vol.resource_id == "vol-0123456789abcdef0"
    assert vol.resource_type == "aws_ebs_volume"
    assert vol.attributes["size"] == 100
    assert vol.attributes["encrypted"] is True
    assert vol.tags["Name"] == "data-vol"

    # Test get_by_id
    mock_ec2.describe_volumes.return_value = {"Volumes": [sample_vol]}
    fetched = scanner.get_by_id("vol-0123456789abcdef0")
    assert fetched is not None
    assert fetched.resource_id == "vol-0123456789abcdef0"


def test_ebs_snapshot_listing_filters_self(mock_session: MagicMock) -> None:
    mock_ec2 = MagicMock()
    mock_session.client.return_value = mock_ec2

    sample_snap = {
        "SnapshotId": "snap-0123456789abcdef0",
        "VolumeId": "vol-0123456789abcdef0",
        "VolumeSize": 100,
        "Description": "Daily backup",
        "Encrypted": True,
        "OwnerId": "123456789012",
        "Tags": [{"Key": "Environment", "Value": "prod"}],
    }

    paginator = MagicMock()
    paginator.paginate.return_value = [{"Snapshots": [sample_snap]}]
    mock_ec2.get_paginator.return_value = paginator

    scanner = EBSScanner(mock_session, "us-east-1")
    snapshots = scanner._list_snapshots()

    # Crucial assertion: paginator was invoked with OwnerIds=['self']
    mock_ec2.get_paginator.assert_called_with("describe_snapshots")
    paginator.paginate.assert_called_with(OwnerIds=["self"])

    assert len(snapshots) == 1
    snap = snapshots[0]
    assert snap.resource_id == "snap-0123456789abcdef0"
    assert snap.resource_type == "aws_ebs_snapshot"
    assert snap.attributes["volume_size"] == 100
    assert snap.tags["Environment"] == "prod"


def test_ami_listing_filters_self(mock_session: MagicMock) -> None:
    mock_ec2 = MagicMock()
    mock_session.client.return_value = mock_ec2

    sample_img = {
        "ImageId": "ami-0123456789abcdef0",
        "Name": "custom-golden-image",
        "Description": "Ubuntu hardened base",
        "Architecture": "x86_64",
        "ImageType": "machine",
        "RootDeviceName": "/dev/sda1",
        "VirtualizationType": "hvm",
        "Tags": [{"Key": "BakedBy", "Value": "Packer"}],
    }

    mock_ec2.describe_images.return_value = {"Images": [sample_img]}

    scanner = EBSScanner(mock_session, "us-east-1")
    images = scanner._list_images()

    # Crucial assertion: describe_images called with Owners=['self']
    mock_ec2.describe_images.assert_called_with(Owners=["self"])

    assert len(images) == 1
    img = images[0]
    assert img.resource_id == "ami-0123456789abcdef0"
    assert img.resource_type == "aws_ami"
    assert img.attributes["name"] == "custom-golden-image"
    assert img.tags["BakedBy"] == "Packer"


def test_rds_cluster_scanner(mock_session: MagicMock) -> None:
    mock_rds = MagicMock()
    mock_session.client.return_value = mock_rds

    # Mock DB instance paginator
    inst_paginator = MagicMock()
    inst_paginator.paginate.return_value = [
        {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "postgres-prod",
                    "Engine": "postgres",
                    "DBInstanceClass": "db.t3.medium",
                }
            ]
        }
    ]

    # Mock DB cluster paginator
    cluster_paginator = MagicMock()
    cluster_paginator.paginate.return_value = [
        {
            "DBClusters": [
                {
                    "DBClusterIdentifier": "aurora-pg-cluster",
                    "Engine": "aurora-postgresql",
                    "DatabaseName": "appdb",
                    "StorageEncrypted": True,
                }
            ]
        }
    ]

    def paginator_side_effect(op: str) -> MagicMock:
        if op == "describe_db_instances":
            return inst_paginator
        elif op == "describe_db_clusters":
            return cluster_paginator
        return MagicMock()

    mock_rds.get_paginator.side_effect = paginator_side_effect

    scanner = RDSScanner(mock_session, "us-east-1")
    assert "aws_rds_cluster" in scanner.resource_types

    all_rds = scanner.list_all()
    types = [r.resource_type for r in all_rds]
    assert "aws_db_instance" in types
    assert "aws_rds_cluster" in types

    cluster_res = next(r for r in all_rds if r.resource_type == "aws_rds_cluster")
    assert cluster_res.resource_id == "aurora-pg-cluster"
    assert cluster_res.attributes["engine"] == "aurora-postgresql"


def test_efs_declarative_scanner(mock_session: MagicMock) -> None:
    catalog = ResourceCatalog()
    specs = catalog.load_all()
    assert "aws_efs_file_system" in specs

    efs_spec = specs["aws_efs_file_system"]
    mock_efs = MagicMock()
    mock_session.client.return_value = mock_efs

    mock_efs.can_paginate.return_value = True
    efs_paginator = MagicMock()
    efs_paginator.paginate.return_value = [
        {
            "FileSystems": [
                {
                    "FileSystemId": "fs-01234567",
                    "CreationToken": "app-data-efs",
                    "Encrypted": True,
                    "PerformanceMode": "generalPurpose",
                    "ThroughputMode": "bursting",
                    "Tags": [{"Key": "Name", "Value": "app-shared-storage"}],
                }
            ]
        }
    ]
    mock_efs.get_paginator.return_value = efs_paginator

    scanner = GenericAWSDeclarativeScanner(mock_session, "us-east-1", efs_spec)
    assert scanner.resource_types == ["aws_efs_file_system"]

    resources = scanner.list_all()
    assert len(resources) == 1
    efs = resources[0]
    assert efs.resource_id == "fs-01234567"
    assert efs.attributes["creation_token"] == "app-data-efs"
    assert efs.attributes["encrypted"] is True
    assert efs.tags["Name"] == "app-shared-storage"
