"""Unit tests for the in-place HCL code patcher."""

from __future__ import annotations

from pathlib import Path

from driftsentry.core.models import (
    AttributeDiff,
    DriftItem,
    DriftSeverity,
    DriftType,
)
from driftsentry.remediation.hcl_patcher import HCLPatcher


def test_hcl_format_hcl_values() -> None:
    assert HCLPatcher.format_hcl_value("test") == '"test"'
    assert HCLPatcher.format_hcl_value('with"quote') == '"with\\"quote"'
    assert HCLPatcher.format_hcl_value(True) == "true"
    assert HCLPatcher.format_hcl_value(False) == "false"
    assert HCLPatcher.format_hcl_value(100) == "100"
    assert HCLPatcher.format_hcl_value(3.14) == "3.14"
    assert HCLPatcher.format_hcl_value(None) == "null"
    assert HCLPatcher.format_hcl_value(["a", "b"]) == '["a", "b"]'

    nested_dict = {"Env": "prod", "Tier": 1}
    formatted_dict = HCLPatcher.format_hcl_value(nested_dict)
    assert 'Env = "prod"' in formatted_dict
    assert "Tier = 1" in formatted_dict


def test_hcl_patcher_update_existing_attribute(tmp_path: Path) -> None:
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        """
resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro" # keep small
  tags = {
    Name = "web-server"
  }
}
""",
        encoding="utf-8",
    )

    item = DriftItem(
        resource_address="aws_instance.web",
        resource_type="aws_instance",
        resource_id="i-1234567890abcdef0",
        drift_type=DriftType.CHANGED,
        severity=DriftSeverity.MEDIUM,
        attribute_diffs=[
            AttributeDiff(
                path="instance_type",
                desired_value="t3.micro",
                actual_value="t3.large",
            )
        ],
    )

    patcher = HCLPatcher(workspace_dir=tmp_path, dry_run=False, format_code=False)
    result = patcher.patch_resource(item)

    assert result.success is True
    assert result.file_path == tf_file
    assert "instance_type" in result.attributes_patched
    assert '-  instance_type = "t3.micro"' in result.diff
    assert '+  instance_type = "t3.large"' in result.diff

    updated = tf_file.read_text(encoding="utf-8")
    assert 'instance_type = "t3.large"' in updated
    assert 'ami           = "ami-12345678"' in updated


def test_hcl_patcher_insert_missing_attribute(tmp_path: Path) -> None:
    tf_file = tmp_path / "db.tf"
    tf_file.write_text(
        """resource "aws_db_instance" "postgres" {
  allocated_storage = 20
  engine            = "postgres"
}
""",
        encoding="utf-8",
    )

    item = DriftItem(
        resource_address="aws_db_instance.postgres",
        resource_type="aws_db_instance",
        resource_id="db-12345",
        drift_type=DriftType.CHANGED,
        severity=DriftSeverity.HIGH,
        attribute_diffs=[
            AttributeDiff(
                path="deletion_protection",
                desired_value=None,
                actual_value=True,
            )
        ],
    )

    patcher = HCLPatcher(workspace_dir=tmp_path, dry_run=False, format_code=False)
    result = patcher.patch_resource(item)

    assert result.success is True
    assert "deletion_protection" in result.attributes_patched

    updated = tf_file.read_text(encoding="utf-8")
    assert "deletion_protection = true" in updated
    assert "allocated_storage = 20" in updated


def test_hcl_patcher_nested_attribute_update_and_insert(tmp_path: Path) -> None:
    tf_file = tmp_path / "compute.tf"
    tf_file.write_text(
        """resource "aws_instance" "app" {
  instance_type = "t3.medium"

  tags = {
    Environment = "staging"
  }
}
""",
        encoding="utf-8",
    )

    item = DriftItem(
        resource_address="aws_instance.app",
        resource_type="aws_instance",
        resource_id="i-999",
        drift_type=DriftType.CHANGED,
        severity=DriftSeverity.LOW,
        attribute_diffs=[
            AttributeDiff(
                path="tags.Environment",
                desired_value="staging",
                actual_value="production",
            ),
            AttributeDiff(
                path="tags.Owner",
                desired_value=None,
                actual_value="cloud-ops",
            ),
        ],
    )

    patcher = HCLPatcher(workspace_dir=tmp_path, dry_run=False, format_code=False)
    result = patcher.patch_resource(item)

    assert result.success is True
    assert "tags.Environment" in result.attributes_patched
    assert "tags.Owner" in result.attributes_patched

    updated = tf_file.read_text(encoding="utf-8")
    assert 'Environment = "production"' in updated
    assert 'Owner = "cloud-ops"' in updated


def test_hcl_patcher_nested_attribute_creates_parent_block(tmp_path: Path) -> None:
    tf_file = tmp_path / "s3.tf"
    tf_file.write_text(
        """resource "aws_s3_bucket" "logs" {
  bucket = "my-logs-bucket"
}
""",
        encoding="utf-8",
    )

    item = DriftItem(
        resource_address="aws_s3_bucket.logs",
        resource_type="aws_s3_bucket",
        resource_id="my-logs-bucket",
        drift_type=DriftType.CHANGED,
        severity=DriftSeverity.LOW,
        attribute_diffs=[
            AttributeDiff(
                path="tags.ManagedBy",
                desired_value=None,
                actual_value="Terraform",
            ),
        ],
    )

    patcher = HCLPatcher(workspace_dir=tmp_path, dry_run=False, format_code=False)
    result = patcher.patch_resource(item)

    assert result.success is True
    updated = tf_file.read_text(encoding="utf-8")
    assert "tags = {" in updated
    assert 'ManagedBy = "Terraform"' in updated


def test_hcl_patcher_dry_run(tmp_path: Path) -> None:
    tf_file = tmp_path / "server.tf"
    initial_content = """resource "aws_instance" "api" {
  instance_type = "t3.small"
}
"""
    tf_file.write_text(initial_content, encoding="utf-8")

    item = DriftItem(
        resource_address="aws_instance.api",
        resource_type="aws_instance",
        resource_id="i-api",
        drift_type=DriftType.CHANGED,
        severity=DriftSeverity.MEDIUM,
        attribute_diffs=[
            AttributeDiff(
                path="instance_type",
                desired_value="t3.small",
                actual_value="t3.large",
            )
        ],
    )

    patcher = HCLPatcher(workspace_dir=tmp_path, dry_run=True, format_code=False)
    result = patcher.patch_resource(item)

    assert result.success is True
    assert '+  instance_type = "t3.large"' in result.diff
    # File content must NOT have changed in dry_run
    assert tf_file.read_text(encoding="utf-8") == initial_content


def test_hcl_patcher_resource_not_found(tmp_path: Path) -> None:
    tf_file = tmp_path / "empty.tf"
    tf_file.write_text('resource "aws_s3_bucket" "other" {}\n', encoding="utf-8")

    item = DriftItem(
        resource_address="aws_instance.nonexistent",
        resource_type="aws_instance",
        resource_id="i-missing",
        drift_type=DriftType.CHANGED,
        attribute_diffs=[
            AttributeDiff(
                path="instance_type",
                desired_value="t3.micro",
                actual_value="t3.large",
            )
        ],
    )

    patcher = HCLPatcher(workspace_dir=tmp_path)
    result = patcher.patch_resource(item)

    assert result.success is False
    assert "Could not locate resource" in result.message


def test_hcl_patcher_rejects_unmanaged(tmp_path: Path) -> None:
    item = DriftItem(
        resource_address="[unmanaged] aws_security_group.sg-1",
        resource_type="aws_security_group",
        resource_id="sg-1",
        drift_type=DriftType.UNMANAGED,
    )

    patcher = HCLPatcher(workspace_dir=tmp_path)
    result = patcher.patch_resource(item)

    assert result.success is False
    assert "HCL patching only applies to CHANGED resources" in result.message


def test_hcl_patcher_patch_all_across_files(tmp_path: Path) -> None:
    file1 = tmp_path / "ec2.tf"
    file1.write_text(
        """resource "aws_instance" "worker" {
  instance_type = "t3.micro"
}
""",
        encoding="utf-8",
    )

    file2 = tmp_path / "rds.tf"
    file2.write_text(
        """resource "aws_db_instance" "prod" {
  instance_class = "db.t3.micro"
}
""",
        encoding="utf-8",
    )

    items = [
        DriftItem(
            resource_address="aws_instance.worker",
            resource_type="aws_instance",
            drift_type=DriftType.CHANGED,
            attribute_diffs=[
                AttributeDiff(
                    path="instance_type",
                    desired_value="t3.micro",
                    actual_value="t3.medium",
                )
            ],
        ),
        DriftItem(
            resource_address="aws_db_instance.prod",
            resource_type="aws_db_instance",
            drift_type=DriftType.CHANGED,
            attribute_diffs=[
                AttributeDiff(
                    path="instance_class",
                    desired_value="db.t3.micro",
                    actual_value="db.t3.large",
                )
            ],
        ),
        DriftItem(
            resource_address="[unmanaged] aws_s3_bucket.shadow",
            resource_type="aws_s3_bucket",
            drift_type=DriftType.UNMANAGED,
        ),
    ]

    patcher = HCLPatcher(workspace_dir=tmp_path, dry_run=False, format_code=False)
    results = patcher.patch_all(items)

    assert len(results) == 2
    assert all(r.success for r in results)
    assert 'instance_type = "t3.medium"' in file1.read_text(encoding="utf-8")
    assert 'instance_class = "db.t3.large"' in file2.read_text(encoding="utf-8")
