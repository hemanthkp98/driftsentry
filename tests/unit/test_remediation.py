"""Unit tests for the remediation generator."""

from __future__ import annotations

from pathlib import Path

from driftsentry.core.models import (
    AttributeDiff,
    CloudResource,
    DriftItem,
    DriftResult,
    DriftSeverity,
    DriftType,
    IaCTool,
    RemediationMode,
    StateBackendType,
)
from driftsentry.remediation.generator import RemediationGenerator


def test_remediation_import_generation(tmp_path: Path) -> None:
    unmanaged_res = CloudResource(
        resource_id="sg-0987654321",
        resource_type="aws_security_group",
        attributes={"id": "sg-0987654321", "name": "shadow_sg", "description": "shadow"},
    )

    item = DriftItem(
        resource_address="[unmanaged] aws_security_group.sg-0987654321",
        resource_type="aws_security_group",
        resource_id="sg-0987654321",
        drift_type=DriftType.UNMANAGED,
        severity=DriftSeverity.CRITICAL,
        cloud_resource=unmanaged_res,
    )

    result = DriftResult(
        scan_id="rem1",
        provider="aws",
        state_backend=StateBackendType.LOCAL,
        state_source="test",
        drift_items=[item],
    )

    generator = RemediationGenerator(
        mode=RemediationMode.IMPORT,
        iac_tool=IaCTool.TERRAFORM,
        output_dir=str(tmp_path),
        dry_run=False,
    )

    output = generator.generate(result)

    assert len(output.import_commands) == 1
    assert (
        "terraform import aws_security_group.shadow_sg sg-0987654321" in output.import_commands[0]
    )
    assert len(output.hcl_blocks) == 1
    assert 'resource "aws_security_group" "shadow_sg"' in output.hcl_blocks[0]

    # Verify files created
    assert (tmp_path / "import.sh").exists()
    assert (tmp_path / "imported_shadow_sg.tf").exists()
    assert (tmp_path / "REMEDIATION_SUMMARY.md").exists()


def test_remediation_opentofu_support(tmp_path: Path) -> None:
    unmanaged_res = CloudResource(
        resource_id="my-bucket-unmanaged",
        resource_type="aws_s3_bucket",
        attributes={"id": "my-bucket-unmanaged", "bucket": "my-bucket-unmanaged"},
    )

    item = DriftItem(
        resource_address="[unmanaged] aws_s3_bucket.my-bucket-unmanaged",
        resource_type="aws_s3_bucket",
        resource_id="my-bucket-unmanaged",
        drift_type=DriftType.UNMANAGED,
        cloud_resource=unmanaged_res,
    )

    result = DriftResult(
        scan_id="rem2",
        provider="aws",
        state_backend=StateBackendType.LOCAL,
        state_source="test",
        drift_items=[item],
    )

    generator = RemediationGenerator(
        mode=RemediationMode.IMPORT,
        iac_tool=IaCTool.OPENTOFU,
        output_dir=str(tmp_path),
        dry_run=False,
    )

    output = generator.generate(result)
    assert len(output.import_commands) == 1
    assert output.import_commands[0].startswith("opentofu import")


def test_remediation_revert_plan(tmp_path: Path) -> None:
    item = DriftItem(
        resource_address="aws_instance.web",
        resource_type="aws_instance",
        resource_id="i-12345",
        drift_type=DriftType.CHANGED,
        attribute_diffs=[
            AttributeDiff(
                path="instance_type",
                desired_value="t3.micro",
                actual_value="t3.2xlarge",
            )
        ],
    )

    result = DriftResult(
        scan_id="rem3",
        provider="aws",
        state_backend=StateBackendType.LOCAL,
        state_source="test",
        drift_items=[item],
    )

    generator = RemediationGenerator(
        mode=RemediationMode.REVERT,
        output_dir=str(tmp_path),
        dry_run=False,
    )

    output = generator.generate(result)

    assert len(output.revert_items) == 1
    assert (tmp_path / "revert_plan.json").exists()
    assert (tmp_path / "revert_instructions.md").exists()
