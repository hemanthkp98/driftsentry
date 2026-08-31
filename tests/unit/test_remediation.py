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


def test_hcl_string_values_are_escaped() -> None:
    escaped = RemediationGenerator._to_hcl_value('quoted "value"\nnext')

    assert escaped == '"quoted \\"value\\"\\nnext"'


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


def test_remediation_with_ai(tmp_path: Path) -> None:
    from driftsentry.core.models import AIHCLResult, AIRemediationResult, AIRootCause

    unmanaged_res = CloudResource(
        resource_id="sg-custom-123",
        resource_type="aws_security_group",
        attributes={"id": "sg-custom-123", "name": "custom_sg"},
    )
    unmanaged_item = DriftItem(
        resource_address="[unmanaged] aws_security_group.sg-custom-123",
        resource_type="aws_security_group",
        resource_id="sg-custom-123",
        drift_type=DriftType.UNMANAGED,
        cloud_resource=unmanaged_res,
    )
    changed_item = DriftItem(
        resource_address="aws_instance.app",
        resource_type="aws_instance",
        resource_id="i-app-1",
        drift_type=DriftType.CHANGED,
        attribute_diffs=[
            AttributeDiff(
                path="instance_type",
                desired_value="t3.small",
                actual_value="t3.large",
            )
        ],
    )

    result = DriftResult(
        scan_id="rem-ai-test",
        provider="aws",
        state_backend=StateBackendType.LOCAL,
        state_source="test",
        drift_items=[unmanaged_item, changed_item],
    )

    ai_hcl = AIHCLResult(
        resource_address="aws_security_group.custom_web_sg",
        resource_type="aws_security_group",
        resource_id="sg-custom-123",
        suggested_name="custom_web_sg",
        hcl_code='resource "aws_security_group" "custom_web_sg" {\n  name = "custom_web_sg"\n}',
        explanation="Idiomatic AI-generated security group with best practices",
        import_command="terraform import aws_security_group.custom_web_sg sg-custom-123",
    )
    ai_rc = AIRootCause(
        resource_address="aws_instance.app",
        resource_type="aws_instance",
        resource_id="i-app-1",
        narrative="Scaled up by devops-engineer during load test",
        risk_assessment="LOW: Cost drift only",
        recommended_action="revert",
    )
    ai_result = AIRemediationResult(
        hcl_results=[ai_hcl],
        root_causes=[ai_rc],
        provider_used="claude",
        model_used="claude-sonnet-4-6",
    )

    generator = RemediationGenerator(
        mode=RemediationMode.BOTH,
        output_dir=str(tmp_path),
        dry_run=False,
    )

    output = generator.generate_with_ai(result, ai_result=ai_result)

    assert len(output.import_commands) == 1
    assert "aws_security_group.custom_web_sg" in output.import_commands[0]
    assert 'resource "aws_security_group" "custom_web_sg"' in output.hcl_blocks[0]

    hcl_file = tmp_path / "imported_custom_web_sg.tf"
    assert hcl_file.exists()
    assert 'resource "aws_security_group" "custom_web_sg"' in hcl_file.read_text()

    summary_file = tmp_path / "REMEDIATION_SUMMARY.md"
    assert summary_file.exists()
    summary_content = summary_file.read_text()
    assert "AI Root Cause & Remediation Insights" in summary_content
    assert "Scaled up by devops-engineer" in summary_content

    revert_file = tmp_path / "revert_instructions.md"
    assert revert_file.exists()
    revert_content = revert_file.read_text(encoding="utf-8")
    assert "AI Root Cause:" in revert_content
