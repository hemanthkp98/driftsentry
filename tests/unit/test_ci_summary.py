"""Unit tests for CISummaryFormatter and GitHub Step Summary generation."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from driftsentry.core.models import (
    AttributeDiff,
    CloudResource,
    DriftAttribution,
    DriftItem,
    DriftResult,
    DriftSeverity,
    DriftType,
    IaCTool,
    StateBackendType,
)
from driftsentry.output.ci_summary import (
    CISummaryFormatter,
    write_step_summary,
)


@pytest.fixture
def clean_drift_result() -> DriftResult:
    return DriftResult(
        scan_id="scan-clean-123",
        timestamp=datetime.datetime(2026, 9, 27, 12, 0, 0),
        iac_tool=IaCTool.TERRAFORM,
        provider="aws",
        region="us-east-1",
        regions=["us-east-1"],
        state_backend=StateBackendType.LOCAL,
        state_source="env/prod/terraform.tfstate",
        total_resources=42,
        total_cloud_resources=42,
        drift_items=[],
        duration_seconds=1.23,
    )


@pytest.fixture
def drifted_result() -> DriftResult:
    changed_item = DriftItem(
        resource_address="aws_security_group.web",
        resource_type="aws_security_group",
        resource_id="sg-12345678",
        drift_type=DriftType.CHANGED,
        severity=DriftSeverity.CRITICAL,
        attribute_diffs=[
            AttributeDiff(
                path="ingress.0.cidr_blocks",
                desired_value=["10.0.0.0/16"],
                actual_value=["0.0.0.0/0"],
            )
        ],
        attribution=DriftAttribution(
            principal="arn:aws:iam::111122223333:user/alice",
            event_name="AuthorizeSecurityGroupIngress",
            event_time=datetime.datetime(2026, 9, 27, 10, 30, 0),
            source_ip="203.0.113.5",
            user_agent="aws-cli/2.15.0",
            is_console_change=False,
        ),
        region="us-east-1",
        account_name="prod",
    )

    deleted_item = DriftItem(
        resource_address="aws_s3_bucket.logs",
        resource_type="aws_s3_bucket",
        resource_id="my-corp-logs",
        drift_type=DriftType.DELETED,
        severity=DriftSeverity.HIGH,
        region="us-east-1",
        account_name="prod",
    )

    unmanaged_item = DriftItem(
        resource_address="[unmanaged] aws_iam_role.shadow_role",
        resource_type="aws_iam_role",
        resource_id="shadow-role-123",
        drift_type=DriftType.UNMANAGED,
        severity=DriftSeverity.CRITICAL,
        cloud_resource=CloudResource(
            resource_id="shadow-role-123",
            resource_type="aws_iam_role",
            attributes={"name": "shadow_admin"},
            tags={"Environment": "Dev", "Owner": "Bob"},
        ),
        attribution=DriftAttribution(
            principal="arn:aws:iam::111122223333:root",
            event_name="CreateRole",
            event_time=datetime.datetime(2026, 9, 27, 9, 0, 0),
            is_console_change=True,
        ),
        region="us-east-1",
        account_name="prod",
    )

    return DriftResult(
        scan_id="scan-drift-456",
        timestamp=datetime.datetime(2026, 9, 27, 12, 0, 0),
        iac_tool=IaCTool.TERRAFORM,
        provider="aws",
        regions=["us-east-1", "us-west-2"],
        accounts=["prod", "staging"],
        state_backend=StateBackendType.S3,
        state_source="s3://my-corp-tfstate/prod.tfstate",
        total_resources=50,
        total_cloud_resources=51,
        drift_items=[changed_item, deleted_item, unmanaged_item],
        duration_seconds=3.45,
        errors=["Failed to scan route53 in us-west-2"],
    )


def test_render_clean_summary(clean_drift_result: DriftResult) -> None:
    formatter = CISummaryFormatter()
    md = formatter.render(clean_drift_result, fail_on="any", failed=False)

    assert "# 🛡️ DriftSentry CI Check: Clean ✅" in md
    assert "No infrastructure drift detected" in md
    assert "| 📦 Total Managed Resources | 42 |" in md
    assert "scan-clean-123" in md
    assert "<details>" not in md  # No drift items to detail


def test_render_drift_failure(drifted_result: DriftResult) -> None:
    formatter = CISummaryFormatter()
    md = formatter.render(drifted_result, fail_on="any", failed=True)

    assert "# 🛡️ DriftSentry CI Check: Drift Detected ❌" in md
    assert "Drift detected matching failure policy (`--fail-on any`)" in md
    assert "### Drifted Resources (3)" in md
    assert "| `aws_security_group.web` |" in md
    assert "| `aws_s3_bucket.logs` |" in md
    assert "| `[unmanaged] aws_iam_role.shadow_role` |" in md

    # Collapsible details
    assert "<details>" in md
    assert "<summary>" in md
    assert "CloudTrail Attribution" in md
    assert "alice" in md
    assert "ClickOps" in md
    assert "Scan Warnings (1)" in md


def test_render_drift_non_blocking(drifted_result: DriftResult) -> None:
    formatter = CISummaryFormatter()
    md = formatter.render(drifted_result, fail_on="none", failed=False)

    assert "# 🛡️ DriftSentry CI Check: Drift Detected (Non-Blocking) ⚠️" in md
    assert "below failure threshold (`--fail-on none`)" in md


def test_render_writes_to_file(tmp_path: Path, clean_drift_result: DriftResult) -> None:
    formatter = CISummaryFormatter()
    output_file = tmp_path / "summary.md"
    md = formatter.render(clean_drift_result, output_path=output_file)

    assert output_file.exists()
    assert output_file.read_text(encoding="utf-8") == md


def test_render_error(tmp_path: Path) -> None:
    formatter = CISummaryFormatter()
    err_file = tmp_path / "error.md"
    err_md = formatter.render_error("AWS Authentication Token Expired", output_path=err_file)

    assert "# 🛡️ DriftSentry CI Check: Error ❌" in err_md
    assert "AWS Authentication Token Expired" in err_md
    assert err_file.exists()


def test_write_step_summary_explicit_path(tmp_path: Path) -> None:
    summary_file = tmp_path / "step_summary.md"
    written = write_step_summary("## Hello Step Summary", step_summary_path=summary_file)

    assert written == summary_file
    assert "## Hello Step Summary" in summary_file.read_text(encoding="utf-8")

    # Appending another message
    write_step_summary("## Second Section", step_summary_path=summary_file)
    content = summary_file.read_text(encoding="utf-8")
    assert "## Hello Step Summary" in content
    assert "## Second Section" in content


def test_write_step_summary_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_summary_file = tmp_path / "github_step_summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(env_summary_file))

    written = write_step_summary("### Automatic Env Summary")
    assert written == env_summary_file
    assert "### Automatic Env Summary" in env_summary_file.read_text(encoding="utf-8")


def test_write_step_summary_none_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    written = write_step_summary("No target")
    assert written is None
