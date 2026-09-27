"""Unit tests for the driftsentry check CI/CD command."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from driftsentry.cli.check import evaluate_drift_failure
from driftsentry.cli.main import app
from driftsentry.core.models import (
    AttributeDiff,
    DriftItem,
    DriftResult,
    DriftSeverity,
    DriftType,
    IaCTool,
    StateBackendType,
)
from driftsentry.state.auto_discovery import DiscoveredState, StateDiscoveryError

runner = CliRunner()


@pytest.fixture
def clean_result() -> DriftResult:
    return DriftResult(
        scan_id="test-clean",
        iac_tool=IaCTool.TERRAFORM,
        provider="aws",
        region="us-east-1",
        state_backend=StateBackendType.LOCAL,
        state_source="terraform.tfstate",
        total_resources=5,
        total_cloud_resources=5,
        drift_items=[],
        duration_seconds=0.8,
    )


@pytest.fixture
def medium_drift_result() -> DriftResult:
    item = DriftItem(
        resource_address="aws_instance.worker",
        resource_type="aws_instance",
        resource_id="i-0123456789abcdef0",
        drift_type=DriftType.CHANGED,
        severity=DriftSeverity.MEDIUM,
        attribute_diffs=[
            AttributeDiff(
                path="tags.Environment",
                desired_value="Production",
                actual_value="Staging",
            )
        ],
    )
    return DriftResult(
        scan_id="test-medium",
        iac_tool=IaCTool.TERRAFORM,
        provider="aws",
        region="us-east-1",
        state_backend=StateBackendType.LOCAL,
        state_source="terraform.tfstate",
        total_resources=5,
        total_cloud_resources=5,
        drift_items=[item],
        duration_seconds=0.9,
    )


@pytest.fixture
def critical_drift_result() -> DriftResult:
    item = DriftItem(
        resource_address="aws_security_group.allow_all",
        resource_type="aws_security_group",
        resource_id="sg-99998888",
        drift_type=DriftType.CHANGED,
        severity=DriftSeverity.CRITICAL,
        attribute_diffs=[
            AttributeDiff(
                path="ingress.0.cidr_blocks",
                desired_value=["10.0.0.0/8"],
                actual_value=["0.0.0.0/0"],
            )
        ],
    )
    return DriftResult(
        scan_id="test-critical",
        iac_tool=IaCTool.TERRAFORM,
        provider="aws",
        region="us-east-1",
        state_backend=StateBackendType.LOCAL,
        state_source="terraform.tfstate",
        total_resources=5,
        total_cloud_resources=5,
        drift_items=[item],
        duration_seconds=1.1,
    )


def test_evaluate_drift_failure_logic(
    clean_result: DriftResult,
    medium_drift_result: DriftResult,
    critical_drift_result: DriftResult,
) -> None:
    # Clean result never fails on any valid policy
    assert not evaluate_drift_failure(clean_result, "any")
    assert not evaluate_drift_failure(clean_result, "critical")
    assert not evaluate_drift_failure(clean_result, "high")
    assert not evaluate_drift_failure(clean_result, "none")
    assert not evaluate_drift_failure(clean_result, "never")

    # Medium drift
    assert evaluate_drift_failure(medium_drift_result, "any")
    assert not evaluate_drift_failure(medium_drift_result, "critical")
    assert not evaluate_drift_failure(medium_drift_result, "high")
    assert not evaluate_drift_failure(medium_drift_result, "none")
    assert not evaluate_drift_failure(medium_drift_result, "never")

    # Critical drift
    assert evaluate_drift_failure(critical_drift_result, "any")
    assert evaluate_drift_failure(critical_drift_result, "critical")
    assert evaluate_drift_failure(critical_drift_result, "high")
    assert not evaluate_drift_failure(critical_drift_result, "none")
    assert not evaluate_drift_failure(critical_drift_result, "never")

    # Invalid policy
    with pytest.raises(ValueError, match="Invalid --fail-on option"):
        evaluate_drift_failure(critical_drift_result, "unsupported")


@patch("driftsentry.cli.check.run_scan_pipeline")
def test_check_clean_exits_zero(
    mock_run_pipeline: MagicMock,
    clean_result: DriftResult,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    mock_run_pipeline.return_value = clean_result

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["check", "--state-file", str(state_file)])
    assert result.exit_code == 0
    assert "CI Check Passed" in result.stdout
    assert "All infrastructure resources match desired IaC state" in result.stdout


@patch("driftsentry.cli.check.run_scan_pipeline")
def test_check_drift_fails_with_code_2(
    mock_run_pipeline: MagicMock,
    critical_drift_result: DriftResult,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    mock_run_pipeline.return_value = critical_drift_result

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["check", "--state-file", str(state_file)])
    assert result.exit_code == 2
    assert "CI Check Failed" in result.stdout
    assert "Exiting with code 2" in result.stdout


@patch("driftsentry.cli.check.run_scan_pipeline")
def test_check_fail_on_critical_passes_when_only_medium_drift(
    mock_run_pipeline: MagicMock,
    medium_drift_result: DriftResult,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    mock_run_pipeline.return_value = medium_drift_result

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(
        app,
        ["check", "--state-file", str(state_file), "--fail-on", "critical"],
    )
    assert result.exit_code == 0
    assert "CI Check Passed with Warnings" in result.stdout
    assert "Exiting with code 0" in result.stdout


@patch("driftsentry.cli.check.run_scan_pipeline")
def test_check_fail_on_none_passes_even_with_critical_drift(
    mock_run_pipeline: MagicMock,
    critical_drift_result: DriftResult,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    mock_run_pipeline.return_value = critical_drift_result

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(
        app,
        ["check", "--state-file", str(state_file), "--fail-on", "none"],
    )
    assert result.exit_code == 0
    assert "CI Check Passed with Warnings" in result.stdout


def test_check_invalid_fail_on_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["check", "--fail-on", "invalid-level"])
    assert result.exit_code == 1
    assert "Invalid --fail-on option" in result.stdout


@patch("driftsentry.cli.check.discover_terraform_state")
def test_check_auto_discovery_failure(
    mock_discover: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    mock_discover.side_effect = StateDiscoveryError(
        "No state found", checked_paths=[tmp_path / "terraform.tfstate"]
    )

    result = runner.invoke(app, ["check"])
    assert result.exit_code == 1
    assert "No Terraform state file or remote backend configuration discovered" in result.stdout


@patch("driftsentry.cli.check.discover_terraform_state")
@patch("driftsentry.cli.check.run_scan_pipeline")
def test_check_auto_discovery_success(
    mock_run_pipeline: MagicMock,
    mock_discover: MagicMock,
    clean_result: DriftResult,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    mock_discover.return_value = DiscoveredState(
        backend=StateBackendType.LOCAL,
        path=tmp_path / "terraform.tfstate",
    )
    mock_run_pipeline.return_value = clean_result

    result = runner.invoke(app, ["check"])
    assert result.exit_code == 0
    assert "Auto-discovered state" in result.stdout
    assert "CI Check Passed" in result.stdout


@patch("driftsentry.cli.check.run_scan_pipeline")
def test_check_writes_github_step_summary_from_env(
    mock_run_pipeline: MagicMock,
    critical_drift_result: DriftResult,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    mock_run_pipeline.return_value = critical_drift_result

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    summary_file = tmp_path / "github_step_summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

    result = runner.invoke(app, ["check", "--state-file", str(state_file)])
    assert result.exit_code == 2

    assert summary_file.exists()
    content = summary_file.read_text(encoding="utf-8")
    assert "# 🛡️ DriftSentry CI Check: Drift Detected ❌" in content
    assert "aws_security_group.allow_all" in content
    assert "<details>" in content


@patch("driftsentry.cli.check.run_scan_pipeline")
def test_check_writes_output_markdown_and_save_json(
    mock_run_pipeline: MagicMock,
    critical_drift_result: DriftResult,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    mock_run_pipeline.return_value = critical_drift_result

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    pr_comment_file = tmp_path / "pr-comment.md"
    save_json_file = tmp_path / "scan.json"

    result = runner.invoke(
        app,
        [
            "check",
            "--state-file",
            str(state_file),
            "--output-markdown",
            str(pr_comment_file),
            "--save",
            str(save_json_file),
            "--output",
            "none",
        ],
    )
    assert result.exit_code == 2
    assert pr_comment_file.exists()
    assert save_json_file.exists()

    saved_data = json.loads(save_json_file.read_text(encoding="utf-8"))
    assert saved_data["scan_id"] == "test-critical"


@patch("driftsentry.cli.check.run_scan_pipeline")
def test_check_operational_error_exits_code_1_and_writes_summary(
    mock_run_pipeline: MagicMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    mock_run_pipeline.side_effect = RuntimeError("AWS Connection Timeout")

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text("{}")

    summary_file = tmp_path / "summary.md"
    result = runner.invoke(
        app,
        [
            "check",
            "--state-file",
            str(state_file),
            "--github-step-summary",
            str(summary_file),
        ],
    )
    assert result.exit_code == 1
    assert "Scan failed: AWS Connection Timeout" in result.stdout
    assert summary_file.exists()
    assert "AWS Connection Timeout" in summary_file.read_text(encoding="utf-8")
