import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from typer.testing import CliRunner

import driftsentry.cli.scan as scan_module
from driftsentry.cli.main import app
from driftsentry.cli.triage import add_exclusion_to_config
from driftsentry.core.models import (
    AttributeDiff,
    DriftAttribution,
    DriftItem,
    DriftResult,
    DriftSeverity,
    DriftType,
    IaCTool,
    StateBackendType,
)

runner = CliRunner()


@pytest.fixture(autouse=True)
def reset_last_scan_result() -> None:
    scan_module._last_scan_result = None


@pytest.fixture
def sample_drift_result() -> DriftResult:
    item1 = DriftItem(
        resource_address="aws_s3_bucket.data_bucket",
        resource_type="aws_s3_bucket",
        resource_id="my-company-data-prod",
        drift_type=DriftType.CHANGED,
        severity=DriftSeverity.HIGH,
        attribute_diffs=[
            AttributeDiff(
                path="server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm",
                desired_value="AES256",
                actual_value="aws:kms",
            )
        ],
        attribution=DriftAttribution(
            principal="developer-alice",
            event_name="PutBucketEncryption",
            event_time=datetime.datetime(2026, 9, 27, 10, 0, 0, tzinfo=datetime.UTC),
        ),
    )

    item2 = DriftItem(
        resource_address="aws_s3_bucket.untracked_bucket",
        resource_type="aws_s3_bucket",
        resource_id="untracked-temp-bucket",
        drift_type=DriftType.UNMANAGED,
        severity=DriftSeverity.MEDIUM,
        attribute_diffs=[],
        attribution=DriftAttribution(
            principal="admin-bob",
            event_name="CreateBucket",
            event_time=datetime.datetime(2026, 9, 27, 11, 0, 0, tzinfo=datetime.UTC),
        ),
    )

    return DriftResult(
        scan_id="test-scan",
        iac_tool=IaCTool.TERRAFORM,
        provider="aws",
        region="us-east-1",
        state_backend=StateBackendType.LOCAL,
        state_source="terraform.tfstate",
        total_resources=5,
        total_cloud_resources=6,
        drift_items=[item1, item2],
    )


def test_triage_no_scan_available(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["triage"])
    assert result.exit_code == 1
    assert "No scan result found" in result.stdout


def test_triage_no_drift_found(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    clean_result = DriftResult(
        scan_id="clean",
        iac_tool=IaCTool.TERRAFORM,
        provider="aws",
        region="us-east-1",
        state_backend=StateBackendType.LOCAL,
        state_source="terraform.tfstate",
        total_resources=3,
        total_cloud_resources=3,
        drift_items=[],
    )
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(clean_result.model_dump_json())

    result = runner.invoke(app, ["triage", "--input", str(scan_file)])
    assert result.exit_code == 0
    assert "Everything in sync" in result.stdout


def test_triage_auto_adopt_non_interactive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sample_drift_result: DriftResult
) -> None:
    monkeypatch.chdir(tmp_path)
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(sample_drift_result.model_dump_json())
    out_dir = tmp_path / "remediation"

    result = runner.invoke(
        app,
        [
            "triage",
            "--input",
            str(scan_file),
            "--output-dir",
            str(out_dir),
            "--non-interactive",
            "--auto-adopt",
        ],
    )

    assert result.exit_code == 0
    assert "Adopted (IaC)" in result.stdout
    assert (out_dir / "import.sh").exists()


def test_triage_auto_revert_non_interactive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sample_drift_result: DriftResult
) -> None:
    monkeypatch.chdir(tmp_path)
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(sample_drift_result.model_dump_json())
    out_dir = tmp_path / "remediation"

    result = runner.invoke(
        app,
        [
            "triage",
            "--input",
            str(scan_file),
            "--output-dir",
            str(out_dir),
            "--non-interactive",
            "--auto-revert",
        ],
    )

    assert result.exit_code == 0
    assert "Reverted (Cloud)" in result.stdout
    assert (out_dir / "revert_plan.json").exists()


def test_triage_auto_ignore_non_interactive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sample_drift_result: DriftResult
) -> None:
    monkeypatch.chdir(tmp_path)
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(sample_drift_result.model_dump_json())
    config_file = tmp_path / ".driftsentry.yaml"

    result = runner.invoke(
        app,
        [
            "triage",
            "--input",
            str(scan_file),
            "--config",
            str(config_file),
            "--non-interactive",
            "--auto-ignore",
        ],
    )

    assert result.exit_code == 0
    assert "Ignored (Config)" in result.stdout
    assert config_file.exists()

    with open(config_file) as f:
        cfg = yaml.safe_load(f)
    assert "my-company-data-prod" in cfg["filters"]["exclude_patterns"]
    assert "untracked-temp-bucket" in cfg["filters"]["exclude_patterns"]


def test_triage_interactive_actions_and_quit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sample_drift_result: DriftResult
) -> None:
    monkeypatch.chdir(tmp_path)
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(sample_drift_result.model_dump_json())
    out_dir = tmp_path / "remediation"

    # Simulate: user chooses 's' (skip) on item 1, then 'q' (quit) on item 2
    with patch("rich.prompt.Prompt.ask", side_effect=["s", "q"]):
        result = runner.invoke(
            app,
            [
                "triage",
                "--input",
                str(scan_file),
                "--output-dir",
                str(out_dir),
            ],
        )

    assert result.exit_code == 0
    assert "Triage session ended early" in result.stdout
    assert "Skipped" in result.stdout


def test_add_exclusion_to_config_idempotent(tmp_path: Path) -> None:
    cfg_file = tmp_path / ".driftsentry.yaml"
    cfg_file.write_text("provider:\n  region: us-west-2\n")

    add_exclusion_to_config("bucket-foo", config_file=cfg_file)
    add_exclusion_to_config("bucket-bar", config_file=cfg_file)
    add_exclusion_to_config("bucket-foo", config_file=cfg_file)  # Duplicate

    with open(cfg_file) as f:
        data = yaml.safe_load(f)

    assert data["provider"]["region"] == "us-west-2"
    assert data["filters"]["exclude_patterns"] == ["bucket-foo", "bucket-bar"]
