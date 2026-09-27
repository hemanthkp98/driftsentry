from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from driftsentry.cli.main import app
from driftsentry.core.models import DriftResult, IaCTool, StateBackendType

runner = CliRunner()


@patch("driftsentry.cli.scan.run_scan_pipeline")
def test_scan_basic_execution(
    mock_run_pipeline: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    mock_result = DriftResult(
        scan_id="test",
        iac_tool=IaCTool.TERRAFORM,
        provider="aws",
        region="us-east-1",
        state_backend=StateBackendType.LOCAL,
        state_source="test.tfstate",
        total_resources=0,
        total_cloud_resources=0,
        duration_seconds=1.0,
    )
    mock_run_pipeline.return_value = mock_result

    state_file = tmp_path / "test.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["scan", "--state-file", str(state_file)])

    assert result.exit_code == 0
    mock_run_pipeline.assert_called_once()


@patch("driftsentry.cli.scan.AWSProvider")
@patch("driftsentry.cli.scan.create_state_reader")
@patch("driftsentry.cli.scan.DriftScanner")
def test_run_scan_pipeline_execution(
    mock_scanner: MagicMock,
    mock_reader: MagicMock,
    mock_aws: MagicMock,
) -> None:
    from driftsentry.cli.scan import run_scan_pipeline
    from driftsentry.core.config import DriftSentryConfig

    expected_result = MagicMock()
    mock_scanner.return_value.scan.return_value = expected_result
    mock_reader.return_value = MagicMock()
    mock_aws.return_value = MagicMock()

    config = DriftSentryConfig()

    result = run_scan_pipeline(config, provider="aws", show_progress=False)

    assert result == expected_result
    mock_scanner.return_value.scan.assert_called_once_with(show_progress=False)


@patch("driftsentry.cli.scan.run_scan_pipeline")
def test_scan_zero_config_auto_discovery_local_success(
    mock_run_pipeline: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    mock_result = DriftResult(
        scan_id="auto-scan",
        iac_tool=IaCTool.TERRAFORM,
        provider="aws",
        region="us-east-1",
        state_backend=StateBackendType.LOCAL,
        state_source="terraform.tfstate",
        total_resources=0,
        total_cloud_resources=0,
        duration_seconds=0.5,
    )
    mock_run_pipeline.return_value = mock_result

    state_file = tmp_path / "terraform.tfstate"
    state_file.write_text('{"version": 4, "resources": []}')

    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 0
    assert "Auto-discovered state" in result.stdout
    mock_run_pipeline.assert_called_once()
    called_config = mock_run_pipeline.call_args[0][0]
    assert called_config.state.path == str(state_file)
    assert called_config.state.backend == StateBackendType.LOCAL


@patch("driftsentry.cli.scan.run_scan_pipeline")
def test_scan_zero_config_auto_discovery_s3_success(
    mock_run_pipeline: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    mock_result = DriftResult(
        scan_id="auto-s3-scan",
        iac_tool=IaCTool.TERRAFORM,
        provider="aws",
        region="eu-west-1",
        state_backend=StateBackendType.S3,
        state_source="s3://my-corp-bucket/prod.tfstate",
        total_resources=0,
        total_cloud_resources=0,
        duration_seconds=0.5,
    )
    mock_run_pipeline.return_value = mock_result

    tf_dir = tmp_path / ".terraform"
    tf_dir.mkdir()
    (tf_dir / "terraform.tfstate").write_text(
        '{"version": 3, "backend": {"type": "s3", "config": {"bucket": "my-corp-bucket", "key": "prod.tfstate", "region": "eu-west-1"}}}'
    )

    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 0
    assert "Auto-discovered state" in result.stdout
    assert "s3://my-corp-bucket/prod.tfstate" in result.stdout
    mock_run_pipeline.assert_called_once()
    called_config = mock_run_pipeline.call_args[0][0]
    assert called_config.state.s3_bucket == "my-corp-bucket"
    assert called_config.state.s3_key == "prod.tfstate"
    assert called_config.state.s3_region == "eu-west-1"
    assert called_config.provider.region == "eu-west-1"


def test_scan_zero_config_no_state_shows_helpful_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 1
    assert "No Terraform state file or remote backend configuration discovered" in result.stdout
    assert "Checked paths" in result.stdout
    assert "--state-file" in result.stdout
