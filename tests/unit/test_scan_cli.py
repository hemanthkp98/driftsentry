from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from driftsentry.cli.main import app
from driftsentry.core.models import DriftResult, IaCTool, StateBackendType

runner = CliRunner()


@patch("driftsentry.cli.scan.run_scan_pipeline")
def test_scan_no_history_flag(
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
    mock_run_pipeline.return_value = (mock_result, None)

    state_file = tmp_path / "test.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(app, ["scan", "--state-file", str(state_file), "--no-history"])

    assert result.exit_code == 0
    mock_run_pipeline.assert_called_once()
    config_passed = mock_run_pipeline.call_args[0][0]
    assert config_passed.history.enabled is False
    assert "Drift delta:" not in result.stdout


@patch("driftsentry.cli.scan.AWSProvider")
@patch("driftsentry.cli.scan.create_state_reader")
@patch("driftsentry.cli.scan.DriftStore")
@patch("driftsentry.cli.scan.RegressionDetector")
@patch("driftsentry.cli.scan.DriftScanner")
def test_run_scan_pipeline_skips_history_when_disabled(
    mock_scanner: MagicMock,
    mock_detector: MagicMock,
    mock_store: MagicMock,
    mock_reader: MagicMock,
    mock_aws: MagicMock,
) -> None:
    from driftsentry.cli.scan import run_scan_pipeline
    from driftsentry.core.config import DriftSentryConfig

    mock_scanner.return_value.scan.return_value = MagicMock()
    mock_reader.return_value = MagicMock()
    mock_aws.return_value = MagicMock()

    config = DriftSentryConfig()
    config.history.enabled = False

    _result, report = run_scan_pipeline(config, provider="aws", show_progress=False)

    assert report is None
    mock_store.assert_not_called()
    mock_detector.assert_not_called()


@patch("driftsentry.cli.scan.run_scan_pipeline")
def test_scan_history_disabled_in_config_behaves_like_no_history(
    mock_run_pipeline: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    config_file = tmp_path / ".driftsentry.yaml"
    config_file.write_text("history:\n  enabled: false\n")

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
    mock_run_pipeline.return_value = (mock_result, None)

    state_file = tmp_path / "test.tfstate"
    state_file.write_text("{}")

    result = runner.invoke(
        app, ["scan", "--state-file", str(state_file), "--config", str(config_file)]
    )

    assert result.exit_code == 0
    mock_run_pipeline.assert_called_once()
    config_passed = mock_run_pipeline.call_args[0][0]
    assert config_passed.history.enabled is False
    assert "Drift delta:" not in result.stdout
