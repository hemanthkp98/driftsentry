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
