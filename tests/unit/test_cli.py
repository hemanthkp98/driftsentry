"""Unit tests for the CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from driftsentry.cli.main import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "DriftSentry" in result.stdout


def test_cli_scan_missing_state() -> None:
    result = runner.invoke(app, ["scan"])
    assert result.exit_code != 0
    assert "Error" in result.stdout or "No state file specified" in result.stdout


def test_cli_report_missing_input() -> None:
    result = runner.invoke(app, ["report"])
    assert result.exit_code == 1
    assert "No scan result available" in result.stdout


def test_cli_report_from_json(tmp_path: Path) -> None:
    # Create sample scan result json
    scan_json = tmp_path / "scan_result.json"
    scan_json.write_text(
        json.dumps(
            {
                "scan_id": "cli-test",
                "iac_tool": "terraform",
                "provider": "aws",
                "region": "us-east-1",
                "state_backend": "local",
                "state_source": "test.tfstate",
                "total_resources": 1,
                "total_cloud_resources": 1,
                "drift_items": [],
                "duration_seconds": 0.5,
                "errors": [],
            }
        )
    )

    result = runner.invoke(app, ["report", "--input", str(scan_json), "--format", "table"])
    assert result.exit_code == 0
    assert "No drift detected" in result.stdout


def test_cli_report_html(tmp_path: Path) -> None:
    scan_json = tmp_path / "scan_result.json"
    scan_json.write_text(
        json.dumps(
            {
                "scan_id": "html-test",
                "iac_tool": "terraform",
                "provider": "aws",
                "region": "us-east-1",
                "state_backend": "local",
                "state_source": "test.tfstate",
                "total_resources": 1,
                "total_cloud_resources": 1,
                "drift_items": [],
                "duration_seconds": 0.5,
                "errors": [],
            }
        )
    )

    html_out = tmp_path / "report.html"
    result = runner.invoke(
        app,
        ["report", "--input", str(scan_json), "--format", "html", "--output", str(html_out)],
    )
    assert result.exit_code == 0
    assert html_out.exists()
    assert "<!DOCTYPE html>" in html_out.read_text()


def test_cli_scan_multi_region_and_account_flags(sample_state_file: Path) -> None:
    from unittest.mock import patch

    with patch("driftsentry.cli.scan.AWSProvider") as mock_aws_cls, patch(
        "driftsentry.cli.scan.DriftScanner"
    ) as mock_scanner_cls:
        mock_scanner = mock_scanner_cls.return_value
        mock_scanner.scan.return_value.has_drift = False
        mock_scanner.scan.return_value.critical_count = 0
        mock_scanner.scan.return_value.total_resources = 5
        mock_scanner.scan.return_value.duration_seconds = 1.0
        mock_scanner.scan.return_value.provider = "aws"
        mock_scanner.scan.return_value.region = "us-east-1"
        mock_scanner.scan.return_value.regions = ["us-east-1", "us-west-2"]
        mock_scanner.scan.return_value.accounts = ["111122223333", "staging"]
        mock_scanner.scan.return_value.changed_count = 0
        mock_scanner.scan.return_value.deleted_count = 0
        mock_scanner.scan.return_value.unmanaged_count = 0
        mock_scanner.scan.return_value.errors = []
        mock_scanner.scan.return_value.iac_tool.value = "terraform"
        mock_scanner.scan.return_value.scan_id = "test-scan"

        result = runner.invoke(
            app,
            [
                "scan",
                "--state-file",
                str(sample_state_file),
                "--regions",
                "us-east-1,us-west-2",
                "--accounts",
                "111122223333,staging",
                "--role-arn-template",
                "arn:aws:iam::{account_id}:role/DriftSentryScanRole",
                "--concurrency",
                "8",
            ],
        )

        assert result.exit_code == 0
        mock_aws_cls.assert_called_once()
        call_kwargs = mock_aws_cls.call_args[1]
        assert call_kwargs["regions"] == ["us-east-1", "us-west-2"]
        assert len(call_kwargs["accounts"]) == 2
        assert call_kwargs["accounts"][0].id == "111122223333"
        assert call_kwargs["accounts"][1].name == "staging"
        assert call_kwargs["role_arn_template"] == "arn:aws:iam::{account_id}:role/DriftSentryScanRole"
        assert call_kwargs["concurrency"] == 8

