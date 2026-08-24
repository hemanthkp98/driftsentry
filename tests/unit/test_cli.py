"""Unit tests for the CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

import driftsentry.cli.scan as scan_module
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
    assert "<!DOCTYPE html>" in html_out.read_text(encoding="utf-8")


def test_last_scan_result_persists_between_invocations(tmp_path: Path, monkeypatch) -> None:
    result_data = {
        "scan_id": "persisted",
        "iac_tool": "terraform",
        "provider": "aws",
        "region": "us-east-1",
        "state_backend": "local",
        "state_source": "test.tfstate",
        "drift_items": [],
        "duration_seconds": 0.5,
        "errors": [],
    }
    from driftsentry.core.models import DriftResult

    monkeypatch.chdir(tmp_path)
    scan_module._last_scan_result = None
    scan_module._save_last_scan_result(DriftResult(**result_data))

    loaded = scan_module.get_last_scan_result()

    assert loaded is not None
    assert loaded.scan_id == "persisted"
