"""Unit and CLI integration tests for baseline management and scan/check integration."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

import driftsentry.cli.scan as scan_module
from driftsentry.cli.main import app
from driftsentry.core.baseline import (
    DEFAULT_BASELINE_FILENAME,
    BaselineEntry,
    DriftBaseline,
    compute_drift_fingerprint,
    load_baseline,
    save_baseline,
)
from driftsentry.core.models import (
    AttributeDiff,
    DriftItem,
    DriftResult,
    DriftSeverity,
    DriftType,
    IaCTool,
    StateBackendType,
)

runner = CliRunner(env={"COLUMNS": "160"})


@pytest.fixture(autouse=True)
def clean_scan_cache() -> Any:
    """Isolate CLI test runs by resetting in-memory scan results."""
    old_result = scan_module._last_scan_result
    scan_module._last_scan_result = None
    yield
    scan_module._last_scan_result = old_result


def _make_dummy_result(items: list[DriftItem]) -> DriftResult:
    """Helper to construct a valid DriftResult for testing."""
    return DriftResult(
        scan_id="test-scan-baseline-cli",
        timestamp=datetime.datetime.now(datetime.UTC),
        iac_tool=IaCTool.TERRAFORM,
        provider="aws",
        region="us-east-1",
        state_backend=StateBackendType.LOCAL,
        state_source="terraform.tfstate",
        total_resources=5,
        total_cloud_resources=5,
        drift_items=items,
    )


def test_baseline_show_empty(tmp_path: Path, monkeypatch: Any) -> None:
    """Verify driftsentry baseline show when no baseline exists."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["baseline", "show"])
    assert result.exit_code == 0
    assert "No active baseline entries found" in result.stdout

    # In JSON format
    result_json = runner.invoke(app, ["baseline", "show", "--format", "json"])
    assert result_json.exit_code == 0
    assert result_json.stdout.strip() == "[]"


def test_baseline_save_and_show(tmp_path: Path, monkeypatch: Any) -> None:
    """Verify driftsentry baseline save and driftsentry baseline show."""
    monkeypatch.chdir(tmp_path)

    item = DriftItem(
        resource_address="aws_security_group.web",
        resource_type="aws_security_group",
        drift_type=DriftType.CHANGED,
        attribute_diffs=[
            AttributeDiff(
                path="ingress.0.cidr_blocks",
                desired_value=["10.0.0.0/8"],
                actual_value=["198.51.100.10/32"],
            )
        ],
    )
    scan_res = _make_dummy_result([item])

    with patch("driftsentry.cli.baseline.get_last_scan_result", return_value=scan_res):
        res = runner.invoke(app, ["baseline", "save", "-m", "Hotfix INC-101", "--by", "alice"])
        assert res.exit_code == 0
        assert "Baseline updated" in res.stdout
        assert "Entries added: 1" in res.stdout

    # File must exist
    baseline_file = tmp_path / DEFAULT_BASELINE_FILENAME
    assert baseline_file.exists()
    loaded = load_baseline(baseline_file)
    assert loaded is not None
    assert len(loaded.entries) == 1
    assert loaded.entries[0].reason == "Hotfix INC-101"
    assert loaded.entries[0].acknowledged_by == "alice"

    # Test driftsentry baseline show table
    show_res = runner.invoke(app, ["baseline", "show"])
    assert show_res.exit_code == 0
    assert "aws_security_group.web" in show_res.stdout
    assert "ingress.0.cidr_blocks" in show_res.stdout
    assert "Hotfix INC-101" in show_res.stdout

    # Test driftsentry baseline show json
    show_json_res = runner.invoke(app, ["baseline", "show", "--format", "json"])
    assert show_json_res.exit_code == 0
    parsed = json.loads(show_json_res.stdout)
    assert "entries" in parsed
    assert len(parsed["entries"]) == 1


def test_baseline_clear(tmp_path: Path, monkeypatch: Any) -> None:
    """Verify driftsentry baseline clear with confirmation and --force."""
    monkeypatch.chdir(tmp_path)
    baseline_file = tmp_path / DEFAULT_BASELINE_FILENAME

    # Create dummy baseline file
    baseline = DriftBaseline()
    save_baseline(baseline, baseline_file)
    assert baseline_file.exists()

    # Cancelled clear
    res_cancel = runner.invoke(app, ["baseline", "clear"], input="n\n")
    assert res_cancel.exit_code == 0
    assert "Operation cancelled" in res_cancel.stdout
    assert baseline_file.exists()

    # Confirmed clear with --force
    res_force = runner.invoke(app, ["baseline", "clear", "--force"])
    assert res_force.exit_code == 0
    assert "Cleared baseline ledger" in res_force.stdout
    assert not baseline_file.exists()


def test_scan_with_baseline_suppression(tmp_path: Path, monkeypatch: Any) -> None:
    """Verify driftsentry scan suppresses acknowledged drift items when baseline exists."""
    monkeypatch.chdir(tmp_path)

    actual_val = ["198.51.100.10/32"]
    fp = compute_drift_fingerprint(
        "aws_security_group.web", DriftType.CHANGED, "ingress.0.cidr_blocks", actual_val
    )
    baseline = DriftBaseline(
        entries=[
            BaselineEntry(
                resource_address="aws_security_group.web",
                resource_type="aws_security_group",
                drift_type=DriftType.CHANGED,
                attribute_path="ingress.0.cidr_blocks",
                fingerprint=fp,
                last_known_value=actual_val,
            )
        ]
    )
    save_baseline(baseline, tmp_path / DEFAULT_BASELINE_FILENAME)

    item = DriftItem(
        resource_address="aws_security_group.web",
        resource_type="aws_security_group",
        drift_type=DriftType.CHANGED,
        severity=DriftSeverity.CRITICAL,
        attribute_diffs=[
            AttributeDiff(
                path="ingress.0.cidr_blocks",
                desired_value=["10.0.0.0/8"],
                actual_value=actual_val,
            )
        ],
    )
    scan_res = _make_dummy_result([item])

    with patch("driftsentry.cli.scan.run_scan_pipeline", return_value=scan_res):
        # Scan with auto-detected baseline enabled
        res = runner.invoke(
            app,
            ["scan", "--state-file", "dummy.tfstate", "--output", "table"],
        )
        assert res.exit_code == 0
        assert "Baseline active: 1 acknowledged drift items suppressed" in res.stdout
        assert "No drift detected!" in res.stdout

        # Scan with --no-baseline flag disabled
        res_no_base = runner.invoke(
            app,
            ["scan", "--state-file", "dummy.tfstate", "--no-baseline", "--output", "table"],
        )
        assert (
            res_no_base.exit_code == 2
        )  # fail_on_critical triggers because item is not suppressed!
        assert "aws_security_group.web" in res_no_base.stdout


def test_check_with_baseline_and_step_summary(tmp_path: Path, monkeypatch: Any) -> None:
    """Verify driftsentry check exits 0 when drift is acknowledged in baseline and writes summary."""
    monkeypatch.chdir(tmp_path)

    actual_val = ["198.51.100.10/32"]
    fp = compute_drift_fingerprint(
        "aws_security_group.web", DriftType.CHANGED, "ingress.0.cidr_blocks", actual_val
    )
    baseline = DriftBaseline(
        entries=[
            BaselineEntry(
                resource_address="aws_security_group.web",
                resource_type="aws_security_group",
                drift_type=DriftType.CHANGED,
                attribute_path="ingress.0.cidr_blocks",
                fingerprint=fp,
                last_known_value=actual_val,
            )
        ]
    )
    save_baseline(baseline, tmp_path / DEFAULT_BASELINE_FILENAME)

    item = DriftItem(
        resource_address="aws_security_group.web",
        resource_type="aws_security_group",
        drift_type=DriftType.CHANGED,
        severity=DriftSeverity.CRITICAL,
        attribute_diffs=[
            AttributeDiff(
                path="ingress.0.cidr_blocks",
                desired_value=["10.0.0.0/8"],
                actual_value=actual_val,
            )
        ],
    )
    scan_res = _make_dummy_result([item])

    summary_file = tmp_path / "step_summary.md"
    with patch("driftsentry.cli.check.run_scan_pipeline", return_value=scan_res):
        res = runner.invoke(
            app,
            [
                "check",
                "--state-file",
                "dummy.tfstate",
                "--fail-on",
                "critical",
                "--github-step-summary",
                str(summary_file),
            ],
        )
        assert res.exit_code == 0
        assert "CI Check Passed" in res.stdout
        assert "All detected drift (1 items) is acknowledged in baseline ledger" in res.stdout

        # Verify step summary file content
        assert summary_file.exists()
        summary_text = summary_file.read_text(encoding="utf-8")
        assert "Acknowledged in Baseline" in summary_text
        assert "Clean (Baseline Active)" in summary_text


def test_triage_auto_acknowledge(tmp_path: Path, monkeypatch: Any) -> None:
    """Verify driftsentry triage --auto-acknowledge records items into baseline."""
    monkeypatch.chdir(tmp_path)

    item = DriftItem(
        resource_address="aws_security_group.web",
        resource_type="aws_security_group",
        drift_type=DriftType.CHANGED,
        attribute_diffs=[
            AttributeDiff(
                path="ingress.0.cidr_blocks",
                desired_value=["10.0.0.0/8"],
                actual_value=["1.2.3.4/32"],
            )
        ],
    )
    scan_res = _make_dummy_result([item])

    with patch("driftsentry.cli.triage.get_last_scan_result", return_value=scan_res):
        res = runner.invoke(
            app,
            ["triage", "--auto-acknowledge", "--non-interactive"],
        )
        assert res.exit_code == 0
        assert "Acknowledged (Baseline)" in res.stdout

    baseline_file = tmp_path / DEFAULT_BASELINE_FILENAME
    assert baseline_file.exists()
    loaded = load_baseline(baseline_file)
    assert loaded is not None
    assert len(loaded.entries) == 1
    assert loaded.entries[0].resource_address == "aws_security_group.web"
    assert loaded.entries[0].attribute_path == "ingress.0.cidr_blocks"
