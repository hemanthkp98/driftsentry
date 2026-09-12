"""Unit tests for the `monitor` CLI command."""

from __future__ import annotations

import datetime
import os
import signal
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from typer.testing import CliRunner

import driftsentry.cli.monitor as monitor_module
from driftsentry.cli.main import app
from driftsentry.core.config import DriftSentryConfig
from driftsentry.core.models import (
    DriftItem,
    DriftResult,
    DriftSeverity,
    DriftType,
    StateBackendType,
)
from driftsentry.history.models import DriftDelta, DriftDeltaItem, RegressionReport

runner = CliRunner()


def _make_result(addresses: list[str]) -> DriftResult:
    items = [
        DriftItem(
            resource_address=address,
            resource_type="aws_instance",
            drift_type=DriftType.CHANGED,
            severity=DriftSeverity.MEDIUM,
        )
        for address in addresses
    ]
    return DriftResult(
        scan_id="scan1",
        timestamp=datetime.datetime(2026, 1, 1, 10, 0, 0),
        provider="aws",
        state_backend=StateBackendType.LOCAL,
        state_source="test.tfstate",
        total_resources=10,
        drift_items=items,
        duration_seconds=1.5,
    )


def _make_delta_item(address: str, delta: DriftDelta) -> DriftDeltaItem:
    return DriftDeltaItem(
        resource_address=address,
        resource_type="aws_instance",
        drift_type=DriftType.CHANGED,
        severity=DriftSeverity.MEDIUM,
        delta=delta,
    )


@pytest.fixture
def config_path(tmp_path: Path) -> str:
    config_file = tmp_path / ".driftsentry.yaml"
    config_file.write_text(yaml.dump({}))
    return str(config_file)


# ─── --max-scans / --once ────────────────────────────────────────


def test_monitor_runs_exactly_max_scans_then_exits(
    monkeypatch: pytest.MonkeyPatch, config_path: str
) -> None:
    result = _make_result(["aws_instance.a"])
    scan_mock = MagicMock(return_value=(result, None))
    monkeypatch.setattr(monitor_module, "run_scan_pipeline", scan_mock)
    monkeypatch.setattr(monitor_module, "_sleep_with_countdown", lambda *a, **k: None)

    cli_result = runner.invoke(
        app,
        ["monitor", "--max-scans", "3", "--interval", "5", "--config", config_path],
    )

    assert cli_result.exit_code == 0
    assert scan_mock.call_count == 3
    assert "Monitor complete (3/3 scans)" in cli_result.stdout


def test_monitor_once_flag_runs_single_scan_and_ignores_max_scans(
    monkeypatch: pytest.MonkeyPatch, config_path: str
) -> None:
    result = _make_result(["aws_instance.a"])
    scan_mock = MagicMock(return_value=(result, None))
    monkeypatch.setattr(monitor_module, "run_scan_pipeline", scan_mock)
    monkeypatch.setattr(monitor_module, "_sleep_with_countdown", lambda *a, **k: None)

    cli_result = runner.invoke(
        app,
        ["monitor", "--once", "--max-scans", "5", "--config", config_path],
    )

    assert cli_result.exit_code == 0
    assert scan_mock.call_count == 1
    assert "Monitor complete (1/1 scans)" in cli_result.stdout


def test_monitor_rejects_interval_below_minimum(config_path: str) -> None:
    cli_result = runner.invoke(app, ["monitor", "--interval", "1", "--config", config_path])

    assert cli_result.exit_code == 1
    assert "--interval must be at least" in cli_result.stdout


# ─── graceful shutdown ────────────────────────────────────────────


def test_monitor_stops_early_on_sigint(monkeypatch: pytest.MonkeyPatch, config_path: str) -> None:
    result = _make_result(["aws_instance.a"])

    def _scan_then_interrupt(*args: object, **kwargs: object) -> tuple[DriftResult, None]:
        os.kill(os.getpid(), signal.SIGINT)
        return result, None

    scan_mock = MagicMock(side_effect=_scan_then_interrupt)
    monkeypatch.setattr(monitor_module, "run_scan_pipeline", scan_mock)
    monkeypatch.setattr(monitor_module, "_sleep_with_countdown", lambda *a, **k: None)

    cli_result = runner.invoke(app, ["monitor", "--config", config_path])

    assert cli_result.exit_code == 0
    assert scan_mock.call_count == 1
    assert "Shutdown requested" in cli_result.stdout
    assert "Monitor complete (1/∞ scans)" in cli_result.stdout


# ─── smart alerting ───────────────────────────────────────────────


def test_smart_alerting_skips_recurring_items() -> None:
    result = _make_result(["aws_instance.a"])
    report = RegressionReport(
        current_scan_id="scan1",
        comparison_scan_id="scan0",
        items=[_make_delta_item("aws_instance.a", DriftDelta.RECURRING)],
    )
    notifier = MagicMock()

    monitor_module._send_smart_alert(notifier, result, report)

    notifier.notify.assert_not_called()


def test_smart_alerting_sends_for_new_and_regression_items() -> None:
    result = _make_result(["aws_instance.a", "aws_instance.b", "aws_instance.c"])
    report = RegressionReport(
        current_scan_id="scan1",
        comparison_scan_id="scan0",
        items=[
            _make_delta_item("aws_instance.a", DriftDelta.NEW),
            _make_delta_item("aws_instance.b", DriftDelta.REGRESSION),
            _make_delta_item("aws_instance.c", DriftDelta.RECURRING),
        ],
    )
    notifier = MagicMock()
    notifier.notify.return_value = True

    monitor_module._send_smart_alert(notifier, result, report)

    notifier.notify.assert_called_once()
    alerted_result = notifier.notify.call_args[0][0]
    alerted_addresses = {item.resource_address for item in alerted_result.drift_items}
    assert alerted_addresses == {"aws_instance.a", "aws_instance.b"}


def test_smart_alerting_includes_worsened_items() -> None:
    result = _make_result(["aws_instance.a"])
    report = RegressionReport(
        current_scan_id="scan1",
        comparison_scan_id="scan0",
        items=[_make_delta_item("aws_instance.a", DriftDelta.WORSENED)],
    )
    notifier = MagicMock()
    notifier.notify.return_value = True

    monitor_module._send_smart_alert(notifier, result, report)

    notifier.notify.assert_called_once()


def test_smart_alerting_no_notifier_configured_is_noop() -> None:
    result = _make_result(["aws_instance.a"])
    report = RegressionReport(
        current_scan_id="scan1",
        comparison_scan_id="scan0",
        items=[_make_delta_item("aws_instance.a", DriftDelta.NEW)],
    )

    # Should not raise when no Slack webhook is configured.
    monitor_module._send_smart_alert(None, result, report)


@patch("driftsentry.cli.monitor.load_config")
@patch("driftsentry.cli.monitor._run_one_scan")
@patch("driftsentry.cli.monitor._sleep_with_countdown")
def test_monitor_honors_config_interval(
    mock_sleep: MagicMock, mock_run: MagicMock, mock_load: MagicMock
) -> None:
    config = DriftSentryConfig()
    config.monitor.interval_minutes = 15
    config.monitor.max_scans = 2
    mock_load.return_value = config

    result = runner.invoke(app, ["monitor"])

    assert result.exit_code == 0
    # It should sleep for 15 minutes = 900 seconds
    assert mock_sleep.call_count == 1
    mock_sleep.assert_called_with(900, mock_sleep.call_args[0][1])
    assert mock_run.call_count == 2


@patch("driftsentry.cli.monitor.load_config")
@patch("driftsentry.cli.monitor._run_one_scan")
@patch("driftsentry.cli.monitor._sleep_with_countdown")
def test_monitor_honors_cli_interval_override(
    mock_sleep: MagicMock, mock_run: MagicMock, mock_load: MagicMock
) -> None:
    config = DriftSentryConfig()
    config.monitor.interval_minutes = 15
    mock_load.return_value = config

    result = runner.invoke(app, ["monitor", "--interval", "10", "--max-scans", "2"])

    assert result.exit_code == 0
    # It should sleep for 10 minutes = 600 seconds
    assert mock_sleep.call_count == 1
    mock_sleep.assert_called_with(600, mock_sleep.call_args[0][1])
