"""Unit tests for the `monitor` CLI command."""

from __future__ import annotations

import datetime
import os
import signal
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

import driftsentry.cli.monitor as monitor_module
from driftsentry.cli.main import app
from driftsentry.core.config import DriftSentryConfig
from driftsentry.core.models import (
    DriftItem,
    DriftResult,
    DriftSeverity,
    DriftType,
    IaCTool,
    StateBackendType,
)
from driftsentry.history.store import DriftStore
from driftsentry.policy.engine import PolicyEvaluation

runner = CliRunner()


def _make_item(
    address: str,
    severity: DriftSeverity = DriftSeverity.MEDIUM,
    drift_type: DriftType = DriftType.CHANGED,
) -> DriftItem:
    return DriftItem(
        resource_address=address,
        resource_type="aws_instance",
        drift_type=drift_type,
        severity=severity,
    )


def _make_result(scan_id: str, items: list[DriftItem] | None = None) -> DriftResult:
    return DriftResult(
        scan_id=scan_id,
        timestamp=datetime.datetime.now(),
        iac_tool=IaCTool.TERRAFORM,
        provider="aws",
        state_backend=StateBackendType.LOCAL,
        state_source="terraform.tfstate",
        drift_items=items or [],
    )


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "history.db"


@pytest.fixture(autouse=True)
def _isolated_store(monkeypatch: pytest.MonkeyPatch, db_path: Path) -> None:
    """Redirect the CLI's `DriftStore()` calls to a temp database."""
    monkeypatch.setattr(monitor_module, "DriftStore", lambda *a, **kw: DriftStore(db_path=db_path))


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skip the real countdown sleep so tests run instantly."""
    monkeypatch.setattr(monitor_module, "_sleep_with_countdown", lambda *a, **kw: None)


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    cfg = tmp_path / ".driftsentry.yaml"
    cfg.write_text("state:\n  backend: local\n  path: dummy.tfstate\n")
    return cfg


@pytest.fixture
def config_file_with_slack(tmp_path: Path) -> Path:
    cfg = tmp_path / ".driftsentry.yaml"
    cfg.write_text(
        "state:\n"
        "  backend: local\n"
        "  path: dummy.tfstate\n"
        "notifications:\n"
        "  slack_webhook_url: https://hooks.slack.com/services/test\n"
    )
    return cfg


def test_monitor_help_lists_options() -> None:
    result = runner.invoke(app, ["monitor", "--help"])
    assert result.exit_code == 0
    assert "--interval" in result.stdout
    assert "--max-scans" in result.stdout
    assert "--once" in result.stdout


def test_monitor_rejects_interval_below_minimum(config_file: Path) -> None:
    result = runner.invoke(app, ["monitor", "--interval", "1", "--config", str(config_file)])
    assert result.exit_code == 1
    assert "at least" in result.stdout


def test_monitor_max_scans_runs_exactly_n_times(
    monkeypatch: pytest.MonkeyPatch, config_file: Path
) -> None:
    call_count = {"n": 0}

    def fake_run_scan(
        config: DriftSentryConfig, show_progress: bool = False
    ) -> tuple[DriftResult, PolicyEvaluation | None]:
        call_count["n"] += 1
        return _make_result(f"scan-{call_count['n']}"), None

    monkeypatch.setattr(monitor_module, "run_scan", fake_run_scan)

    result = runner.invoke(
        app,
        [
            "monitor",
            "--interval",
            "5",
            "--max-scans",
            "3",
            "--config",
            str(config_file),
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert call_count["n"] == 3
    assert "3/3 scans" in result.stdout


def test_monitor_once_flag_runs_single_scan(
    monkeypatch: pytest.MonkeyPatch, config_file: Path
) -> None:
    call_count = {"n": 0}

    def fake_run_scan(
        config: DriftSentryConfig, show_progress: bool = False
    ) -> tuple[DriftResult, PolicyEvaluation | None]:
        call_count["n"] += 1
        return _make_result(f"scan-{call_count['n']}"), None

    monkeypatch.setattr(monitor_module, "run_scan", fake_run_scan)

    result = runner.invoke(app, ["monitor", "--once", "--config", str(config_file)])
    assert result.exit_code == 0, result.stdout
    assert call_count["n"] == 1
    assert "1/1 scans" in result.stdout


def test_monitor_smart_alerting_skips_recurring(
    monkeypatch: pytest.MonkeyPatch, config_file_with_slack: Path, db_path: Path
) -> None:
    seed_store = DriftStore(db_path=db_path)
    try:
        seed_store.save(_make_result("scan-1", [_make_item("aws_instance.recurring")]))
    finally:
        seed_store.close()

    def fake_run_scan(
        config: DriftSentryConfig, show_progress: bool = False
    ) -> tuple[DriftResult, PolicyEvaluation | None]:
        return _make_result("scan-2", [_make_item("aws_instance.recurring")]), None

    monkeypatch.setattr(monitor_module, "run_scan", fake_run_scan)

    notify_calls: list[DriftResult] = []

    def fake_notify(self: object, result: DriftResult) -> bool:
        notify_calls.append(result)
        return True

    monkeypatch.setattr(monitor_module.SlackNotifier, "notify", fake_notify)

    result = runner.invoke(app, ["monitor", "--once", "--config", str(config_file_with_slack)])
    assert result.exit_code == 0, result.stdout
    assert not notify_calls
    assert "Slack alert" not in result.stdout


def test_monitor_smart_alerting_sends_for_new_and_regression(
    monkeypatch: pytest.MonkeyPatch, config_file_with_slack: Path, db_path: Path
) -> None:
    seed_store = DriftStore(db_path=db_path)
    try:
        seed_store.save(_make_result("scan-1", [_make_item("aws_instance.recurring")]))
    finally:
        seed_store.close()

    def fake_run_scan(
        config: DriftSentryConfig, show_progress: bool = False
    ) -> tuple[DriftResult, PolicyEvaluation | None]:
        return (
            _make_result(
                "scan-2",
                [
                    _make_item("aws_instance.recurring"),
                    _make_item("aws_instance.brand_new"),
                ],
            ),
            None,
        )

    monkeypatch.setattr(monitor_module, "run_scan", fake_run_scan)

    notify_calls: list[DriftResult] = []

    def fake_notify(self: object, result: DriftResult) -> bool:
        notify_calls.append(result)
        return True

    monkeypatch.setattr(monitor_module.SlackNotifier, "notify", fake_notify)

    result = runner.invoke(app, ["monitor", "--once", "--config", str(config_file_with_slack)])
    assert result.exit_code == 0, result.stdout
    assert len(notify_calls) == 1
    alerted_addresses = {item.resource_address for item in notify_calls[0].drift_items}
    assert alerted_addresses == {"aws_instance.brand_new"}
    assert "Slack alert sent for 1" in result.stdout


def test_monitor_graceful_shutdown_stops_loop(
    monkeypatch: pytest.MonkeyPatch, config_file: Path
) -> None:
    call_count = {"n": 0}

    def fake_run_scan(
        config: DriftSentryConfig, show_progress: bool = False
    ) -> tuple[DriftResult, PolicyEvaluation | None]:
        call_count["n"] += 1
        return _make_result(f"scan-{call_count['n']}"), None

    monkeypatch.setattr(monitor_module, "run_scan", fake_run_scan)

    def sleep_then_shutdown(total_seconds: float, should_stop: Callable[[], bool]) -> None:
        os.kill(os.getpid(), signal.SIGINT)

    monkeypatch.setattr(monitor_module, "_sleep_with_countdown", sleep_then_shutdown)

    result = runner.invoke(app, ["monitor", "--interval", "5", "--config", str(config_file)])
    assert result.exit_code == 0, result.stdout
    assert call_count["n"] == 1
    assert "Shutdown requested" in result.stdout
    assert "1 scans" in result.stdout
