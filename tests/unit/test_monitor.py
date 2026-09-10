"""Unit tests for the `monitor` CLI command."""

from __future__ import annotations

import os
import signal
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

import driftsentry.cli.monitor as monitor_module
from conftest import make_drift_item, make_scan_result, seed_history
from driftsentry.cli.main import app
from driftsentry.core.config import DriftSentryConfig
from driftsentry.core.models import DriftResult
from driftsentry.history.store import DriftStore
from driftsentry.policy.engine import PolicyEvaluation

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated_store(monkeypatch: pytest.MonkeyPatch, history_db_path: Path) -> None:
    """Redirect the CLI's `DriftStore()` calls to a temp database."""
    monkeypatch.setattr(
        monitor_module, "DriftStore", lambda *a, **kw: DriftStore(db_path=history_db_path)
    )


def _counting_run_scan() -> tuple[
    Callable[..., tuple[DriftResult, PolicyEvaluation | None]], dict[str, int]
]:
    """Return a `run_scan` stub that counts calls and returns a fresh scan each time."""
    call_count = {"n": 0}

    def fake_run_scan(
        config: DriftSentryConfig, show_progress: bool = False
    ) -> tuple[DriftResult, PolicyEvaluation | None]:
        call_count["n"] += 1
        return make_scan_result(f"scan-{call_count['n']}"), None

    return fake_run_scan, call_count


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


def test_monitor_max_scans_runs_exactly_n_times(
    monkeypatch: pytest.MonkeyPatch, config_file: Path
) -> None:
    fake_run_scan, call_count = _counting_run_scan()
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
        return make_scan_result(f"scan-{call_count['n']}"), None

    monkeypatch.setattr(monitor_module, "run_scan", fake_run_scan)

    result = runner.invoke(app, ["monitor", "--once", "--config", str(config_file)])
    assert result.exit_code == 0, result.stdout
    assert call_count["n"] == 1
    assert "1/1 scans" in result.stdout


def test_monitor_smart_alerting_skips_recurring(
    monkeypatch: pytest.MonkeyPatch, config_file_with_slack: Path, history_db_path: Path
) -> None:
    seed_history(
        history_db_path, make_scan_result("scan-1", [make_drift_item("aws_instance.recurring")])
    )

    def fake_run_scan(
        config: DriftSentryConfig, show_progress: bool = False
    ) -> tuple[DriftResult, PolicyEvaluation | None]:
        return make_scan_result("scan-2", [make_drift_item("aws_instance.recurring")]), None

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
    monkeypatch: pytest.MonkeyPatch, config_file_with_slack: Path, history_db_path: Path
) -> None:
    seed_history(
        history_db_path, make_scan_result("scan-1", [make_drift_item("aws_instance.recurring")])
    )

    def fake_run_scan(
        config: DriftSentryConfig, show_progress: bool = False
    ) -> tuple[DriftResult, PolicyEvaluation | None]:
        return (
            make_scan_result(
                "scan-2",
                [
                    make_drift_item("aws_instance.recurring"),
                    make_drift_item("aws_instance.brand_new"),
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
        return make_scan_result(f"scan-{call_count['n']}"), None

    monkeypatch.setattr(monitor_module, "run_scan", fake_run_scan)

    def sleep_then_shutdown(total_seconds: float, should_stop: Callable[[], bool]) -> None:
        os.kill(os.getpid(), signal.SIGINT)

    monkeypatch.setattr(monitor_module, "_sleep_with_countdown", sleep_then_shutdown)

    result = runner.invoke(app, ["monitor", "--interval", "5", "--config", str(config_file)])
    assert result.exit_code == 0, result.stdout
    assert call_count["n"] == 1
    assert "Shutdown requested" in result.stdout
    assert "1 scans" in result.stdout
