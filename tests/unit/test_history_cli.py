"""Unit tests for the `history` CLI command group."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

import driftsentry.cli.history as history_module
from driftsentry.cli.main import app
from driftsentry.history.store import DriftStore
from tests.conftest import make_drift_item, make_scan_result, seed_history

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated_store(monkeypatch: pytest.MonkeyPatch, history_db_path: Path) -> None:
    """Redirect the CLI's `DriftStore()` calls to a temp database."""
    monkeypatch.setattr(
        history_module, "DriftStore", lambda *a, **kw: DriftStore(db_path=history_db_path)
    )


@pytest.fixture(autouse=True)
def _wide_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Widen the Rich console so table columns aren't truncated in assertions."""
    monkeypatch.setenv("COLUMNS", "200")


def _get_snapshot(db_path: Path, scan_id: str) -> object | None:
    store = DriftStore(db_path=db_path)
    try:
        return store.get_snapshot(scan_id)
    finally:
        store.close()


def test_history_list_shows_scans(history_db_path: Path) -> None:
    seed_history(history_db_path, make_scan_result("scan-1", [make_drift_item("aws_instance.web")]))

    result = runner.invoke(app, ["history", "list", "--limit", "5"])
    assert result.exit_code == 0
    assert "scan-1"[:8] in result.stdout


def test_history_show_valid_scan_id(history_db_path: Path) -> None:
    seed_history(history_db_path, make_scan_result("scan-1", [make_drift_item("aws_instance.web")]))

    result = runner.invoke(app, ["history", "show", "scan-1"])
    assert result.exit_code == 0
    assert "aws_instance.web" in result.stdout


def test_history_show_invalid_scan_id() -> None:
    result = runner.invoke(app, ["history", "show", "does-not-exist"])
    assert result.exit_code == 1
    assert "No scan found" in result.stdout


def test_history_diff_reports_delta(history_db_path: Path) -> None:
    seed_history(
        history_db_path,
        make_scan_result("scan-1", [make_drift_item("aws_instance.web")]),
        make_scan_result(
            "scan-2",
            [make_drift_item("aws_instance.web"), make_drift_item("aws_instance.new")],
            timestamp=datetime.datetime.now() + datetime.timedelta(minutes=1),
        ),
    )

    result = runner.invoke(app, ["history", "diff"])
    assert result.exit_code == 0
    assert "aws_instance.new" in result.stdout
    assert "Summary:" in result.stdout


def test_history_offenders_shows_repeat_drift(history_db_path: Path) -> None:
    seed_history(
        history_db_path,
        make_scan_result("scan-1", [make_drift_item("aws_instance.web")]),
        make_scan_result(
            "scan-2",
            [make_drift_item("aws_instance.web")],
            timestamp=datetime.datetime.now() + datetime.timedelta(minutes=1),
        ),
    )

    result = runner.invoke(app, ["history", "offenders", "--min", "2"])
    assert result.exit_code == 0
    assert "aws_instance.web" in result.stdout


def test_history_prune_dry_run_does_not_delete(history_db_path: Path) -> None:
    seed_history(history_db_path, make_scan_result("scan-1", timestamp=datetime.datetime(2020, 1, 1)))

    result = runner.invoke(app, ["history", "prune", "--before", "2025-01-01"])
    assert result.exit_code == 0
    assert "Dry run" in result.stdout
    assert _get_snapshot(history_db_path, "scan-1") is not None


def test_history_prune_confirmed_deletes(history_db_path: Path) -> None:
    seed_history(history_db_path, make_scan_result("scan-1", timestamp=datetime.datetime(2020, 1, 1)))

    result = runner.invoke(app, ["history", "prune", "--before", "2025-01-01", "--confirm"])
    assert result.exit_code == 0
    assert "Deleted 1" in result.stdout
    assert _get_snapshot(history_db_path, "scan-1") is None
