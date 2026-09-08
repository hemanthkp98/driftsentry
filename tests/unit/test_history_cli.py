"""Unit tests for the `history` CLI command group."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

import driftsentry.cli.history as history_module
from driftsentry.cli.main import app
from driftsentry.core.models import DriftItem, DriftResult, DriftSeverity, DriftType
from driftsentry.history.store import DriftStore

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


def _make_result(
    scan_id: str,
    items: list[DriftItem] | None = None,
    timestamp: datetime.datetime | None = None,
) -> DriftResult:
    return DriftResult(
        scan_id=scan_id,
        timestamp=timestamp or datetime.datetime.now(),
        iac_tool="terraform",
        provider="aws",
        state_backend="local",
        state_source="terraform.tfstate",
        drift_items=items or [],
    )


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "history.db"


@pytest.fixture(autouse=True)
def _isolated_store(monkeypatch: pytest.MonkeyPatch, db_path: Path):
    """Redirect the CLI's `DriftStore()` calls to a temp database."""
    monkeypatch.setattr(history_module, "DriftStore", lambda *a, **kw: DriftStore(db_path=db_path))


@pytest.fixture(autouse=True)
def _wide_terminal(monkeypatch: pytest.MonkeyPatch):
    """Widen the Rich console so table columns aren't truncated in assertions."""
    monkeypatch.setenv("COLUMNS", "200")


def test_history_help_lists_subcommands() -> None:
    result = runner.invoke(app, ["history", "--help"])
    assert result.exit_code == 0
    for name in ("list", "show", "diff", "offenders", "prune"):
        assert name in result.stdout


def test_history_list_empty() -> None:
    result = runner.invoke(app, ["history", "list"])
    assert result.exit_code == 0
    assert "No scan history found" in result.stdout


def test_history_list_shows_scans(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        store.save(_make_result("scan-1", [_make_item("aws_instance.web")]))
    finally:
        store.close()

    result = runner.invoke(app, ["history", "list", "--limit", "5"])
    assert result.exit_code == 0
    assert "scan-1"[:8] in result.stdout


def test_history_list_invalid_date() -> None:
    result = runner.invoke(app, ["history", "list", "--since", "not-a-date"])
    assert result.exit_code == 1
    assert "Invalid date" in result.stdout


def test_history_show_valid_scan_id(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        store.save(_make_result("scan-1", [_make_item("aws_instance.web")]))
    finally:
        store.close()

    result = runner.invoke(app, ["history", "show", "scan-1"])
    assert result.exit_code == 0
    assert "aws_instance.web" in result.stdout


def test_history_show_partial_prefix(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        store.save(_make_result("abcdef123456", [_make_item("aws_instance.web")]))
    finally:
        store.close()

    result = runner.invoke(app, ["history", "show", "abcdef12"])
    assert result.exit_code == 0
    assert "aws_instance.web" in result.stdout


def test_history_show_invalid_scan_id() -> None:
    result = runner.invoke(app, ["history", "show", "does-not-exist"])
    assert result.exit_code == 1
    assert "No scan found" in result.stdout


def test_history_diff_first_scan(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        store.save(_make_result("scan-1", [_make_item("aws_instance.web")]))
    finally:
        store.close()

    result = runner.invoke(app, ["history", "diff"])
    assert result.exit_code == 0
    assert "first scan" in result.stdout.lower()


def test_history_diff_reports_delta(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        store.save(_make_result("scan-1", [_make_item("aws_instance.web")]))
        store.save(
            _make_result(
                "scan-2",
                [_make_item("aws_instance.web"), _make_item("aws_instance.new")],
                timestamp=datetime.datetime.now() + datetime.timedelta(minutes=1),
            )
        )
    finally:
        store.close()

    result = runner.invoke(app, ["history", "diff"])
    assert result.exit_code == 0
    assert "aws_instance.new" in result.stdout
    assert "Summary:" in result.stdout


def test_history_offenders_empty() -> None:
    result = runner.invoke(app, ["history", "offenders"])
    assert result.exit_code == 0
    assert "No chronic offenders found" in result.stdout


def test_history_offenders_shows_repeat_drift(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        store.save(_make_result("scan-1", [_make_item("aws_instance.web")]))
        store.save(
            _make_result(
                "scan-2",
                [_make_item("aws_instance.web")],
                timestamp=datetime.datetime.now() + datetime.timedelta(minutes=1),
            )
        )
    finally:
        store.close()

    result = runner.invoke(app, ["history", "offenders", "--min", "2"])
    assert result.exit_code == 0
    assert "aws_instance.web" in result.stdout


def test_history_prune_dry_run_does_not_delete(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        store.save(_make_result("scan-1", timestamp=datetime.datetime(2020, 1, 1)))
    finally:
        store.close()

    result = runner.invoke(app, ["history", "prune", "--before", "2025-01-01"])
    assert result.exit_code == 0
    assert "Dry run" in result.stdout

    store = DriftStore(db_path=db_path)
    try:
        assert store.get_snapshot("scan-1") is not None
    finally:
        store.close()


def test_history_prune_confirmed_deletes(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        store.save(_make_result("scan-1", timestamp=datetime.datetime(2020, 1, 1)))
    finally:
        store.close()

    result = runner.invoke(app, ["history", "prune", "--before", "2025-01-01", "--confirm"])
    assert result.exit_code == 0
    assert "Deleted 1" in result.stdout

    store = DriftStore(db_path=db_path)
    try:
        assert store.get_snapshot("scan-1") is None
    finally:
        store.close()
