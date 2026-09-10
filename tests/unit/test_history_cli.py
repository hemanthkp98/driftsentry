"""Unit tests for the `history` CLI command group."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from driftsentry.cli.main import app
from driftsentry.core.models import (
    DriftItem,
    DriftResult,
    DriftSeverity,
    DriftType,
    StateBackendType,
)
from driftsentry.history.store import DriftStore

runner = CliRunner()


def _make_result(scan_id: str, timestamp: datetime.datetime, addresses: list[str]) -> DriftResult:
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
        scan_id=scan_id,
        timestamp=timestamp,
        provider="aws",
        state_backend=StateBackendType.LOCAL,
        state_source="test.tfstate",
        total_resources=10,
        drift_items=items,
        duration_seconds=1.5,
    )


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "history.db"


@pytest.fixture
def config_path(tmp_path: Path, db_path: Path) -> str:
    config_file = tmp_path / ".driftsentry.yaml"
    config_file.write_text(yaml.dump({"history": {"db_path": str(db_path)}}))
    return str(config_file)


def _populate(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        store.save(
            _make_result("scan11111", datetime.datetime(2026, 1, 1, 10, 0, 0), ["aws_instance.a"])
        )
        store.save(
            _make_result(
                "scan22222",
                datetime.datetime(2026, 1, 2, 10, 0, 0),
                ["aws_instance.a", "aws_instance.b"],
            )
        )
    finally:
        store.close()


# ─── history list ────────────────────────────────────────────────


def test_history_list_empty(config_path: str) -> None:
    result = runner.invoke(app, ["history", "list", "--config", config_path])
    assert result.exit_code == 0
    assert "No scan history found" in result.stdout


def test_history_list_shows_scans(db_path: Path, config_path: str) -> None:
    _populate(db_path)

    result = runner.invoke(app, ["history", "list", "--config", config_path])

    assert result.exit_code == 0
    assert "scan1111" in result.stdout
    assert "scan2222" in result.stdout
    assert "Scan History" in result.stdout


def test_history_list_respects_limit(db_path: Path, config_path: str) -> None:
    _populate(db_path)

    result = runner.invoke(app, ["history", "list", "--limit", "1", "--config", config_path])

    assert result.exit_code == 0
    assert "scan2222" in result.stdout
    assert "scan1111" not in result.stdout


def test_history_list_since_filter_excludes_older_scans(db_path: Path, config_path: str) -> None:
    _populate(db_path)

    result = runner.invoke(
        app, ["history", "list", "--since", "2026-01-02", "--config", config_path]
    )

    assert result.exit_code == 0
    assert "scan2222" in result.stdout
    assert "scan1111" not in result.stdout


def test_history_list_invalid_date_errors(config_path: str) -> None:
    result = runner.invoke(
        app, ["history", "list", "--since", "not-a-date", "--config", config_path]
    )

    assert result.exit_code == 1
    assert "Invalid date" in result.stdout


# ─── history show ────────────────────────────────────────────────


def test_history_show_valid_full_scan_id(db_path: Path, config_path: str) -> None:
    _populate(db_path)

    result = runner.invoke(app, ["history", "show", "scan22222", "--config", config_path])

    assert result.exit_code == 0
    assert "aws_instance.a" in result.stdout
    assert "aws_instance.b" in result.stdout


def test_history_show_accepts_partial_prefix(db_path: Path, config_path: str) -> None:
    _populate(db_path)

    result = runner.invoke(app, ["history", "show", "scan2222", "--config", config_path])

    assert result.exit_code == 0
    assert "aws_instance.a" in result.stdout
    assert "aws_instance.b" in result.stdout


def test_history_show_invalid_scan_id(db_path: Path, config_path: str) -> None:
    _populate(db_path)

    result = runner.invoke(app, ["history", "show", "does-not-exist", "--config", config_path])

    assert result.exit_code == 1
    assert "No scan found matching" in result.stdout


# ─── history diff ────────────────────────────────────────────────


def test_history_diff_reports_regression(db_path: Path, config_path: str) -> None:
    _populate(db_path)

    result = runner.invoke(app, ["history", "diff", "--config", config_path])

    assert result.exit_code == 0
    assert "aws_instance.b" in result.stdout
    assert "Summary:" in result.stdout
    assert "1 new" in result.stdout
    assert "1 recurring" in result.stdout


def test_history_diff_no_history(config_path: str) -> None:
    result = runner.invoke(app, ["history", "diff", "--config", config_path])

    assert result.exit_code == 0
    assert "No scan history found" in result.stdout


def test_history_diff_explicit_scan_id(db_path: Path, config_path: str) -> None:
    _populate(db_path)

    result = runner.invoke(
        app, ["history", "diff", "--scan-id", "scan1111", "--config", config_path]
    )

    assert result.exit_code == 0
    assert "Summary:" in result.stdout


# ─── history offenders ───────────────────────────────────────────


def test_history_offenders_lists_chronic_resources(db_path: Path, config_path: str) -> None:
    _populate(db_path)

    result = runner.invoke(app, ["history", "offenders", "--min", "2", "--config", config_path])

    assert result.exit_code == 0
    assert "aws_instance.a" in result.stdout
    assert "aws_instance.b" not in result.stdout


def test_history_offenders_empty(config_path: str) -> None:
    result = runner.invoke(app, ["history", "offenders", "--config", config_path])

    assert result.exit_code == 0
    assert "No chronic offenders found" in result.stdout


# ─── history prune ───────────────────────────────────────────────


def test_history_prune_dry_run_does_not_delete(db_path: Path, config_path: str) -> None:
    _populate(db_path)

    result = runner.invoke(
        app, ["history", "prune", "--before", "2026-01-02", "--config", config_path]
    )

    assert result.exit_code == 0
    assert "Dry run" in result.stdout
    assert "1 scan(s)" in result.stdout

    store = DriftStore(db_path=db_path)
    try:
        assert len(store.list_snapshots(limit=50)) == 2
    finally:
        store.close()


def test_history_prune_confirmed_deletes(db_path: Path, config_path: str) -> None:
    _populate(db_path)

    result = runner.invoke(
        app,
        ["history", "prune", "--before", "2026-01-02", "--confirm", "--config", config_path],
    )

    assert result.exit_code == 0
    assert "Deleted 1" in result.stdout

    store = DriftStore(db_path=db_path)
    try:
        remaining = store.list_snapshots(limit=50)
        assert [s.scan_id for s in remaining] == ["scan22222"]
    finally:
        store.close()
