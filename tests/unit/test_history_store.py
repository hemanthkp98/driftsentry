"""Unit tests for the SQLite-backed drift history store."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from driftsentry.core.models import (
    DriftAttribution,
    DriftItem,
    DriftResult,
    DriftSeverity,
    DriftType,
    IaCTool,
    StateBackendType,
)
from driftsentry.history.store import DriftStore, HistoryStoreError


def _make_drift_item(
    address: str = "aws_security_group.web",
    drift_type: DriftType = DriftType.CHANGED,
    severity: DriftSeverity = DriftSeverity.CRITICAL,
    with_attribution: bool = True,
) -> DriftItem:
    return DriftItem(
        resource_address=address,
        resource_type="aws_security_group",
        resource_id="sg-0abc123",
        drift_type=drift_type,
        severity=severity,
        account_id="111122223333",
        region="us-east-1",
        attribution=(
            DriftAttribution(
                principal="arn:aws:iam::111122223333:user/alice",
                event_name="ModifySecurityGroupRules",
                event_time=datetime(2026, 9, 1, 12, 0, 0),
                is_console_change=True,
            )
            if with_attribution
            else None
        ),
    )


def _make_result(
    scan_id: str = "scan-1",
    timestamp: datetime | None = None,
    drift_items: list[DriftItem] | None = None,
) -> DriftResult:
    return DriftResult(
        scan_id=scan_id,
        timestamp=timestamp or datetime(2026, 9, 1, 12, 0, 0),
        iac_tool=IaCTool.TERRAFORM,
        provider="aws",
        region="us-east-1",
        regions=["us-east-1", "us-west-2"],
        accounts=["111122223333"],
        state_backend=StateBackendType.LOCAL,
        state_source="terraform.tfstate",
        total_resources=10,
        total_cloud_resources=12,
        drift_items=drift_items if drift_items is not None else [_make_drift_item()],
        duration_seconds=2.5,
        errors=["warning: rate limited"],
    )


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "history.db"


@pytest.fixture
def store(db_path: Path) -> Iterator[DriftStore]:
    s = DriftStore(db_path=db_path)
    yield s
    s.close()


def test_instantiation_has_no_side_effects_on_real_filesystem(tmp_path: Path) -> None:
    custom_path = tmp_path / "nested" / "custom.db"
    store = DriftStore(db_path=custom_path)
    try:
        assert custom_path.exists()
    finally:
        store.close()


def test_schema_created_on_fresh_database(db_path: Path, store: DriftStore) -> None:
    conn = sqlite3.connect(str(db_path))
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    conn.close()
    assert "scan_snapshots" in tables
    assert "drift_item_snapshots" in tables


def test_save_and_get_snapshot_round_trip(store: DriftStore) -> None:
    result = _make_result()
    saved = store.save(result)

    assert saved.scan_id == "scan-1"
    assert saved.total_drifted == 1
    assert saved.critical_count == 1

    fetched = store.get_snapshot("scan-1")
    assert fetched is not None
    assert fetched.scan_id == result.scan_id
    assert fetched.timestamp == result.timestamp
    assert fetched.total_resources == result.total_resources
    assert fetched.total_drifted == result.total_drifted
    assert fetched.changed_count == result.changed_count
    assert fetched.deleted_count == result.deleted_count
    assert fetched.unmanaged_count == result.unmanaged_count
    assert fetched.critical_count == result.critical_count
    assert fetched.duration_seconds == result.duration_seconds
    assert fetched.state_source == result.state_source
    assert fetched.regions == result.regions
    assert fetched.accounts == result.accounts
    assert fetched.errors_count == len(result.errors)


def test_get_snapshot_missing_returns_none(store: DriftStore) -> None:
    assert store.get_snapshot("does-not-exist") is None


def test_get_latest_returns_most_recent_scan(store: DriftStore) -> None:
    store.save(_make_result(scan_id="scan-1", timestamp=datetime(2026, 9, 1, 12, 0, 0)))
    store.save(_make_result(scan_id="scan-2", timestamp=datetime(2026, 9, 2, 12, 0, 0)))
    store.save(_make_result(scan_id="scan-3", timestamp=datetime(2026, 9, 1, 18, 0, 0)))

    latest = store.get_latest()
    assert latest is not None
    assert latest.scan_id == "scan-2"


def test_get_drift_items_round_trip(store: DriftStore) -> None:
    item = _make_drift_item()
    result = _make_result(scan_id="scan-1", drift_items=[item])
    store.save(result)

    items = store.get_drift_items("scan-1")
    assert len(items) == 1

    fetched = items[0]
    assert fetched.scan_id == "scan-1"
    assert fetched.resource_address == item.resource_address
    assert fetched.resource_type == item.resource_type
    assert fetched.resource_id == item.resource_id
    assert fetched.drift_type == item.drift_type
    assert fetched.severity == item.severity
    assert fetched.account_id == item.account_id
    assert fetched.region == item.region
    assert item.attribution is not None
    assert fetched.attribution_principal == item.attribution.principal
    assert fetched.attribution_event_time == item.attribution.event_time


def test_get_drift_items_without_attribution(store: DriftStore) -> None:
    item = _make_drift_item(with_attribution=False)
    store.save(_make_result(scan_id="scan-1", drift_items=[item]))

    items = store.get_drift_items("scan-1")
    assert len(items) == 1
    assert items[0].attribution_principal is None
    assert items[0].attribution_event_time is None


def test_save_replaces_existing_scan_and_its_items(store: DriftStore) -> None:
    first = _make_result(scan_id="scan-1", drift_items=[_make_drift_item("aws_instance.web")])
    store.save(first)

    second = _make_result(
        scan_id="scan-1",
        drift_items=[
            _make_drift_item("aws_instance.web"),
            _make_drift_item("aws_s3_bucket.logs"),
        ],
    )
    store.save(second)

    items = store.get_drift_items("scan-1")
    assert len(items) == 2
    snapshot = store.get_snapshot("scan-1")
    assert snapshot is not None
    assert snapshot.total_drifted == 2


def test_list_snapshots_time_range_filtering(store: DriftStore) -> None:
    store.save(_make_result(scan_id="old", timestamp=datetime(2026, 8, 1, 0, 0, 0)))
    store.save(_make_result(scan_id="mid", timestamp=datetime(2026, 9, 1, 0, 0, 0)))
    store.save(_make_result(scan_id="new", timestamp=datetime(2026, 9, 10, 0, 0, 0)))

    all_snapshots = store.list_snapshots(limit=50)
    assert [s.scan_id for s in all_snapshots] == ["new", "mid", "old"]

    since_filtered = store.list_snapshots(since=datetime(2026, 8, 15, 0, 0, 0))
    assert [s.scan_id for s in since_filtered] == ["new", "mid"]

    before_filtered = store.list_snapshots(before=datetime(2026, 9, 5, 0, 0, 0))
    assert [s.scan_id for s in before_filtered] == ["mid", "old"]

    ranged = store.list_snapshots(
        since=datetime(2026, 8, 15, 0, 0, 0), before=datetime(2026, 9, 5, 0, 0, 0)
    )
    assert [s.scan_id for s in ranged] == ["mid"]


def test_list_snapshots_respects_limit(store: DriftStore) -> None:
    for i in range(5):
        store.save(
            _make_result(
                scan_id=f"scan-{i}", timestamp=datetime(2026, 9, 1, 0, 0, 0) + timedelta(hours=i)
            )
        )
    limited = store.list_snapshots(limit=2)
    assert len(limited) == 2
    assert [s.scan_id for s in limited] == ["scan-4", "scan-3"]


def test_get_resource_history_across_multiple_scans(store: DriftStore) -> None:
    address = "aws_security_group.web"
    store.save(
        _make_result(
            scan_id="scan-1",
            timestamp=datetime(2026, 9, 1, 0, 0, 0),
            drift_items=[_make_drift_item(address, severity=DriftSeverity.LOW)],
        )
    )
    store.save(
        _make_result(
            scan_id="scan-2",
            timestamp=datetime(2026, 9, 2, 0, 0, 0),
            drift_items=[_make_drift_item(address, severity=DriftSeverity.CRITICAL)],
        )
    )
    store.save(
        _make_result(
            scan_id="scan-3",
            timestamp=datetime(2026, 9, 3, 0, 0, 0),
            drift_items=[_make_drift_item("aws_instance.other")],
        )
    )

    history = store.get_resource_history(address)
    assert [h.scan_id for h in history] == ["scan-2", "scan-1"]
    assert history[0].severity == DriftSeverity.CRITICAL
    assert history[1].severity == DriftSeverity.LOW


def test_get_resource_history_respects_limit(store: DriftStore) -> None:
    address = "aws_security_group.web"
    for i in range(5):
        store.save(
            _make_result(
                scan_id=f"scan-{i}",
                timestamp=datetime(2026, 9, 1, 0, 0, 0) + timedelta(hours=i),
                drift_items=[_make_drift_item(address)],
            )
        )
    history = store.get_resource_history(address, limit=3)
    assert len(history) == 3
    assert [h.scan_id for h in history] == ["scan-4", "scan-3", "scan-2"]


def test_delete_before_prunes_old_scans(store: DriftStore) -> None:
    store.save(_make_result(scan_id="old", timestamp=datetime(2026, 6, 1, 0, 0, 0)))
    store.save(_make_result(scan_id="new", timestamp=datetime(2026, 9, 1, 0, 0, 0)))

    deleted = store.delete_before(datetime(2026, 8, 1, 0, 0, 0))
    assert deleted == 1

    assert store.get_snapshot("old") is None
    assert store.get_snapshot("new") is not None
    # Drift items cascade-delete with their parent scan snapshot.
    assert store.get_drift_items("old") == []


def test_concurrent_store_instances_share_db(db_path: Path) -> None:
    writer = DriftStore(db_path=db_path)
    reader = DriftStore(db_path=db_path)
    try:
        writer.save(_make_result(scan_id="scan-1"))
        fetched = reader.get_snapshot("scan-1")
        assert fetched is not None
        assert fetched.scan_id == "scan-1"

        reader.save(_make_result(scan_id="scan-2", timestamp=datetime(2026, 9, 2, 0, 0, 0)))
        assert writer.get_snapshot("scan-2") is not None
    finally:
        writer.close()
        reader.close()


def test_corrupted_database_file_raises_history_store_error(tmp_path: Path) -> None:
    bad_db = tmp_path / "corrupted.db"
    bad_db.write_bytes(b"not a valid sqlite database")

    with pytest.raises(HistoryStoreError):
        DriftStore(db_path=bad_db)


def test_missing_database_file_is_created_automatically(tmp_path: Path) -> None:
    missing_path = tmp_path / "does" / "not" / "exist" / "history.db"
    assert not missing_path.exists()

    store = DriftStore(db_path=missing_path)
    try:
        assert missing_path.exists()
        assert store.get_latest() is None
    finally:
        store.close()


def test_default_db_path_used_when_none_given(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from driftsentry.history import store as store_module

    monkeypatch.setattr(store_module, "DEFAULT_DB_PATH", tmp_path / ".driftsentry" / "history.db")
    store = DriftStore()
    try:
        assert (tmp_path / ".driftsentry" / "history.db").exists()
    finally:
        store.close()
