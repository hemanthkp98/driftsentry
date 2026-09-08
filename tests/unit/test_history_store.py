"""Unit tests for the SQLite-backed drift history store."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from driftsentry.core.models import (
    AttributeDiff,
    DriftAttribution,
    DriftItem,
    DriftResult,
    DriftSeverity,
    DriftType,
    StateBackendType,
)
from driftsentry.history.store import DriftStore, DriftStoreError


def _make_result(
    scan_id: str = "scan-1",
    timestamp: datetime.datetime | None = None,
    resource_address: str = "aws_security_group.web",
) -> DriftResult:
    item = DriftItem(
        resource_address=resource_address,
        resource_type="aws_security_group",
        resource_id="sg-12345",
        drift_type=DriftType.CHANGED,
        severity=DriftSeverity.CRITICAL,
        attribute_diffs=[
            AttributeDiff(
                path="ingress.0.cidr_blocks",
                desired_value=["10.0.0.0/8"],
                actual_value=["0.0.0.0/0"],
            )
        ],
        attribution=DriftAttribution(
            principal="arn:aws:iam::123456789012:user/alice",
            event_time=datetime.datetime(2026, 1, 1, 12, 0, 0),
        ),
        account_id="123456789012",
        region="us-east-1",
    )
    return DriftResult(
        scan_id=scan_id,
        timestamp=timestamp or datetime.datetime(2026, 1, 1, 12, 0, 0),
        provider="aws",
        regions=["us-east-1"],
        accounts=["123456789012"],
        state_backend=StateBackendType.LOCAL,
        state_source="test.tfstate",
        total_resources=10,
        drift_items=[item],
        duration_seconds=1.5,
        errors=["a warning"],
    )


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "history.db"


def test_schema_creation_on_fresh_database(db_path: Path) -> None:
    assert not db_path.exists()
    store = DriftStore(db_path=db_path)
    try:
        assert db_path.exists()
        tables = {
            row[0]
            for row in store._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {"schema_version", "scan_snapshots", "drift_item_snapshots"} <= tables
        version_row = store._conn.execute("SELECT version FROM schema_version").fetchone()
        assert version_row is not None
    finally:
        store.close()


def test_default_db_path_not_touched_by_temp_store(
    db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Sanity check: instantiating with an explicit path has no side effects
    # on the real filesystem default location.
    fake_home = db_path.parent / "fake_home"
    monkeypatch.setattr(
        "driftsentry.history.store.DEFAULT_DB_PATH", fake_home / ".driftsentry" / "history.db"
    )
    store = DriftStore(db_path=db_path)
    store.close()
    assert not fake_home.exists()


def test_save_and_get_snapshot_round_trip(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        result = _make_result()
        saved = store.save(result)

        assert saved.scan_id == "scan-1"
        assert saved.total_resources == 10
        assert saved.total_drifted == 1
        assert saved.changed_count == 1
        assert saved.deleted_count == 0
        assert saved.unmanaged_count == 0
        assert saved.critical_count == 1
        assert saved.duration_seconds == 1.5
        assert saved.state_source == "test.tfstate"
        assert saved.regions == ["us-east-1"]
        assert saved.accounts == ["123456789012"]
        assert saved.errors_count == 1

        fetched = store.get_snapshot("scan-1")
        assert fetched is not None
        assert fetched == saved
    finally:
        store.close()


def test_get_snapshot_missing_returns_none(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        assert store.get_snapshot("does-not-exist") is None
    finally:
        store.close()


def test_get_latest_returns_most_recent(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        store.save(_make_result(scan_id="scan-1", timestamp=datetime.datetime(2026, 1, 1)))
        store.save(_make_result(scan_id="scan-2", timestamp=datetime.datetime(2026, 1, 3)))
        store.save(_make_result(scan_id="scan-3", timestamp=datetime.datetime(2026, 1, 2)))

        latest = store.get_latest()
        assert latest is not None
        assert latest.scan_id == "scan-2"
    finally:
        store.close()


def test_get_latest_empty_store_returns_none(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        assert store.get_latest() is None
    finally:
        store.close()


def test_get_drift_items_for_scan(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        result = _make_result()
        store.save(result)

        items = store.get_drift_items("scan-1")
        assert len(items) == 1
        item = items[0]
        assert item.scan_id == "scan-1"
        assert item.resource_address == "aws_security_group.web"
        assert item.resource_type == "aws_security_group"
        assert item.resource_id == "sg-12345"
        assert item.drift_type == "changed"
        assert item.severity == "critical"
        assert item.account_id == "123456789012"
        assert item.region == "us-east-1"
        assert item.attribution_principal == "arn:aws:iam::123456789012:user/alice"
        assert item.attribution_event_time == datetime.datetime(2026, 1, 1, 12, 0, 0)
    finally:
        store.close()


def test_list_snapshots_time_range_filtering(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        store.save(_make_result(scan_id="scan-1", timestamp=datetime.datetime(2026, 1, 1)))
        store.save(_make_result(scan_id="scan-2", timestamp=datetime.datetime(2026, 1, 5)))
        store.save(_make_result(scan_id="scan-3", timestamp=datetime.datetime(2026, 1, 10)))

        all_snapshots = store.list_snapshots(limit=50)
        assert [s.scan_id for s in all_snapshots] == ["scan-3", "scan-2", "scan-1"]

        since_filtered = store.list_snapshots(since=datetime.datetime(2026, 1, 4))
        assert [s.scan_id for s in since_filtered] == ["scan-3", "scan-2"]

        before_filtered = store.list_snapshots(before=datetime.datetime(2026, 1, 6))
        assert [s.scan_id for s in before_filtered] == ["scan-2", "scan-1"]

        range_filtered = store.list_snapshots(
            since=datetime.datetime(2026, 1, 2), before=datetime.datetime(2026, 1, 9)
        )
        assert [s.scan_id for s in range_filtered] == ["scan-2"]

        limited = store.list_snapshots(limit=1)
        assert [s.scan_id for s in limited] == ["scan-3"]
    finally:
        store.close()


def test_get_resource_history_across_scans(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        store.save(
            _make_result(
                scan_id="scan-1",
                timestamp=datetime.datetime(2026, 1, 1),
                resource_address="aws_security_group.web",
            )
        )
        store.save(
            _make_result(
                scan_id="scan-2",
                timestamp=datetime.datetime(2026, 1, 2),
                resource_address="aws_instance.other",
            )
        )
        store.save(
            _make_result(
                scan_id="scan-3",
                timestamp=datetime.datetime(2026, 1, 3),
                resource_address="aws_security_group.web",
            )
        )

        history = store.get_resource_history("aws_security_group.web")
        assert [h.scan_id for h in history] == ["scan-3", "scan-1"]

        limited = store.get_resource_history("aws_security_group.web", limit=1)
        assert [h.scan_id for h in limited] == ["scan-3"]

        assert store.get_resource_history("does.not.exist") == []
    finally:
        store.close()


def test_delete_before_prunes_old_records(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        store.save(_make_result(scan_id="scan-1", timestamp=datetime.datetime(2026, 1, 1)))
        store.save(_make_result(scan_id="scan-2", timestamp=datetime.datetime(2026, 1, 5)))
        store.save(_make_result(scan_id="scan-3", timestamp=datetime.datetime(2026, 1, 10)))

        deleted = store.delete_before(datetime.datetime(2026, 1, 6))
        assert deleted == 2

        remaining = store.list_snapshots(limit=50)
        assert [s.scan_id for s in remaining] == ["scan-3"]

        # Drift items for pruned scans should be cascade-deleted.
        assert store.get_drift_items("scan-1") == []
    finally:
        store.close()


def test_concurrent_access_two_store_instances(db_path: Path) -> None:
    store_a = DriftStore(db_path=db_path)
    store_b = DriftStore(db_path=db_path)
    try:
        store_a.save(_make_result(scan_id="scan-1"))
        # Second connection to the same underlying database file should see it.
        fetched = store_b.get_snapshot("scan-1")
        assert fetched is not None
        assert fetched.scan_id == "scan-1"

        store_b.save(_make_result(scan_id="scan-2", timestamp=datetime.datetime(2026, 1, 2)))
        snapshots = store_a.list_snapshots(limit=50)
        assert {s.scan_id for s in snapshots} == {"scan-1", "scan-2"}
    finally:
        store_a.close()
        store_b.close()


def test_corrupted_database_file_raises_clear_error(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"this is not a valid sqlite database file")

    with pytest.raises(DriftStoreError):
        DriftStore(db_path=db_path)


def test_missing_database_file_is_created(tmp_path: Path) -> None:
    nested_path = tmp_path / "nested" / "dir" / "history.db"
    assert not nested_path.parent.exists()

    store = DriftStore(db_path=nested_path)
    try:
        assert nested_path.exists()
        assert store.get_latest() is None
    finally:
        store.close()


def test_save_overwrites_existing_scan_id(db_path: Path) -> None:
    store = DriftStore(db_path=db_path)
    try:
        store.save(_make_result(scan_id="scan-1", resource_address="aws_instance.a"))
        store.save(_make_result(scan_id="scan-1", resource_address="aws_instance.b"))

        items = store.get_drift_items("scan-1")
        assert len(items) == 1
        assert items[0].resource_address == "aws_instance.b"
    finally:
        store.close()
