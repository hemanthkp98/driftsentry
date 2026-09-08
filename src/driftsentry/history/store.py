"""SQLite-backed durable history store for drift scan results.

Persists every `DriftResult` as a normalized `ScanSnapshot` row plus one
`DriftItemSnapshot` row per drift item, so operational questions ("is
drift improving?", "which resources keep drifting?") can be answered by
querying history instead of relying on the last overwritten scan.
"""

from __future__ import annotations

import datetime
import json
import sqlite3
from pathlib import Path

from driftsentry.core.models import DriftResult, DriftSeverity, DriftType
from driftsentry.history.models import DriftItemSnapshot, ScanSnapshot

DEFAULT_DB_PATH = Path.home() / ".driftsentry" / "history.db"

_CREATE_SCAN_SNAPSHOTS_SQL = """
CREATE TABLE IF NOT EXISTS scan_snapshots (
    scan_id        TEXT PRIMARY KEY,
    timestamp      TEXT NOT NULL,
    total_resources    INTEGER NOT NULL DEFAULT 0,
    total_drifted      INTEGER NOT NULL DEFAULT 0,
    changed_count      INTEGER NOT NULL DEFAULT 0,
    deleted_count      INTEGER NOT NULL DEFAULT 0,
    unmanaged_count    INTEGER NOT NULL DEFAULT 0,
    critical_count     INTEGER NOT NULL DEFAULT 0,
    duration_seconds   REAL NOT NULL DEFAULT 0.0,
    state_source       TEXT NOT NULL DEFAULT '',
    regions            TEXT NOT NULL DEFAULT '[]',
    accounts           TEXT NOT NULL DEFAULT '[]',
    errors_count       INTEGER NOT NULL DEFAULT 0
)
"""

_CREATE_DRIFT_ITEM_SNAPSHOTS_SQL = """
CREATE TABLE IF NOT EXISTS drift_item_snapshots (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id               TEXT NOT NULL REFERENCES scan_snapshots(scan_id) ON DELETE CASCADE,
    resource_address      TEXT NOT NULL,
    resource_type         TEXT NOT NULL,
    resource_id           TEXT,
    drift_type            TEXT NOT NULL,
    severity              TEXT NOT NULL,
    account_id            TEXT,
    region                TEXT,
    attribution_principal TEXT,
    attribution_event_time TEXT
)
"""

_CREATE_INDEX_SCAN_ID_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_drift_items_scan_id ON drift_item_snapshots(scan_id)"
)
_CREATE_INDEX_RESOURCE_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_drift_items_resource ON drift_item_snapshots(resource_address)"
)


class HistoryStoreError(Exception):
    """Raised when the drift history database cannot be opened or read."""


def _row_to_scan_snapshot(row: sqlite3.Row) -> ScanSnapshot:
    return ScanSnapshot(
        scan_id=row["scan_id"],
        timestamp=datetime.datetime.fromisoformat(row["timestamp"]),
        total_resources=row["total_resources"],
        total_drifted=row["total_drifted"],
        changed_count=row["changed_count"],
        deleted_count=row["deleted_count"],
        unmanaged_count=row["unmanaged_count"],
        critical_count=row["critical_count"],
        duration_seconds=row["duration_seconds"],
        state_source=row["state_source"],
        regions=json.loads(row["regions"]),
        accounts=json.loads(row["accounts"]),
        errors_count=row["errors_count"],
    )


def _row_to_drift_item_snapshot(row: sqlite3.Row) -> DriftItemSnapshot:
    event_time = row["attribution_event_time"]
    return DriftItemSnapshot(
        scan_id=row["scan_id"],
        resource_address=row["resource_address"],
        resource_type=row["resource_type"],
        resource_id=row["resource_id"],
        drift_type=DriftType(row["drift_type"]),
        severity=DriftSeverity(row["severity"]),
        account_id=row["account_id"],
        region=row["region"],
        attribution_principal=row["attribution_principal"],
        attribution_event_time=datetime.datetime.fromisoformat(event_time) if event_time else None,
    )


class DriftStore:
    """Durable, queryable history of drift scan results, backed by SQLite."""

    def __init__(self, db_path: Path | None = None) -> None:
        """Open (and if needed, create) the drift history database.

        Args:
            db_path: Path to the SQLite database file. Defaults to
                `~/.driftsentry/history.db`. The parent directory is
                created automatically if it does not exist.
        """
        self._db_path = db_path or DEFAULT_DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False, timeout=30.0)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA busy_timeout = 5000")
            self._create_schema()
        except sqlite3.DatabaseError as e:
            raise HistoryStoreError(
                f"Failed to open drift history database at {self._db_path}: {e}"
            ) from e

    def _create_schema(self) -> None:
        """Create the history schema if it doesn't already exist."""
        with self._conn:
            self._conn.execute(_CREATE_SCAN_SNAPSHOTS_SQL)
            self._conn.execute(_CREATE_DRIFT_ITEM_SNAPSHOTS_SQL)
            self._conn.execute(_CREATE_INDEX_SCAN_ID_SQL)
            self._conn.execute(_CREATE_INDEX_RESOURCE_SQL)

    def save(self, result: DriftResult) -> ScanSnapshot:
        """Persist a `DriftResult` as a `ScanSnapshot` row plus its drift item rows.

        Re-saving a scan with the same `scan_id` replaces the prior snapshot
        and its drift items atomically.
        """
        snapshot = ScanSnapshot(
            scan_id=result.scan_id,
            timestamp=result.timestamp,
            total_resources=result.total_resources,
            total_drifted=result.total_drifted,
            changed_count=result.changed_count,
            deleted_count=result.deleted_count,
            unmanaged_count=result.unmanaged_count,
            critical_count=result.critical_count,
            duration_seconds=result.duration_seconds,
            state_source=result.state_source,
            regions=result.regions,
            accounts=result.accounts,
            errors_count=len(result.errors),
        )

        try:
            with self._conn:
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO scan_snapshots (
                        scan_id, timestamp, total_resources, total_drifted,
                        changed_count, deleted_count, unmanaged_count, critical_count,
                        duration_seconds, state_source, regions, accounts, errors_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot.scan_id,
                        snapshot.timestamp.isoformat(),
                        snapshot.total_resources,
                        snapshot.total_drifted,
                        snapshot.changed_count,
                        snapshot.deleted_count,
                        snapshot.unmanaged_count,
                        snapshot.critical_count,
                        snapshot.duration_seconds,
                        snapshot.state_source,
                        json.dumps(snapshot.regions),
                        json.dumps(snapshot.accounts),
                        snapshot.errors_count,
                    ),
                )

                for item in result.drift_items:
                    attribution_principal = item.attribution.principal if item.attribution else None
                    attribution_event_time = (
                        item.attribution.event_time.isoformat()
                        if item.attribution and item.attribution.event_time
                        else None
                    )
                    self._conn.execute(
                        """
                        INSERT INTO drift_item_snapshots (
                            scan_id, resource_address, resource_type, resource_id,
                            drift_type, severity, account_id, region,
                            attribution_principal, attribution_event_time
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            result.scan_id,
                            item.resource_address,
                            item.resource_type,
                            item.resource_id,
                            item.drift_type.value,
                            item.severity.value,
                            item.account_id,
                            item.region,
                            attribution_principal,
                            attribution_event_time,
                        ),
                    )
        except sqlite3.DatabaseError as e:
            raise HistoryStoreError(f"Failed to save scan {result.scan_id} to history: {e}") from e

        return snapshot

    def get_latest(self) -> ScanSnapshot | None:
        """Return the most recent scan snapshot, or None if history is empty."""
        cursor = self._conn.execute(
            "SELECT * FROM scan_snapshots ORDER BY timestamp DESC, rowid DESC LIMIT 1"
        )
        row = cursor.fetchone()
        return _row_to_scan_snapshot(row) if row else None

    def get_snapshot(self, scan_id: str) -> ScanSnapshot | None:
        """Retrieve a specific scan snapshot by its scan_id."""
        cursor = self._conn.execute("SELECT * FROM scan_snapshots WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        return _row_to_scan_snapshot(row) if row else None

    def list_snapshots(
        self,
        limit: int = 50,
        since: datetime.datetime | None = None,
        before: datetime.datetime | None = None,
    ) -> list[ScanSnapshot]:
        """List scan snapshots, most recent first, with optional time-range filtering."""
        clauses = []
        params: list[str | int] = []
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since.isoformat())
        if before is not None:
            clauses.append("timestamp <= ?")
            params.append(before.isoformat())

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)

        cursor = self._conn.execute(
            f"SELECT * FROM scan_snapshots{where} ORDER BY timestamp DESC, rowid DESC LIMIT ?",
            params,
        )
        return [_row_to_scan_snapshot(row) for row in cursor.fetchall()]

    def get_drift_items(self, scan_id: str) -> list[DriftItemSnapshot]:
        """Retrieve all drift items recorded for a given scan."""
        cursor = self._conn.execute(
            "SELECT * FROM drift_item_snapshots WHERE scan_id = ? ORDER BY id", (scan_id,)
        )
        return [_row_to_drift_item_snapshot(row) for row in cursor.fetchall()]

    def get_resource_history(
        self, resource_address: str, limit: int = 20
    ) -> list[DriftItemSnapshot]:
        """Get the drift history for a specific resource across scans, most recent first."""
        cursor = self._conn.execute(
            """
            SELECT dis.* FROM drift_item_snapshots dis
            JOIN scan_snapshots ss ON dis.scan_id = ss.scan_id
            WHERE dis.resource_address = ?
            ORDER BY ss.timestamp DESC, dis.id DESC
            LIMIT ?
            """,
            (resource_address, limit),
        )
        return [_row_to_drift_item_snapshot(row) for row in cursor.fetchall()]

    def delete_before(self, before: datetime.datetime) -> int:
        """Prune scan snapshots (and their drift items) older than `before`.

        Returns:
            The number of scan snapshots deleted.
        """
        with self._conn:
            cursor = self._conn.execute(
                "DELETE FROM scan_snapshots WHERE timestamp < ?", (before.isoformat(),)
            )
            return cursor.rowcount

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()
