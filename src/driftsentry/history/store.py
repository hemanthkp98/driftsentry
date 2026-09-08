"""SQLite-backed durable history store for drift scan results.

`DriftStore` persists every `DriftResult` as a normalized `ScanSnapshot`
row plus per-resource `DriftItemSnapshot` rows, enabling queries like
"how many scans over time" or "history of a specific resource" without
holding the full scan payload in memory or on disk as a JSON blob.
"""

from __future__ import annotations

import datetime
import json
import sqlite3
from pathlib import Path

from driftsentry.core.models import DriftResult
from driftsentry.history.models import DriftItemSnapshot, ScanSnapshot

DEFAULT_DB_PATH = Path.home() / ".driftsentry" / "history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS scan_snapshots (
    scan_id            TEXT PRIMARY KEY,
    timestamp          TEXT NOT NULL,
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
);

CREATE TABLE IF NOT EXISTS drift_item_snapshots (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id                TEXT NOT NULL REFERENCES scan_snapshots(scan_id) ON DELETE CASCADE,
    resource_address       TEXT NOT NULL,
    resource_type          TEXT NOT NULL,
    resource_id            TEXT,
    drift_type             TEXT NOT NULL,
    severity               TEXT NOT NULL,
    account_id             TEXT,
    region                 TEXT,
    attribution_principal  TEXT,
    attribution_event_time TEXT
);

CREATE INDEX IF NOT EXISTS idx_drift_items_scan_id ON drift_item_snapshots(scan_id);
CREATE INDEX IF NOT EXISTS idx_drift_items_resource ON drift_item_snapshots(resource_address);
"""

_SCHEMA_VERSION = 1


class DriftStoreError(Exception):
    """Raised when the drift history database cannot be opened or initialized."""


class DriftStore:
    """SQLite-backed store for durable drift scan history."""

    def __init__(self, db_path: Path | None = None) -> None:
        """Open (and if necessary create) the drift history database.

        Args:
            db_path: Path to the SQLite database file. Defaults to
                `~/.driftsentry/history.db`. The parent directory is
                created automatically if it doesn't exist.

        Raises:
            DriftStoreError: If the database file exists but is corrupted
                or otherwise cannot be initialized.
        """
        self.db_path = db_path if db_path is not None else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.row_factory = sqlite3.Row
            with self._conn:
                self._conn.executescript(_SCHEMA)
                self._conn.execute(
                    "INSERT OR IGNORE INTO schema_version (version) VALUES (?)",
                    (_SCHEMA_VERSION,),
                )
        except sqlite3.DatabaseError as e:
            raise DriftStoreError(f"Failed to initialize drift history database: {e}") from e

    def save(self, result: DriftResult) -> ScanSnapshot:
        """Persist a `DriftResult` as a scan snapshot plus its drift items.

        The snapshot row and all drift item rows are written within a
        single transaction.
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
            self._conn.execute(
                "DELETE FROM drift_item_snapshots WHERE scan_id = ?", (snapshot.scan_id,)
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
                        snapshot.scan_id,
                        item.resource_address,
                        item.resource_type,
                        item.resource_id,
                        str(item.drift_type),
                        str(item.severity),
                        item.account_id,
                        item.region,
                        attribution_principal,
                        attribution_event_time,
                    ),
                )

        return snapshot

    def get_latest(self) -> ScanSnapshot | None:
        """Return the most recent scan snapshot, or None if history is empty."""
        row = self._conn.execute(
            "SELECT * FROM scan_snapshots ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()
        return self._row_to_snapshot(row) if row else None

    def get_snapshot(self, scan_id: str) -> ScanSnapshot | None:
        """Retrieve a specific scan snapshot by ID, or None if not found."""
        row = self._conn.execute(
            "SELECT * FROM scan_snapshots WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        return self._row_to_snapshot(row) if row else None

    def list_snapshots(
        self,
        limit: int = 50,
        since: datetime.datetime | None = None,
        before: datetime.datetime | None = None,
    ) -> list[ScanSnapshot]:
        """List scan snapshots, most recent first, with optional time-range filtering.

        Args:
            limit: Maximum number of snapshots to return.
            since: Only include scans at or after this timestamp.
            before: Only include scans at or before this timestamp.
        """
        query = "SELECT * FROM scan_snapshots WHERE 1=1"
        params: list[str | int] = []
        if since is not None:
            query += " AND timestamp >= ?"
            params.append(since.isoformat())
        if before is not None:
            query += " AND timestamp <= ?"
            params.append(before.isoformat())
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_snapshot(row) for row in rows]

    def get_drift_items(self, scan_id: str) -> list[DriftItemSnapshot]:
        """Retrieve all drift items recorded for a given scan."""
        rows = self._conn.execute(
            "SELECT * FROM drift_item_snapshots WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
        return [self._row_to_drift_item(row) for row in rows]

    def get_resource_history(
        self, resource_address: str, limit: int = 20
    ) -> list[DriftItemSnapshot]:
        """Get the drift history for a specific resource across scans, most recent first."""
        rows = self._conn.execute(
            """
            SELECT drift_item_snapshots.*
            FROM drift_item_snapshots
            JOIN scan_snapshots ON scan_snapshots.scan_id = drift_item_snapshots.scan_id
            WHERE drift_item_snapshots.resource_address = ?
            ORDER BY scan_snapshots.timestamp DESC
            LIMIT ?
            """,
            (resource_address, limit),
        ).fetchall()
        return [self._row_to_drift_item(row) for row in rows]

    def get_chronic_offenders(
        self, min_occurrences: int = 3, limit: int = 10
    ) -> list[tuple[str, int]]:
        """Get resources that have drifted frequently.

        Returns:
            A list of tuples (resource_address, occurrence_count), sorted by count descending.
        """
        rows = self._conn.execute(
            """
            SELECT resource_address, COUNT(DISTINCT scan_id) as occurrences
            FROM drift_item_snapshots
            GROUP BY resource_address
            HAVING occurrences >= ?
            ORDER BY occurrences DESC
            LIMIT ?
            """,
            (min_occurrences, limit),
        ).fetchall()
        return [(row["resource_address"], row["occurrences"]) for row in rows]

    def delete_before(self, before: datetime.datetime) -> int:
        """Delete scan snapshots (and their drift items) older than `before`.

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

    @staticmethod
    def _row_to_snapshot(row: sqlite3.Row) -> ScanSnapshot:
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

    @staticmethod
    def _row_to_drift_item(row: sqlite3.Row) -> DriftItemSnapshot:
        return DriftItemSnapshot(
            scan_id=row["scan_id"],
            resource_address=row["resource_address"],
            resource_type=row["resource_type"],
            resource_id=row["resource_id"],
            drift_type=row["drift_type"],
            severity=row["severity"],
            account_id=row["account_id"],
            region=row["region"],
            attribution_principal=row["attribution_principal"],
            attribution_event_time=(
                datetime.datetime.fromisoformat(row["attribution_event_time"])
                if row["attribution_event_time"]
                else None
            ),
        )
