"""History command group — query drift scan history and trends from the terminal."""

from __future__ import annotations

import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from driftsentry.core.config import DriftSentryConfig, load_config
from driftsentry.core.models import (
    DriftAttribution,
    DriftItem,
    DriftResult,
    DriftSeverity,
    DriftType,
    StateBackendType,
)
from driftsentry.history.models import DriftDelta, ScanSnapshot
from driftsentry.history.regression import RegressionDetector
from driftsentry.history.store import DriftStore

console = Console()

history_app = typer.Typer(name="history", help="Query drift scan history and trends.")

# Used for client-side prefix search / dry-run counting without adding new
# query methods to `DriftStore` (its public API is treated as read-only here).
_LARGE_LIMIT = 1_000_000

DELTA_ICONS: dict[DriftDelta, str] = {
    DriftDelta.NEW: "🆕",
    DriftDelta.REGRESSION: "🔄",
    DriftDelta.RESOLVED: "✅",
    DriftDelta.RECURRING: "⏩",
    DriftDelta.WORSENED: "⚠️",
}


def _open_store(config: DriftSentryConfig) -> DriftStore:
    """Open the drift history store at the configured (or default) path."""
    db_path = Path(config.history.db_path) if config.history.db_path else None
    return DriftStore(db_path=db_path)


def _parse_date(value: str) -> datetime.datetime:
    """Parse a `YYYY-MM-DD` date, exiting with a friendly error if invalid."""
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        console.print(f"[bold red]Error:[/] Invalid date '{value}'. Expected format: YYYY-MM-DD")
        raise typer.Exit(code=1) from None


def _resolve_scan_id(store: DriftStore, scan_id: str) -> ScanSnapshot | None:
    """Resolve a scan ID, accepting a unique prefix for convenience."""
    snapshot = store.get_snapshot(scan_id)
    if snapshot is not None:
        return snapshot

    matches = [s for s in store.list_snapshots(limit=_LARGE_LIMIT) if s.scan_id.startswith(scan_id)]
    return matches[0] if matches else None


def _snapshot_to_drift_result(store: DriftStore, snapshot: ScanSnapshot) -> DriftResult:
    """Reconstruct a `DriftResult` from a stored snapshot for regression comparison."""
    items = store.get_drift_items(snapshot.scan_id)
    drift_items = [
        DriftItem(
            resource_address=item.resource_address,
            resource_type=item.resource_type,
            resource_id=item.resource_id,
            drift_type=DriftType(item.drift_type),
            severity=DriftSeverity(item.severity),
            account_id=item.account_id,
            region=item.region,
            attribution=(
                DriftAttribution(
                    principal=item.attribution_principal,
                    event_time=item.attribution_event_time,
                )
                if item.attribution_principal or item.attribution_event_time
                else None
            ),
        )
        for item in items
    ]
    return DriftResult(
        scan_id=snapshot.scan_id,
        timestamp=snapshot.timestamp,
        provider="aws",
        regions=snapshot.regions,
        accounts=snapshot.accounts,
        state_backend=StateBackendType.LOCAL,
        state_source=snapshot.state_source,
        total_resources=snapshot.total_resources,
        drift_items=drift_items,
        duration_seconds=snapshot.duration_seconds,
    )


@history_app.command(name="list")
def list_scans(
    limit: int = typer.Option(20, "--limit", help="Maximum number of scans to show"),
    since: str | None = typer.Option(
        None, "--since", help="Only show scans at or after this date (YYYY-MM-DD)"
    ),
    before: str | None = typer.Option(
        None, "--before", help="Only show scans at or before this date (YYYY-MM-DD)"
    ),
    config_file: str | None = typer.Option(
        None, "--config", "-c", help="Path to .driftsentry.yaml config file"
    ),
) -> None:
    """Show recent scan summaries."""
    config = load_config(config_file)
    since_dt = _parse_date(since) if since else None
    before_dt = _parse_date(before) if before else None

    store = _open_store(config)
    try:
        snapshots = store.list_snapshots(limit=limit, since=since_dt, before=before_dt)
    finally:
        store.close()

    if not snapshots:
        console.print("[dim]No scan history found.[/]")
        return

    table = Table(title=f"Scan History (Last {len(snapshots)} Scans)", header_style="bold cyan")
    table.add_column("Scan ID")
    table.add_column("Timestamp")
    table.add_column("Resources", justify="right")
    table.add_column("Drifted", justify="right")
    table.add_column("Changed", justify="right")
    table.add_column("Deleted", justify="right")
    table.add_column("Unmanaged", justify="right")
    table.add_column("Critical", justify="right")
    table.add_column("Duration", justify="right")

    for snapshot in snapshots:
        table.add_row(
            snapshot.scan_id[:8],
            snapshot.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            str(snapshot.total_resources),
            str(snapshot.total_drifted),
            str(snapshot.changed_count),
            str(snapshot.deleted_count),
            str(snapshot.unmanaged_count),
            str(snapshot.critical_count),
            f"{snapshot.duration_seconds:.1f}s",
        )

    console.print(table)


@history_app.command(name="show")
def show_scan(
    scan_id: str = typer.Argument(..., help="Scan ID (or unique prefix) to show"),
    config_file: str | None = typer.Option(
        None, "--config", "-c", help="Path to .driftsentry.yaml config file"
    ),
) -> None:
    """Show detailed drift items for a specific scan."""
    config = load_config(config_file)

    store = _open_store(config)
    try:
        snapshot = _resolve_scan_id(store, scan_id)
        if snapshot is None:
            console.print(f"[bold red]Error:[/] No scan found matching '{scan_id}'.")
            raise typer.Exit(code=1)
        items = store.get_drift_items(snapshot.scan_id)
    finally:
        store.close()

    table = Table(title=f"Drift Items — Scan {snapshot.scan_id[:8]}", header_style="bold cyan")
    table.add_column("Resource Address")
    table.add_column("Resource Type")
    table.add_column("Drift Type")
    table.add_column("Severity")
    table.add_column("Account")
    table.add_column("Region")
    table.add_column("Attribution Principal")

    if not items:
        console.print("[dim]No drift items recorded for this scan.[/]")
        return

    for item in items:
        table.add_row(
            item.resource_address,
            item.resource_type,
            item.drift_type,
            item.severity,
            item.account_id or "-",
            item.region or "-",
            item.attribution_principal or "-",
        )

    console.print(table)


@history_app.command(name="diff")
def diff_scans(
    scan_id: str | None = typer.Option(
        None,
        "--scan-id",
        help="Compare against this specific scan ID (or unique prefix) instead of the previous scan",
    ),
    config_file: str | None = typer.Option(
        None, "--config", "-c", help="Path to .driftsentry.yaml config file"
    ),
) -> None:
    """Compare the latest scan against a previous scan using regression detection."""
    config = load_config(config_file)

    store = _open_store(config)
    try:
        latest = store.get_latest()
        if latest is None:
            console.print("[dim]No scan history found.[/]")
            return

        comparison_scan_id = None
        if scan_id:
            comparison_snapshot = _resolve_scan_id(store, scan_id)
            if comparison_snapshot is None:
                console.print(f"[bold red]Error:[/] No scan found matching '{scan_id}'.")
                raise typer.Exit(code=1)
            comparison_scan_id = comparison_snapshot.scan_id

        current_result = _snapshot_to_drift_result(store, latest)
        report = RegressionDetector(store).compare(
            current_result, previous_scan_id=comparison_scan_id
        )
    finally:
        store.close()

    if report.is_first_scan:
        console.print("[dim]Only one scan recorded — nothing to compare against.[/]")
        return

    comparison_label = report.comparison_scan_id[:8] if report.comparison_scan_id else "-"
    table = Table(
        title=f"Drift Delta: {report.current_scan_id[:8]} vs {comparison_label}",
        header_style="bold cyan",
    )
    table.add_column("Delta")
    table.add_column("Resource")
    table.add_column("Type")
    table.add_column("Drift")
    table.add_column("Severity")

    for item in report.items:
        table.add_row(
            DELTA_ICONS.get(item.delta, ""),
            item.resource_address,
            item.resource_type,
            item.drift_type.value,
            item.severity.value,
        )

    console.print(table)
    console.print(
        f"\nSummary: 🆕 {report.new_count} new · ✅ {report.resolved_count} resolved · "
        f"⏩ {report.recurring_count} recurring · 🔄 {report.regression_count} regressions · "
        f"⚠️ {report.worsened_count} worsened"
    )


@history_app.command(name="offenders")
def offenders(
    min_occurrences: int = typer.Option(
        3, "--min", help="Minimum number of scans a resource must have drifted in"
    ),
    limit: int = typer.Option(10, "--limit", help="Maximum number of resources to show"),
    config_file: str | None = typer.Option(
        None, "--config", "-c", help="Path to .driftsentry.yaml config file"
    ),
) -> None:
    """Show resources that drift chronically across scans."""
    config = load_config(config_file)

    store = _open_store(config)
    try:
        chronic = store.get_chronic_offenders(min_occurrences=min_occurrences, limit=limit)
    finally:
        store.close()

    if not chronic:
        console.print("[dim]No chronic offenders found.[/]")
        return

    table = Table(title="Chronic Drift Offenders", header_style="bold cyan")
    table.add_column("Resource Address")
    table.add_column("Drift Count", justify="right")

    for resource_address, drift_count in chronic:
        table.add_row(resource_address, str(drift_count))

    console.print(table)


@history_app.command(name="prune")
def prune(
    before: str = typer.Option(
        ..., "--before", help="Delete scans recorded before this date (YYYY-MM-DD)"
    ),
    confirm: bool = typer.Option(
        False, "--confirm", help="Actually delete records (otherwise a dry-run preview is shown)"
    ),
    config_file: str | None = typer.Option(
        None, "--config", "-c", help="Path to .driftsentry.yaml config file"
    ),
) -> None:
    """Delete scan history older than a given date."""
    config = load_config(config_file)
    before_dt = _parse_date(before)

    store = _open_store(config)
    try:
        if not confirm:
            matching = [
                s for s in store.list_snapshots(limit=_LARGE_LIMIT) if s.timestamp < before_dt
            ]
            console.print(
                f"[yellow]Dry run:[/] {len(matching)} scan(s) recorded before {before} would be "
                "deleted. Pass [bold]--confirm[/] to delete them."
            )
            return

        deleted = store.delete_before(before_dt)
        console.print(f"[green]✅ Deleted {deleted} scan record(s) recorded before {before}.[/]")
    finally:
        store.close()
