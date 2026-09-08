"""History command — query drift scan history, trends, and chronic offenders."""

from __future__ import annotations

import datetime

import typer
from rich.console import Console
from rich.table import Table

from driftsentry.core.models import (
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

# Large enough to effectively mean "all rows" for the tables involved.
_UNBOUNDED_LIMIT = 1_000_000

_DELTA_ICONS: dict[DriftDelta, str] = {
    DriftDelta.NEW: "🆕",
    DriftDelta.REGRESSION: "🔄",
    DriftDelta.RESOLVED: "✅",
    DriftDelta.RECURRING: "⏩",
    DriftDelta.WORSENED: "⚠️",
}


def _parse_date(value: str) -> datetime.datetime:
    """Parse a `YYYY-MM-DD` date string, exiting with an error on failure."""
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        console.print(f"[bold red]Error:[/] Invalid date '{value}'. Expected format: YYYY-MM-DD.")
        raise typer.Exit(code=1) from None


def _resolve_scan(store: DriftStore, scan_id: str) -> ScanSnapshot | None:
    """Resolve a scan ID, accepting an exact match or a unique prefix."""
    exact = store.get_snapshot(scan_id)
    if exact is not None:
        return exact
    for snapshot in store.list_snapshots(limit=_UNBOUNDED_LIMIT):
        if snapshot.scan_id.startswith(scan_id):
            return snapshot
    return None


def _reconstruct_result(store: DriftStore, snapshot: ScanSnapshot) -> DriftResult:
    """Rebuild a minimal `DriftResult` for a stored snapshot, for regression comparison."""
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


@history_app.command("list")
def list_scans(
    limit: int = typer.Option(20, "--limit", help="Maximum number of scans to show"),
    since: str | None = typer.Option(
        None, "--since", help="Only show scans on/after this date (YYYY-MM-DD)"
    ),
    before: str | None = typer.Option(
        None, "--before", help="Only show scans on/before this date (YYYY-MM-DD)"
    ),
) -> None:
    """Show recent scan summaries."""
    since_dt = _parse_date(since) if since else None
    before_dt = _parse_date(before) if before else None

    store = DriftStore()
    try:
        snapshots = store.list_snapshots(limit=limit, since=since_dt, before=before_dt)
    finally:
        store.close()

    if not snapshots:
        console.print("[yellow]No scan history found.[/]")
        return

    table = Table(
        title=f"Scan History (Last {len(snapshots)} Scans)",
        show_lines=False,
        border_style="dim",
        header_style="bold cyan",
    )
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


@history_app.command("show")
def show(
    scan_id: str = typer.Argument(..., help="Scan ID (or unique prefix) to show details for"),
) -> None:
    """Show detailed drift items for a specific scan."""
    store = DriftStore()
    try:
        snapshot = _resolve_scan(store, scan_id)
        if snapshot is None:
            console.print(f"[bold red]Error:[/] No scan found matching ID '{scan_id}'.")
            raise typer.Exit(code=1)
        items = store.get_drift_items(snapshot.scan_id)
    finally:
        store.close()

    if not items:
        console.print(f"[green]No drift items recorded for scan {snapshot.scan_id[:8]}.[/]")
        return

    table = Table(
        title=f"Drift Items — Scan {snapshot.scan_id[:8]}",
        show_lines=False,
        border_style="dim",
        header_style="bold cyan",
    )
    table.add_column("Resource Address")
    table.add_column("Resource Type")
    table.add_column("Drift Type")
    table.add_column("Severity")
    table.add_column("Account")
    table.add_column("Region")
    table.add_column("Attribution")

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


@history_app.command("diff")
def diff(
    scan_id: str | None = typer.Option(
        None,
        "--scan-id",
        help="Scan ID to treat as the 'current' scan (defaults to the most recent scan)",
    ),
) -> None:
    """Compare a scan against the previous one using regression detection."""
    store = DriftStore()
    try:
        if scan_id:
            snapshot = _resolve_scan(store, scan_id)
            if snapshot is None:
                console.print(f"[bold red]Error:[/] No scan found matching ID '{scan_id}'.")
                raise typer.Exit(code=1)
        else:
            snapshot = store.get_latest()
            if snapshot is None:
                console.print("[yellow]No scan history found.[/]")
                return

        current_result = _reconstruct_result(store, snapshot)
        report = RegressionDetector(store).compare(current_result)
    finally:
        store.close()

    if report.is_first_scan:
        console.print(
            "[yellow]No previous scan to compare against (this is the first scan in history).[/]"
        )
        return

    comparison_id = report.comparison_scan_id or ""
    table = Table(
        title=f"Drift Delta: {snapshot.scan_id[:8]} vs {comparison_id[:8]}",
        show_lines=False,
        border_style="dim",
        header_style="bold cyan",
    )
    table.add_column("Delta", justify="center")
    table.add_column("Resource")
    table.add_column("Type")
    table.add_column("Drift")
    table.add_column("Severity")

    for item in report.items:
        table.add_row(
            _DELTA_ICONS.get(item.delta, ""),
            item.resource_address,
            item.resource_type,
            item.drift_type.value,
            item.severity.value,
        )

    console.print(table)
    console.print(
        f"\nSummary: 🆕 {report.new_count} new · "
        f"✅ {report.resolved_count} resolved · "
        f"⏩ {report.recurring_count} recurring · "
        f"🔄 {report.regression_count} regressions · "
        f"⚠️ {report.worsened_count} worsened"
    )


@history_app.command("offenders")
def offenders(
    min_occurrences: int = typer.Option(
        3, "--min", help="Minimum number of scans a resource must have drifted in"
    ),
    limit: int = typer.Option(10, "--limit", help="Maximum number of offenders to show"),
) -> None:
    """Show chronic offender resources — those that drift repeatedly."""
    store = DriftStore()
    try:
        rows = store.get_chronic_offenders(min_occurrences=min_occurrences, limit=limit)
    finally:
        store.close()

    if not rows:
        console.print("[green]No chronic offenders found.[/]")
        return

    table = Table(
        title="Chronic Offenders",
        show_lines=False,
        border_style="dim",
        header_style="bold cyan",
    )
    table.add_column("Resource Address")
    table.add_column("Drift Count", justify="right")

    for resource_address, count in rows:
        table.add_row(resource_address, str(count))

    console.print(table)


@history_app.command("prune")
def prune(
    before: str = typer.Option(
        ..., "--before", help="Delete scans recorded before this date (YYYY-MM-DD)"
    ),
    confirm: bool = typer.Option(
        False, "--confirm", help="Actually delete matching records (otherwise dry-run)"
    ),
) -> None:
    """Delete scan records older than a given date."""
    before_dt = _parse_date(before)

    store = DriftStore()
    try:
        if not confirm:
            candidates = store.list_snapshots(limit=_UNBOUNDED_LIMIT, before=before_dt)
            count = sum(1 for snapshot in candidates if snapshot.timestamp < before_dt)
            console.print(
                f"[yellow]Dry run:[/] {count} scan record(s) would be deleted "
                f"(before {before}). Pass [bold]--confirm[/] to delete."
            )
        else:
            count = store.delete_before(before_dt)
            console.print(f"[green]Deleted {count} scan record(s) before {before}.[/]")
    finally:
        store.close()
