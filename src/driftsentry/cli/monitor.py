"""Monitor command — run continuous scheduled drift scans with smart alerting."""

from __future__ import annotations

import logging
import signal
import time
from collections.abc import Callable
from pathlib import Path
from types import FrameType

import typer
from rich.console import Console

from driftsentry.cli.scan import run_scan
from driftsentry.core.config import DriftSentryConfig, load_config
from driftsentry.core.models import DriftResult
from driftsentry.history.models import DriftDelta
from driftsentry.history.regression import RegressionDetector
from driftsentry.history.store import DriftStore
from driftsentry.notifications.slack import SlackNotifier

logger = logging.getLogger(__name__)
console = Console()

MIN_INTERVAL_MINUTES = 5

# Only these delta classifications are alert-worthy — RECURRING drift is
# suppressed to avoid paging on drift that's already known.
ALERT_DELTAS = frozenset({DriftDelta.NEW, DriftDelta.REGRESSION, DriftDelta.WORSENED})


def _sleep_with_countdown(total_seconds: float, should_stop: Callable[[], bool]) -> None:
    """Sleep for `total_seconds`, showing a spinner countdown, until `should_stop()` is True."""
    remaining = int(total_seconds)
    with console.status("") as status:
        while remaining > 0 and not should_stop():
            minutes, seconds = divmod(remaining, 60)
            status.update(f"[dim]Next scan in {minutes:02d}:{seconds:02d}...[/]")
            time.sleep(1)
            remaining -= 1


def monitor(
    interval: float = typer.Option(60, "--interval", help="Minutes between scans (minimum 5)"),
    max_scans: int | None = typer.Option(
        None, "--max-scans", help="Stop after N scans (default: unlimited)"
    ),
    once: bool = typer.Option(
        False, "--once", help="Run a single scan and exit (shorthand for --max-scans 1)"
    ),
    config_file: str | None = typer.Option(
        None, "--config", "-c", help="Path to .driftsentry.yaml config file"
    ),
) -> None:
    """Run the drift scan pipeline on a repeating schedule with smart alerting.

    After each scan, regression detection classifies drift against the
    previous scan. Only NEW, REGRESSION, or WORSENED drift triggers a
    Slack alert (if configured) — RECURRING drift is suppressed to avoid
    alert fatigue.

    Examples:

        driftsentry monitor --interval 60

        driftsentry monitor --once

        driftsentry monitor --max-scans 5
    """
    if once:
        max_scans = 1

    if interval < MIN_INTERVAL_MINUTES:
        console.print(
            f"[bold red]Error:[/] --interval must be at least {MIN_INTERVAL_MINUTES} minutes."
        )
        raise typer.Exit(code=1)

    config = load_config(config_file)

    if not config.state.path and config.state.backend.value == "local":
        console.print("[bold red]Error:[/] No state file specified.")
        console.print("Configure [bold]state.path[/] in [bold].driftsentry.yaml[/]")
        raise typer.Exit(code=1)

    shutdown_requested = False

    def _handle_shutdown(signum: int, frame: FrameType | None) -> None:
        nonlocal shutdown_requested
        shutdown_requested = True
        console.print("\n[yellow]Shutdown requested — finishing current scan...[/]")

    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    scan_count = 0
    while not shutdown_requested:
        scan_count += 1
        console.print(f"\n🔍 Running scan #{scan_count}...")

        try:
            result, _evaluation = run_scan(config, show_progress=False)
        except (ValueError, FileNotFoundError) as e:
            console.print(f"[bold red]Error:[/] {e}")
            raise typer.Exit(code=1) from None

        console.print(
            f"  Scan complete: {result.total_resources} resources, "
            f"{result.total_drifted} drifted ({result.duration_seconds:.1f}s)"
        )

        _report_and_alert(config, result)

        if max_scans is not None and scan_count >= max_scans:
            break
        if shutdown_requested:
            break

        _sleep_with_countdown(interval * 60, lambda: shutdown_requested)

    scans_label = f"{scan_count}/{max_scans}" if max_scans is not None else f"{scan_count}"
    console.print(f"\n✅ Monitor complete ({scans_label} scans).")


def _report_and_alert(config: DriftSentryConfig, result: DriftResult) -> None:
    """Run regression detection, print a compact delta summary, and alert on new drift."""
    db_path = Path(config.history.db_path) if config.history.db_path else None
    store = DriftStore(db_path=db_path)
    try:
        report = RegressionDetector(store).compare(result)
    finally:
        store.close()

    if report.is_first_scan:
        console.print("  [dim]Drift delta: first scan, nothing to compare against[/]")
        return

    console.print(
        f"  Drift delta: {report.new_count} new, {report.resolved_count} resolved, "
        f"{report.recurring_count} recurring, {report.regression_count} regressions, "
        f"{report.worsened_count} worsened since last scan"
    )

    alert_items = [item for item in report.items if item.delta in ALERT_DELTAS]
    if not alert_items or not config.notifications.slack_webhook_url:
        return

    alert_addresses = {item.resource_address for item in alert_items}
    alert_result = result.model_copy(
        update={
            "drift_items": [
                item for item in result.drift_items if item.resource_address in alert_addresses
            ]
        }
    )

    notifier = SlackNotifier(config.notifications.slack_webhook_url)
    if notifier.notify(alert_result):
        console.print(f"  📢 Slack alert sent for {len(alert_items)} new drift item(s)")
    else:
        console.print("  [yellow]⚠️  Slack alert failed to send[/]")
