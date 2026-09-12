"""Monitor command — run continuous, regression-aware drift scans on a schedule."""

from __future__ import annotations

import logging
import signal
import time
from collections.abc import Callable
from types import FrameType

import typer
from rich.console import Console

from driftsentry.cli.scan import run_scan_pipeline
from driftsentry.core.config import DriftSentryConfig, load_config
from driftsentry.core.models import DriftItem, DriftResult
from driftsentry.history.models import DriftDelta, RegressionReport
from driftsentry.notifications.slack import SlackNotifier

logger = logging.getLogger(__name__)
console = Console()

MIN_INTERVAL_MINUTES = 5

# Delta classifications that warrant a Slack alert — RECURRING (already-known,
# chronic drift) is deliberately excluded to avoid alert fatigue.
ALERT_DELTAS = {DriftDelta.NEW, DriftDelta.REGRESSION, DriftDelta.WORSENED}


def monitor(
    interval: int | None = typer.Option(
        None,
        "--interval",
        help=f"Minutes between scans (minimum {MIN_INTERVAL_MINUTES})",
    ),
    provider: str = typer.Option(
        "aws",
        "--provider",
        "-p",
        help="Cloud provider: aws",
    ),
    config_file: str | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to .driftsentry.yaml config file",
    ),
    max_scans: int | None = typer.Option(
        None,
        "--max-scans",
        help="Stop after this many scans (default: unlimited)",
    ),
    once: bool = typer.Option(
        False,
        "--once",
        help="Run a single scan and exit (shorthand for --max-scans 1)",
    ),
) -> None:
    """Run the scan pipeline continuously with regression-aware smart alerting.

    Only sends Slack alerts for NEW, REGRESSION, or WORSENED drift — chronic,
    already-known (RECURRING) drift is skipped to avoid alert fatigue.

    Examples:

        driftsentry monitor --interval 30

        driftsentry monitor --once

        driftsentry monitor --max-scans 5 --interval 15
    """
    config = load_config(config_file)

    actual_interval = interval if interval is not None else config.monitor.interval_minutes
    if actual_interval < MIN_INTERVAL_MINUTES:
        console.print(
            f"[bold red]Error:[/] --interval must be at least {MIN_INTERVAL_MINUTES} minutes."
        )
        raise typer.Exit(code=1)

    scan_limit = 1 if once else (max_scans if max_scans is not None else config.monitor.max_scans)

    if not config.history.enabled:
        console.print(
            "[yellow]⚠️  Warning: Continuous monitoring requires history to perform regression detection. History is disabled, proceeding without smart alerting.[/]"
        )

    notifier = (
        SlackNotifier(config.notifications.slack_webhook_url)
        if config.notifications.slack_webhook_url
        else None
    )

    shutdown_requested = False

    def _handle_shutdown(signum: int, frame: FrameType | None) -> None:
        nonlocal shutdown_requested
        if not shutdown_requested:
            console.print("\n[yellow]⏹  Shutdown requested — finishing current scan...[/]")
        shutdown_requested = True

    previous_sigint = signal.signal(signal.SIGINT, _handle_shutdown)
    previous_sigterm = signal.signal(signal.SIGTERM, _handle_shutdown)

    scans_run = 0
    try:
        while True:
            scans_run += 1
            console.print(f"\n🔍 Running scan #{scans_run}...")
            _run_one_scan(config, provider, notifier)

            if shutdown_requested or (scan_limit is not None and scans_run >= scan_limit):
                break

            _sleep_with_countdown(actual_interval * 60, lambda: shutdown_requested)
            if shutdown_requested:
                break
    finally:
        signal.signal(signal.SIGINT, previous_sigint)
        signal.signal(signal.SIGTERM, previous_sigterm)

    limit_label = str(scan_limit) if scan_limit is not None else "∞"
    console.print(f"\n✅ Monitor complete ({scans_run}/{limit_label} scans).")


def _run_one_scan(config: DriftSentryConfig, provider: str, notifier: SlackNotifier | None) -> None:
    """Run a single scan, print a compact summary, and send smart alerts."""
    try:
        result, regression_report = run_scan_pipeline(
            config, provider=provider, show_progress=False
        )
    except (ValueError, FileNotFoundError) as e:
        console.print(f"  [bold red]Error:[/] {e}")
        return

    console.print(
        f"  Scan complete: {result.total_resources} resources, "
        f"{result.total_drifted} drifted ({result.duration_seconds:.1f}s)"
    )

    if regression_report is None:
        return

    if not regression_report.is_first_scan:
        console.print(f"  {_format_regression_summary(regression_report)}")

    _send_smart_alert(notifier, result, regression_report)


def _format_regression_summary(report: RegressionReport) -> str:
    """Format a compact one-line drift delta summary."""
    parts = [
        f"{report.new_count} new",
        f"{report.resolved_count} resolved",
        f"{report.recurring_count} recurring",
    ]
    if report.regression_count:
        parts.append(f"{report.regression_count} regressions")
    if report.worsened_count:
        parts.append(f"{report.worsened_count} worsened")
    return f"Drift delta: {', '.join(parts)} since last scan"


def _collect_alert_items(result: DriftResult, report: RegressionReport) -> list[DriftItem]:
    """Select the drift items from `result` that warrant a smart alert."""
    alert_addresses = {item.resource_address for item in report.items if item.delta in ALERT_DELTAS}
    return [item for item in result.drift_items if item.resource_address in alert_addresses]


def _send_smart_alert(
    notifier: SlackNotifier | None, result: DriftResult, report: RegressionReport
) -> None:
    """Send a Slack alert for NEW/REGRESSION/WORSENED drift only (smart alerting)."""
    if notifier is None:
        return

    alert_items = _collect_alert_items(result, report)
    if not alert_items:
        return

    alert_result = result.model_copy(update={"drift_items": alert_items})
    if notifier.notify(alert_result):
        plural = "s" if len(alert_items) != 1 else ""
        console.print(f"  📢 Slack alert sent for {len(alert_items)} drift item{plural}")
    else:
        console.print("  [yellow]⚠️  Failed to send Slack alert[/]")


def _sleep_with_countdown(total_seconds: int, should_stop: Callable[[], bool]) -> None:
    """Sleep in one-second increments, showing a countdown spinner, until `should_stop()`."""
    remaining = total_seconds
    with console.status("") as status:
        while remaining > 0 and not should_stop():
            minutes, seconds = divmod(remaining, 60)
            status.update(f"⏳ Next scan in {minutes:02d}:{seconds:02d}...")
            time.sleep(1)
            remaining -= 1
