"""Baseline command — manage acknowledged drift ledger.

Allows infrastructure teams to snapshot, view, and clear acknowledged drift items
in `.driftsentry-baseline.json`.
"""

from __future__ import annotations

import getpass
import logging
import os
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from driftsentry.cli.scan import get_last_scan_result, run_scan_pipeline
from driftsentry.core.baseline import (
    DEFAULT_BASELINE_FILENAME,
    BaselineEntry,
    DriftBaseline,
    compute_drift_fingerprint,
    load_baseline,
    save_baseline,
)
from driftsentry.core.config import load_config
from driftsentry.core.models import DriftResult, DriftType, StateBackendType
from driftsentry.state.auto_discovery import (
    StateDiscoveryError,
    apply_auto_discovered_state,
    discover_terraform_state,
    format_discovery_error,
)

logger = logging.getLogger(__name__)
console = Console()

baseline_app = typer.Typer(
    name="baseline",
    help="Manage acknowledged drift baselines to prevent alert fatigue.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def _get_default_author() -> str:
    """Detect current user name from git config or OS environment."""
    try:
        user = getpass.getuser()
        if user:
            return user
    except Exception:
        pass
    return os.environ.get("USER") or os.environ.get("USERNAME") or "operator"


@baseline_app.command(name="save")
def save_command(
    reason: str | None = typer.Option(
        None,
        "--reason",
        "-m",
        help="Reason or ticket reference attached to acknowledged drift entries",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Custom path for baseline JSON file (default: .driftsentry-baseline.json)",
    ),
    state_file: str | None = typer.Option(
        None,
        "--state-file",
        "-s",
        help="Path to state file if a new scan must be executed",
    ),
    by: str | None = typer.Option(
        None,
        "--by",
        help="Author or operator identity (defaults to current system user)",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing baseline entries completely instead of merging",
    ),
) -> None:
    """Save detected drift from the last scan (or a new scan) into the baseline ledger."""
    result: DriftResult | None = None

    # Check for existing scan result unless state_file is explicitly provided
    if not state_file:
        result = get_last_scan_result()

    if result is None:
        console.print("[dim]No previous scan result found. Running scan pipeline...[/]")
        config = load_config()
        if state_file:
            config.state.backend = StateBackendType.LOCAL
            config.state.path = state_file
        elif not config.state.path and not config.state.s3_bucket:
            try:
                discovered = discover_terraform_state()
                apply_auto_discovered_state(config, discovered)
            except StateDiscoveryError as e:
                console.print(format_discovery_error(e))
                raise typer.Exit(code=1) from None

        try:
            result = run_scan_pipeline(config, show_progress=True)
        except Exception as e:
            console.print(f"[bold red]Scan failed:[/] {e}")
            raise typer.Exit(code=1) from None

    if not result.has_drift:
        console.print(
            "[bold green]✔ Infrastructure is clean![/] No drift detected to add to baseline."
        )
        return

    # Load or initialize baseline
    target_path = Path(output) if output else (Path.cwd() / DEFAULT_BASELINE_FILENAME)
    baseline = DriftBaseline() if force else (load_baseline(target_path) or DriftBaseline())

    author = by or _get_default_author()
    added_count = 0
    updated_count = 0

    for item in result.drift_items:
        if item.drift_type == DriftType.CHANGED and item.attribute_diffs:
            for diff in item.attribute_diffs:
                fp = compute_drift_fingerprint(
                    resource_address=item.resource_address,
                    drift_type=item.drift_type,
                    attribute_path=diff.path,
                    actual_value=diff.actual_value,
                )
                existing = baseline.find_entry(item.resource_address, diff.path)
                entry = BaselineEntry(
                    resource_address=item.resource_address,
                    resource_type=item.resource_type,
                    resource_id=item.resource_id,
                    drift_type=item.drift_type,
                    attribute_path=diff.path,
                    fingerprint=fp,
                    acknowledged_by=author,
                    reason=reason,
                    last_known_value=diff.actual_value,
                )
                baseline.add_or_update_entry(entry)
                if existing is not None:
                    updated_count += 1
                else:
                    added_count += 1
        else:
            actual_val: Any = None
            if item.drift_type == DriftType.UNMANAGED and item.cloud_resource:
                actual_val = item.cloud_resource.attributes

            fp = compute_drift_fingerprint(
                resource_address=item.resource_address,
                drift_type=item.drift_type,
                attribute_path=None,
                actual_value=actual_val,
            )
            existing = baseline.find_entry(item.resource_address, None)
            entry = BaselineEntry(
                resource_address=item.resource_address,
                resource_type=item.resource_type,
                resource_id=item.resource_id,
                drift_type=item.drift_type,
                attribute_path=None,
                fingerprint=fp,
                acknowledged_by=author,
                reason=reason,
                last_known_value=actual_val,
            )
            baseline.add_or_update_entry(entry)
            if existing is not None:
                updated_count += 1
            else:
                added_count += 1

    saved = save_baseline(baseline, target_path)

    console.print(f"\n[bold green]✔ Baseline updated:[/] [cyan]{saved}[/]")
    console.print(f"  • Entries added: [bold]{added_count}[/]")
    console.print(f"  • Entries updated: [bold]{updated_count}[/]")
    console.print(f"  • Total entries in baseline: [bold]{len(baseline.entries)}[/]")


@baseline_app.command(name="show")
def show_command(
    file: str | None = typer.Option(
        None,
        "--file",
        "-f",
        help="Path to baseline file (default: .driftsentry-baseline.json)",
    ),
    format_opt: str = typer.Option(
        "table",
        "--format",
        help="Output format: table, json",
    ),
) -> None:
    """Display active acknowledged entries in the baseline ledger."""
    target_path = Path(file) if file else (Path.cwd() / DEFAULT_BASELINE_FILENAME)
    baseline = load_baseline(target_path)

    if baseline is None or not baseline.entries:
        if format_opt == "json":
            console.print("[]")
        else:
            console.print(f"[dim]No active baseline entries found in {target_path}[/]")
        return

    if format_opt.lower() == "json":
        console.print(baseline.model_dump_json(indent=2))
        return

    table = Table(
        title=f"🛡️ Drift Baseline Ledger ({len(baseline.entries)} entries)",
        header_style="bold cyan",
    )
    table.add_column("Resource Address", style="white")
    table.add_column("Type", style="dim")
    table.add_column("Drift Type")
    table.add_column("Attribute", style="yellow")
    table.add_column("Acknowledged", style="dim")
    table.add_column("By", style="dim")
    table.add_column("Reason")

    for entry in baseline.entries:
        type_style = {
            DriftType.CHANGED: "[yellow]changed[/]",
            DriftType.DELETED: "[red]deleted[/]",
            DriftType.UNMANAGED: "[cyan]unmanaged[/]",
        }.get(entry.drift_type, entry.drift_type.value)

        ack_date = entry.acknowledged_at.strftime("%Y-%m-%d %H:%M")
        table.add_row(
            entry.resource_address,
            entry.resource_type,
            type_style,
            entry.attribute_path or "(entire resource)",
            ack_date,
            entry.acknowledged_by or "—",
            entry.reason or "[dim]—[/]",
        )

    console.print(table)


@baseline_app.command(name="clear")
def clear_command(
    file: str | None = typer.Option(
        None,
        "--file",
        help="Path to baseline file to clear (default: .driftsentry-baseline.json)",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Skip confirmation prompt",
    ),
) -> None:
    """Clear or reset the baseline ledger."""
    target_path = Path(file) if file else (Path.cwd() / DEFAULT_BASELINE_FILENAME)

    if not target_path.exists():
        console.print(f"[dim]No baseline file found at {target_path}[/]")
        return

    if not force:
        confirm = typer.confirm(
            f"Are you sure you want to clear all baseline entries in {target_path}?",
            default=False,
        )
        if not confirm:
            console.print("[dim]Operation cancelled.[/]")
            return

    try:
        target_path.unlink()
        console.print(f"[bold green]✔ Cleared baseline ledger:[/] {target_path}")
    except OSError as e:
        console.print(f"[bold red]Failed to remove baseline file:[/] {e}")
        raise typer.Exit(code=1) from None
