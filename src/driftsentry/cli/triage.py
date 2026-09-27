"""Triage command — interactive drift resolution and reconciliation.

Provides a human-in-the-loop interactive wizard to review detected drift items one-by-one
and take immediate, concrete actions:
  - [A]dopt into Terraform (generate import blocks or updated HCL)
  - [R]evert in AWS (generate reverse remediation plans and instructions)
  - [I]gnore in config (append to .driftsentry.yaml exclusion patterns)
  - [S]kip / [Q]uit
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from driftsentry.cli.scan import get_last_scan_result, run_scan_pipeline
from driftsentry.core.config import load_config
from driftsentry.core.models import (
    DriftItem,
    DriftResult,
    DriftType,
    IaCTool,
    RemediationMode,
    StateBackendType,
)
from driftsentry.remediation.generator import RemediationGenerator
from driftsentry.state.auto_discovery import (
    StateDiscoveryError,
    apply_auto_discovered_state,
    discover_terraform_state,
    format_discovery_error,
)

console = Console()


@dataclass
class TriageSummary:
    """Tracks counts and created artifacts during an interactive triage session."""

    total_reviewed: int = 0
    adopted: int = 0
    reverted: int = 0
    ignored: int = 0
    skipped: int = 0
    files_created: set[str] = field(default_factory=set)
    config_file_updated: str | None = None


def add_exclusion_to_config(
    identifier: str,
    config_file: str | Path | None = None,
) -> Path:
    """Add an identifier or glob pattern to filters.exclude_patterns in .driftsentry.yaml."""
    target_path = Path(config_file) if config_file else Path.cwd() / ".driftsentry.yaml"

    data: dict[str, Any] = {}
    if target_path.exists():
        try:
            with open(target_path, encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    data = loaded
        except Exception:
            data = {}

    filters = data.setdefault("filters", {})
    if not isinstance(filters, dict):
        filters = {}
        data["filters"] = filters

    patterns = filters.setdefault("exclude_patterns", [])
    if not isinstance(patterns, list):
        patterns = []
        filters["exclude_patterns"] = patterns

    if identifier not in patterns:
        patterns.append(identifier)

    with open(target_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)

    return target_path


def _display_drift_item(idx: int, total: int, item: DriftItem) -> None:
    """Render a formatted Rich panel showing details of a single drifted resource."""
    severity_color = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }.get(
        item.severity.value if hasattr(item.severity, "value") else str(item.severity).lower(),
        "white",
    )

    type_color = {
        DriftType.CHANGED: "yellow",
        DriftType.UNMANAGED: "cyan",
        DriftType.DELETED: "red",
    }.get(item.drift_type, "white")

    header = (
        f"[bold]Item {idx}/{total}:[/] [{type_color}]{item.drift_type.value.upper()}[/] "
        f"[bold white]{item.resource_type}[/] [dim]({item.resource_id or item.resource_address})[/] "
        f"[{severity_color}][{item.severity.value.upper() if hasattr(item.severity, 'value') else item.severity}][/]"
    )

    details = []

    # Attribution
    if item.attribution and item.attribution.principal:
        details.append(
            f"  [bold]Attribution:[/] Culprit [bold yellow]{item.attribution.principal}[/] "
            f"via [bold]{item.attribution.event_name or 'CloudTrail'}[/] "
            f"[dim]({item.attribution.event_time or 'recently'})[/]"
        )

    # Diffs
    if item.attribute_diffs:
        table = Table(
            title="Attribute Differences", show_header=True, header_style="bold magenta", box=None
        )
        table.add_column("Attribute", style="cyan")
        table.add_column("Desired (Terraform)", style="green")
        table.add_column("Actual (Cloud)", style="red")
        for diff in item.attribute_diffs:
            table.add_row(
                diff.path,
                str(diff.desired_value) if diff.desired_value is not None else "[dim]null[/]",
                str(diff.actual_value) if diff.actual_value is not None else "[dim]null[/]",
            )
        console.print(Panel(header, style="blue", expand=False))
        for line in details:
            console.print(line)
        console.print(table)
    else:
        if item.drift_type == DriftType.UNMANAGED:
            details.append(
                "  [dim]Resource exists in cloud but is not tracked in Terraform state.[/]"
            )
        elif item.drift_type == DriftType.DELETED:
            details.append(
                "  [dim]Resource exists in Terraform state but has been deleted from cloud.[/]"
            )

        content = "\n".join(details) if details else f"  Resource: {item.resource_address}"
        console.print(Panel(f"{header}\n\n{content}", style="blue", expand=False))


def triage_item(
    item: DriftItem,
    action: str,
    output_dir: Path,
    iac_tool: IaCTool,
    config_file: str | Path | None,
    summary: TriageSummary,
    base_result: DriftResult | None = None,
) -> None:
    """Execute the chosen triage action on a single drift item."""
    action = action.lower().strip()
    single_item_result = DriftResult(
        scan_id="triage",
        provider=base_result.provider if base_result else "aws",
        state_backend=base_result.state_backend if base_result else StateBackendType.LOCAL,
        state_source=base_result.state_source if base_result else "triage",
        iac_tool=iac_tool,
        drift_items=[item],
    )

    if action == "a":  # Adopt
        generator = RemediationGenerator(
            mode=RemediationMode.IMPORT,
            iac_tool=iac_tool,
            output_dir=str(output_dir),
        )
        out = generator.generate(single_item_result)
        summary.adopted += 1
        summary.files_created.update(out.files_created)
        console.print(f"  [green]✔ Adopted {item.resource_address} into {output_dir}/[/]")

    elif action == "r":  # Revert
        generator = RemediationGenerator(
            mode=RemediationMode.REVERT,
            iac_tool=iac_tool,
            output_dir=str(output_dir),
        )
        out = generator.generate(single_item_result)
        summary.reverted += 1
        summary.files_created.update(out.files_created)
        console.print(
            f"  [yellow]✔ Generated revert instructions for {item.resource_address} in {output_dir}/[/]"
        )

    elif action == "i":  # Ignore
        pattern = item.resource_id or item.resource_address
        cfg_path = add_exclusion_to_config(pattern, config_file=config_file)
        summary.ignored += 1
        summary.config_file_updated = str(cfg_path)
        console.print(f"  [blue]✔ Ignored '{pattern}' — added to {cfg_path}[/]")

    elif action == "s":  # Skip
        summary.skipped += 1
        console.print(f"  [dim]Skipped {item.resource_address}[/]")


def triage(
    input_file: str | None = typer.Option(
        None,
        "--input",
        "-i",
        help="Path to a saved scan result JSON file",
    ),
    state_file: str | None = typer.Option(
        None,
        "--state-file",
        "-s",
        help="Path to local .tfstate file (auto-discovered if omitted)",
    ),
    config_file: str | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to .driftsentry.yaml config file",
    ),
    output_dir: str = typer.Option(
        "./driftsentry-remediation",
        "--output-dir",
        "-o",
        help="Directory to write adopted/reverted remediation artifacts",
    ),
    iac_tool: str = typer.Option(
        "terraform",
        "--iac-tool",
        help="IaC tool: terraform, opentofu",
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Run without interactive prompts (for scripts or CI)",
    ),
    auto_adopt: bool = typer.Option(
        False,
        "--auto-adopt",
        help="Automatically adopt all drift items (non-interactive mode)",
    ),
    auto_revert: bool = typer.Option(
        False,
        "--auto-revert",
        help="Automatically revert all drift items (non-interactive mode)",
    ),
    auto_ignore: bool = typer.Option(
        False,
        "--auto-ignore",
        help="Automatically ignore all drift items (non-interactive mode)",
    ),
) -> None:
    """Interactively triage detected drift items and reconcile infrastructure.

    Walks through each drifted resource and prompts for action:
      - [a] Adopt: generate Terraform import or HCL update code
      - [r] Revert: generate live cloud undo plan and command
      - [i] Ignore: add pattern to .driftsentry.yaml exclusion list
      - [s] Skip: do nothing for this resource
      - [q] Quit: exit the triage session

    Examples:

        driftsentry triage

        driftsentry triage --input scan-result.json

        driftsentry triage --state-file terraform.tfstate --auto-adopt --non-interactive
    """
    config = load_config(config_file)
    tool = IaCTool(iac_tool)
    out_dir_path = Path(output_dir)

    # 1. Retrieve or run scan result
    result: DriftResult | None = None
    if input_file:
        input_path = Path(input_file)
        if not input_path.exists():
            console.print(f"[bold red]Error:[/] Input file '{input_file}' not found.")
            raise typer.Exit(code=1)
        try:
            result = DriftResult.model_validate_json(input_path.read_text(encoding="utf-8"))
        except Exception as e:
            console.print(f"[bold red]Error parsing scan result:[/] {e}")
            raise typer.Exit(code=1) from None
    else:
        result = get_last_scan_result()

    if result is None:
        if state_file:
            config.state.backend = StateBackendType.LOCAL
            config.state.path = state_file
            console.print(f"[dim]No previous scan found. Scanning state {state_file}...[/]")
            try:
                result = run_scan_pipeline(config)
            except Exception as e:
                console.print(f"[bold red]Scan error:[/] {e}")
                raise typer.Exit(code=1) from None
        elif config.state.path or config.state.s3_bucket:
            target = config.state.path or f"s3://{config.state.s3_bucket}/{config.state.s3_key}"
            console.print(
                f"[dim]No previous scan found. Scanning configured state ({target})...[/]"
            )
            try:
                result = run_scan_pipeline(config)
            except Exception as e:
                console.print(f"[bold red]Scan error:[/] {e}")
                raise typer.Exit(code=1) from None
        else:
            try:
                discovered = discover_terraform_state()
                apply_auto_discovered_state(config, discovered)
                console.print(f"[dim]Auto-discovered state:[/] {discovered.summary}")
                console.print(
                    f"[dim]No previous scan found. Scanning state ({discovered.summary})...[/]"
                )
                result = run_scan_pipeline(config)
            except StateDiscoveryError as e:
                console.print(
                    "[bold red]Error:[/] No scan result found and state auto-discovery failed.\n"
                )
                console.print(format_discovery_error(e))
                raise typer.Exit(code=1) from None
            except Exception as e:
                console.print(f"[bold red]Scan error:[/] {e}")
                raise typer.Exit(code=1) from None

    if not result.has_drift or not result.drift_items:
        console.print("[bold green]✅ Everything in sync! No drift to triage.[/]")
        return

    items = result.drift_items
    total = len(items)
    console.print(
        f"\n[bold cyan]🛡️  DriftSentry Interactive Triage[/] — {total} drifted resource(s) found.\n"
    )

    summary = TriageSummary()

    # Determine default action for non-interactive mode
    default_non_interactive_action = "s"
    if auto_adopt:
        default_non_interactive_action = "a"
    elif auto_revert:
        default_non_interactive_action = "r"
    elif auto_ignore:
        default_non_interactive_action = "i"

    for idx, item in enumerate(items, 1):
        _display_drift_item(idx, total, item)
        summary.total_reviewed += 1

        if non_interactive:
            action = default_non_interactive_action
        else:
            prompt_text = (
                "[bold cyan]Action:[/] "
                "[bold green][A][/]dopt into TF  "
                "[bold yellow][R][/]evert in AWS  "
                "[bold blue][I][/]gnore in config  "
                "[dim][S]kip[/]  "
                "[bold red][Q][/]uit"
            )
            action = Prompt.ask(
                prompt_text,
                choices=["a", "r", "i", "s", "q", "A", "R", "I", "S", "Q"],
                default="s",
            ).lower()

        if action == "q":
            console.print("\n[yellow]Triage session ended early.[/]")
            break

        triage_item(
            item=item,
            action=action,
            output_dir=out_dir_path,
            iac_tool=tool,
            config_file=config_file,
            summary=summary,
            base_result=result,
        )
        console.print()

    # Display final summary table
    summary_table = Table(
        title="Triage Session Summary", show_header=True, header_style="bold cyan"
    )
    summary_table.add_column("Category", style="bold")
    summary_table.add_column("Count", justify="right")
    summary_table.add_row("Total Reviewed", str(summary.total_reviewed))
    summary_table.add_row("[green]Adopted (IaC)[/]", str(summary.adopted))
    summary_table.add_row("[yellow]Reverted (Cloud)[/]", str(summary.reverted))
    summary_table.add_row("[blue]Ignored (Config)[/]", str(summary.ignored))
    summary_table.add_row("[dim]Skipped[/]", str(summary.skipped))

    console.print(summary_table)

    if summary.files_created:
        console.print(f"\n[green]Artifacts created in [bold]{output_dir}/[/]:[/]")
        for fpath in sorted(summary.files_created):
            console.print(f"  • {fpath}")

    if summary.config_file_updated:
        console.print(f"[blue]Exclusion rules saved to:[/] {summary.config_file_updated}")
