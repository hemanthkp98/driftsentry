"""Rich table formatter for cloud resource discovery output."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from driftsentry.discovery.models import DiscoveryResult


class DiscoveryTableFormatter:
    """Renders discovery results as beautiful Rich tables in the terminal."""

    def __init__(self, console: Console | None = None, verbose: bool = False) -> None:
        self.console = console or Console()
        self.verbose = verbose

    def render(self, result: DiscoveryResult) -> None:
        """Render the complete discovery report."""
        self._render_summary_panel(result)

        if result.total_resources > 0:
            self.console.print()
            self._render_resources_table(result)
        else:
            self.console.print()
            self.console.print(
                "  [dim]No active cloud resources found matching the specified criteria.[/]"
            )

        if result.errors:
            self.console.print()
            self._render_errors(result)

        self.console.print()

    def _render_summary_panel(self, result: DiscoveryResult) -> None:
        """Render the discovery summary panel."""
        parts = [
            f"🔍 Discovered: [bold green]{result.total_resources}[/] resources",
            f"📦 Types: [bold]{len(result.resources_by_type)}[/]",
            f"⏱  Duration: [bold]{result.duration_seconds}s[/]",
        ]

        if result.regions:
            regions_str = ", ".join(result.regions[:5])
            if len(result.regions) > 5:
                regions_str += f" (+{len(result.regions) - 5} more)"
            parts.append(f"🌐 Regions: [bold]{regions_str}[/]")

        if result.accounts:
            acc_str = ", ".join(result.accounts[:3])
            if len(result.accounts) > 3:
                acc_str += f" (+{len(result.accounts) - 3} more)"
            parts.append(f"🏢 Accounts: [bold]{acc_str}[/]")

        if result.errors:
            parts.append(f"[bold red]⚠️  Errors: {len(result.errors)}[/]")

        content = "  •  ".join(parts)
        panel = Panel(
            content,
            title="[bold cyan]🛡️  DriftSentry Cloud Discovery[/]",
            border_style="cyan",
            padding=(0, 1),
        )
        self.console.print(panel)

    def _render_resources_table(self, result: DiscoveryResult) -> None:
        """Render the tabular breakdown of discovered resources."""
        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            row_styles=["", "dim"],
            expand=True,
        )

        table.add_column("Resource Type", style="bold blue", ratio=3)
        table.add_column("Resource ID", style="green", ratio=3)
        table.add_column("Name", ratio=3)
        table.add_column("Region", style="dim", ratio=2)
        if len(result.accounts) > 1:
            table.add_column("Account", style="dim", ratio=2)
        if self.verbose:
            table.add_column("ARN / Tags", style="dim", ratio=4)

        for rtype in sorted(result.resources_by_type.keys()):
            for res in result.resources_by_type[rtype]:
                name = (
                    res.tags.get("Name")
                    or res.attributes.get("name")
                    or res.attributes.get("id")
                    or "—"
                )
                region = res.region or "—"
                row = [
                    rtype,
                    res.resource_id,
                    name,
                    region,
                ]
                if len(result.accounts) > 1:
                    account_val = res.account_name or res.account_id or "—"
                    row.append(account_val)
                if self.verbose:
                    detail_parts = []
                    if res.arn:
                        detail_parts.append(res.arn)
                    if res.tags:
                        tag_str = ", ".join(f"{k}={v}" for k, v in list(res.tags.items())[:3])
                        detail_parts.append(f"Tags: [{tag_str}]")
                    row.append(" | ".join(detail_parts) if detail_parts else "—")

                table.add_row(*row)

        self.console.print(table)

    def _render_errors(self, result: DiscoveryResult) -> None:
        """Render any scan errors encountered."""
        error_text = Text()
        for err in result.errors:
            error_text.append(f"  ⚠️  {err}\n", style="yellow")

        panel = Panel(
            error_text,
            title="[bold yellow]Scan Warnings / Errors[/]",
            border_style="yellow",
            padding=(0, 1),
        )
        self.console.print(panel)
