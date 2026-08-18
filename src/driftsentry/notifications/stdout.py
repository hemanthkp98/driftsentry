"""Stdout notification — console-based drift alerts (default)."""

from __future__ import annotations

from rich.console import Console

from driftsentry.core.models import DriftResult


class StdoutNotifier:
    """Prints a brief drift notification to stdout."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def notify(self, result: DriftResult) -> bool:
        """Print a brief drift summary to the console."""
        if not result.has_drift:
            self.console.print("[bold green]✅ No drift detected.[/]")
            return True

        self.console.print(
            f"\n[bold yellow]⚠️  Drift detected![/] "
            f"[bold]{result.total_drifted}[/] drifted resources "
            f"({result.critical_count} critical)"
        )
        return True
