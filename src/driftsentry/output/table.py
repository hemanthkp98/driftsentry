"""Rich table formatter — beautiful terminal output for drift results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from driftsentry.core.models import DriftResult, DriftSeverity, DriftType

# ─── Severity styling ───────────────────────────────────────────

SEVERITY_ICONS: dict[DriftSeverity, str] = {
    DriftSeverity.CRITICAL: "🔴",
    DriftSeverity.HIGH: "🟠",
    DriftSeverity.MEDIUM: "🟡",
    DriftSeverity.LOW: "🟢",
    DriftSeverity.INFO: "🔵",
}

SEVERITY_STYLES: dict[DriftSeverity, str] = {
    DriftSeverity.CRITICAL: "bold red",
    DriftSeverity.HIGH: "bold yellow",
    DriftSeverity.MEDIUM: "yellow",
    DriftSeverity.LOW: "green",
    DriftSeverity.INFO: "blue",
}

DRIFT_TYPE_LABELS: dict[DriftType, str] = {
    DriftType.CHANGED: "CHANGED",
    DriftType.DELETED: "DELETED",
    DriftType.UNMANAGED: "UNMANAGED",
}

DRIFT_TYPE_STYLES: dict[DriftType, str] = {
    DriftType.CHANGED: "yellow",
    DriftType.DELETED: "red",
    DriftType.UNMANAGED: "magenta",
}


class TableFormatter:
    """Renders drift scan results as beautiful Rich tables in the terminal."""

    def __init__(self, console: Console | None = None, verbose: bool = False) -> None:
        self.console = console or Console()
        self.verbose = verbose

    def render(self, result: DriftResult) -> None:
        """Render the full drift report to the console."""
        self._render_summary_panel(result)

        if result.has_drift:
            self.console.print()
            self._render_drift_table(result)

            if self.verbose:
                self.console.print()
                self._render_detailed_diffs(result)
        else:
            self.console.print()
            self.console.print(
                "  [bold green]✅ No drift detected![/] All resources match their desired state.",
            )

        if result.errors:
            self.console.print()
            self._render_errors(result)

        self.console.print()

    def _render_summary_panel(self, result: DriftResult) -> None:
        """Render the summary statistics panel."""
        iac_label = result.iac_tool.value.capitalize()
        parts = [
            f"📊 Scanned: [bold]{result.total_resources}[/] resources",
            f"⏱  Duration: [bold]{result.duration_seconds}s[/]",
            f"🌍 Provider: [bold]{result.provider}[/]",
        ]
        if result.region:
            parts.append(f"📍 Region: [bold]{result.region}[/]")

        summary_line = "  │  ".join(parts)

        # Count by severity
        counts = []
        critical = result.critical_count
        changed = result.changed_count
        deleted = result.deleted_count
        unmanaged = result.unmanaged_count

        if critical > 0:
            counts.append(f"🔴 CRITICAL: [bold red]{critical}[/]")
        counts.append(f"📝 Changed: [bold yellow]{changed}[/]")
        counts.append(f"🗑️  Deleted: [bold red]{deleted}[/]")
        counts.append(f"👻 Unmanaged: [bold magenta]{unmanaged}[/]")
        ok_count = result.total_resources - changed - deleted
        if ok_count > 0:
            counts.append(f"✅ OK: [bold green]{ok_count}[/]")

        counts_line = "  │  ".join(counts)

        panel_content = f"\n{summary_line}\n\n{counts_line}\n"

        self.console.print(
            Panel(
                panel_content,
                title=f"[bold]{iac_label} Drift Scan — DriftSentry[/]",
                subtitle=f"scan_id: {result.scan_id}",
                border_style="cyan",
                expand=True,
            )
        )

    def _render_drift_table(self, result: DriftResult) -> None:
        """Render the main drift table."""
        table = Table(
            title="Drifted Resources",
            show_lines=True,
            border_style="dim",
            header_style="bold cyan",
        )

        table.add_column("Resource", style="bold", min_width=30)
        table.add_column("Drift Type", justify="center", min_width=12)
        table.add_column("Severity", justify="center", min_width=10)
        table.add_column("Changes", justify="center", min_width=8)
        table.add_column("Changed By", min_width=20)

        for item in result.drift_items:
            # Resource address
            address = Text(item.resource_address)

            # Drift type with color
            dtype = Text(
                DRIFT_TYPE_LABELS.get(item.drift_type, item.drift_type.value),
                style=DRIFT_TYPE_STYLES.get(item.drift_type, ""),
            )

            # Severity with icon
            icon = SEVERITY_ICONS.get(item.severity, "")
            sev_text = Text(
                f"{icon} {item.severity.value.upper()}",
                style=SEVERITY_STYLES.get(item.severity, ""),
            )

            # Number of attribute changes
            changes = str(len(item.attribute_diffs)) if item.attribute_diffs else "-"

            # Attribution
            changed_by = "-"
            if item.attribution:
                changed_by = item.attribution.principal or "unknown"
                if item.attribution.is_console_change:
                    changed_by += " [dim](console)[/dim]"

            table.add_row(address, dtype, sev_text, changes, changed_by)

        self.console.print(table)

    def _render_detailed_diffs(self, result: DriftResult) -> None:
        """Render detailed attribute-level diffs for each drifted resource."""
        self.console.print("[bold]Detailed Attribute Diffs[/]")
        self.console.print()

        for item in result.drift_items:
            if not item.attribute_diffs:
                continue

            self.console.print(f"  [bold cyan]{item.resource_address}[/]")

            diff_table = Table(show_header=True, border_style="dim", padding=(0, 1))
            diff_table.add_column("Attribute", style="bold")
            diff_table.add_column("Desired (State)", style="green")
            diff_table.add_column("Actual (Cloud)", style="red")

            for diff in item.attribute_diffs:
                desired = self._truncate(str(diff.desired_value), 50)
                actual = self._truncate(str(diff.actual_value), 50)
                diff_table.add_row(diff.path, desired, actual)

            self.console.print(diff_table)
            self.console.print()

    def _render_errors(self, result: DriftResult) -> None:
        """Render non-fatal errors."""
        self.console.print("[bold yellow]⚠️  Warnings & Errors[/]")
        for error in result.errors:
            self.console.print(f"  [yellow]• {error}[/]")

    @staticmethod
    def _truncate(text: str, max_len: int) -> str:
        if len(text) <= max_len:
            return text
        return text[: max_len - 3] + "..."
