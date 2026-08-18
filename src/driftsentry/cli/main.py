"""DriftSentry CLI — main entry point.

Usage:
    driftsentry scan --state-file terraform.tfstate
    driftsentry report --format html --output drift-report.html
    driftsentry remediate --mode both --create-pr
"""

from __future__ import annotations

import typer
from rich.console import Console

from driftsentry import __version__
from driftsentry.cli.remediate import remediate
from driftsentry.cli.report import report
from driftsentry.cli.scan import scan

console = Console()

app = typer.Typer(
    name="driftsentry",
    help=(
        "🛡️ DriftSentry — Your infrastructure's immune system.\n\n"
        "Detect IaC drift, attribute blame, auto-remediate with PRs.\n"
        "Supports Terraform and OpenTofu."
    ),
    add_completion=True,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# Register sub-commands
app.command(name="scan", help="Scan for infrastructure drift")(scan)
app.command(name="report", help="Generate a drift report from the last scan")(report)
app.command(name="remediate", help="Generate remediation artifacts and optionally create a PR")(
    remediate
)


@app.command()
def version() -> None:
    """Show DriftSentry version."""
    console.print(f"[bold cyan]DriftSentry[/] v{__version__}")


@app.callback()
def main_callback() -> None:
    """DriftSentry — IaC Drift Detection & Auto-Remediation Engine."""
    pass


if __name__ == "__main__":
    app()
