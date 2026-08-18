"""Report command — generate drift reports in various formats."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from driftsentry.cli.scan import get_last_scan_result
from driftsentry.core.models import DriftResult
from driftsentry.output.html import HTMLFormatter
from driftsentry.output.json_fmt import JSONFormatter
from driftsentry.output.markdown import MarkdownFormatter
from driftsentry.output.table import TableFormatter

console = Console()


def report(
    input_file: str | None = typer.Option(
        None,
        "--input",
        "-i",
        help="Path to a saved scan result JSON file (from driftsentry scan --save)",
    ),
    output_format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table, json, html, markdown",
    ),
    output_file: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Path to write the report file (required for html/markdown)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed attribute diffs",
    ),
) -> None:
    """Generate a drift report from a saved scan result or the last scan.

    Examples:

        driftsentry report --format html --output drift-report.html

        driftsentry report --input scan-result.json --format markdown --output report.md

        driftsentry report --format json
    """
    # Load the result
    result = _load_result(input_file)
    if result is None:
        console.print(
            "[bold red]Error:[/] No scan result available. "
            "Run [bold]driftsentry scan[/] first or use [bold]--input[/] "
            "to load a saved result."
        )
        raise typer.Exit(code=1)

    # Generate report
    if output_format == "table":
        formatter = TableFormatter(console=console, verbose=verbose)
        formatter.render(result)

    elif output_format == "json":
        formatter_json = JSONFormatter(pretty=True)
        if output_file:
            with open(output_file, "w") as f:
                formatter_json.render(result, output=f)
            console.print(f"[green]✅ JSON report written to {output_file}[/]")
        else:
            formatter_json.render(result)

    elif output_format == "html":
        if not output_file:
            output_file = "driftsentry-report.html"
        formatter_html = HTMLFormatter()
        formatter_html.render(result, output_path=output_file)
        console.print(f"[green]✅ HTML report written to {output_file}[/]")

    elif output_format == "markdown":
        formatter_md = MarkdownFormatter()
        if output_file:
            formatter_md.render(result, output_path=output_file)
            console.print(f"[green]✅ Markdown report written to {output_file}[/]")
        else:
            md = formatter_md.render(result)
            console.print(md)

    else:
        console.print(f"[bold red]Error:[/] Unknown format: {output_format}")
        raise typer.Exit(code=1)


def _load_result(input_file: str | None) -> DriftResult | None:
    """Load a DriftResult from a file or the last scan."""
    if input_file:
        path = Path(input_file)
        if not path.exists():
            console.print(f"[bold red]Error:[/] File not found: {input_file}")
            raise typer.Exit(code=1)

        data = json.loads(path.read_text())
        return DriftResult(**data)

    return get_last_scan_result()
