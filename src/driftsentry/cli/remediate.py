"""Remediate command — generate remediation artifacts and optionally create PRs."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from driftsentry.cli.scan import get_last_scan_result
from driftsentry.core.config import LLMConfig, load_config
from driftsentry.core.models import (
    AIRemediationResult,
    DriftResult,
    IaCTool,
    RemediationMode,
)
from driftsentry.remediation.generator import RemediationGenerator, RemediationOutput

console = Console()


def remediate(
    input_file: str | None = typer.Option(
        None,
        "--input",
        "-i",
        help="Path to a saved scan result JSON file",
    ),
    mode: str = typer.Option(
        "both",
        "--mode",
        "-m",
        help="Remediation mode: import, revert, both",
    ),
    output_dir: str = typer.Option(
        "./driftsentry-remediation",
        "--output-dir",
        "-o",
        help="Directory to write remediation artifacts",
    ),
    iac_tool: str = typer.Option(
        "terraform",
        "--iac-tool",
        help="IaC tool: terraform, opentofu",
    ),
    create_pr: bool = typer.Option(
        False,
        "--create-pr",
        help="Create a GitHub PR with remediation code",
    ),
    github_repo: str | None = typer.Option(
        None,
        "--repo",
        help="GitHub repo (owner/name) for PR creation",
    ),
    github_token: str | None = typer.Option(
        None,
        "--github-token",
        help="GitHub token (or set GITHUB_TOKEN env var)",
        envvar="GITHUB_TOKEN",
    ),
    base_branch: str = typer.Option(
        "main",
        "--base-branch",
        help="Base branch for PRs",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview remediation without writing files",
    ),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Enable AI-powered smart HCL generation and root-cause analysis",
    ),
    ai_provider: str = typer.Option(
        "claude",
        "--ai-provider",
        help="LLM provider: claude or gemini",
    ),
    ai_model: str | None = typer.Option(
        None,
        "--ai-model",
        help="Override default LLM model name",
    ),
    ai_max_items: int = typer.Option(
        20,
        "--ai-max-items",
        help="Maximum drift items to analyze with AI",
    ),
    config_file: str | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to .driftsentry.yaml config file",
    ),
) -> None:
    """Generate remediation artifacts for drifted resources.

    Supports three modes:
    - import: Generate terraform import commands for unmanaged resources
    - revert: Generate revert plan for changed resources
    - both: Generate both (default, configurable per-resource)

    With --ai:
    - Generates idiomatic, structured HCL blocks for unmanaged resources
    - Generates root-cause narratives and security risk assessments from audit logs

    Examples:

        driftsentry remediate --input scan-result.json --mode both

        driftsentry remediate --ai --ai-provider claude

        driftsentry remediate --mode import --iac-tool opentofu --ai

        driftsentry remediate --create-pr --repo myorg/infra --ai
    """
    config = load_config(config_file)

    # Load result
    result = _load_result(input_file)
    if result is None:
        console.print(
            "[bold red]Error:[/] No scan result available. "
            "Run [bold]driftsentry scan[/] first or use [bold]--input[/]."
        )
        raise typer.Exit(code=1)

    if not result.has_drift:
        console.print("[bold green]✅ No drift to remediate![/]")
        return

    # Run AI smart analysis if requested or configured
    ai_result: AIRemediationResult | None = None
    use_ai = ai or config.llm.enabled

    if use_ai:
        provider_name = ai_provider if ai else (config.llm.provider or "claude")
        model_name = ai_model if ai_model is not None else config.llm.model
        max_items = ai_max_items if ai else config.llm.max_items

        with console.status(
            f"[bold cyan]🤖 Running AI smart remediation with {provider_name}...[/]"
        ):
            try:
                from driftsentry.llm import get_llm_provider
                from driftsentry.llm.analyzer import LLMAnalyzer

                llm_cfg = LLMConfig(
                    enabled=True,
                    provider=provider_name,
                    model=model_name,
                    max_items=max_items,
                )
                provider = get_llm_provider(llm_cfg)
                analyzer = LLMAnalyzer(provider=provider, max_items=max_items)
                ai_result = analyzer.analyze(result)
                console.print(
                    f"[bold green]✨ AI analysis completed using {provider.provider_name} ({provider.model_name})[/]\n"
                )
            except (OSError, ImportError, ValueError) as e:
                console.print(f"[bold yellow]⚠️  AI analysis skipped:[/] {e}")
                console.print("[dim]Falling back to standard template remediation.[/]\n")
            except Exception as e:
                console.print(f"[bold red]❌ AI analysis encountered error:[/] {e}")
                console.print("[dim]Falling back to standard template remediation.[/]\n")

    # Generate remediation
    generator = RemediationGenerator(
        mode=RemediationMode(mode),
        iac_tool=IaCTool(iac_tool),
        output_dir=output_dir,
        dry_run=dry_run,
    )

    output = generator.generate(result, ai_result=ai_result)

    # Display summary
    if dry_run:
        console.print("[bold yellow]🏃 Dry run — no files written[/]\n")

    if ai_result and ai_result.root_causes:
        console.print("[bold cyan]🤖 AI Root Cause Insights:[/]")
        for rc in ai_result.root_causes[:3]:
            console.print(f"  [bold]{rc.resource_address}:[/] {rc.narrative}")
            if rc.risk_assessment:
                console.print(f"    [yellow]⚠️  {rc.risk_assessment}[/]")
        if len(ai_result.root_causes) > 3:
            console.print(f"  [dim]... and {len(ai_result.root_causes) - 3} more[/]")
        console.print()

    if output.import_commands:
        console.print(f"[bold]📥 Import commands:[/] {len(output.import_commands)}")
        for cmd in output.import_commands[:5]:
            console.print(f"  [dim]$ {cmd}[/]")
        if len(output.import_commands) > 5:
            console.print(f"  [dim]... and {len(output.import_commands) - 5} more[/]")
        console.print()

    if output.revert_items:
        console.print(f"[bold]🔄 Revert items:[/] {len(output.revert_items)}")
        for item in output.revert_items[:5]:
            console.print(f"  [dim]{item['resource']} ({len(item['changes'])} changes)[/]")
        console.print()

    if output.deleted_resources:
        console.print(f"[bold]🗑️  Deleted resources:[/] {len(output.deleted_resources)}")
        for addr in output.deleted_resources[:5]:
            console.print(f"  [dim]{addr}[/]")
        console.print()

    if not dry_run:
        console.print(f"[green]✅ Remediation artifacts written to {output_dir}/[/]")
        for f in sorted(output.files_created):
            console.print(f"  [dim]• {f}[/]")

    # Create PR if requested
    if create_pr and not dry_run:
        _create_pr(
            result,
            output,
            github_repo or config.remediation.github_repo,
            github_token or config.remediation.github_token,
            base_branch or config.remediation.pr_base_branch,
        )


def _create_pr(
    result: DriftResult,
    remediation_output: RemediationOutput,
    repo: str | None,
    token: str | None,
    base_branch: str,
) -> None:
    """Create a GitHub PR with remediation code."""
    if not repo:
        console.print("[bold red]Error:[/] --repo is required for PR creation")
        raise typer.Exit(code=1)

    if not token:
        console.print(
            "[bold red]Error:[/] GitHub token required. "
            "Use --github-token or set GITHUB_TOKEN env var."
        )
        raise typer.Exit(code=1)

    try:
        from driftsentry.remediation.pr_creator import PRCreator

        creator = PRCreator(
            github_token=token,
            repo=repo,
            base_branch=base_branch,
        )

        pr_url = creator.create_pr(result, remediation_output)
        console.print(f"\n[bold green]✅ Created PR:[/] {pr_url}")
    except ImportError:
        console.print("[bold red]Error:[/] PyGithub not installed. Run: pip install pygithub")
        raise typer.Exit(code=1) from None
    except Exception as e:
        console.print(f"[bold red]Error creating PR:[/] {e}")
        raise typer.Exit(code=1) from None


def _load_result(input_file: str | None) -> DriftResult | None:
    """Load a DriftResult from a file or the last scan."""
    if input_file:
        path = Path(input_file)
        if not path.exists():
            console.print(f"[bold red]Error not found:[/] {input_file}")
            raise typer.Exit(code=1)
        data = json.loads(path.read_text())
        return DriftResult(**data)

    return get_last_scan_result()
