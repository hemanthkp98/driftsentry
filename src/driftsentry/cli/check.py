"""Check command — non-interactive CI/CD drift check with deterministic exit codes.

Designed specifically for automated pipelines (GitHub Actions, GitLab CI).
Supports:
  - Deterministic exit codes: 0 (clean / below threshold), 2 (drift failure), 1 (operational error)
  - Customizable failure policies via --fail-on: any, critical, high, none, never
  - Automatic GitHub Actions Step Summary rendering ($GITHUB_STEP_SUMMARY)
  - PR / Issue comment markdown export via --output-markdown
  - Zero-config state auto-discovery by default
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import typer
from rich.console import Console

from driftsentry.cli.scan import (
    _save_last_scan_result,
    apply_cli_overrides,
    run_scan_pipeline,
)
from driftsentry.core.config import load_config
from driftsentry.core.models import (
    DriftResult,
    DriftSeverity,
    StateBackendType,
)
from driftsentry.output.ci_summary import CISummaryFormatter, write_step_summary
from driftsentry.output.json_fmt import JSONFormatter
from driftsentry.output.table import TableFormatter
from driftsentry.state.auto_discovery import (
    StateDiscoveryError,
    apply_auto_discovered_state,
    discover_terraform_state,
    format_discovery_error,
)

logger = logging.getLogger(__name__)
console = Console()

VALID_FAIL_ON_OPTIONS = {"any", "critical", "high", "none", "never"}


def evaluate_drift_failure(result: DriftResult, fail_on: str) -> bool:
    """Evaluate whether the scan result breaches the specified --fail-on threshold.

    Returns:
        True if drift matches the failure criteria (should trigger exit code 2),
        False if drift is absent or below the threshold (should exit code 0).

    Raises:
        ValueError: If fail_on is not one of the allowed options.
    """
    threshold = fail_on.strip().lower()
    if threshold not in VALID_FAIL_ON_OPTIONS:
        raise ValueError(
            f"Invalid --fail-on option: '{fail_on}'. "
            f"Valid options are: {', '.join(sorted(VALID_FAIL_ON_OPTIONS))}."
        )

    if threshold in ("none", "never"):
        return False

    if not result.has_drift:
        return False

    if threshold == "any":
        return True

    if threshold == "critical":
        return result.critical_count > 0

    if threshold == "high":
        return any(
            item.severity in (DriftSeverity.CRITICAL, DriftSeverity.HIGH)
            for item in result.drift_items
        )

    return False


def _write_error_reports(
    error_message: str,
    github_step_summary: str | None,
    output_markdown: str | None,
) -> None:
    """Best-effort write of error summaries to step summary and PR markdown outputs."""
    formatter = CISummaryFormatter()
    err_md = formatter.render_error(error_message)

    try:
        write_step_summary(err_md, github_step_summary)
    except Exception as exc:
        logger.debug("Failed writing error to step summary: %s", exc)

    if output_markdown:
        try:
            out_path = Path(output_markdown)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(err_md, encoding="utf-8")
        except Exception as exc:
            logger.debug("Failed writing error to output markdown: %s", exc)


def check(
    state_file: str | None = typer.Option(
        None,
        "--state-file",
        "-s",
        help="Path to local .tfstate file (auto-discovered if omitted)",
    ),
    state_backend: str | None = typer.Option(
        None,
        "--state-backend",
        help="State backend type: local, s3",
    ),
    s3_bucket: str | None = typer.Option(
        None,
        "--s3-bucket",
        help="S3 bucket for remote state",
    ),
    s3_key: str | None = typer.Option(
        None,
        "--s3-key",
        help="S3 key (path) for remote state",
    ),
    fail_on: str = typer.Option(
        "any",
        "--fail-on",
        help="Failure policy: any (default), critical, high, none, never",
    ),
    github_step_summary: str | None = typer.Option(
        None,
        "--github-step-summary",
        help="Path to GitHub step summary file (auto-detects $GITHUB_STEP_SUMMARY)",
    ),
    output_markdown: str | None = typer.Option(
        None,
        "--output-markdown",
        help="Export PR-ready comment markdown file",
    ),
    provider: str = typer.Option(
        "aws",
        "--provider",
        "-p",
        help="Cloud provider: aws",
    ),
    region: str | None = typer.Option(
        None,
        "--region",
        "-r",
        help="Primary cloud region to scan",
    ),
    regions: str | None = typer.Option(
        None,
        "--regions",
        "-R",
        help="Comma-separated AWS regions to scan, or 'all'",
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        help="AWS profile name",
    ),
    role_arn: str | None = typer.Option(
        None,
        "--role-arn",
        help="AWS IAM Role ARN to assume",
    ),
    accounts: str | None = typer.Option(
        None,
        "--accounts",
        "-A",
        help="Comma-separated AWS accounts (IDs, names, or profiles) to scan",
    ),
    role_arn_template: str | None = typer.Option(
        None,
        "--role-arn-template",
        help="Template for cross-account role assumption, e.g. 'arn:aws:iam::{account_id}:role/DriftSentryScanRole'",
    ),
    concurrency: int = typer.Option(
        4,
        "--concurrency",
        help="Max concurrent worker threads for parallel scanning across targets",
    ),
    iac_tool: str = typer.Option(
        "terraform",
        "--iac-tool",
        help="IaC tool: terraform, opentofu",
    ),
    output_format: str = typer.Option(
        "table",
        "--output",
        "-o",
        help="Console output format: table, json, none",
    ),
    include_types: str | None = typer.Option(
        None,
        "--include-types",
        help="Comma-separated resource types to include",
    ),
    exclude_types: str | None = typer.Option(
        None,
        "--exclude-types",
        help="Comma-separated resource types to exclude",
    ),
    config_file: str | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to .driftsentry.yaml config file",
    ),
    no_attribution: bool = typer.Option(
        False,
        "--no-attribution",
        help="Skip drift attribution (faster scan)",
    ),
    no_policy: bool = typer.Option(
        False,
        "--no-policy",
        help="Skip policy evaluation",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed output including attribute diffs",
    ),
    save_result: str | None = typer.Option(
        None,
        "--save",
        help="Save scan result to JSON file",
    ),
) -> None:
    """CI/CD drift check command with deterministic exit codes and step summaries.

    Exit Codes:
      0: Clean (no drift) OR drift detected below --fail-on threshold.
      2: Drift detected matching failure threshold (--fail-on).
      1: Operational, scan, or configuration error.

    Examples:

        # Zero-config check: auto-discovers state, fails on any drift
        driftsentry check

        # Only block pipeline on critical security drift
        driftsentry check --fail-on critical

        # Non-blocking check for summary reports and PR comments
        driftsentry check --fail-on none --output-markdown pr-drift-comment.md

        # Explicit remote S3 state check in GitHub Actions
        driftsentry check --state-backend s3 --s3-bucket prod-tf-state --s3-key vpc/terraform.tfstate
    """
    # Validate --fail-on flag early
    threshold = fail_on.strip().lower()
    if threshold not in VALID_FAIL_ON_OPTIONS:
        msg = (
            f"Invalid --fail-on option: '{fail_on}'. "
            f"Valid options are: {', '.join(sorted(VALID_FAIL_ON_OPTIONS))}."
        )
        console.print(f"[bold red]Error:[/] {msg}")
        _write_error_reports(msg, github_step_summary, output_markdown)
        raise typer.Exit(code=1)

    # Load config
    config = load_config(config_file)

    # CLI overrides
    apply_cli_overrides(
        config=config,
        state_file=state_file,
        state_backend=state_backend,
        s3_bucket=s3_bucket,
        s3_key=s3_key,
        region=region,
        regions=regions,
        profile=profile,
        role_arn=role_arn,
        accounts=accounts,
        role_arn_template=role_arn_template,
        concurrency=concurrency,
        iac_tool=iac_tool,
        include_types=include_types,
        exclude_types=exclude_types,
        no_attribution=no_attribution,
        no_policy=no_policy,
        verbose=verbose,
    )

    # Auto-discovery if no state source was specified via CLI or config
    if not config.state.path and not config.state.s3_bucket:
        try:
            discovered = discover_terraform_state()
            apply_auto_discovered_state(config, discovered)
            if output_format == "table":
                console.print(f"[dim]Auto-discovered state:[/] {discovered.summary}")
        except StateDiscoveryError as e:
            err_formatted = format_discovery_error(e)
            console.print(err_formatted)
            _write_error_reports(str(e), github_step_summary, output_markdown)
            raise typer.Exit(code=1) from None

    # Validate config
    if not config.state.path and config.state.backend == StateBackendType.LOCAL:
        msg = "No state file specified. Use --state-file or configure in .driftsentry.yaml"
        console.print(f"[bold red]Error:[/] {msg}")
        _write_error_reports(msg, github_step_summary, output_markdown)
        raise typer.Exit(code=1)

    # Execute scan pipeline
    show_progress = output_format == "table"
    try:
        result = run_scan_pipeline(config, provider=provider, show_progress=show_progress)
    except Exception as e:
        err_msg = f"Scan failed: {e}"
        console.print(f"[bold red]Error:[/] {err_msg}")
        _write_error_reports(err_msg, github_step_summary, output_markdown)
        raise typer.Exit(code=1) from None

    # Save last scan result
    _save_last_scan_result(result)

    # Optional JSON save
    if save_result:
        save_path = Path(save_result)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(
            json.dumps(result.model_dump(mode="json"), indent=2, default=str),
            encoding="utf-8",
        )
        if output_format != "none":
            console.print(f"[dim]Scan result saved to {save_result}[/]")

    # Evaluate failure policy
    failed = evaluate_drift_failure(result, threshold)

    # Render CI Markdown
    ci_formatter = CISummaryFormatter()
    markdown_content = ci_formatter.render(
        result=result,
        fail_on=threshold,
        failed=failed,
    )

    # Write GitHub Step Summary ($GITHUB_STEP_SUMMARY or --github-step-summary)
    summary_written_path = write_step_summary(markdown_content, github_step_summary)
    if summary_written_path and output_format != "none":
        console.print(f"[dim]GitHub Step Summary updated: {summary_written_path}[/]")

    # Write PR comment markdown if requested
    if output_markdown:
        out_path = Path(output_markdown)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(markdown_content, encoding="utf-8")
        if output_format != "none":
            console.print(f"[dim]PR comment Markdown saved: {output_markdown}[/]")

    # Console output
    if output_format == "json":
        formatter_json = JSONFormatter()
        formatter_json.render(result)
    elif output_format == "table":
        formatter_table = TableFormatter(console=console, verbose=verbose)
        formatter_table.render(result)

    # Final summary status and deterministic exit
    if failed:
        console.print(
            f"\n[bold red]❌ CI Check Failed:[/] Drift detected matching failure policy "
            f"(`--fail-on {threshold}`). Exiting with code 2."
        )
        raise typer.Exit(code=2)

    if result.has_drift:
        console.print(
            f"\n[bold yellow]⚠️ CI Check Passed with Warnings:[/] Drift detected, but below failure "
            f"threshold (`--fail-on {threshold}`). Exiting with code 0."
        )
        raise typer.Exit(code=0)

    console.print(
        "\n[bold green]✅ CI Check Passed:[/] All infrastructure resources match desired IaC state."
    )
    raise typer.Exit(code=0)
