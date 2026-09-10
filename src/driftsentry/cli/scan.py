"""Scan command — detect infrastructure drift."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import typer
from rich.console import Console

from driftsentry.core.config import DriftSentryConfig, load_config
from driftsentry.core.models import DriftResult, IaCTool, StateBackendType
from driftsentry.core.scanner import DriftScanner
from driftsentry.history.regression import RegressionDetector
from driftsentry.history.store import DriftStore
from driftsentry.output.json_fmt import JSONFormatter
from driftsentry.output.table import TableFormatter
from driftsentry.policy.engine import PolicyEngine, PolicyEvaluation
from driftsentry.providers.aws.provider import AWSProvider
from driftsentry.state.factory import create_state_reader

logger = logging.getLogger(__name__)
console = Console()

# ─── Shared state for passing scan results to report/remediate ──

LAST_SCAN_FILENAME = ".driftsentry-last-scan.json"
_last_scan_result: DriftResult | None = None


def get_last_scan_result() -> DriftResult | None:
    """Get the result of the last scan (used by report and remediate commands)."""
    if _last_scan_result is not None:
        return _last_scan_result

    last_scan_path = Path.cwd() / LAST_SCAN_FILENAME
    if not last_scan_path.exists():
        return None

    try:
        return DriftResult.model_validate_json(last_scan_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _save_last_scan_result(result: DriftResult) -> None:
    """Persist the latest result so separate CLI invocations can reuse it."""
    last_scan_path = Path.cwd() / LAST_SCAN_FILENAME
    last_scan_path.write_text(
        json.dumps(result.model_dump(mode="json"), indent=2, default=str),
        encoding="utf-8",
    )


def run_scan(
    config: DriftSentryConfig,
    provider: str = "aws",
    show_progress: bool = True,
) -> tuple[DriftResult, PolicyEvaluation | None]:
    """Run the scan pipeline and persist the result to history. Shared by `scan` and `monitor`.

    Raises ValueError if `provider` is unsupported, or FileNotFoundError if the
    configured state file cannot be found.
    """
    state_reader = create_state_reader(config)

    if provider == "aws":
        cloud_provider = AWSProvider(
            region=config.provider.region,
            regions=config.provider.regions,
            profile=config.provider.profile,
            role_arn=config.provider.role_arn,
            accounts=config.accounts,
            role_arn_template=config.role_arn_template,
            custom_resources=config.provider.custom_resources,
            resource_definitions_dirs=config.provider.resource_definitions_dirs,
            plugins=config.provider.plugins,
            concurrency=config.concurrency,
        )
    else:
        raise ValueError(f"Unsupported provider: {provider}")

    scanner = DriftScanner(config, state_reader, cloud_provider)
    result = scanner.scan(show_progress=show_progress)

    evaluation: PolicyEvaluation | None = None
    if config.policy.enabled:
        engine = PolicyEngine(config.policy.policy_file)
        evaluation = engine.evaluate(result)

    if config.history.enabled:
        try:
            history_db_path = Path(config.history.db_path) if config.history.db_path else None
            history_store = DriftStore(db_path=history_db_path)
            try:
                history_store.save(result)
            finally:
                history_store.close()
        except Exception as e:
            logger.warning(f"Failed to persist scan result to history store: {e}")

    return result, evaluation


def scan(
    state_file: str | None = typer.Option(
        None,
        "--state-file",
        "-s",
        help="Path to local .tfstate file",
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
        help="Output format: table, json",
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
    """Scan infrastructure for drift between IaC state and live cloud resources.

    Examples:

        driftsentry scan --state-file terraform.tfstate

        driftsentry scan --state-file terraform.tfstate --regions us-east-1,us-west-2

        driftsentry scan --accounts 111122223333,444455556666 --role-arn-template "arn:aws:iam::{account_id}:role/DriftSentry"

        driftsentry scan --state-backend s3 --s3-bucket my-state --s3-key prod/terraform.tfstate
    """
    global _last_scan_result

    # Load config
    config = load_config(config_file)

    # CLI overrides
    if state_file:
        config.state.backend = StateBackendType.LOCAL
        config.state.path = state_file
    if state_backend:
        config.state.backend = StateBackendType(state_backend)
    if s3_bucket:
        config.state.s3_bucket = s3_bucket
    if s3_key:
        config.state.s3_key = s3_key
    if region:
        config.provider.region = region
    if regions:
        config.provider.regions = [r.strip() for r in regions.split(",") if r.strip()]
    if profile:
        config.provider.profile = profile
    if role_arn:
        config.provider.role_arn = role_arn
    if role_arn_template:
        config.role_arn_template = role_arn_template
    if concurrency:
        config.concurrency = concurrency
    if accounts:
        from driftsentry.core.config import AccountConfig

        acc_list: list[AccountConfig] = []
        for a in accounts.split(","):
            a_clean = a.strip()
            if not a_clean:
                continue
            if a_clean.isdigit() and len(a_clean) == 12:
                acc_list.append(AccountConfig(id=a_clean))
            else:
                acc_list.append(AccountConfig(name=a_clean))
        config.accounts = acc_list

    if iac_tool:
        config.iac_tool = IaCTool(iac_tool)
    if include_types:
        config.filters.include_types = [t.strip() for t in include_types.split(",")]
    if exclude_types:
        config.filters.exclude_types = [t.strip() for t in exclude_types.split(",")]
    if no_attribution:
        config.attribution.enabled = False
    if no_policy:
        config.policy.enabled = False
    config.verbose = verbose

    # Validate config
    if not config.state.path and config.state.backend == StateBackendType.LOCAL:
        console.print("[bold red]Error:[/] No state file specified.")
        console.print("Use [bold]--state-file[/] or configure in [bold].driftsentry.yaml[/]")
        raise typer.Exit(code=1)

    # Run scan
    try:
        result, evaluation = run_scan(
            config, provider=provider, show_progress=output_format == "table"
        )
    except (ValueError, FileNotFoundError) as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1) from None

    if evaluation is not None and evaluation.ignored_count > 0 and output_format == "table":
        console.print(
            f"  [dim]Policy: {evaluation.ignored_count} drift items ignored by policy rules[/]"
        )

    # Store for report/remediate commands
    _last_scan_result = result
    _save_last_scan_result(result)

    # Regression summary vs the previous scan in history
    if config.history.enabled and output_format == "table":
        try:
            history_db_path = Path(config.history.db_path) if config.history.db_path else None
            history_store = DriftStore(db_path=history_db_path)
            try:
                regression_report = RegressionDetector(history_store).compare(result)
            finally:
                history_store.close()
            if not regression_report.is_first_scan:
                console.print(
                    f"  [dim]Drift delta: {regression_report.new_count} new, "
                    f"{regression_report.resolved_count} resolved, "
                    f"{regression_report.recurring_count} recurring since last scan[/]"
                )
        except Exception as e:
            logger.warning(f"Failed to compute regression summary: {e}")

    # Output
    if output_format == "json":
        formatter = JSONFormatter()
        formatter.render(result)
    else:
        formatter_table = TableFormatter(console=console, verbose=verbose)
        formatter_table.render(result)

    # Save result
    if save_result:
        save_path = Path(save_result)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(
            json.dumps(result.model_dump(mode="json"), indent=2, default=str),
            encoding="utf-8",
        )
        console.print(f"\n[dim]Result saved to {save_result}[/]")

    # Exit code based on drift
    if result.has_drift and config.policy.fail_on_critical and result.critical_count > 0:
        raise typer.Exit(code=2)
