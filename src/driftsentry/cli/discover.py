"""Discover command — scan and list live cloud resources without IaC state."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import typer
from rich.console import Console

from driftsentry.core.config import AccountConfig, load_config
from driftsentry.discovery.engine import DiscoveryEngine
from driftsentry.discovery.table import DiscoveryTableFormatter
from driftsentry.providers.aws.provider import AWSProvider

logger = logging.getLogger(__name__)
console = Console()


def discover(
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
        help="Primary cloud region to scan (e.g. us-east-1)",
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
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed output including ARNs and resource tags",
    ),
    save_result: str | None = typer.Option(
        None,
        "--save",
        help="Save discovery result to JSON file",
    ),
    config_file: str | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to .driftsentry.yaml config file",
    ),
) -> None:
    """Discover and list live cloud resources in an AWS account across regions.

    Runs standalone discovery without requiring any Terraform/OpenTofu state files.

    Examples:

        # Scan a single region
        driftsentry discover --region us-east-1

        # Scan multiple regions
        driftsentry discover --regions us-east-1,us-west-2

        # Filter by specific resource types
        driftsentry discover --region us-east-1 --include-types aws_s3_bucket,aws_instance

        # Cross-account scanning
        driftsentry discover --accounts 111122223333,444455556666 --role-arn-template "arn:aws:iam::{account_id}:role/DriftSentry"

        # Output machine-readable JSON
        driftsentry discover --region us-east-1 -o json --save inventory.json
    """
    # Load optional config file
    config = load_config(config_file)

    # CLI overrides
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

    resolved_include_types: list[str] | None = None
    if include_types:
        resolved_include_types = [t.strip() for t in include_types.split(",") if t.strip()]
    elif config.filters.include_types:
        resolved_include_types = list(config.filters.include_types)

    resolved_exclude_types: list[str] | None = None
    if exclude_types:
        resolved_exclude_types = [t.strip() for t in exclude_types.split(",") if t.strip()]
    elif config.filters.exclude_types:
        resolved_exclude_types = list(config.filters.exclude_types)

    # Initialize cloud provider
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
        console.print(f"[bold red]Error:[/] Unsupported provider: {provider}")
        raise typer.Exit(code=1)

    # Execute discovery
    engine = DiscoveryEngine(
        provider=cloud_provider,
        include_types=resolved_include_types,
        exclude_types=resolved_exclude_types,
        filters=config.filters,
    )

    try:
        result = engine.discover(show_progress=output_format == "table")
    except Exception as e:
        console.print(f"[bold red]Error during discovery:[/] {e}")
        raise typer.Exit(code=1) from None

    # Render output
    if output_format == "json":
        json_output = json.dumps(result.model_dump(mode="json"), indent=2, default=str)
        console.print(json_output)
    else:
        formatter = DiscoveryTableFormatter(console=console, verbose=verbose)
        formatter.render(result)

    # Save to file if requested
    if save_result:
        save_path = Path(save_result)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(
            json.dumps(result.model_dump(mode="json"), indent=2, default=str),
            encoding="utf-8",
        )
        if output_format != "json":
            console.print(f"[dim]Discovery result saved to {save_result}[/]")
