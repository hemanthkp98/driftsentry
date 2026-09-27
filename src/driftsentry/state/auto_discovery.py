"""Terraform and OpenTofu state auto-discovery.

Automatically detects Terraform state in the current working directory or
parent directories up to the git repository root. Supports:
  - Remote backends (e.g. S3 configured in .terraform/terraform.tfstate)
  - Local state (terraform.tfstate or *.tfstate)
  - AWS region auto-resolution hierarchy:
      backend region -> AWS_REGION -> AWS_DEFAULT_REGION -> us-east-1
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from driftsentry.core.config import DriftSentryConfig
from driftsentry.core.models import StateBackendType

logger = logging.getLogger(__name__)

DEFAULT_REGION = "us-east-1"


@dataclass
class DiscoveredState:
    """Represents auto-discovered Terraform state configuration."""

    backend: StateBackendType
    path: Path | None = None
    s3_bucket: str | None = None
    s3_key: str | None = None
    s3_region: str | None = None
    region: str = DEFAULT_REGION
    workspace_dir: Path | None = None

    @property
    def summary(self) -> str:
        """Human-readable summary of discovered state."""
        if self.backend == StateBackendType.LOCAL:
            return f"local ({self.path})"
        if self.backend == StateBackendType.S3:
            region_info = f" (region: {self.region})" if self.region else ""
            return f"s3://{self.s3_bucket}/{self.s3_key}{region_info}"
        return f"{self.backend.value}"


class StateDiscoveryError(FileNotFoundError):
    """Raised when auto-discovery fails to find any Terraform state or workspace."""

    def __init__(self, message: str, checked_paths: list[Path]) -> None:
        super().__init__(message)
        self.checked_paths = checked_paths


def resolve_aws_region(backend_region: str | None = None) -> str:
    """Resolve the AWS region using the fallback hierarchy.

    Hierarchy:
        1. Backend region (from .terraform backend config)
        2. AWS_REGION environment variable
        3. AWS_DEFAULT_REGION environment variable
        4. Default fallback: 'us-east-1'
    """
    if backend_region and backend_region.strip():
        return backend_region.strip()

    env_region = os.environ.get("AWS_REGION")
    if env_region and env_region.strip():
        return env_region.strip()

    env_default_region = os.environ.get("AWS_DEFAULT_REGION")
    if env_default_region and env_default_region.strip():
        return env_default_region.strip()

    return DEFAULT_REGION


def find_git_root(start_dir: Path) -> Path | None:
    """Find the root directory of the enclosing git repository, if any."""
    current = start_dir.resolve()
    for directory in [current, *current.parents]:
        if (directory / ".git").exists():
            return directory
    return None


def get_search_directories(start_dir: Path) -> list[Path]:
    """Get the sequence of directories to search from start_dir up to git root."""
    resolved_start = start_dir.resolve()
    git_root = find_git_root(resolved_start)

    dirs: list[Path] = []
    curr: Path | None = resolved_start
    while curr is not None:
        dirs.append(curr)
        if git_root is not None and curr == git_root:
            break
        if curr.parent == curr:
            break
        if git_root is None:
            # If not in a git repo, only check start_dir
            break
        curr = curr.parent

    return dirs


def _inspect_terraform_meta(
    tf_state_meta: Path,
    workspace_dir: Path,
) -> DiscoveredState | None:
    """Parse .terraform/terraform.tfstate to detect backend configuration."""
    try:
        with open(tf_state_meta, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.debug("Failed to parse %s: %s", tf_state_meta, e)
        return None

    if not isinstance(data, dict):
        return None

    backend = data.get("backend")
    if not isinstance(backend, dict):
        return None

    backend_type = backend.get("type")
    backend_config = backend.get("config")
    if not isinstance(backend_config, dict):
        backend_config = {}

    if backend_type == "s3":
        bucket = backend_config.get("bucket")
        key = backend_config.get("key")
        backend_region = backend_config.get("region")

        if bucket and key:
            resolved_region = resolve_aws_region(backend_region)
            return DiscoveredState(
                backend=StateBackendType.S3,
                s3_bucket=str(bucket),
                s3_key=str(key),
                s3_region=str(backend_region) if backend_region else None,
                region=resolved_region,
                workspace_dir=workspace_dir,
            )

    elif backend_type == "local":
        path_str = backend_config.get("path")
        if path_str:
            candidate = (workspace_dir / path_str).resolve()
            if candidate.is_file():
                return DiscoveredState(
                    backend=StateBackendType.LOCAL,
                    path=candidate,
                    region=resolve_aws_region(None),
                    workspace_dir=workspace_dir,
                )

    return None


def discover_terraform_state(start_dir: Path | str | None = None) -> DiscoveredState:
    """Inspect current directory and parent directories up to git root for Terraform state.

    Checks each directory in order:
      1. Remote backend: .terraform/terraform.tfstate (S3 backend bucket, key, region)
      2. Local state: terraform.tfstate or *.tfstate

    Args:
        start_dir: Starting directory (defaults to current working directory).

    Returns:
        DiscoveredState containing the detected backend and region configuration.

    Raises:
        StateDiscoveryError: If no Terraform state or remote backend is found.
    """
    target_dir = Path(start_dir).resolve() if start_dir else Path.cwd().resolve()
    search_dirs = get_search_directories(target_dir)

    checked_paths: list[Path] = []

    for d in search_dirs:
        # 1. Check for remote backend in .terraform/terraform.tfstate
        tf_state_meta = d / ".terraform" / "terraform.tfstate"
        checked_paths.append(tf_state_meta)

        if tf_state_meta.is_file():
            discovered = _inspect_terraform_meta(tf_state_meta, workspace_dir=d)
            if discovered is not None:
                return discovered

        # 2. Check for local state: terraform.tfstate
        local_tfstate = d / "terraform.tfstate"
        checked_paths.append(local_tfstate)

        if local_tfstate.is_file():
            region = resolve_aws_region(None)
            return DiscoveredState(
                backend=StateBackendType.LOCAL,
                path=local_tfstate,
                region=region,
                workspace_dir=d,
            )

        # 3. Check for any other *.tfstate in d
        other_states = sorted(
            [
                p
                for p in d.glob("*.tfstate")
                if p.is_file() and not p.name.startswith(".") and p != local_tfstate
            ]
        )
        if other_states:
            selected = other_states[0]
            region = resolve_aws_region(None)
            return DiscoveredState(
                backend=StateBackendType.LOCAL,
                path=selected,
                region=region,
                workspace_dir=d,
            )

    msg = (
        "No Terraform state file or remote backend configuration discovered in "
        f"'{target_dir}' or its parent directories up to git root."
    )
    raise StateDiscoveryError(msg, checked_paths=checked_paths)


def apply_auto_discovered_state(
    config: DriftSentryConfig,
    discovered: DiscoveredState,
) -> None:
    """Apply auto-discovered state configuration to DriftSentryConfig."""
    config.state.backend = discovered.backend
    if discovered.backend == StateBackendType.LOCAL:
        if discovered.path:
            config.state.path = str(discovered.path)
    elif discovered.backend == StateBackendType.S3:
        config.state.s3_bucket = discovered.s3_bucket
        config.state.s3_key = discovered.s3_key
        config.state.s3_region = discovered.s3_region or discovered.region

    # Set cloud provider region if not explicitly configured
    if not config.provider.region:
        config.provider.region = discovered.region


def format_discovery_error(err: StateDiscoveryError) -> str:
    """Format a user-friendly error message showing checked paths and remediation tips."""
    lines = [
        "[bold red]Error:[/] No Terraform state file or remote backend configuration discovered.",
        "\n[bold]Checked paths (searched up to git root):[/]",
    ]
    for p in err.checked_paths:
        lines.append(f"  • [dim]{p}[/]")
    lines.append(
        "\n[bold yellow]To fix this:[/] Run driftsentry inside a Terraform workspace, or specify:\n"
        "  • [bold]--state-file <path>[/] for local state\n"
        "  • [bold]--state-backend s3 --s3-bucket <bucket> --s3-key <key>[/] for S3 remote state\n"
        "  • Configure [bold]state.path[/] or [bold]state.s3_bucket[/] in [bold].driftsentry.yaml[/]"
    )
    return "\n".join(lines)
