"""Configuration management for DriftSentry.

Loads and validates configuration from `.driftsentry.yaml` files,
environment variables, and CLI arguments (in order of precedence).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from driftsentry.core.models import IaCTool, RemediationMode, StateBackendType

# ─── Default Config Filename ────────────────────────────────────

CONFIG_FILENAME = ".driftsentry.yaml"
DEFAULT_CONFIG_PATHS = [
    Path.cwd() / CONFIG_FILENAME,
    Path.home() / CONFIG_FILENAME,
]


# ─── Config Models ──────────────────────────────────────────────


class StateConfig(BaseModel):
    """Configuration for reading Terraform/OpenTofu state."""

    backend: StateBackendType = Field(default=StateBackendType.LOCAL)
    path: str | None = Field(default=None, description="Local path to .tfstate file")
    s3_bucket: str | None = Field(default=None, description="S3 bucket for remote state")
    s3_key: str | None = Field(default=None, description="S3 key (path) for remote state")
    s3_region: str | None = Field(default=None, description="S3 bucket region")


class ProviderConfig(BaseModel):
    """Configuration for cloud provider access."""

    name: str = Field(default="aws", description="Cloud provider name")
    region: str | None = Field(default=None, description="Cloud region to scan")
    profile: str | None = Field(default=None, description="AWS profile name")
    role_arn: str | None = Field(default=None, description="AWS role ARN to assume")


class AttributionConfig(BaseModel):
    """Configuration for drift attribution via audit logs."""

    enabled: bool = Field(default=True, description="Enable drift attribution")
    lookback_hours: int = Field(
        default=168,
        description="How far back to look in audit logs (default: 7 days)",
    )


class PolicyConfig(BaseModel):
    """Configuration for the policy engine."""

    enabled: bool = Field(default=True, description="Enable policy evaluation")
    policy_file: str | None = Field(
        default=None,
        description="Path to policy rules YAML file",
    )
    fail_on_critical: bool = Field(
        default=True,
        description="Exit with non-zero code if critical drift is found",
    )


class RemediationConfig(BaseModel):
    """Configuration for auto-remediation."""

    mode: RemediationMode = Field(
        default=RemediationMode.BOTH,
        description="Remediation mode: import, revert, or both",
    )
    output_dir: str = Field(
        default="./driftsentry-remediation",
        description="Directory to write remediation artifacts",
    )
    create_pr: bool = Field(default=False, description="Automatically create a PR")
    github_repo: str | None = Field(
        default=None,
        description="GitHub repo (owner/name) for PR creation",
    )
    github_token: str | None = Field(
        default=None,
        description="GitHub token (or set GITHUB_TOKEN env var)",
    )
    pr_base_branch: str = Field(
        default="main",
        description="Base branch for PRs",
    )
    dry_run: bool = Field(
        default=False,
        description="Preview remediation without writing files or creating PRs",
    )


class NotificationConfig(BaseModel):
    """Configuration for notifications."""

    slack_webhook_url: str | None = Field(
        default=None,
        description="Slack webhook URL for drift alerts",
    )
    notify_on: list[str] = Field(
        default_factory=lambda: ["critical", "high"],
        description="Severity levels that trigger notifications",
    )


class ScanFilters(BaseModel):
    """Filters to include/exclude resources from scanning."""

    include_types: list[str] = Field(
        default_factory=list,
        description="Only scan these resource types (empty = all)",
    )
    exclude_types: list[str] = Field(
        default_factory=list,
        description="Exclude these resource types from scanning",
    )
    ignore_attributes: list[str] = Field(
        default_factory=lambda: [
            "tags_all",
            "arn",
            "id",
            "owner_id",
            "unique_id",
            "create_date",
            "last_modified",
        ],
        description="Attributes to ignore during diff (noise reduction)",
    )
    ignore_unmanaged_types: list[str] = Field(
        default_factory=list,
        description="Resource types to exclude from unmanaged detection",
    )


class LLMConfig(BaseModel):
    """Configuration for AI-powered smart remediation."""

    enabled: bool = Field(default=False, description="Enable AI-powered smart remediation")
    provider: str = Field(default="claude", description="LLM provider ('claude' or 'gemini')")
    model: str | None = Field(default=None, description="Override default LLM model name")
    max_items: int = Field(
        default=20, description="Maximum number of drift items to process with AI"
    )
    thinking_budget: int = Field(default=5000, description="Token budget for LLM extended thinking")


class DriftSentryConfig(BaseModel):
    """Root configuration for DriftSentry."""

    iac_tool: IaCTool = Field(
        default=IaCTool.TERRAFORM, description="IaC tool: terraform or opentofu"
    )
    state: StateConfig = Field(default_factory=StateConfig)
    provider: ProviderConfig = Field(default_factory=ProviderConfig)
    attribution: AttributionConfig = Field(default_factory=AttributionConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    remediation: RemediationConfig = Field(default_factory=RemediationConfig)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)
    filters: ScanFilters = Field(default_factory=ScanFilters)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    verbose: bool = Field(default=False, description="Enable verbose output")


# ─── Config Loading ─────────────────────────────────────────────


def find_config_file() -> Path | None:
    """Search for a `.driftsentry.yaml` config file in standard locations."""
    for path in DEFAULT_CONFIG_PATHS:
        if path.exists():
            return path
    return None


def load_config(config_path: str | Path | None = None) -> DriftSentryConfig:
    """Load configuration from a YAML file, falling back to defaults.

    Priority (highest to lowest):
    1. Explicit config_path argument
    2. Environment variable DRIFTSENTRY_CONFIG
    3. .driftsentry.yaml in current directory
    4. .driftsentry.yaml in home directory
    5. Default values
    """
    resolved_path: Path | None = None

    if config_path:
        resolved_path = Path(config_path)
    elif env_path := os.environ.get("DRIFTSENTRY_CONFIG"):
        resolved_path = Path(env_path)
    else:
        resolved_path = find_config_file()

    if resolved_path and resolved_path.exists():
        return _load_from_yaml(resolved_path)

    return DriftSentryConfig()


def _load_from_yaml(path: Path) -> DriftSentryConfig:
    """Parse a YAML config file into a DriftSentryConfig."""
    with open(path) as f:
        raw: dict[str, Any] = yaml.safe_load(f) or {}

    # Resolve GitHub token from env var if not set in config
    remediation = raw.get("remediation", {})
    if not remediation.get("github_token"):
        remediation["github_token"] = os.environ.get("GITHUB_TOKEN")
        raw["remediation"] = remediation

    # Resolve Slack webhook from env var if not set in config
    notifications = raw.get("notifications", {})
    if not notifications.get("slack_webhook_url"):
        notifications["slack_webhook_url"] = os.environ.get("DRIFTSENTRY_SLACK_WEBHOOK")
        raw["notifications"] = notifications

    return DriftSentryConfig(**raw)
