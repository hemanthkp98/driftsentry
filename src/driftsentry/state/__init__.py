"""State reading — parse Terraform/OpenTofu state from various backends."""

from driftsentry.state.auto_discovery import (
    DiscoveredState,
    StateDiscoveryError,
    apply_auto_discovered_state,
    discover_terraform_state,
    format_discovery_error,
    resolve_aws_region,
)
from driftsentry.state.base import StateReader
from driftsentry.state.factory import create_state_reader
from driftsentry.state.local import LocalStateReader
from driftsentry.state.s3 import S3StateReader

__all__ = [
    "DiscoveredState",
    "LocalStateReader",
    "S3StateReader",
    "StateDiscoveryError",
    "StateReader",
    "apply_auto_discovered_state",
    "create_state_reader",
    "discover_terraform_state",
    "format_discovery_error",
    "resolve_aws_region",
]
