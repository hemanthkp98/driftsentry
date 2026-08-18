"""Factory for creating state readers based on backend configuration."""

from __future__ import annotations

from driftsentry.core.config import DriftSentryConfig
from driftsentry.core.models import StateBackendType
from driftsentry.state.base import StateReader
from driftsentry.state.local import LocalStateReader
from driftsentry.state.s3 import S3StateReader


def create_state_reader(config: DriftSentryConfig) -> StateReader:
    """Create the appropriate StateReader based on the configuration.

    Args:
        config: DriftSentry configuration with state backend settings.

    Returns:
        A StateReader implementation for the configured backend.

    Raises:
        ValueError: If the backend type is unsupported or misconfigured.
    """
    backend = config.state.backend

    if backend == StateBackendType.LOCAL:
        if not config.state.path:
            raise ValueError(
                "State backend is 'local' but no state file path was provided. "
                "Set 'state.path' in .driftsentry.yaml or use --state-file."
            )
        return LocalStateReader(path=config.state.path)

    if backend == StateBackendType.S3:
        if not config.state.s3_bucket or not config.state.s3_key:
            raise ValueError(
                "State backend is 's3' but bucket/key not provided. "
                "Set 'state.s3_bucket' and 'state.s3_key' in .driftsentry.yaml."
            )
        return S3StateReader(
            bucket=config.state.s3_bucket,
            key=config.state.s3_key,
            region=config.state.s3_region or config.provider.region,
            profile=config.provider.profile,
            role_arn=config.provider.role_arn,
        )

    raise ValueError(f"Unsupported state backend: {backend}")
