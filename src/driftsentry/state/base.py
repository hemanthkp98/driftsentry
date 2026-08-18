"""Abstract base class for state readers.

All state backend implementations (local, S3, GCS, etc.) must
implement the `StateReader` interface defined here.
"""

from __future__ import annotations

import abc
from typing import Any

from driftsentry.core.models import ResourceState


class StateReader(abc.ABC):
    """Abstract interface for reading Terraform/OpenTofu state files."""

    @abc.abstractmethod
    def read_state(self) -> list[ResourceState]:
        """Read and parse the state file, returning a list of managed resources.

        Returns:
            List of ResourceState objects representing all managed resources.

        Raises:
            FileNotFoundError: If the state file does not exist.
            StateParseError: If the state file is malformed.
        """
        ...

    @abc.abstractmethod
    def get_raw_state(self) -> dict[str, Any]:
        """Return the raw parsed JSON state as a dictionary.

        Useful for debugging or when full state access is needed.
        """
        ...

    @property
    @abc.abstractmethod
    def source_description(self) -> str:
        """Human-readable description of the state source for logging."""
        ...


class StateParseError(Exception):
    """Raised when a state file cannot be parsed."""

    def __init__(self, message: str, source: str | None = None) -> None:
        self.source = source
        super().__init__(f"Failed to parse state from {source}: {message}" if source else message)
