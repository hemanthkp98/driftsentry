"""Local state reader — reads .tfstate files from the local filesystem."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from driftsentry.core.models import ResourceState
from driftsentry.state.base import StateParseError, StateReader


class LocalStateReader(StateReader):
    """Reads Terraform/OpenTofu state from a local `.tfstate` JSON file.

    Supports state format version 4 (Terraform 0.12+).
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path).resolve()
        self._raw_state: dict[str, Any] | None = None

    def read_state(self) -> list[ResourceState]:
        """Parse the local .tfstate file and extract all managed resources."""
        raw = self.get_raw_state()
        return self._extract_resources(raw)

    def get_raw_state(self) -> dict[str, Any]:
        """Load and cache the raw JSON state."""
        if self._raw_state is not None:
            return self._raw_state

        if not self._path.exists():
            raise FileNotFoundError(f"State file not found: {self._path}")

        try:
            with open(self._path) as f:
                self._raw_state = json.load(f)
        except json.JSONDecodeError as e:
            raise StateParseError(str(e), source=str(self._path)) from e

        self._validate_state_format(self._raw_state)
        return self._raw_state

    @property
    def source_description(self) -> str:
        return f"local:{self._path}"

    def _validate_state_format(self, state: dict[str, Any]) -> None:
        """Validate that the state file is a supported format version."""
        version = state.get("version")
        if version is None:
            raise StateParseError("Missing 'version' field", source=str(self._path))
        if version != 4:
            raise StateParseError(
                f"Unsupported state format version {version} (expected 4)",
                source=str(self._path),
            )

    def _extract_resources(self, state: dict[str, Any]) -> list[ResourceState]:
        """Walk the state file and extract all managed resource instances."""
        resources: list[ResourceState] = []

        for resource_block in state.get("resources", []):
            mode = resource_block.get("mode", "managed")

            # Skip data sources — we only care about managed resources
            if mode != "managed":
                continue

            resource_type = resource_block.get("type", "")
            resource_name = resource_block.get("name", "")
            provider = resource_block.get("provider", "")
            module = resource_block.get("module")

            # Build the full resource address
            address = self._build_address(module, resource_type, resource_name)

            for instance in resource_block.get("instances", []):
                attributes = instance.get("attributes", {})
                sensitive_attrs = instance.get("sensitive_attributes", [])

                # Flatten sensitive_attributes from nested path format
                flat_sensitive = self._flatten_sensitive_paths(sensitive_attrs)

                resource_id = attributes.get("id")

                resources.append(
                    ResourceState(
                        address=address,
                        resource_type=resource_type,
                        resource_name=resource_name,
                        provider=provider,
                        mode=mode,
                        module=module,
                        resource_id=resource_id,
                        attributes=attributes,
                        sensitive_attributes=flat_sensitive,
                        dependencies=instance.get("dependencies", []),
                    )
                )

        return resources

    @staticmethod
    def _build_address(
        module: str | None,
        resource_type: str,
        resource_name: str,
    ) -> str:
        """Build a full Terraform resource address.

        Examples:
            - "aws_instance.web"
            - "module.vpc.aws_subnet.private"
        """
        base = f"{resource_type}.{resource_name}"
        if module:
            return f"{module}.{base}"
        return base

    @staticmethod
    def _flatten_sensitive_paths(sensitive_attrs: list[Any]) -> list[str]:
        """Convert Terraform's nested sensitive_attributes format to flat dot-notation paths.

        Terraform stores sensitive attributes as nested arrays like:
        [["password"], ["connection", 0, "password"]]

        We flatten these to: ["password", "connection.0.password"]
        """
        result: list[str] = []
        for path in sensitive_attrs:
            if isinstance(path, list):
                result.append(".".join(str(p) for p in path))
            elif isinstance(path, str):
                result.append(path)
        return result
