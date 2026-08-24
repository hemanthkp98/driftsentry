"""JSON formatter — machine-readable output."""

from __future__ import annotations

import json
import sys
from typing import IO

from driftsentry.core.models import DriftResult


class JSONFormatter:
    """Renders drift scan results as JSON for machine consumption and piping."""

    def __init__(self, pretty: bool = True) -> None:
        self.pretty = pretty

    def render(self, result: DriftResult, output: IO[str] | None = None) -> str:
        """Render drift result as JSON string.

        Args:
            result: The drift scan result.
            output: Optional file-like object to write to. Defaults to stdout.

        Returns:
            The JSON string.
        """
        data = result.model_dump(mode="json")
        self._redact_sensitive_resources(data)
        indent = 2 if self.pretty else None
        json_str = json.dumps(data, indent=indent, default=str, sort_keys=False)

        if output:
            output.write(json_str)
            output.write("\n")
        else:
            sys.stdout.write(json_str)
            sys.stdout.write("\n")

        return json_str

    @staticmethod
    def _redact_sensitive_resources(data: dict[str, object]) -> None:
        """Redact sensitive state paths before emitting machine-readable output."""
        drift_items = data.get("drift_items")
        if not isinstance(drift_items, list):
            return

        for item in drift_items:
            if not isinstance(item, dict):
                continue
            state_resource = item.get("state_resource")
            if not isinstance(state_resource, dict):
                continue
            sensitive = state_resource.get("sensitive_attributes", [])
            attributes = state_resource.get("attributes")
            if not isinstance(sensitive, list) or not isinstance(attributes, dict):
                continue
            for path in sensitive:
                if isinstance(path, str):
                    JSONFormatter._redact_path(attributes, path.split("."))

            cloud_resource = item.get("cloud_resource")
            if isinstance(cloud_resource, dict) and isinstance(cloud_resource.get("attributes"), dict):
                for path in sensitive:
                    if isinstance(path, str):
                        JSONFormatter._redact_path(
                            cloud_resource["attributes"], path.split(".")
                        )

    @staticmethod
    def _redact_path(attributes: dict[str, object], path: list[str]) -> None:
        """Replace a nested attribute value with a non-sensitive marker."""
        current: object = attributes
        for part in path[:-1]:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list) and part.isdigit():
                index = int(part)
                current = current[index] if index < len(current) else None
            else:
                return
        if not path:
            return
        final = path[-1]
        if isinstance(current, dict) and final in current:
            current[final] = "[REDACTED]"
        elif isinstance(current, list) and final.isdigit():
            index = int(final)
            if index < len(current):
                current[index] = "[REDACTED]"
