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
        indent = 2 if self.pretty else None
        json_str = json.dumps(data, indent=indent, default=str, sort_keys=False)

        if output:
            output.write(json_str)
            output.write("\n")
        else:
            sys.stdout.write(json_str)
            sys.stdout.write("\n")

        return json_str
