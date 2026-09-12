"""Executable module entrypoint for DriftSentry.

Enables running DriftSentry directly via:
    python -m driftsentry [args]
or
    py -m driftsentry [args] (on Windows)
"""

from __future__ import annotations

from driftsentry.cli.main import app


def main() -> None:
    """Execute DriftSentry CLI."""
    app()


if __name__ == "__main__":
    main()
