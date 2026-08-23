"""AWS Resource Catalog Loader.

Discovers and loads declarative resource definitions from:
1. Built-in package YAML directory (`driftsentry/resources/aws/*.yaml`)
2. User-configured resource definition directories (`resource_definitions_dirs`)
3. Inline custom resource specifications in `.driftsentry.yaml`
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from driftsentry.attribution.cloudtrail import register_resource_events
from driftsentry.providers.aws.mapping import ResourceTypeMapping, register_mapping
from driftsentry.providers.base import DeclarativeResourceSpec

logger = logging.getLogger(__name__)

BUILTIN_RESOURCES_DIR = Path(__file__).parent.parent.parent / "resources" / "aws"


class ResourceCatalog:
    """Manages discovery and registration of declarative AWS resource specifications."""

    def __init__(
        self,
        custom_dirs: Sequence[str | Path] | None = None,
        inline_specs: dict[str, Any] | None = None,
    ) -> None:
        self._custom_dirs = [Path(p).expanduser().resolve() for p in (custom_dirs or [])]
        self._inline_specs = inline_specs or {}
        self._specs: dict[str, DeclarativeResourceSpec] = {}

    def load_all(self) -> dict[str, DeclarativeResourceSpec]:
        """Load all built-in, directory, and inline resource specifications.

        Returns:
            Dict mapping Terraform resource type to DeclarativeResourceSpec.
        """
        # 1. Load built-in YAML specs
        if BUILTIN_RESOURCES_DIR.exists():
            self._load_from_directory(BUILTIN_RESOURCES_DIR)

        # 2. Load custom directories
        for directory in self._custom_dirs:
            if directory.exists() and directory.is_dir():
                self._load_from_directory(directory)
            else:
                logger.debug(f"Custom resource directory not found: {directory}")

        # 3. Load inline specs from config
        for tf_type, raw_spec in self._inline_specs.items():
            try:
                spec_dict = dict(raw_spec)
                if "terraform_type" not in spec_dict:
                    spec_dict["terraform_type"] = tf_type
                spec = DeclarativeResourceSpec(**spec_dict)
                self._register_spec(spec)
            except Exception as e:
                logger.error(f"Failed to parse inline custom resource '{tf_type}': {e}")

        return self._specs

    def _load_from_directory(self, directory: Path) -> None:
        """Load all .yaml and .yml files from a directory."""
        for file_path in sorted(directory.glob("*.y*ml")):
            try:
                with open(file_path, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if not isinstance(data, dict):
                    continue

                # Support both single-spec and multi-spec YAML documents
                if "terraform_type" in data:
                    spec = DeclarativeResourceSpec(**data)
                    self._register_spec(spec)
                elif "resources" in data and isinstance(data["resources"], list):
                    for item in data["resources"]:
                        if isinstance(item, dict):
                            spec = DeclarativeResourceSpec(**item)
                            self._register_spec(spec)
            except Exception as e:
                logger.warning(f"Error loading resource definition from {file_path}: {e}")

    def _register_spec(self, spec: DeclarativeResourceSpec) -> None:
        """Store the spec and update global mappings and CloudTrail registries."""
        self._specs[spec.terraform_type] = spec

        # Register in mapping.py
        mapping = ResourceTypeMapping(
            terraform_type=spec.terraform_type,
            aws_service=spec.service,
            description=spec.description or spec.terraform_type,
            security_critical_attributes=spec.security_critical,
            noise_attributes=spec.noise_attributes,
        )
        register_mapping(mapping)

        # Register in cloudtrail.py
        if spec.cloudtrail_events:
            register_resource_events(spec.terraform_type, spec.cloudtrail_events)
