"""AWS provider — main implementation for scanning AWS resources."""

from __future__ import annotations

import importlib
import logging
from typing import Any

import boto3

# Ensure built-in scanners are imported so their @register_scanner decorators run
import driftsentry.providers.aws.resources  # noqa: F401
from driftsentry.core.models import CloudResource
from driftsentry.providers.aws.catalog import ResourceCatalog
from driftsentry.providers.aws.declarative import GenericAWSDeclarativeScanner
from driftsentry.providers.base import (
    CloudProvider,
    ResourceScanner,
    get_registered_scanners,
)

logger = logging.getLogger(__name__)


class AWSProvider(CloudProvider):
    """AWS cloud provider implementation.

    Supports both specialized Python scanners and declarative YAML-defined
    scanners via Boto3 dynamic discovery and JMESPath attribute normalization.
    """

    def __init__(
        self,
        region: str | None = None,
        profile: str | None = None,
        role_arn: str | None = None,
        custom_resources: dict[str, Any] | None = None,
        resource_definitions_dirs: list[str] | None = None,
        plugins: list[str] | None = None,
    ) -> None:
        self._session = self._create_session(region, profile, role_arn)
        self._region = region or self._session.region_name or "us-east-1"
        self._custom_resources = custom_resources or {}
        self._resource_definitions_dirs = resource_definitions_dirs or []
        self._plugins = plugins or []
        self._scanners: dict[str, ResourceScanner] = {}
        self._register_scanners()

    @property
    def provider_name(self) -> str:
        return "aws"

    def supported_resource_types(self) -> list[str]:
        """Return all Terraform resource types that this provider can scan."""
        types: list[str] = []
        for scanner in self._scanners.values():
            types.extend(scanner.resource_types)
        return sorted(set(types))

    def list_resources(self, resource_type: str) -> list[CloudResource]:
        """List all resources of a given Terraform type in AWS."""
        scanner = self._get_scanner(resource_type)
        if scanner is None:
            logger.warning(f"No scanner registered for resource type: {resource_type}")
            return []

        try:
            return scanner.list_all()
        except Exception as e:
            logger.error(f"Error scanning {resource_type}: {e}")
            return []

    def get_resource(self, resource_type: str, resource_id: str) -> CloudResource | None:
        """Get a specific AWS resource by its ID."""
        scanner = self._get_scanner(resource_type)
        if scanner is None:
            return None

        try:
            return scanner.get_by_id(resource_id)
        except Exception as e:
            logger.error(f"Error getting {resource_type}/{resource_id}: {e}")
            return None

    def normalize_attributes(
        self, resource_type: str, cloud_attrs: dict[str, Any]
    ) -> dict[str, Any]:
        """Normalize AWS API attributes to match Terraform state format."""
        scanner = self._get_scanner(resource_type)
        if scanner is None:
            return cloud_attrs
        return scanner.normalize(cloud_attrs)

    def _register_scanners(self) -> None:
        """Register all built-in, plugin, and declarative resource scanners."""
        # 1. Load external Python plugins
        for plugin_mod in self._plugins:
            try:
                importlib.import_module(plugin_mod)
                logger.info(f"Loaded DriftSentry plugin module: {plugin_mod}")
            except Exception as e:
                logger.error(f"Failed to load plugin '{plugin_mod}': {e}")

        # 2. Register Python scanners from the registry
        for scanner_cls in get_registered_scanners("aws"):
            try:
                scanner = scanner_cls(self._session, self._region)
                for rtype in scanner.resource_types:
                    self._scanners[rtype] = scanner
            except Exception as e:
                logger.error(f"Failed to initialize scanner {scanner_cls.__name__}: {e}")

        # 3. Load declarative YAML resource definitions (built-in and custom)
        catalog = ResourceCatalog(
            custom_dirs=self._resource_definitions_dirs,
            inline_specs=self._custom_resources,
        )
        declarative_specs = catalog.load_all()

        for tf_type, spec in declarative_specs.items():
            # Specialized Python scanners take precedence if already registered
            if tf_type not in self._scanners:
                dec_scanner = GenericAWSDeclarativeScanner(self._session, self._region, spec)
                self._scanners[tf_type] = dec_scanner

    def _get_scanner(self, resource_type: str) -> ResourceScanner | None:
        """Look up the scanner for a given Terraform resource type."""
        return self._scanners.get(resource_type)

    @staticmethod
    def _create_session(
        region: str | None,
        profile: str | None,
        role_arn: str | None,
    ) -> boto3.Session:
        """Create a boto3 session with optional role assumption."""
        session_kwargs: dict[str, Any] = {}
        if profile:
            session_kwargs["profile_name"] = profile
        if region:
            session_kwargs["region_name"] = region

        session = boto3.Session(**session_kwargs)

        if role_arn:
            sts = session.client("sts")
            assumed = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="driftsentry-scanner",
            )
            creds = assumed["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )

        return session
