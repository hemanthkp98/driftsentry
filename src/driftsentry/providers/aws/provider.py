"""AWS provider — main implementation for scanning AWS resources."""

from __future__ import annotations

import concurrent.futures
import importlib
import logging
from typing import Any

import boto3

# Ensure built-in scanners are imported so their @register_scanner decorators run
import driftsentry.providers.aws.resources  # noqa: F401
from driftsentry.core.config import AccountConfig
from driftsentry.core.models import CloudResource
from driftsentry.providers.aws.catalog import ResourceCatalog
from driftsentry.providers.aws.declarative import GenericAWSDeclarativeScanner
from driftsentry.providers.aws.target import ScanTarget, TargetResolver
from driftsentry.providers.base import (
    CloudProvider,
    ResourceScanner,
    get_registered_scanners,
)

logger = logging.getLogger(__name__)

# Resource types that are global to an AWS account (not per-region)
GLOBAL_RESOURCE_TYPES: set[str] = {
    "aws_iam_role",
    "aws_iam_policy",
    "aws_iam_user",
    "aws_route53_zone",
    "aws_cloudfront_distribution",
}


class AWSProvider(CloudProvider):
    """AWS cloud provider implementation.

    Supports single-target and multi-account / multi-region scanning,
    specialized Python scanners, declarative YAML-defined scanners,
    and automatic deduplication for global services.
    """

    def __init__(
        self,
        region: str | None = None,
        regions: list[str] | None = None,
        profile: str | None = None,
        role_arn: str | None = None,
        accounts: list[AccountConfig] | None = None,
        role_arn_template: str | None = None,
        custom_resources: dict[str, Any] | None = None,
        resource_definitions_dirs: list[str] | None = None,
        plugins: list[str] | None = None,
        concurrency: int = 4,
    ) -> None:
        self._custom_resources = custom_resources or {}
        self._resource_definitions_dirs = resource_definitions_dirs or []
        self._plugins = plugins or []
        self._concurrency = max(1, concurrency)

        # Load plugins first so any decorators run
        self._load_plugins()

        # Resolve all (Account, Region) scan targets
        resolver = TargetResolver(
            region=region,
            regions=regions,
            profile=profile,
            role_arn=role_arn,
            accounts=accounts,
            role_arn_template=role_arn_template,
        )
        self._targets: list[ScanTarget] = resolver.resolve_targets()

        # Primary region for single-target backwards compatibility
        self._region = region or (self._targets[0].region if self._targets else "us-east-1")

        # Map target_id -> { resource_type -> ResourceScanner }
        self._target_scanners: dict[str, dict[str, ResourceScanner]] = {}
        self._init_target_scanners()

    @property
    def provider_name(self) -> str:
        return "aws"

    @property
    def targets(self) -> list[ScanTarget]:
        """All resolved scan targets."""
        return self._targets

    @property
    def scanned_regions(self) -> list[str]:
        """List of all distinct regions being scanned."""
        seen: set[str] = set()
        regions: list[str] = []
        for t in self._targets:
            if t.region not in seen:
                seen.add(t.region)
                regions.append(t.region)
        return regions

    @property
    def scanned_accounts(self) -> list[str]:
        """List of all distinct account identifiers being scanned."""
        seen: set[str] = set()
        accounts: list[str] = []
        for t in self._targets:
            key = t.account_key
            if key not in seen:
                seen.add(key)
                accounts.append(key)
        return accounts

    def supported_resource_types(self) -> list[str]:
        """Return all Terraform resource types that this provider can scan."""
        types: set[str] = set()
        for scanners_dict in self._target_scanners.values():
            for scanner in scanners_dict.values():
                types.update(scanner.resource_types)
        return sorted(types)

    def list_resources(self, resource_type: str) -> list[CloudResource]:
        """List all resources of a given Terraform type across all targets.

        Executes queries concurrently across targets using a thread pool.
        Global services (e.g., IAM) are queried only once per account.
        """
        targets_to_query = self._get_targets_for_type(resource_type)
        if not targets_to_query:
            logger.warning(f"No targets or scanners registered for resource type: {resource_type}")
            return []

        # If single target, run synchronously
        if len(targets_to_query) == 1:
            return self._scan_target(targets_to_query[0], resource_type)

        # Run concurrently across multiple targets
        all_resources: list[CloudResource] = []
        max_workers = min(self._concurrency, len(targets_to_query))

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {
                executor.submit(self._scan_target, target, resource_type): target
                for target in targets_to_query
            }
            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    res_list = future.result()
                    all_resources.extend(res_list)
                except Exception as e:
                    logger.error(
                        f"Error scanning {resource_type} on target {target.target_id}: {e}"
                    )

        return all_resources

    def get_resource(self, resource_type: str, resource_id: str) -> CloudResource | None:
        """Get a specific AWS resource by its ID across targets."""
        # Check if ARN contains region/account hints to prioritize matching target
        prioritized_targets = self._prioritize_targets_for_id(resource_id)

        for target in prioritized_targets:
            scanners = self._target_scanners.get(target.target_id, {})
            scanner = scanners.get(resource_type)
            if scanner is None:
                continue

            try:
                res = scanner.get_by_id(resource_id)
                if res is not None:
                    self._enrich_resource(res, target)
                    return res
            except Exception as e:
                logger.error(
                    f"Error getting {resource_type}/{resource_id} on {target.target_id}: {e}"
                )

        return None

    def normalize_attributes(
        self, resource_type: str, cloud_attrs: dict[str, Any]
    ) -> dict[str, Any]:
        """Normalize AWS API attributes to match Terraform state format."""
        for scanners in self._target_scanners.values():
            scanner = scanners.get(resource_type)
            if scanner is not None:
                return scanner.normalize(cloud_attrs)
        return cloud_attrs

    def _scan_target(self, target: ScanTarget, resource_type: str) -> list[CloudResource]:
        """Scan a single target for a resource type and enrich results."""
        scanners = self._target_scanners.get(target.target_id, {})
        scanner = scanners.get(resource_type)
        if scanner is None:
            return []

        try:
            resources = scanner.list_all()
            for res in resources:
                self._enrich_resource(res, target)
            return resources
        except Exception as e:
            logger.error(f"Error scanning {resource_type} on target {target.target_id}: {e}")
            raise

    def _get_targets_for_type(self, resource_type: str) -> list[ScanTarget]:
        """Determine targets to query, deduplicating global services to 1 per account."""
        if resource_type in GLOBAL_RESOURCE_TYPES:
            # Only scan one region per unique account
            seen_accounts: set[str] = set()
            global_targets: list[ScanTarget] = []
            for t in self._targets:
                if t.account_key not in seen_accounts:
                    seen_accounts.add(t.account_key)
                    global_targets.append(t)
            return global_targets

        return self._targets

    def _prioritize_targets_for_id(self, resource_id: str) -> list[ScanTarget]:
        """Sort targets to put most likely matches first based on ARN parsing."""
        if not resource_id.startswith("arn:aws:"):
            return self._targets

        parts = resource_id.split(":")
        # ARN format: arn:partition:service:region:account-id:resource
        arn_region = parts[3] if len(parts) > 3 else ""
        arn_account = parts[4] if len(parts) > 4 else ""

        def sort_key(t: ScanTarget) -> int:
            score = 0
            if arn_account and (t.account_id == arn_account or t.account_name == arn_account):
                score -= 10
            if arn_region and t.region == arn_region:
                score -= 5
            return score

        return sorted(self._targets, key=sort_key)

    @staticmethod
    def _enrich_resource(res: CloudResource, target: ScanTarget) -> None:
        """Tag resource with target account and region metadata."""
        if not res.account_id:
            res.account_id = target.account_id
        if not res.account_name:
            res.account_name = target.account_name
        if not res.region:
            res.region = target.region

    def _load_plugins(self) -> None:
        """Load external Python plugins."""
        for plugin_mod in self._plugins:
            try:
                importlib.import_module(plugin_mod)
                logger.info(f"Loaded DriftSentry plugin module: {plugin_mod}")
            except Exception as e:
                logger.error(f"Failed to load plugin '{plugin_mod}': {e}")

    def _init_target_scanners(self) -> None:
        """Initialize scanner instances for each ScanTarget."""
        # Load declarative specs catalog once
        catalog = ResourceCatalog(
            custom_dirs=self._resource_definitions_dirs,
            inline_specs=self._custom_resources,
        )
        declarative_specs = catalog.load_all()

        for target in self._targets:
            scanners_dict: dict[str, ResourceScanner] = {}

            # 1. Register Python scanners from the registry
            for scanner_cls in get_registered_scanners("aws"):
                try:
                    scanner = scanner_cls(target.session, target.region)
                    for rtype in scanner.resource_types:
                        scanners_dict[rtype] = scanner
                except Exception as e:
                    logger.error(
                        f"Failed to init scanner {scanner_cls.__name__} for {target.target_id}: {e}"
                    )

            # 2. Register declarative YAML resource definitions
            for tf_type, spec in declarative_specs.items():
                if tf_type not in scanners_dict:
                    dec_scanner = GenericAWSDeclarativeScanner(target.session, target.region, spec)
                    scanners_dict[tf_type] = dec_scanner

            self._target_scanners[target.target_id] = scanners_dict

    @staticmethod
    def _create_session(
        region: str | None = None,
        profile: str | None = None,
        role_arn: str | None = None,
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
