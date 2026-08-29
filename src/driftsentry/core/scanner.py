"""Drift scanner — orchestrates the full drift detection pipeline.

This is the main entry point for drift scanning. It coordinates:
1. Reading Terraform/OpenTofu state
2. Scanning live cloud resources
3. Computing diffs
4. Detecting unmanaged resources
5. Attributing drift to actors
"""

from __future__ import annotations

import logging
import time
import uuid

from rich.progress import Progress, SpinnerColumn, TextColumn

from driftsentry.core.config import DriftSentryConfig
from driftsentry.core.differ import DriftDiffer
from driftsentry.core.models import (
    CloudResource,
    DriftItem,
    DriftResult,
    ResourceState,
)
from driftsentry.providers.base import CloudProvider
from driftsentry.state.base import StateReader

logger = logging.getLogger(__name__)


class DriftScanner:
    """Orchestrates the full drift detection pipeline.

    Usage:
        scanner = DriftScanner(config, state_reader, cloud_provider)
        result = scanner.scan()
    """

    def __init__(
        self,
        config: DriftSentryConfig,
        state_reader: StateReader,
        cloud_provider: CloudProvider,
    ) -> None:
        self._config = config
        self._state_reader = state_reader
        self._provider = cloud_provider
        self._differ = DriftDiffer(
            custom_noise_attributes=config.filters.ignore_attributes,
        )

    def scan(self, show_progress: bool = True) -> DriftResult:
        """Execute a full drift scan and return the results.

        Args:
            show_progress: Whether to display a Rich progress bar.

        Returns:
            DriftResult with all detected drift items.
        """
        scan_id = str(uuid.uuid4())[:8]
        start_time = time.time()
        errors: list[str] = []

        if show_progress:
            return self._scan_with_progress(scan_id, start_time, errors)
        return self._scan_silent(scan_id, start_time, errors)

    def _scan_with_progress(
        self,
        scan_id: str,
        start_time: float,
        errors: list[str],
    ) -> DriftResult:
        """Run scan with Rich progress display."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            # Step 1: Read state
            task = progress.add_task("📖 Reading Terraform state...", total=None)
            state_resources = self._read_state(errors)
            progress.update(
                task, description=f"📖 Read {len(state_resources)} resources from state"
            )
            progress.remove_task(task)

            # Step 2: Scan cloud resources
            task = progress.add_task("☁️  Scanning cloud resources...", total=None)
            resource_types = self._get_scan_types(state_resources)
            cloud_resources = self._scan_cloud(resource_types, errors)
            progress.update(
                task,
                description=f"☁️  Found {len(cloud_resources)} cloud resources",
            )
            progress.remove_task(task)

            # Step 3: Detect drift
            task = progress.add_task("🔍 Detecting drift...", total=None)
            drift_items = self._detect_drift(state_resources, cloud_resources, errors)
            progress.update(
                task,
                description=f"🔍 Found {len(drift_items)} drifted resources",
            )
            progress.remove_task(task)

            # Step 4: Attribution (if enabled)
            if self._config.attribution.enabled and drift_items:
                task = progress.add_task("🕵️  Attributing drift...", total=None)
                self._attribute_drift(drift_items, errors)
                progress.update(task, description="🕵️  Attribution complete")
                progress.remove_task(task)

        return self._build_result(
            scan_id=scan_id,
            start_time=start_time,
            state_resources=state_resources,
            cloud_resources=cloud_resources,
            drift_items=drift_items,
            errors=errors,
        )

    def _scan_silent(
        self,
        scan_id: str,
        start_time: float,
        errors: list[str],
    ) -> DriftResult:
        """Run scan without progress display (for CI/CD)."""
        state_resources = self._read_state(errors)
        resource_types = self._get_scan_types(state_resources)
        cloud_resources = self._scan_cloud(resource_types, errors)
        drift_items = self._detect_drift(state_resources, cloud_resources, errors)

        if self._config.attribution.enabled and drift_items:
            self._attribute_drift(drift_items, errors)

        return self._build_result(
            scan_id=scan_id,
            start_time=start_time,
            state_resources=state_resources,
            cloud_resources=cloud_resources,
            drift_items=drift_items,
            errors=errors,
        )

    def _read_state(self, errors: list[str]) -> list[ResourceState]:
        """Read resources from the state file."""
        try:
            resources = self._state_reader.read_state()
            logger.info(
                f"Read {len(resources)} resources from {self._state_reader.source_description}"
            )
            return resources
        except Exception as e:
            errors.append(f"Error reading state: {e}")
            logger.error(f"Failed to read state: {e}")
            return []

    def _get_scan_types(self, state_resources: list[ResourceState]) -> set[str]:
        """Determine which resource types to scan based on state, provider, and config."""
        # Include all supported types from provider plus any types from state
        types = set(self._provider.supported_resource_types()) | {
            r.resource_type for r in state_resources
        }

        # Apply include/exclude filters
        if self._config.filters.include_types:
            types = types & set(self._config.filters.include_types)

        types -= set(self._config.filters.exclude_types)

        # Only scan types the provider supports
        supported = set(self._provider.supported_resource_types())
        types = types & supported

        return types

    def _scan_cloud(
        self,
        resource_types: set[str],
        errors: list[str],
    ) -> dict[str, list[CloudResource]]:
        """Scan cloud resources for all relevant types.

        Returns a dict mapping resource_type -> list of cloud resources.
        """
        cloud_resources: dict[str, list[CloudResource]] = {}

        for rtype in resource_types:
            try:
                resources = self._provider.list_resources(rtype)
                cloud_resources[rtype] = resources
                logger.debug(f"Found {len(resources)} {rtype} resources in cloud")
            except Exception as e:
                errors.append(f"Error scanning {rtype}: {e}")
                logger.error(f"Error scanning {rtype}: {e}")
                cloud_resources[rtype] = []

        return cloud_resources

    def _detect_drift(
        self,
        state_resources: list[ResourceState],
        cloud_resources: dict[str, list[CloudResource]],
        errors: list[str],
    ) -> list[DriftItem]:
        """Compare state resources with cloud resources to detect drift."""
        drift_items: list[DriftItem] = []

        # Build a lookup of cloud resources by (type, id) and by ARN
        cloud_lookup: dict[tuple[str, str], CloudResource] = {}
        arn_lookup: dict[str, CloudResource] = {}

        for rtype, resources in cloud_resources.items():
            for cr in resources:
                cloud_lookup[(rtype, cr.resource_id)] = cr
                if cr.arn:
                    arn_lookup[cr.arn] = cr

        # Track which cloud resources are matched to state resources
        matched_cloud_keys: set[tuple[str, str]] = set()

        # 1. Check each state resource against the cloud
        for state_res in state_resources:
            if state_res.resource_type not in cloud_resources:
                continue  # Provider doesn't support this type

            resource_id = state_res.resource_id
            if not resource_id:
                continue

            cloud_key = (state_res.resource_type, resource_id)
            cloud_res = cloud_lookup.get(cloud_key)

            # Fallback to ARN matching if resource_id didn't match directly
            state_arn = state_res.attributes.get("arn")
            if cloud_res is None and state_arn:
                cloud_res = arn_lookup.get(state_arn)
                if cloud_res:
                    cloud_key = (cloud_res.resource_type, cloud_res.resource_id)

            if cloud_res is None:
                # Resource exists in state but not in cloud → DELETED
                del_item = self._differ.detect_deleted(state_res)
                acc, reg = self._extract_state_location(state_res)
                del_item.account_id = acc
                del_item.region = reg
                drift_items.append(del_item)
            else:
                matched_cloud_keys.add(cloud_key)
                # Resource exists in both → diff attributes
                try:
                    drift_item = self._differ.diff_resource(state_res, cloud_res)
                    if drift_item:
                        drift_item.account_id = cloud_res.account_id
                        drift_item.account_name = cloud_res.account_name
                        drift_item.region = cloud_res.region
                        drift_items.append(drift_item)
                except Exception as e:
                    errors.append(f"Error diffing {state_res.address}: {e}")

        # 2. Check for unmanaged resources (in cloud but not in state)
        state_ids = {(r.resource_type, r.resource_id) for r in state_resources if r.resource_id}
        state_arns = {r.attributes.get("arn") for r in state_resources if r.attributes.get("arn")}

        for key, cloud_res in cloud_lookup.items():
            is_matched_by_id = key in state_ids
            is_matched_by_arn = cloud_res.arn is not None and cloud_res.arn in state_arns

            if not is_matched_by_id and not is_matched_by_arn:
                if cloud_res.resource_type in self._config.filters.ignore_unmanaged_types:
                    continue
                unmanaged_item = self._differ.detect_unmanaged(cloud_res)
                unmanaged_item.account_id = cloud_res.account_id
                unmanaged_item.account_name = cloud_res.account_name
                unmanaged_item.region = cloud_res.region
                drift_items.append(unmanaged_item)

        # Sort by severity (critical first)
        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }
        drift_items.sort(key=lambda d: severity_order.get(d.severity.value, 99))

        return drift_items

    @staticmethod
    def _extract_state_location(state_res: ResourceState) -> tuple[str | None, str | None]:
        """Extract account_id and region from state resource if present in ARN or attributes."""
        arn = state_res.attributes.get("arn")
        if not arn and state_res.resource_id and state_res.resource_id.startswith("arn:aws:"):
            arn = state_res.resource_id

        if arn and isinstance(arn, str) and arn.startswith("arn:aws:"):
            parts = arn.split(":")
            reg = parts[3] if len(parts) > 3 and parts[3] else None
            acc = parts[4] if len(parts) > 4 and parts[4] else None
            return acc, reg

        reg = state_res.attributes.get("region")
        acc = state_res.attributes.get("account_id") or state_res.attributes.get("owner_id")
        return (str(acc) if acc else None, str(reg) if reg else None)

    def _attribute_drift(
        self,
        drift_items: list[DriftItem],
        errors: list[str],
    ) -> None:
        """Attempt to attribute drift to actors via CloudTrail."""
        try:
            from driftsentry.attribution.cloudtrail import CloudTrailAttributor

            targets = getattr(self._provider, "targets", None)
            attributor = CloudTrailAttributor(
                region=self._config.provider.region or "us-east-1",
                profile=self._config.provider.profile,
                lookback_hours=self._config.attribution.lookback_hours,
                targets=targets,
            )

            for item in drift_items:
                if item.drift_type in ("changed", "deleted"):
                    try:
                        attribution = attributor.attribute(item)
                        if attribution:
                            item.attribution = attribution
                    except Exception as e:
                        logger.debug(f"Attribution failed for {item.resource_address}: {e}")
        except ImportError:
            errors.append("CloudTrail attribution not available")
        except Exception as e:
            errors.append(f"Attribution error: {e}")

    def _build_result(
        self,
        scan_id: str,
        start_time: float,
        state_resources: list[ResourceState],
        cloud_resources: dict[str, list[CloudResource]],
        drift_items: list[DriftItem],
        errors: list[str],
    ) -> DriftResult:
        """Build the final DriftResult object."""
        total_cloud = sum(len(v) for v in cloud_resources.values())

        scanned_regions = getattr(self._provider, "scanned_regions", None) or (
            self._config.provider.regions
            if self._config.provider.regions
            else ([self._config.provider.region] if self._config.provider.region else [])
        )
        scanned_accounts = getattr(self._provider, "scanned_accounts", None) or (
            [acc.name or acc.id for acc in self._config.accounts if acc.name or acc.id]
        )
        primary_region = self._config.provider.region or (
            scanned_regions[0] if scanned_regions else None
        )

        return DriftResult(
            scan_id=scan_id,
            iac_tool=self._config.iac_tool,
            provider=self._config.provider.name,
            region=primary_region,
            regions=scanned_regions,
            accounts=scanned_accounts,
            state_backend=self._config.state.backend,
            state_source=self._state_reader.source_description,
            total_resources=len(state_resources),
            total_cloud_resources=total_cloud,
            drift_items=drift_items,
            duration_seconds=round(time.time() - start_time, 2),
            errors=errors,
        )
