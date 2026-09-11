"""Discovery engine — orchestrates cloud resource discovery without IaC state."""

from __future__ import annotations

import logging
import time
import uuid

from rich.progress import Progress, SpinnerColumn, TextColumn

from driftsentry.core.models import CloudResource
from driftsentry.discovery.models import DiscoveryResult
from driftsentry.providers.base import CloudProvider

logger = logging.getLogger(__name__)


class DiscoveryEngine:
    """Discovers and catalogs active cloud resources using a CloudProvider."""

    def __init__(
        self,
        provider: CloudProvider,
        include_types: list[str] | None = None,
        exclude_types: list[str] | None = None,
    ) -> None:
        self._provider = provider
        self._include_types = set(include_types) if include_types else None
        self._exclude_types = set(exclude_types) if exclude_types else set()

    def get_scan_types(self) -> list[str]:
        """Determine the set of resource types to scan based on filters."""
        supported = set(self._provider.supported_resource_types())
        types = supported

        if self._include_types:
            types = types & self._include_types

        types = types - self._exclude_types
        return sorted(types)

    def discover(self, show_progress: bool = True) -> DiscoveryResult:
        """Execute discovery across all targeted regions/accounts for all selected types.

        Args:
            show_progress: Whether to display a terminal spinner/progress bar.

        Returns:
            DiscoveryResult containing all discovered resources and metadata.
        """
        scan_id = str(uuid.uuid4())[:8]
        start_time = time.time()
        errors: list[str] = []
        resources_by_type: dict[str, list[CloudResource]] = {}
        target_types = self.get_scan_types()

        if show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                task = progress.add_task(
                    f"🔍 Discovering resources across {len(target_types)} types...",
                    total=None,
                )
                for rtype in target_types:
                    progress.update(
                        task,
                        description=f"🔍 Scanning {rtype}...",
                    )
                    try:
                        found = self._provider.list_resources(rtype)
                        if found:
                            resources_by_type[rtype] = found
                    except Exception as e:
                        err_msg = f"Failed to list {rtype}: {e}"
                        errors.append(err_msg)
                        logger.error(err_msg)

                total_count = sum(len(r) for r in resources_by_type.values())
                progress.update(
                    task,
                    description=f"✅ Discovery complete: found {total_count} resources",
                )
        else:
            for rtype in target_types:
                try:
                    found = self._provider.list_resources(rtype)
                    if found:
                        resources_by_type[rtype] = found
                except Exception as e:
                    err_msg = f"Failed to list {rtype}: {e}"
                    errors.append(err_msg)
                    logger.error(err_msg)

        duration = round(time.time() - start_time, 2)
        total_found = sum(len(r) for r in resources_by_type.values())

        # Extract scanned regions and accounts from provider if available
        regions = getattr(self._provider, "scanned_regions", [])
        accounts = getattr(self._provider, "scanned_accounts", [])

        return DiscoveryResult(
            scan_id=scan_id,
            provider=self._provider.provider_name,
            regions=regions,
            accounts=accounts,
            total_resources=total_found,
            resources_by_type=resources_by_type,
            duration_seconds=duration,
            errors=errors,
        )
