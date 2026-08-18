"""Diff engine — deep comparison between Terraform state and live cloud resources.

Uses deepdiff for structural comparison with noise-filtering and
severity classification based on security-critical attribute mappings.
"""

from __future__ import annotations

import logging
from typing import Any

from deepdiff import DeepDiff

from driftsentry.core.models import (
    AttributeDiff,
    CloudResource,
    DriftItem,
    DriftSeverity,
    DriftType,
    ResourceState,
)
from driftsentry.providers.aws.mapping import (
    get_noise_attributes,
    is_security_critical,
)

logger = logging.getLogger(__name__)

# ─── Global Noise Attributes (ignored across all resource types) ─────

DEFAULT_IGNORE_ATTRIBUTES: set[str] = {
    "tags_all",
    "arn",
    "id",
    "owner_id",
    "unique_id",
    "create_date",
    "last_modified",
    "self",
}


class DriftDiffer:
    """Compares Terraform state attributes with live cloud attributes.

    Produces DriftItem objects with attribute-level diffs, severity
    classification, and noise filtering.
    """

    def __init__(
        self,
        ignore_attributes: set[str] | None = None,
        custom_noise_attributes: list[str] | None = None,
    ) -> None:
        self._ignore = ignore_attributes or DEFAULT_IGNORE_ATTRIBUTES.copy()
        if custom_noise_attributes:
            self._ignore.update(custom_noise_attributes)

    def diff_resource(
        self,
        state_resource: ResourceState,
        cloud_resource: CloudResource,
    ) -> DriftItem | None:
        """Compare a state resource with its cloud counterpart.

        Returns a DriftItem if drift is detected, or None if they match.
        """
        state_attrs = self._filter_attributes(
            state_resource.attributes,
            state_resource.resource_type,
        )
        cloud_attrs = self._filter_attributes(
            cloud_resource.attributes,
            cloud_resource.resource_type,
        )

        # Deep-diff with appropriate settings
        diff = DeepDiff(
            state_attrs,
            cloud_attrs,
            ignore_order=True,
            report_repetition=False,
            verbose_level=2,
            exclude_regex_paths=[
                r"root\['tags_all'\]",
                r"root\['arn'\]",
            ],
        )

        if not diff:
            return None

        # Convert deepdiff output to AttributeDiff objects
        attr_diffs = self._extract_attribute_diffs(diff, state_resource.resource_type)

        if not attr_diffs:
            return None

        # Classify severity based on which attributes changed
        severity = self._classify_severity(attr_diffs, state_resource.resource_type)

        return DriftItem(
            resource_address=state_resource.address,
            resource_type=state_resource.resource_type,
            resource_id=state_resource.resource_id,
            drift_type=DriftType.CHANGED,
            severity=severity,
            attribute_diffs=attr_diffs,
            state_resource=state_resource,
            cloud_resource=cloud_resource,
        )

    def detect_deleted(self, state_resource: ResourceState) -> DriftItem:
        """Create a DriftItem for a resource that exists in state but not in the cloud."""
        return DriftItem(
            resource_address=state_resource.address,
            resource_type=state_resource.resource_type,
            resource_id=state_resource.resource_id,
            drift_type=DriftType.DELETED,
            severity=DriftSeverity.HIGH,
            state_resource=state_resource,
        )

    def detect_unmanaged(self, cloud_resource: CloudResource) -> DriftItem:
        """Create a DriftItem for a resource that exists in cloud but not in state."""
        severity = DriftSeverity.MEDIUM
        # IAM resources and security groups are higher severity when unmanaged
        if cloud_resource.resource_type in (
            "aws_iam_role",
            "aws_iam_policy",
            "aws_iam_user",
            "aws_security_group",
        ):
            severity = DriftSeverity.CRITICAL

        return DriftItem(
            resource_address=f"[unmanaged] {cloud_resource.resource_type}.{cloud_resource.resource_id}",
            resource_type=cloud_resource.resource_type,
            resource_id=cloud_resource.resource_id,
            drift_type=DriftType.UNMANAGED,
            severity=severity,
            cloud_resource=cloud_resource,
        )

    def _filter_attributes(
        self,
        attributes: dict[str, Any],
        resource_type: str,
    ) -> dict[str, Any]:
        """Remove noise attributes before diffing."""
        noise = set(get_noise_attributes(resource_type))
        all_ignored = self._ignore | noise

        filtered: dict[str, Any] = {}
        for key, value in attributes.items():
            if key in all_ignored:
                continue
            # Skip None values — they're often unset optional fields
            if value is None:
                continue
            filtered[key] = value

        return filtered

    def _extract_attribute_diffs(
        self,
        diff: DeepDiff,
        resource_type: str,
    ) -> list[AttributeDiff]:
        """Convert DeepDiff output into a list of AttributeDiff objects."""
        diffs: list[AttributeDiff] = []

        # Values changed
        for path, change in diff.get("values_changed", {}).items():
            attr_path = self._deepdiff_path_to_dot(path)
            if self._should_ignore_path(attr_path):
                continue
            diffs.append(
                AttributeDiff(
                    path=attr_path,
                    desired_value=change.get("old_value"),
                    actual_value=change.get("new_value"),
                    is_sensitive=False,
                )
            )

        # Items added (in cloud but not in state)
        for path, value in diff.get("dictionary_item_added", {}).items():
            attr_path = self._deepdiff_path_to_dot(path)
            if self._should_ignore_path(attr_path):
                continue
            diffs.append(
                AttributeDiff(
                    path=attr_path,
                    desired_value=None,
                    actual_value=value,
                )
            )

        # Items removed (in state but not in cloud)
        for path, value in diff.get("dictionary_item_removed", {}).items():
            attr_path = self._deepdiff_path_to_dot(path)
            if self._should_ignore_path(attr_path):
                continue
            diffs.append(
                AttributeDiff(
                    path=attr_path,
                    desired_value=value,
                    actual_value=None,
                )
            )

        # Type changes
        for path, change in diff.get("type_changes", {}).items():
            attr_path = self._deepdiff_path_to_dot(path)
            if self._should_ignore_path(attr_path):
                continue
            diffs.append(
                AttributeDiff(
                    path=attr_path,
                    desired_value=change.get("old_value"),
                    actual_value=change.get("new_value"),
                )
            )

        # Iterable item added/removed
        for diff_type in ("iterable_item_added", "iterable_item_removed"):
            for path, value in diff.get(diff_type, {}).items():
                attr_path = self._deepdiff_path_to_dot(path)
                if self._should_ignore_path(attr_path):
                    continue
                diffs.append(
                    AttributeDiff(
                        path=attr_path,
                        desired_value=value if diff_type == "iterable_item_removed" else None,
                        actual_value=value if diff_type == "iterable_item_added" else None,
                    )
                )

        return diffs

    def _classify_severity(
        self,
        diffs: list[AttributeDiff],
        resource_type: str,
    ) -> DriftSeverity:
        """Classify drift severity based on which attributes changed.

        Returns the highest severity found across all diffs.
        """
        max_severity = DriftSeverity.LOW

        for diff in diffs:
            # Get the top-level attribute name
            top_attr = diff.path.split(".")[0]

            if is_security_critical(resource_type, top_attr):
                return DriftSeverity.CRITICAL  # Short-circuit on critical

            # Default to MEDIUM for any non-trivial attribute change
            if max_severity.value < DriftSeverity.MEDIUM.value:
                max_severity = DriftSeverity.MEDIUM

        return max_severity

    def _should_ignore_path(self, path: str) -> bool:
        """Check if an attribute path should be ignored."""
        top_level = path.split(".")[0]
        return top_level in self._ignore

    @staticmethod
    def _deepdiff_path_to_dot(path: str) -> str:
        """Convert DeepDiff path format to dot notation.

        DeepDiff: root['ingress'][0]['cidr_blocks']
        Output:   ingress.0.cidr_blocks
        """
        # Remove 'root' prefix
        path = path.replace("root", "")
        # Replace ['key'] with .key
        import re

        path = re.sub(r"\['(\w+)'\]", r".\1", path)
        path = re.sub(r"\[(\d+)\]", r".\1", path)
        # Remove leading dot
        return path.lstrip(".")
