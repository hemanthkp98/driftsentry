"""Resource filtering utility — checks resources against tag and pattern exclusion rules."""

from __future__ import annotations

import fnmatch
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from driftsentry.core.config import ScanFilters
    from driftsentry.core.models import CloudResource, ResourceState


def _match_pattern(value: str, pattern: str) -> bool:
    """Check if a string matches a pattern (glob or regex prefixed with 're:')."""
    if pattern.startswith("re:"):
        return bool(re.search(pattern[3:], value, re.IGNORECASE))
    return fnmatch.fnmatch(value.lower(), pattern.lower())


def _match_tag(actual_val: str, expected_spec: str | list[str]) -> bool:
    """Check if an actual tag value matches an expected spec (string or list)."""
    if expected_spec == "*":
        return True
    if isinstance(expected_spec, str):
        return _match_pattern(actual_val, expected_spec)
    if isinstance(expected_spec, list):
        return any(_match_pattern(actual_val, s) for s in expected_spec)
    return False


def is_resource_excluded(resource: CloudResource, filters: ScanFilters | None) -> bool:
    """Determine whether a live CloudResource should be excluded based on tags or patterns.

    Args:
        resource: The CloudResource to inspect.
        filters: The ScanFilters configuration containing exclusion rules.

    Returns:
        True if the resource matches any exclusion tag or pattern rule; False otherwise.
    """
    if filters is None:
        return False

    # 1. Tag-based exclusion
    if filters.exclude_tags:
        tags: dict[str, Any] = dict(resource.tags)
        if not tags and isinstance(resource.attributes.get("tags"), dict):
            tags = resource.attributes["tags"]
        if isinstance(resource.attributes.get("tags_all"), dict):
            tags.update(resource.attributes["tags_all"])

        lower_tags = {str(k).lower(): str(v) for k, v in tags.items()}

        for rule_key, rule_val in filters.exclude_tags.items():
            rule_key_lower = rule_key.lower()
            if rule_key_lower in lower_tags:
                actual_val = lower_tags[rule_key_lower]
                if _match_tag(actual_val, rule_val):
                    return True

    # 2. Pattern-based exclusion (resource_id, name, ARN)
    if filters.exclude_patterns:
        candidates: list[str] = [resource.resource_id]
        if resource.arn:
            candidates.append(resource.arn)

        name_tag = resource.tags.get("Name") or resource.tags.get("name")
        if name_tag:
            candidates.append(name_tag)

        attr_name = resource.attributes.get("name")
        if isinstance(attr_name, str):
            candidates.append(attr_name)

        attr_id = resource.attributes.get("id")
        if isinstance(attr_id, str):
            candidates.append(attr_id)

        for pattern in filters.exclude_patterns:
            for candidate in candidates:
                if candidate and _match_pattern(candidate, pattern):
                    return True

    return False


def is_state_resource_excluded(state_res: ResourceState, filters: ScanFilters | None) -> bool:
    """Determine whether a ResourceState should be excluded based on tags or patterns.

    Args:
        state_res: The ResourceState from state file.
        filters: The ScanFilters configuration containing exclusion rules.

    Returns:
        True if the state resource matches any exclusion tag or pattern rule; False otherwise.
    """
    if filters is None:
        return False

    # 1. Tag-based exclusion from attributes
    if filters.exclude_tags:
        tags: dict[str, Any] = {}
        if isinstance(state_res.attributes.get("tags"), dict):
            tags.update(state_res.attributes["tags"])
        if isinstance(state_res.attributes.get("tags_all"), dict):
            tags.update(state_res.attributes["tags_all"])

        lower_tags = {str(k).lower(): str(v) for k, v in tags.items()}
        for rule_key, rule_val in filters.exclude_tags.items():
            rule_key_lower = rule_key.lower()
            if rule_key_lower in lower_tags:
                actual_val = lower_tags[rule_key_lower]
                if _match_tag(actual_val, rule_val):
                    return True

    # 2. Pattern-based exclusion
    if filters.exclude_patterns:
        candidates: list[str] = [
            state_res.address,
            state_res.resource_name,
        ]
        if state_res.resource_id:
            candidates.append(state_res.resource_id)

        arn = state_res.attributes.get("arn")
        if isinstance(arn, str):
            candidates.append(arn)

        name = state_res.attributes.get("name")
        if isinstance(name, str):
            candidates.append(name)

        tags_dict = state_res.attributes.get("tags")
        if isinstance(tags_dict, dict):
            name_tag = tags_dict.get("Name") or tags_dict.get("name")
            if isinstance(name_tag, str):
                candidates.append(name_tag)

        for pattern in filters.exclude_patterns:
            for candidate in candidates:
                if candidate and _match_pattern(candidate, pattern):
                    return True

    return False
