"""Policy rules — models and matching logic for drift policy evaluation."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from driftsentry.core.models import DriftItem, DriftType


class PolicyAction(StrEnum):
    """Action to take when a policy rule matches."""

    IGNORE = "ignore"
    """Suppress this drift item from the report."""

    WARN = "warn"
    """Escalate to HIGH severity."""

    CRITICAL = "critical"
    """Escalate to CRITICAL severity."""

    BLOCK = "block"
    """Fail the pipeline (exit non-zero) and escalate to CRITICAL."""


class RuleMatch:
    """Records a match between a policy rule and a drift item."""

    def __init__(
        self,
        rule_name: str,
        resource_address: str,
        action: PolicyAction,
    ) -> None:
        self.rule_name = rule_name
        self.resource_address = resource_address
        self.action = action


class PolicyRule:
    """A single policy rule with conditions and an action."""

    def __init__(
        self,
        name: str,
        description: str,
        action: PolicyAction,
        resource_types: list[str] | None = None,
        drift_types: list[DriftType] | None = None,
        attributes_match: list[str] | None = None,
    ) -> None:
        self.name = name
        self.description = description
        self.action = action
        self.resource_types = resource_types
        self.drift_types = drift_types
        self.attributes_match = attributes_match

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyRule:
        """Create a PolicyRule from a dictionary (YAML config)."""
        conditions = data.get("conditions", {})

        drift_types = None
        if "drift_types" in conditions:
            drift_types = [DriftType(dt) for dt in conditions["drift_types"]]

        return cls(
            name=data["name"],
            description=data.get("description", ""),
            action=PolicyAction(data["action"]),
            resource_types=conditions.get("resource_types"),
            drift_types=drift_types,
            attributes_match=conditions.get("attributes_match"),
        )

    def matches(self, item: DriftItem) -> RuleMatch | None:
        """Check if this rule matches a drift item.

        Returns a RuleMatch if all conditions are satisfied, None otherwise.
        """
        # Check resource type filter
        if self.resource_types and item.resource_type not in self.resource_types:
            return None

        # Check drift type filter
        if self.drift_types and item.drift_type not in self.drift_types:
            return None

        # Check attribute match
        if self.attributes_match:
            if not item.attribute_diffs:
                return None

            # Get top-level attribute names from diffs
            diff_attrs = {d.path.split(".")[0] for d in item.attribute_diffs}

            # Check if any diff attribute matches the rule's attributes
            rule_attrs = set(self.attributes_match)
            if not diff_attrs & rule_attrs:
                return None

            # For "ignore" action, ALL diffs must be in the ignore list
            if self.action == PolicyAction.IGNORE and not diff_attrs.issubset(rule_attrs):
                return None

        return RuleMatch(
            rule_name=self.name,
            resource_address=item.resource_address,
            action=self.action,
        )
