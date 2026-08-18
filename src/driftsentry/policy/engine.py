"""Policy engine — evaluates drift against configurable rules."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from driftsentry.core.models import DriftItem, DriftResult, DriftSeverity
from driftsentry.policy.rules import PolicyAction, PolicyRule, RuleMatch

logger = logging.getLogger(__name__)

# ─── Default Built-in Rules ────────────────────────────────────

DEFAULT_RULES: list[dict[str, Any]] = [
    {
        "name": "ignore-tags-only-drift",
        "description": "Ignore drift that only affects tags",
        "action": "ignore",
        "conditions": {
            "attributes_match": ["tags", "tags_all"],
        },
    },
    {
        "name": "critical-security-group-changes",
        "description": "Flag security group changes as critical",
        "action": "critical",
        "conditions": {
            "resource_types": ["aws_security_group"],
            "attributes_match": ["ingress", "egress"],
        },
    },
    {
        "name": "critical-iam-changes",
        "description": "Flag IAM policy/role changes as critical",
        "action": "critical",
        "conditions": {
            "resource_types": [
                "aws_iam_role",
                "aws_iam_policy",
            ],
            "attributes_match": [
                "assume_role_policy",
                "policy",
                "managed_policy_arns",
            ],
        },
    },
    {
        "name": "critical-public-access",
        "description": "Flag any changes to public access settings",
        "action": "critical",
        "conditions": {
            "attributes_match": [
                "publicly_accessible",
                "map_public_ip_on_launch",
                "public_access_block",
            ],
        },
    },
]


class PolicyEngine:
    """Evaluates drift items against a set of policy rules.

    Rules can:
    - Ignore certain drift (e.g., tag-only changes)
    - Escalate severity (e.g., SG changes → critical)
    - Block the pipeline (exit non-zero)
    """

    def __init__(self, policy_file: str | Path | None = None) -> None:
        self._rules: list[PolicyRule] = []
        self._load_default_rules()

        if policy_file:
            self._load_custom_rules(Path(policy_file))

    def evaluate(self, result: DriftResult) -> PolicyEvaluation:
        """Evaluate all drift items against policy rules.

        Modifies drift item severities in-place and returns evaluation summary.
        """
        evaluation = PolicyEvaluation()

        items_to_remove: list[DriftItem] = []

        for item in result.drift_items:
            for rule in self._rules:
                match = rule.matches(item)
                if match is None:
                    continue

                evaluation.matches.append(match)

                if match.action == PolicyAction.IGNORE:
                    items_to_remove.append(item)
                    logger.debug(f"Policy '{rule.name}' ignoring {item.resource_address}")
                    break  # First matching ignore wins

                if match.action == PolicyAction.CRITICAL:
                    item.severity = DriftSeverity.CRITICAL
                    logger.debug(
                        f"Policy '{rule.name}' escalated {item.resource_address} to CRITICAL"
                    )

                if match.action == PolicyAction.WARN and item.severity not in (
                    DriftSeverity.CRITICAL,
                    DriftSeverity.HIGH,
                ):
                    item.severity = DriftSeverity.HIGH

                if match.action == PolicyAction.BLOCK:
                    item.severity = DriftSeverity.CRITICAL
                    evaluation.should_block = True

        # Remove ignored items
        for item in items_to_remove:
            result.drift_items.remove(item)
            evaluation.ignored_count += 1

        evaluation.total_evaluated = len(result.drift_items) + evaluation.ignored_count
        evaluation.remaining_count = len(result.drift_items)

        return evaluation

    def _load_default_rules(self) -> None:
        """Load built-in default rules."""
        for rule_dict in DEFAULT_RULES:
            self._rules.append(PolicyRule.from_dict(rule_dict))

    def _load_custom_rules(self, path: Path) -> None:
        """Load custom rules from a YAML file."""
        if not path.exists():
            logger.warning(f"Policy file not found: {path}")
            return

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        custom_rules = data.get("rules", [])
        for rule_dict in custom_rules:
            self._rules.append(PolicyRule.from_dict(rule_dict))

        logger.info(f"Loaded {len(custom_rules)} custom policy rules from {path}")


class PolicyEvaluation:
    """Result of policy evaluation."""

    def __init__(self) -> None:
        self.matches: list[RuleMatch] = []
        self.should_block: bool = False
        self.ignored_count: int = 0
        self.total_evaluated: int = 0
        self.remaining_count: int = 0
