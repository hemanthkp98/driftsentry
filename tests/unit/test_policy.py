"""Unit tests for the policy engine."""

from __future__ import annotations

from pathlib import Path

from driftsentry.core.models import (
    AttributeDiff,
    DriftItem,
    DriftResult,
    DriftSeverity,
    DriftType,
    StateBackendType,
)
from driftsentry.policy.engine import PolicyEngine


def test_policy_escalates_security_group_changes() -> None:
    engine = PolicyEngine()  # Loads default rules

    sg_item = DriftItem(
        resource_address="aws_security_group.web",
        resource_type="aws_security_group",
        resource_id="sg-12345",
        drift_type=DriftType.CHANGED,
        severity=DriftSeverity.MEDIUM,
        attribute_diffs=[
            AttributeDiff(
                path="ingress.0.cidr_blocks",
                desired_value=["10.0.0.0/8"],
                actual_value=["0.0.0.0/0"],
            )
        ],
    )

    result = DriftResult(
        scan_id="test1",
        provider="aws",
        state_backend=StateBackendType.LOCAL,
        state_source="test",
        drift_items=[sg_item],
    )

    eval_result = engine.evaluate(result)

    assert sg_item.severity == DriftSeverity.CRITICAL
    assert len(eval_result.matches) > 0


def test_policy_ignores_tags_only_drift() -> None:
    engine = PolicyEngine()

    tag_item = DriftItem(
        resource_address="aws_instance.web",
        resource_type="aws_instance",
        resource_id="i-12345",
        drift_type=DriftType.CHANGED,
        severity=DriftSeverity.LOW,
        attribute_diffs=[
            AttributeDiff(
                path="tags.Environment",
                desired_value="staging",
                actual_value="production",
            )
        ],
    )

    result = DriftResult(
        scan_id="test2",
        provider="aws",
        state_backend=StateBackendType.LOCAL,
        state_source="test",
        drift_items=[tag_item],
    )

    eval_result = engine.evaluate(result)

    assert eval_result.ignored_count == 1
    assert len(result.drift_items) == 0


def test_custom_policy_file(tmp_path: Path) -> None:
    policy_yaml = tmp_path / "custom_policy.yaml"
    policy_yaml.write_text("""
rules:
  - name: block-rds-deletion
    description: Block if RDS database is deleted
    action: block
    conditions:
      resource_types:
        - aws_db_instance
      drift_types:
        - deleted
""")

    engine = PolicyEngine(policy_file=policy_yaml)

    rds_deleted = DriftItem(
        resource_address="aws_db_instance.prod",
        resource_type="aws_db_instance",
        resource_id="prod-db",
        drift_type=DriftType.DELETED,
        severity=DriftSeverity.HIGH,
    )

    result = DriftResult(
        scan_id="test3",
        provider="aws",
        state_backend=StateBackendType.LOCAL,
        state_source="test",
        drift_items=[rds_deleted],
    )

    eval_result = engine.evaluate(result)

    assert eval_result.should_block
    assert rds_deleted.severity == DriftSeverity.CRITICAL
