"""Unit tests for Drift Baseline models, fingerprinting, persistence, and filtering."""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any

from driftsentry.core.baseline import (
    BaselineEntry,
    DriftBaseline,
    compute_drift_fingerprint,
    filter_against_baseline,
    fingerprint_from_drift_item,
    load_baseline,
    save_baseline,
)
from driftsentry.core.models import (
    AttributeDiff,
    CloudResource,
    DriftItem,
    DriftResult,
    DriftType,
    IaCTool,
    StateBackendType,
)


def _make_dummy_result(items: list[DriftItem]) -> DriftResult:
    """Helper to construct a valid DriftResult for testing."""
    return DriftResult(
        scan_id="test-scan-123",
        timestamp=datetime.datetime.now(datetime.UTC),
        iac_tool=IaCTool.TERRAFORM,
        provider="aws",
        region="us-east-1",
        state_backend=StateBackendType.LOCAL,
        state_source="terraform.tfstate",
        drift_items=items,
    )


def test_fingerprint_deterministic_and_stable() -> None:
    """Verify that dict key ordering does not alter the fingerprint."""
    dict_a = {"cidr_blocks": ["10.0.0.0/16"], "description": "web", "from_port": 80}
    dict_b = {"from_port": 80, "cidr_blocks": ["10.0.0.0/16"], "description": "web"}

    fp_a = compute_drift_fingerprint(
        resource_address="aws_security_group.web",
        drift_type=DriftType.CHANGED,
        attribute_path="ingress.0",
        actual_value=dict_a,
    )
    fp_b = compute_drift_fingerprint(
        resource_address="aws_security_group.web",
        drift_type=DriftType.CHANGED,
        attribute_path="ingress.0",
        actual_value=dict_b,
    )

    assert fp_a == fp_b
    assert len(fp_a) == 64  # SHA-256 length

    # Address case insensitivity
    fp_c = compute_drift_fingerprint(
        resource_address="AWS_SECURITY_GROUP.WEB",
        drift_type=DriftType.CHANGED,
        attribute_path="ingress.0",
        actual_value=dict_a,
    )
    assert fp_a == fp_c

    # Different attribute produces distinct fingerprint
    fp_diff = compute_drift_fingerprint(
        resource_address="aws_security_group.web",
        drift_type=DriftType.CHANGED,
        attribute_path="egress.0",
        actual_value=dict_a,
    )
    assert fp_a != fp_diff


def test_fingerprint_from_drift_item() -> None:
    """Verify helper generates accurate fingerprints across different drift types."""
    # Changed item
    changed_item = DriftItem(
        resource_address="aws_instance.app",
        resource_type="aws_instance",
        resource_id="i-12345678",
        drift_type=DriftType.CHANGED,
        attribute_diffs=[
            AttributeDiff(
                path="instance_type",
                desired_value="t3.small",
                actual_value="t3.large",
            )
        ],
    )
    fp_changed = fingerprint_from_drift_item(changed_item, changed_item.attribute_diffs[0])
    expected_fp = compute_drift_fingerprint(
        "aws_instance.app", DriftType.CHANGED, "instance_type", "t3.large"
    )
    assert fp_changed == expected_fp

    # Deleted item
    deleted_item = DriftItem(
        resource_address="aws_s3_bucket.logs",
        resource_type="aws_s3_bucket",
        resource_id="my-logs-bucket",
        drift_type=DriftType.DELETED,
    )
    fp_deleted = fingerprint_from_drift_item(deleted_item)
    assert fp_deleted == compute_drift_fingerprint(
        "aws_s3_bucket.logs", DriftType.DELETED, None, None
    )

    # Unmanaged item
    cloud_res = CloudResource(
        resource_id="sg-unmanaged",
        resource_type="aws_security_group",
        attributes={"description": "manual", "name": "rogue-sg"},
    )
    unmanaged_item = DriftItem(
        resource_address="[unmanaged] aws_security_group.sg-unmanaged",
        resource_type="aws_security_group",
        resource_id="sg-unmanaged",
        drift_type=DriftType.UNMANAGED,
        cloud_resource=cloud_res,
    )
    fp_unmanaged = fingerprint_from_drift_item(unmanaged_item)
    assert fp_unmanaged == compute_drift_fingerprint(
        "[unmanaged] aws_security_group.sg-unmanaged",
        DriftType.UNMANAGED,
        None,
        {"description": "manual", "name": "rogue-sg"},
    )


def test_baseline_entry_and_baseline_crud() -> None:
    """Test DriftBaseline CRUD operations and entry lookup."""
    baseline = DriftBaseline()
    assert baseline.version == 1
    assert len(baseline.entries) == 0

    entry1 = BaselineEntry(
        resource_address="aws_security_group.web",
        resource_type="aws_security_group",
        drift_type=DriftType.CHANGED,
        attribute_path="ingress.0.cidr_blocks",
        fingerprint="fp1",
        acknowledged_by="alice",
        reason="INC-1234 hotfix",
        last_known_value=["10.0.0.0/16"],
    )
    baseline.add_or_update_entry(entry1)
    assert len(baseline.entries) == 1

    # Find entry
    found = baseline.find_entry("aws_security_group.web", "ingress.0.cidr_blocks")
    assert found is not None
    assert found.reason == "INC-1234 hotfix"

    # Case-insensitive lookup
    found_upper = baseline.find_entry("AWS_SECURITY_GROUP.WEB", "ingress.0.cidr_blocks")
    assert found_upper is not None

    # Missing entry
    assert baseline.find_entry("aws_security_group.web", "nonexistent") is None

    # Update entry
    entry1_updated = entry1.model_copy(
        update={"reason": "Updated reason", "fingerprint": "fp1_new"}
    )
    baseline.add_or_update_entry(entry1_updated)
    assert len(baseline.entries) == 1
    assert baseline.entries[0].reason == "Updated reason"
    assert baseline.entries[0].fingerprint == "fp1_new"

    # Remove entry
    removed = baseline.remove_entry("aws_security_group.web", "ingress.0.cidr_blocks")
    assert removed is True
    assert len(baseline.entries) == 0

    # Remove nonexistent
    assert baseline.remove_entry("nonexistent") is False


def test_baseline_file_persistence(tmp_path: Path) -> None:
    """Verify saving to and loading from JSON file."""
    file_path = tmp_path / "custom-baseline.json"

    # Nonexistent file returns None
    assert load_baseline(file_path) is None

    # Save baseline
    baseline = DriftBaseline()
    entry = BaselineEntry(
        resource_address="aws_instance.bastion",
        resource_type="aws_instance",
        drift_type=DriftType.CHANGED,
        attribute_path="instance_type",
        fingerprint="fp_bastion",
        reason="Approved resize",
        last_known_value="t3.medium",
    )
    baseline.add_or_update_entry(entry)

    saved_path = save_baseline(baseline, file_path)
    assert saved_path == file_path
    assert file_path.exists()

    # Load baseline
    loaded = load_baseline(file_path)
    assert loaded is not None
    assert len(loaded.entries) == 1
    assert loaded.entries[0].resource_address == "aws_instance.bastion"
    assert loaded.entries[0].fingerprint == "fp_bastion"
    assert loaded.entries[0].last_known_value == "t3.medium"

    # Corrupted file returns None
    file_path.write_text("{ corrupt json ...", encoding="utf-8")
    assert load_baseline(file_path) is None


def test_filter_against_baseline_all_active() -> None:
    """Verify that when baseline is empty, all items are active."""
    baseline = DriftBaseline()
    item = DriftItem(
        resource_address="aws_security_group.web",
        resource_type="aws_security_group",
        drift_type=DriftType.CHANGED,
        attribute_diffs=[
            AttributeDiff(
                path="ingress.0.cidr_blocks",
                desired_value=["10.0.0.0/8"],
                actual_value=["0.0.0.0/0"],
            )
        ],
    )
    result = _make_dummy_result([item])

    filtered_res, breakdown = filter_against_baseline(result, baseline)
    assert breakdown.total_active == 1
    assert breakdown.total_acknowledged == 0
    assert len(breakdown.active_items) == 1
    assert len(breakdown.acknowledged_items) == 0
    assert len(breakdown.regression_items) == 0
    assert len(filtered_res.drift_items) == 1


def test_filter_against_baseline_acknowledged() -> None:
    """Verify exact match suppresses item into acknowledged_items."""
    actual_val = ["198.51.100.1/32"]
    fp = compute_drift_fingerprint(
        "aws_security_group.web", DriftType.CHANGED, "ingress.0.cidr_blocks", actual_val
    )
    baseline = DriftBaseline(
        entries=[
            BaselineEntry(
                resource_address="aws_security_group.web",
                resource_type="aws_security_group",
                drift_type=DriftType.CHANGED,
                attribute_path="ingress.0.cidr_blocks",
                fingerprint=fp,
                reason="Temporary vendor IP",
                last_known_value=actual_val,
            )
        ]
    )

    item = DriftItem(
        resource_address="aws_security_group.web",
        resource_type="aws_security_group",
        drift_type=DriftType.CHANGED,
        attribute_diffs=[
            AttributeDiff(
                path="ingress.0.cidr_blocks",
                desired_value=["10.0.0.0/8"],
                actual_value=actual_val,
            )
        ],
    )
    result = _make_dummy_result([item])

    filtered_res, breakdown = filter_against_baseline(result, baseline)
    assert breakdown.total_active == 0
    assert breakdown.total_acknowledged == 1
    assert len(breakdown.acknowledged_items) == 1
    assert len(filtered_res.drift_items) == 0


def test_filter_against_baseline_detects_regression() -> None:
    """Verify that if live value changes after acknowledgment, it triggers regression."""
    initial_val = ["198.51.100.1/32"]
    fp_initial = compute_drift_fingerprint(
        "aws_security_group.web", DriftType.CHANGED, "ingress.0.cidr_blocks", initial_val
    )
    baseline = DriftBaseline(
        entries=[
            BaselineEntry(
                resource_address="aws_security_group.web",
                resource_type="aws_security_group",
                drift_type=DriftType.CHANGED,
                attribute_path="ingress.0.cidr_blocks",
                fingerprint=fp_initial,
                last_known_value=initial_val,
            )
        ]
    )

    # Now someone changed it again to 0.0.0.0/0
    new_val = ["0.0.0.0/0"]
    item = DriftItem(
        resource_address="aws_security_group.web",
        resource_type="aws_security_group",
        drift_type=DriftType.CHANGED,
        attribute_diffs=[
            AttributeDiff(
                path="ingress.0.cidr_blocks",
                desired_value=["10.0.0.0/8"],
                actual_value=new_val,
            )
        ],
    )
    result = _make_dummy_result([item])

    filtered_res, breakdown = filter_against_baseline(result, baseline)
    assert breakdown.total_active == 1
    assert breakdown.total_acknowledged == 0
    assert len(breakdown.regression_items) == 1
    assert len(filtered_res.drift_items) == 1
    assert filtered_res.drift_items[0].attribute_diffs[0].actual_value == new_val


def test_filter_against_baseline_deleted_and_unmanaged() -> None:
    """Verify handling of DELETED and UNMANAGED resources."""
    del_fp = compute_drift_fingerprint("aws_s3_bucket.old", DriftType.DELETED, None, None)
    unm_attrs: dict[str, Any] = {"name": "test-sg", "vpc_id": "vpc-1"}
    unm_fp = compute_drift_fingerprint(
        "[unmanaged] aws_security_group.sg-1", DriftType.UNMANAGED, None, unm_attrs
    )

    baseline = DriftBaseline(
        entries=[
            BaselineEntry(
                resource_address="aws_s3_bucket.old",
                resource_type="aws_s3_bucket",
                drift_type=DriftType.DELETED,
                fingerprint=del_fp,
            ),
            BaselineEntry(
                resource_address="[unmanaged] aws_security_group.sg-1",
                resource_type="aws_security_group",
                drift_type=DriftType.UNMANAGED,
                fingerprint=unm_fp,
            ),
        ]
    )

    del_item = DriftItem(
        resource_address="aws_s3_bucket.old",
        resource_type="aws_s3_bucket",
        drift_type=DriftType.DELETED,
    )
    unm_item = DriftItem(
        resource_address="[unmanaged] aws_security_group.sg-1",
        resource_type="aws_security_group",
        drift_type=DriftType.UNMANAGED,
        cloud_resource=CloudResource(
            resource_id="sg-1", resource_type="aws_security_group", attributes=unm_attrs
        ),
    )

    result = _make_dummy_result([del_item, unm_item])
    filtered_res, breakdown = filter_against_baseline(result, baseline)
    assert breakdown.total_active == 0
    assert breakdown.total_acknowledged == 2
    assert len(filtered_res.drift_items) == 0
