"""Unit tests for the regression detection engine."""

from __future__ import annotations

import datetime

import pytest

from driftsentry.core.models import DriftItem, DriftResult, DriftSeverity, DriftType
from driftsentry.history.models import DriftDelta
from driftsentry.history.regression import RegressionDetector
from driftsentry.history.store import DriftStore


@pytest.fixture
def store(tmp_path):
    db_path = tmp_path / "test.db"
    return DriftStore(db_path)


@pytest.fixture
def detector(store):
    return RegressionDetector(store)


def create_drift_result(scan_id, items):
    return DriftResult(
        scan_id=scan_id,
        timestamp=datetime.datetime.now(),
        iac_tool="terraform",
        provider="aws",
        state_backend="local",
        state_source="terraform.tfstate",
        drift_items=items,
    )


def create_item(address, severity=DriftSeverity.MEDIUM, drift_type=DriftType.CHANGED):
    return DriftItem(
        resource_address=address,
        resource_type="aws_instance",
        drift_type=drift_type,
        severity=severity,
    )


def test_first_ever_scan(detector):
    current = create_drift_result("scan-1", [create_item("aws_instance.web1")])
    report = detector.compare(current)

    assert report.is_first_scan
    assert report.new_count == 1
    assert report.items[0].delta == DriftDelta.NEW
    assert report.items[0].first_seen_scan_id == "scan-1"
    assert report.items[0].consecutive_scans == 1


def test_new_and_recurring(store, detector):
    scan1 = create_drift_result("scan-1", [create_item("aws_instance.web1")])
    store.save(scan1)

    scan2 = create_drift_result(
        "scan-2",
        [
            create_item("aws_instance.web1"),
            create_item("aws_instance.web2"),
        ],
    )
    report = detector.compare(scan2)

    assert not report.is_first_scan
    assert report.new_count == 1
    assert report.recurring_count == 1

    web1 = next(i for i in report.items if i.resource_address == "aws_instance.web1")
    assert web1.delta == DriftDelta.RECURRING
    assert web1.first_seen_scan_id == "scan-1"
    assert web1.consecutive_scans == 2

    web2 = next(i for i in report.items if i.resource_address == "aws_instance.web2")
    assert web2.delta == DriftDelta.NEW
    assert web2.first_seen_scan_id == "scan-2"
    assert web2.consecutive_scans == 1


def test_resolved(store, detector):
    scan1 = create_drift_result("scan-1", [create_item("aws_instance.web1")])
    store.save(scan1)

    scan2 = create_drift_result("scan-2", [])
    report = detector.compare(scan2)

    assert report.resolved_count == 1
    assert report.items[0].resource_address == "aws_instance.web1"
    assert report.items[0].delta == DriftDelta.RESOLVED
    assert report.items[0].first_seen_scan_id == "scan-1"
    assert report.items[0].consecutive_scans == 1


def test_regression(store, detector):
    # drifted in scan 1
    scan1 = create_drift_result("scan-1", [create_item("aws_instance.web1")])
    store.save(scan1)

    # resolved in scan 2
    scan2 = create_drift_result("scan-2", [])
    store.save(scan2)

    # drifted again in scan 3
    scan3 = create_drift_result("scan-3", [create_item("aws_instance.web1")])
    report = detector.compare(scan3)

    assert report.regression_count == 1
    assert report.items[0].resource_address == "aws_instance.web1"
    assert report.items[0].delta == DriftDelta.REGRESSION
    # first seen in scan-1
    assert report.items[0].first_seen_scan_id == "scan-1"
    assert report.items[0].consecutive_scans == 1


def test_worsened(store, detector):
    scan1 = create_drift_result(
        "scan-1", [create_item("aws_instance.web1", severity=DriftSeverity.LOW)]
    )
    store.save(scan1)

    scan2 = create_drift_result(
        "scan-2", [create_item("aws_instance.web1", severity=DriftSeverity.CRITICAL)]
    )
    report = detector.compare(scan2)

    assert report.worsened_count == 1
    assert report.items[0].delta == DriftDelta.WORSENED
    assert report.items[0].previous_severity == DriftSeverity.LOW


def test_chronic_offenders(store):
    store.save(create_drift_result("s1", [create_item("r1"), create_item("r2")]))
    store.save(create_drift_result("s2", [create_item("r1"), create_item("r2")]))
    store.save(create_drift_result("s3", [create_item("r1")]))

    offenders = store.get_chronic_offenders(min_occurrences=2)
    assert len(offenders) == 2
    assert offenders[0] == ("r1", 3)
    assert offenders[1] == ("r2", 2)

    offenders = store.get_chronic_offenders(min_occurrences=3)
    assert len(offenders) == 1
    assert offenders[0] == ("r1", 3)


def test_edge_case_empty(detector):
    report = detector.compare(create_drift_result("scan-1", []))
    assert report.is_first_scan
    assert len(report.items) == 0


def test_resource_matching_by_address(store, detector):
    scan1 = create_drift_result("scan-1", [create_item("addr1"), create_item("addr2")])
    store.save(scan1)

    scan2 = create_drift_result("scan-2", [create_item("addr1"), create_item("addr3")])
    report = detector.compare(scan2)

    addr1 = next(i for i in report.items if i.resource_address == "addr1")
    addr2 = next(i for i in report.items if i.resource_address == "addr2")
    addr3 = next(i for i in report.items if i.resource_address == "addr3")

    assert addr1.delta == DriftDelta.RECURRING
    assert addr2.delta == DriftDelta.RESOLVED
    assert addr3.delta == DriftDelta.NEW
