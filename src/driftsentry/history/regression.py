"""Regression detection engine — classifies drift against scan history.

Compares a current `DriftResult` against a previous scan (and, for
regression detection, the full resource history) to classify each
drifted resource as new, recurring, resolved, a regression, or worsened.
"""

from __future__ import annotations

import datetime

from driftsentry.core.models import DriftResult, DriftSeverity, DriftType
from driftsentry.history.models import DriftDelta, DriftDeltaItem, RegressionReport
from driftsentry.history.store import DriftStore

SEVERITY_RANKS = {
    DriftSeverity.INFO: 0,
    DriftSeverity.LOW: 1,
    DriftSeverity.MEDIUM: 2,
    DriftSeverity.HIGH: 3,
    DriftSeverity.CRITICAL: 4,
}


class RegressionDetector:
    """Detects changes in drift between scans (new, resolved, regressions)."""

    def __init__(self, store: DriftStore) -> None:
        self.store = store

    def compare(
        self, current: DriftResult, previous_scan_id: str | None = None
    ) -> RegressionReport:
        # Determine the comparison scan
        comparison_scan = None
        all_past_scans = [
            s for s in self.store.list_snapshots(limit=1000) if s.scan_id != current.scan_id
        ]

        if previous_scan_id:
            comparison_scan = self.store.get_snapshot(previous_scan_id)
        elif all_past_scans:
            comparison_scan = all_past_scans[0]

        report = RegressionReport(
            current_scan_id=current.scan_id,
            comparison_scan_id=comparison_scan.scan_id if comparison_scan else None,
            timestamp=datetime.datetime.now(),
            items=[],
        )

        prev_items = {}
        if comparison_scan:
            prev_items = {
                i.resource_address: i for i in self.store.get_drift_items(comparison_scan.scan_id)
            }

        # Find New, Recurring, Worsened, Regression
        current_addresses = set()
        for item in current.drift_items:
            current_addresses.add(item.resource_address)

            # Get resource history (excluding current scan if present)
            history = [
                h
                for h in self.store.get_resource_history(item.resource_address)
                if h.scan_id != current.scan_id
            ]

            # Calculate consecutive_scans
            consecutive_scans = 1
            for past_scan in all_past_scans:
                # Check if it was drifted in this past scan
                if any(h.scan_id == past_scan.scan_id for h in history):
                    consecutive_scans += 1
                else:
                    break

            first_seen_scan_id = history[-1].scan_id if history else current.scan_id

            delta = None
            prev_severity = None
            prev_drift_type = None

            if item.resource_address in prev_items:
                prev_item = prev_items[item.resource_address]
                prev_severity = DriftSeverity(prev_item.severity)
                prev_drift_type = DriftType(prev_item.drift_type)

                curr_rank = SEVERITY_RANKS.get(item.severity, -1)
                prev_rank = SEVERITY_RANKS.get(prev_severity, -1)

                delta = DriftDelta.WORSENED if curr_rank > prev_rank else DriftDelta.RECURRING
            else:
                delta = DriftDelta.REGRESSION if history else DriftDelta.NEW

            report.items.append(
                DriftDeltaItem(
                    resource_address=item.resource_address,
                    resource_type=item.resource_type,
                    drift_type=item.drift_type,
                    severity=item.severity,
                    delta=delta,
                    previous_severity=prev_severity,
                    previous_drift_type=prev_drift_type,
                    first_seen_scan_id=first_seen_scan_id,
                    consecutive_scans=consecutive_scans,
                )
            )

        # Find Resolved
        for prev_address, prev_item in prev_items.items():
            if prev_address not in current_addresses:
                # Calculate consecutive scans for the resolved item
                history = [
                    h
                    for h in self.store.get_resource_history(prev_address)
                    if h.scan_id != current.scan_id
                ]

                consecutive_scans = 0
                started_counting = False
                for past_scan in all_past_scans:
                    if comparison_scan and past_scan.scan_id == comparison_scan.scan_id:
                        started_counting = True

                    if started_counting:
                        if any(h.scan_id == past_scan.scan_id for h in history):
                            consecutive_scans += 1
                        else:
                            break

                first_seen_scan_id = history[-1].scan_id if history else prev_item.scan_id

                report.items.append(
                    DriftDeltaItem(
                        resource_address=prev_address,
                        resource_type=prev_item.resource_type,
                        drift_type=DriftType(prev_item.drift_type),
                        severity=DriftSeverity(prev_item.severity),
                        delta=DriftDelta.RESOLVED,
                        previous_severity=DriftSeverity(prev_item.severity),
                        previous_drift_type=DriftType(prev_item.drift_type),
                        first_seen_scan_id=first_seen_scan_id,
                        consecutive_scans=consecutive_scans,
                    )
                )

        return report
