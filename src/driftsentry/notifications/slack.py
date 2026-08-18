"""Slack notification — send drift alerts to Slack channels."""

from __future__ import annotations

import json
import logging
import urllib.request
from typing import Any

from driftsentry.core.models import DriftResult, DriftSeverity

logger = logging.getLogger(__name__)

SEVERITY_EMOJI: dict[DriftSeverity, str] = {
    DriftSeverity.CRITICAL: "🔴",
    DriftSeverity.HIGH: "🟠",
    DriftSeverity.MEDIUM: "🟡",
    DriftSeverity.LOW: "🟢",
    DriftSeverity.INFO: "🔵",
}


class SlackNotifier:
    """Sends drift alerts to Slack via incoming webhooks."""

    def __init__(self, webhook_url: str) -> None:
        self._webhook_url = webhook_url

    def notify(self, result: DriftResult) -> bool:
        """Send a drift summary to Slack.

        Returns True if the notification was sent successfully.
        """
        if not result.has_drift:
            logger.debug("No drift detected, skipping Slack notification")
            return True

        payload = self._build_payload(result)

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self._webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req) as response:
                if response.status == 200:
                    logger.info("Slack notification sent successfully")
                    return True
                else:
                    logger.error(f"Slack notification failed: HTTP {response.status}")
                    return False
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False

    def _build_payload(self, result: DriftResult) -> dict[str, Any]:
        """Build the Slack message payload."""
        # Summary text
        summary = (
            f"🛡️ *DriftSentry Drift Detected*\n"
            f"Scan `{result.scan_id}` | {result.provider} "
            f"({result.region or 'multi-region'}) | "
            f"{result.iac_tool.value.capitalize()}\n\n"
            f"📊 *{result.total_drifted}* drifted resources found "
            f"out of *{result.total_resources}* managed\n"
        )

        # Counts block
        counts = (
            f"🔴 Critical: *{result.critical_count}* | "
            f"📝 Changed: *{result.changed_count}* | "
            f"🗑️ Deleted: *{result.deleted_count}* | "
            f"👻 Unmanaged: *{result.unmanaged_count}*"
        )

        # Top drift items (max 10)
        items_text = ""
        for item in result.drift_items[:10]:
            emoji = SEVERITY_EMOJI.get(item.severity, "")
            changed_by = ""
            if item.attribution and item.attribution.principal:
                changed_by = f" — by `{item.attribution.principal}`"

            items_text += (
                f"{emoji} `{item.resource_address}` [{item.drift_type.value}]{changed_by}\n"
            )

        if len(result.drift_items) > 10:
            items_text += f"\n_...and {len(result.drift_items) - 10} more_"

        blocks: list[dict[str, Any]] = [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": summary},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": counts},
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": items_text},
            },
        ]

        return {"blocks": blocks}
