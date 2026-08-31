"""Markdown formatter — drift report as Markdown (for PR descriptions, docs)."""

from __future__ import annotations

from pathlib import Path

from driftsentry.core.models import DriftResult, DriftSeverity

SEVERITY_EMOJI: dict[DriftSeverity, str] = {
    DriftSeverity.CRITICAL: "🔴",
    DriftSeverity.HIGH: "🟠",
    DriftSeverity.MEDIUM: "🟡",
    DriftSeverity.LOW: "🟢",
    DriftSeverity.INFO: "🔵",
}


class MarkdownFormatter:
    """Renders drift scan results as Markdown."""

    def render(self, result: DriftResult, output_path: str | Path | None = None) -> str:
        """Generate the Markdown report."""
        lines: list[str] = []

        # Header
        lines.append("# 🛡️ DriftSentry Drift Report")
        lines.append("")
        lines.append(f"**Scan ID:** `{result.scan_id}`  ")
        lines.append(f"**IaC Tool:** {result.iac_tool.value.capitalize()}  ")

        provider_line = f"**Provider:** {result.provider}"
        if result.accounts:
            provider_line += f" | **Accounts:** {', '.join(result.accounts)}"
        if result.regions:
            provider_line += f" | **Regions:** {', '.join(result.regions)}"
        elif result.region:
            provider_line += f" | **Region:** {result.region}"
        lines.append(f"{provider_line}  ")

        lines.append(f"**State Source:** `{result.state_source}`  ")
        lines.append(f"**Duration:** {result.duration_seconds}s  ")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Count |")
        lines.append("|--------|-------|")
        lines.append(f"| Total managed resources | {result.total_resources} |")
        lines.append(f"| Total cloud resources | {result.total_cloud_resources} |")
        lines.append(f"| 📝 Changed | {result.changed_count} |")
        lines.append(f"| 🗑️ Deleted | {result.deleted_count} |")
        lines.append(f"| 👻 Unmanaged | {result.unmanaged_count} |")
        lines.append(f"| 🔴 Critical | {result.critical_count} |")
        lines.append("")

        if not result.has_drift:
            lines.append("✅ **No drift detected!** All resources match their desired state.")
            return self._finalize(lines, output_path)

        # Drift table
        show_account = len(result.accounts) > 1 or any(
            (item.account_name or item.account_id) for item in result.drift_items
        )
        show_region = len(result.regions) > 1 or any(item.region for item in result.drift_items)

        lines.append("## Drifted Resources")
        lines.append("")

        header_cols = []
        divider_cols = []
        if show_account:
            header_cols.append("Account")
            divider_cols.append("-------")
        if show_region:
            header_cols.append("Region")
            divider_cols.append("------")
        header_cols.extend(["Resource", "Type", "Severity", "Changes", "Changed By"])
        divider_cols.extend(["----------", "------", "----------", "---------", "------------"])

        lines.append("| " + " | ".join(header_cols) + " |")
        lines.append("| " + " | ".join(divider_cols) + " |")

        for item in result.drift_items:
            emoji = SEVERITY_EMOJI.get(item.severity, "")
            changes = str(len(item.attribute_diffs)) if item.attribute_diffs else "-"
            changed_by = "-"
            if item.attribution and item.attribution.principal:
                changed_by = f"`{item.attribution.principal}`"

            row = []
            if show_account:
                row.append(f"`{item.account_name or item.account_id or '-'}`")
            if show_region:
                row.append(f"`{item.region or '-'}`")

            row.extend(
                [
                    f"`{item.resource_address}`",
                    item.drift_type.value,
                    f"{emoji} {item.severity.value}",
                    changes,
                    changed_by,
                ]
            )
            lines.append("| " + " | ".join(row) + " |")

        lines.append("")

        # Detailed diffs
        has_diffs = any(item.attribute_diffs for item in result.drift_items)
        if has_diffs:
            lines.append("## Detailed Diffs")
            lines.append("")

            for item in result.drift_items:
                if not item.attribute_diffs:
                    continue

                lines.append(f"### `{item.resource_address}`")
                lines.append("")
                lines.append("| Attribute | Desired (State) | Actual (Cloud) |")
                lines.append("|-----------|----------------|----------------|")

                for diff in item.attribute_diffs:
                    desired = self._truncate(str(diff.desired_value), 40)
                    actual = self._truncate(str(diff.actual_value), 40)
                    lines.append(f"| `{diff.path}` | `{desired}` | `{actual}` |")

                lines.append("")

        # Errors
        if result.errors:
            lines.append("## Warnings")
            lines.append("")
            for error in result.errors:
                lines.append(f"- ⚠️ {error}")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append("*Generated by [DriftSentry](https://github.com/hemanthkp98/driftsentry)*")

        return self._finalize(lines, output_path)

    def _finalize(self, lines: list[str], output_path: str | Path | None) -> str:
        md = "\n".join(lines)
        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(md, encoding="utf-8")
        return md

    @staticmethod
    def _truncate(text: str, max_len: int) -> str:
        if len(text) <= max_len:
            return text
        return text[: max_len - 3] + "..."
