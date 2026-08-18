"""HTML report generator — self-contained HTML drift report."""

from __future__ import annotations

from pathlib import Path

from driftsentry.core.models import DriftResult, DriftSeverity, DriftType

SEVERITY_COLORS: dict[DriftSeverity, str] = {
    DriftSeverity.CRITICAL: "#ef4444",
    DriftSeverity.HIGH: "#f97316",
    DriftSeverity.MEDIUM: "#eab308",
    DriftSeverity.LOW: "#22c55e",
    DriftSeverity.INFO: "#3b82f6",
}

DRIFT_TYPE_COLORS: dict[DriftType, str] = {
    DriftType.CHANGED: "#eab308",
    DriftType.DELETED: "#ef4444",
    DriftType.UNMANAGED: "#a855f7",
}


class HTMLFormatter:
    """Generates a self-contained HTML drift report with embedded CSS."""

    def render(self, result: DriftResult, output_path: str | Path | None = None) -> str:
        """Generate the HTML report.

        Args:
            result: The drift scan result.
            output_path: Path to write the HTML file. If None, returns the string.

        Returns:
            The HTML string.
        """
        html = self._build_html(result)

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(html, encoding="utf-8")

        return html

    def _build_html(self, result: DriftResult) -> str:
        """Build the complete HTML document."""
        rows = self._build_table_rows(result)
        details = self._build_detail_sections(result)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DriftSentry Report — {result.scan_id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            padding: 2rem;
            line-height: 1.6;
        }}
        .header {{
            text-align: center;
            margin-bottom: 2rem;
            padding: 2rem;
            background: linear-gradient(135deg, #1e293b, #334155);
            border-radius: 12px;
            border: 1px solid #475569;
        }}
        .header h1 {{
            font-size: 2rem;
            background: linear-gradient(135deg, #06b6d4, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        .header .meta {{ color: #94a3b8; font-size: 0.9rem; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 1.25rem;
            text-align: center;
        }}
        .stat-card .number {{
            font-size: 2rem;
            font-weight: 700;
        }}
        .stat-card .label {{
            color: #94a3b8;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 2rem;
            background: #1e293b;
            border-radius: 8px;
            overflow: hidden;
        }}
        th {{
            background: #334155;
            padding: 0.75rem 1rem;
            text-align: left;
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #94a3b8;
        }}
        td {{
            padding: 0.75rem 1rem;
            border-top: 1px solid #334155;
        }}
        tr:hover {{ background: #334155; }}
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .detail-section {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }}
        .detail-section h3 {{
            margin-bottom: 1rem;
            color: #06b6d4;
        }}
        .diff-row {{
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 0.5rem;
            padding: 0.5rem;
            border-bottom: 1px solid #334155;
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
        }}
        .diff-row .attr {{ color: #94a3b8; }}
        .diff-row .desired {{ color: #22c55e; }}
        .diff-row .actual {{ color: #ef4444; }}
        .footer {{
            text-align: center;
            color: #64748b;
            padding-top: 2rem;
            border-top: 1px solid #334155;
            font-size: 0.85rem;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ DriftSentry Report</h1>
        <div class="meta">
            Scan ID: {result.scan_id} | {result.iac_tool.value.capitalize()} |
            Provider: {result.provider} | Region: {result.region or "N/A"} |
            Duration: {result.duration_seconds}s
        </div>
    </div>

    <div class="stats">
        <div class="stat-card">
            <div class="number">{result.total_resources}</div>
            <div class="label">Total Resources</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color: {SEVERITY_COLORS[DriftSeverity.CRITICAL]}">{result.critical_count}</div>
            <div class="label">Critical</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color: {DRIFT_TYPE_COLORS[DriftType.CHANGED]}">{result.changed_count}</div>
            <div class="label">Changed</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color: {DRIFT_TYPE_COLORS[DriftType.DELETED]}">{result.deleted_count}</div>
            <div class="label">Deleted</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color: {DRIFT_TYPE_COLORS[DriftType.UNMANAGED]}">{result.unmanaged_count}</div>
            <div class="label">Unmanaged</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Resource</th>
                <th>Drift Type</th>
                <th>Severity</th>
                <th>Changes</th>
                <th>Changed By</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>

    {details}

    <div class="footer">
        Generated by DriftSentry v0.1.0 — Your infrastructure's immune system
    </div>
</body>
</html>"""

    def _build_table_rows(self, result: DriftResult) -> str:
        rows: list[str] = []
        for item in result.drift_items:
            sev_color = SEVERITY_COLORS.get(item.severity, "#94a3b8")
            type_color = DRIFT_TYPE_COLORS.get(item.drift_type, "#94a3b8")
            changes = str(len(item.attribute_diffs)) if item.attribute_diffs else "-"
            changed_by = "-"
            if item.attribution and item.attribution.principal:
                changed_by = item.attribution.principal
                if item.attribution.is_console_change:
                    changed_by += " (console)"

            rows.append(f"""
            <tr>
                <td><code>{item.resource_address}</code></td>
                <td><span class="badge" style="background:{type_color}20; color:{type_color}">{item.drift_type.value}</span></td>
                <td><span class="badge" style="background:{sev_color}20; color:{sev_color}">{item.severity.value}</span></td>
                <td>{changes}</td>
                <td>{changed_by}</td>
            </tr>""")

        return "\n".join(rows)

    def _build_detail_sections(self, result: DriftResult) -> str:
        sections: list[str] = []
        for item in result.drift_items:
            if not item.attribute_diffs:
                continue

            diff_rows: list[str] = []
            for diff in item.attribute_diffs:
                diff_rows.append(f"""
                <div class="diff-row">
                    <div class="attr">{diff.path}</div>
                    <div class="desired">{self._escape_html(str(diff.desired_value))}</div>
                    <div class="actual">{self._escape_html(str(diff.actual_value))}</div>
                </div>""")

            sections.append(f"""
    <div class="detail-section">
        <h3>{item.resource_address}</h3>
        <div class="diff-row" style="font-weight:600; color:#94a3b8;">
            <div>Attribute</div>
            <div>Desired (State)</div>
            <div>Actual (Cloud)</div>
        </div>
        {"".join(diff_rows)}
    </div>""")

        return "\n".join(sections)

    @staticmethod
    def _escape_html(text: str) -> str:
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
