"""Remediation generator — produces import commands and HCL code.

Supports three modes:
- IMPORT: Generate `terraform import` / `tofu import` commands + HCL resource blocks
  for unmanaged resources.
- REVERT: Generate instructions to revert drifted resources to their desired state.
- BOTH: Generate both artifacts, letting the user choose per-resource.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from driftsentry.core.models import (
    DriftItem,
    DriftResult,
    DriftType,
    IaCTool,
    RemediationMode,
)

logger = logging.getLogger(__name__)

# ─── Templates directory ────────────────────────────────────────

TEMPLATES_DIR = Path(__file__).parent / "templates"


class RemediationGenerator:
    """Generates remediation artifacts for drifted resources.

    Produces:
    - Import commands and HCL blocks for unmanaged resources
    - Revert instructions for changed resources
    - Summary report
    """

    def __init__(
        self,
        mode: RemediationMode = RemediationMode.BOTH,
        iac_tool: IaCTool = IaCTool.TERRAFORM,
        output_dir: str = "./driftsentry-remediation",
        dry_run: bool = False,
    ) -> None:
        self._mode = mode
        self._iac_tool = iac_tool
        self._output_dir = Path(output_dir)
        self._dry_run = dry_run

        # Initialize Jinja2 template environment
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate(self, result: DriftResult) -> RemediationOutput:
        """Generate remediation artifacts for all drift items.

        Returns:
            RemediationOutput with file paths and summary.
        """
        output = RemediationOutput(output_dir=self._output_dir)

        if not self._dry_run:
            self._output_dir.mkdir(parents=True, exist_ok=True)

        tool_cmd = self._iac_tool.value  # "terraform" or "opentofu"

        # Process by drift type
        for item in result.drift_items:
            if item.drift_type == DriftType.UNMANAGED and self._mode in (
                RemediationMode.IMPORT,
                RemediationMode.BOTH,
            ):
                self._generate_import(item, tool_cmd, output)

            if item.drift_type == DriftType.CHANGED and self._mode in (
                RemediationMode.REVERT,
                RemediationMode.BOTH,
            ):
                self._generate_revert(item, tool_cmd, output)

            if item.drift_type == DriftType.DELETED:
                output.deleted_resources.append(item.resource_address)

        # Write summary
        if not self._dry_run:
            self._write_summary(result, output)

        return output

    def _generate_import(
        self,
        item: DriftItem,
        tool_cmd: str,
        output: RemediationOutput,
    ) -> None:
        """Generate import command and HCL resource block for an unmanaged resource."""
        resource_id = item.resource_id or "UNKNOWN_ID"
        # Suggest a Terraform resource name from the cloud resource ID or name
        suggested_name = self._suggest_resource_name(item)
        tf_address = f"{item.resource_type}.{suggested_name}"

        # Import command
        import_cmd = f"{tool_cmd} import {tf_address} {resource_id}"
        output.import_commands.append(import_cmd)

        # Generate HCL resource block
        hcl_block = self._generate_hcl_block(item, suggested_name)
        output.hcl_blocks.append(hcl_block)

        if not self._dry_run:
            # Write import script
            import_file = self._output_dir / "import.sh"
            with open(import_file, "a") as f:
                f.write(f"# Import {item.resource_type} — {resource_id}\n")
                f.write(f"{import_cmd}\n\n")
            import_file.chmod(0o755)
            output.files_created.add(str(import_file))

            # Write HCL
            hcl_file = self._output_dir / f"imported_{suggested_name}.tf"
            with open(hcl_file, "w") as f:
                f.write(hcl_block)
            output.files_created.add(str(hcl_file))

    def _generate_revert(
        self,
        item: DriftItem,
        tool_cmd: str,
        output: RemediationOutput,
    ) -> None:
        """Generate revert instructions for a changed resource."""
        changes_list: list[dict[str, Any]] = []
        revert_info: dict[str, Any] = {
            "resource": item.resource_address,
            "resource_type": item.resource_type,
            "resource_id": item.resource_id,
            "changes": changes_list,
        }

        for diff in item.attribute_diffs:
            changes_list.append(
                {
                    "attribute": diff.path,
                    "desired": diff.desired_value,
                    "actual": diff.actual_value,
                }
            )

        output.revert_items.append(revert_info)

        if not self._dry_run:
            # Write revert plan
            revert_file = self._output_dir / "revert_plan.json"
            # Append to existing plan
            existing: list[dict[str, Any]] = []
            if revert_file.exists():
                existing = json.loads(revert_file.read_text())
            existing.append(revert_info)
            revert_file.write_text(json.dumps(existing, indent=2, default=str))
            output.files_created.add(str(revert_file))

            # Also write a human-readable revert instruction
            revert_md = self._output_dir / "revert_instructions.md"
            with open(revert_md, "a") as f:
                f.write(f"## {item.resource_address}\n\n")
                f.write(f"Run `{tool_cmd} apply` to revert the following changes:\n\n")
                f.write("| Attribute | Desired (will apply) | Current (cloud) |\n")
                f.write("|-----------|---------------------|------------------|\n")
                for diff in item.attribute_diffs:
                    f.write(f"| `{diff.path}` | `{diff.desired_value}` | `{diff.actual_value}` |\n")
                f.write("\n---\n\n")
            output.files_created.add(str(revert_md))

    def _generate_hcl_block(self, item: DriftItem, suggested_name: str) -> str:
        """Generate an HCL resource block from cloud resource attributes."""
        attrs = {}
        if item.cloud_resource:
            attrs = item.cloud_resource.attributes.copy()
            # Remove computed attributes that shouldn't be in HCL
            for key in ("id", "arn", "owner_id", "unique_id"):
                attrs.pop(key, None)

        lines: list[str] = []
        lines.append(f'resource "{item.resource_type}" "{suggested_name}" {{')

        for key, value in sorted(attrs.items()):
            hcl_value = self._to_hcl_value(value)
            if hcl_value is not None:
                lines.append(f"  {key} = {hcl_value}")

        lines.append("}")
        lines.append("")

        return "\n".join(lines)

    def _write_summary(self, result: DriftResult, output: RemediationOutput) -> None:
        """Write a summary file."""
        summary_file = self._output_dir / "REMEDIATION_SUMMARY.md"
        tool_name = self._iac_tool.value.capitalize()

        with open(summary_file, "w") as f:
            f.write("# DriftSentry Remediation Plan\n\n")
            f.write(f"**Scan ID:** `{result.scan_id}`\n")
            f.write(f"**Mode:** {self._mode.value}\n")
            f.write(f"**IaC Tool:** {tool_name}\n\n")

            if output.import_commands:
                f.write("## Unmanaged Resources — Import\n\n")
                f.write(
                    f"Run these commands to bring {len(output.import_commands)} unmanaged resources under {tool_name} management:\n\n"
                )
                f.write("```bash\n")
                f.write("# Run the import script:\n")
                f.write(f"bash {self._output_dir}/import.sh\n")
                f.write("```\n\n")
                f.write("Or run individual imports:\n\n")
                for cmd in output.import_commands:
                    f.write(f"```bash\n{cmd}\n```\n\n")

            if output.revert_items:
                f.write("## Changed Resources — Revert\n\n")
                f.write(
                    f"Run `{self._iac_tool.value} apply` to revert {len(output.revert_items)} resources to their desired state.\n\n"
                )
                f.write("See `revert_instructions.md` for details.\n\n")

            if output.deleted_resources:
                f.write("## Deleted Resources\n\n")
                f.write("These resources exist in state but have been deleted from the cloud:\n\n")
                for addr in output.deleted_resources:
                    f.write(f"- `{addr}`\n")
                f.write(
                    f"\nRun `{self._iac_tool.value} apply` to recreate them, or `{self._iac_tool.value} state rm` to remove from state.\n\n"
                )

            f.write("---\n")
            f.write(
                "*Generated by [DriftSentry](https://github.com/hemanthkp98/driftsentry)*\n"
            )

        output.files_created.add(str(summary_file))

    def _suggest_resource_name(self, item: DriftItem) -> str:
        """Suggest a Terraform resource name from cloud resource name, tag, or ID."""
        if item.cloud_resource:
            if name := item.cloud_resource.attributes.get("name"):
                return self._sanitize_name(str(name))
            if name := item.cloud_resource.tags.get("Name"):
                return self._sanitize_name(str(name))
            if name := item.cloud_resource.attributes.get("bucket"):
                return self._sanitize_name(str(name))

        resource_id = item.resource_id or "imported"
        return self._sanitize_name(resource_id)

    @staticmethod
    def _sanitize_name(raw_name: str) -> str:
        """Sanitize a string to be a valid Terraform HCL identifier."""
        name = raw_name.replace("-", "_").replace(".", "_").replace("/", "_")
        for prefix in ("i_", "sg_", "vpc_", "subnet_", "arn_aws_"):
            if name.startswith(prefix):
                name = name[len(prefix) :]
                break
        if name and not name[0].isalpha() and name[0] != "_":
            name = f"imported_{name}"
        return name[:60] or "imported"

    @staticmethod
    def _to_hcl_value(value: Any) -> str | None:
        """Convert a Python value to an HCL-compatible string representation."""
        if value is None:
            return None
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, int | float):
            return str(value)
        if isinstance(value, str):
            return f'"{value}"'
        if isinstance(value, list):
            if not value:
                return "[]"
            items = [RemediationGenerator._to_hcl_value(v) for v in value if v is not None]
            valid = [i for i in items if i is not None]
            return "[" + ", ".join(valid) + "]"
        if isinstance(value, dict):
            return None  # Skip nested blocks for now — complex to serialize
        return f'"{value}"'


class RemediationOutput:
    """Container for remediation generation results."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.import_commands: list[str] = []
        self.hcl_blocks: list[str] = []
        self.revert_items: list[dict[str, Any]] = []
        self.deleted_resources: list[str] = []
        self.files_created: set[str] = set()

    @property
    def total_items(self) -> int:
        return len(self.import_commands) + len(self.revert_items) + len(self.deleted_resources)
