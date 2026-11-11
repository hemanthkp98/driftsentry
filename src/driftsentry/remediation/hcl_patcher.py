"""In-place HCL code reconciler — patches Terraform/OpenTofu code to match live cloud state."""

from __future__ import annotations

import difflib
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from driftsentry.core.models import AttributeDiff, DriftItem, DriftType

logger = logging.getLogger(__name__)


@dataclass
class HCLPatchResult:
    """Result of an HCL patching operation."""

    file_path: Path | None
    resource_address: str
    diff: str = ""
    attributes_patched: list[str] = field(default_factory=list)
    success: bool = False
    message: str = ""


class HCLPatcher:
    """Reconciles live drift into Terraform/OpenTofu source files in-place."""

    def __init__(
        self,
        workspace_dir: str | Path | None = None,
        dry_run: bool = False,
        format_code: bool = True,
    ) -> None:
        """Initialize the HCL patcher.

        Args:
            workspace_dir: Directory containing Terraform source files (.tf).
            dry_run: If True, preview diff without modifying files on disk.
            format_code: If True, runs `terraform fmt` / `tofu fmt` if installed.
        """
        self.workspace_dir = Path(workspace_dir).resolve() if workspace_dir else Path.cwd()
        self.dry_run = dry_run
        self.format_code = format_code

    def patch_resource(
        self,
        item: DriftItem,
        workspace_dir: str | Path | None = None,
    ) -> HCLPatchResult:
        """Patch a drifted resource in the corresponding .tf file.

        Args:
            item: DriftItem representing the drifted resource.
            workspace_dir: Optional override for the workspace directory.

        Returns:
            HCLPatchResult containing status and generated diff.
        """
        search_dir = Path(workspace_dir).resolve() if workspace_dir else self.workspace_dir

        if item.drift_type != DriftType.CHANGED:
            return HCLPatchResult(
                file_path=None,
                resource_address=item.resource_address,
                success=False,
                message=f"HCL patching only applies to CHANGED resources (got {item.drift_type.value})",
            )

        if not item.attribute_diffs:
            return HCLPatchResult(
                file_path=None,
                resource_address=item.resource_address,
                success=False,
                message="No attribute diffs to reconcile",
            )

        res_type, res_name = self._parse_resource_address(
            item.resource_address, expected_type=item.resource_type
        )

        tf_file, block_span = self._find_resource_block(search_dir, res_type, res_name)
        if not tf_file or block_span is None:
            return HCLPatchResult(
                file_path=None,
                resource_address=item.resource_address,
                success=False,
                message=(
                    f'Could not locate resource "{res_type}" "{res_name}" '
                    f"in any .tf file under {search_dir}"
                ),
            )

        try:
            content = tf_file.read_text(encoding="utf-8")
        except OSError as e:
            return HCLPatchResult(
                file_path=tf_file,
                resource_address=item.resource_address,
                success=False,
                message=f"Failed to read file {tf_file}: {e}",
            )

        start_idx, end_idx = block_span
        block_text = content[start_idx:end_idx]

        patched_block, attributes_patched = self._patch_block_attributes(
            block_text, item.attribute_diffs
        )

        if not attributes_patched:
            return HCLPatchResult(
                file_path=tf_file,
                resource_address=item.resource_address,
                success=False,
                message="No attributes could be patched in the resource block",
            )

        new_content = content[:start_idx] + patched_block + content[end_idx:]

        diff_str = "".join(
            difflib.unified_diff(
                content.splitlines(keepends=True),
                new_content.splitlines(keepends=True),
                fromfile=f"a/{tf_file.name}",
                tofile=f"b/{tf_file.name}",
            )
        )

        if not self.dry_run:
            try:
                tf_file.write_text(new_content, encoding="utf-8")
                if self.format_code:
                    self._run_formatter(tf_file)
            except OSError as e:
                return HCLPatchResult(
                    file_path=tf_file,
                    resource_address=item.resource_address,
                    success=False,
                    message=f"Failed to write patched file {tf_file}: {e}",
                )

        return HCLPatchResult(
            file_path=tf_file,
            resource_address=item.resource_address,
            diff=diff_str,
            attributes_patched=attributes_patched,
            success=True,
            message=(
                f"Successfully reconciled {len(attributes_patched)} attribute(s) in {tf_file.name}"
            ),
        )

    def patch_all(
        self,
        items: list[DriftItem],
        workspace_dir: str | Path | None = None,
    ) -> list[HCLPatchResult]:
        """Patch all changed drift items across the workspace.

        Args:
            items: List of DriftItems.
            workspace_dir: Optional override for the workspace directory.

        Returns:
            List of HCLPatchResult.
        """
        results: list[HCLPatchResult] = []
        for item in items:
            if item.drift_type == DriftType.CHANGED:
                results.append(self.patch_resource(item, workspace_dir=workspace_dir))
        return results

    @staticmethod
    def _parse_resource_address(address: str, expected_type: str | None = None) -> tuple[str, str]:
        """Extract resource type and resource name from a Terraform address."""
        clean = address.replace("[unmanaged] ", "").strip()
        parts = clean.split(".")

        if expected_type and expected_type in parts:
            idx = parts.index(expected_type)
            res_type = expected_type
            res_name = parts[idx + 1].split("[")[0] if idx + 1 < len(parts) else "main"
            return res_type, res_name

        if len(parts) >= 2:
            res_name = parts[-1].split("[")[0]
            res_type = parts[-2]
            return res_type, res_name

        return expected_type or "resource", parts[0]

    def _find_resource_block(
        self,
        search_dir: Path,
        res_type: str,
        res_name: str,
    ) -> tuple[Path | None, tuple[int, int] | None]:
        """Search .tf files for the matching resource block span."""
        if not search_dir.exists():
            return None, None

        tf_files: list[Path] = []
        if search_dir.is_file() and search_dir.suffix == ".tf":
            tf_files = [search_dir]
        else:
            for p in search_dir.rglob("*.tf"):
                # Skip hidden/vendor directories
                parts = p.parts
                if any(
                    part.startswith(".")
                    or part in ("node_modules", "vendor", "dist", "build", "__pycache__")
                    for part in parts
                ):
                    continue
                tf_files.append(p)

        pattern = re.compile(
            r'(?:^|\n)([ \t]*resource\s+"'
            + re.escape(res_type)
            + r'"\s+"'
            + re.escape(res_name)
            + r'"\s*\{)',
            re.MULTILINE,
        )

        for tf_file in sorted(tf_files):
            try:
                content = tf_file.read_text(encoding="utf-8")
            except OSError:
                continue

            match = pattern.search(content)
            if not match:
                continue

            header_start = match.start(1)
            # Find closing brace of this block
            span = self._find_matching_brace_span(content, header_start)
            if span:
                return tf_file, span

        return None, None

    @staticmethod
    def _find_matching_brace_span(text: str, start_pos: int) -> tuple[int, int] | None:
        """Find the start and end indices of the block starting at start_pos."""
        brace_pos = text.find("{", start_pos)
        if brace_pos == -1:
            return None

        depth = 0
        in_string = False
        escape = False
        in_line_comment = False
        in_block_comment = False
        i = brace_pos
        n = len(text)

        while i < n:
            c = text[i]

            if in_line_comment:
                if c == "\n":
                    in_line_comment = False
                i += 1
                continue

            if in_block_comment:
                if c == "*" and i + 1 < n and text[i + 1] == "/":
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue

            if in_string:
                if escape:
                    escape = False
                elif c == "\\":
                    escape = True
                elif c == '"':
                    in_string = False
                i += 1
                continue

            # Check comments
            if c == "#" or (c == "/" and i + 1 < n and text[i + 1] == "/"):
                in_line_comment = True
                i += 1
                continue

            if c == "/" and i + 1 < n and text[i + 1] == "*":
                in_block_comment = True
                i += 2
                continue

            if c == '"':
                in_string = True
                i += 1
                continue

            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return (start_pos, i + 1)

            i += 1

        return None

    def _patch_block_attributes(
        self,
        block_text: str,
        attribute_diffs: list[AttributeDiff],
    ) -> tuple[str, list[str]]:
        """Patch attributes inside a single resource block string."""
        patched_text = block_text
        patched_attributes: list[str] = []

        # Detect block indentation (default: 2 spaces)
        indent_match = re.search(r"\n([ \t]+)[a-zA-Z0-9_]+", block_text)
        attr_indent = indent_match.group(1) if indent_match else "  "

        for diff in attribute_diffs:
            if diff.is_sensitive:
                continue

            path = diff.path.strip()
            new_val = diff.actual_value

            if not path:
                continue

            # Handle nested map attribute like 'tags.Environment'
            if "." in path:
                parent_key, child_key = path.split(".", 1)
                success, updated_text = self._patch_nested_attribute(
                    patched_text, parent_key, child_key, new_val, attr_indent
                )
                if success:
                    patched_text = updated_text
                    patched_attributes.append(path)
                continue

            # Top-level attribute
            success, updated_text = self._patch_top_level_attribute(
                patched_text, path, new_val, attr_indent
            )
            if success:
                patched_text = updated_text
                patched_attributes.append(path)

        return patched_text, patched_attributes

    def _patch_top_level_attribute(
        self,
        block_text: str,
        attr_name: str,
        value: Any,
        attr_indent: str,
    ) -> tuple[bool, str]:
        """Update or insert a top-level attribute inside the resource block."""
        formatted_val = self.format_hcl_value(value, indent_level=len(attr_indent))

        # Check if attribute assignment already exists
        # e.g.:   instance_type = "t3.micro"
        pattern = re.compile(
            r"^([ \t]*" + re.escape(attr_name) + r"\s*=\s*)([^\n#]+)(.*)$",
            re.MULTILINE,
        )

        match = pattern.search(block_text)
        if match:
            # Replace existing assignment, keeping inline comments if any
            prefix = match.group(1)
            comment = match.group(3) if match.group(3).strip().startswith("#") else ""
            trailing = f" {comment.strip()}" if comment else ""
            replacement = f"{prefix}{formatted_val}{trailing}"
            updated = pattern.sub(lambda m: replacement, block_text, count=1)
            return True, updated

        # Check if block/map with that name exists, e.g. tags = { ... }
        map_pattern = re.compile(
            r"^([ \t]*" + re.escape(attr_name) + r"\s*=\s*\{[\s\S]*?\})",
            re.MULTILINE,
        )
        if map_pattern.search(block_text) and isinstance(value, dict):
            replacement = f"{attr_indent}{attr_name} = {formatted_val}"
            updated = map_pattern.sub(replacement, block_text, count=1)
            return True, updated

        # Attribute not found — insert right before the closing brace
        closing_brace_idx = block_text.rfind("}")
        if closing_brace_idx == -1:
            return False, block_text

        insert_line = f"{attr_indent}{attr_name} = {formatted_val}\n"
        prefix = block_text[:closing_brace_idx]
        if not prefix.endswith("\n"):
            prefix += "\n"
        suffix = block_text[closing_brace_idx:]
        updated = prefix + insert_line + suffix
        return True, updated

    def _patch_nested_attribute(
        self,
        block_text: str,
        parent_key: str,
        child_key: str,
        value: Any,
        attr_indent: str,
    ) -> tuple[bool, str]:
        """Update or insert an attribute inside a map block, e.g. tags.Environment."""
        # Find parent map block, e.g. tags = { ... }
        parent_pattern = re.compile(
            r"(^[ \t]*" + re.escape(parent_key) + r"\s*=\s*\{)",
            re.MULTILINE,
        )
        match = parent_pattern.search(block_text)

        child_indent = attr_indent + "  "
        formatted_val = self.format_hcl_value(value, indent_level=len(child_indent))

        if match:
            start_pos = match.start(1)
            span = self._find_matching_brace_span(block_text, start_pos)
            if not span:
                return False, block_text

            map_start, map_end = span
            map_content = block_text[map_start:map_end]

            # Look for child key inside map
            child_pattern = re.compile(
                r"^([ \t]*(?:\""
                + re.escape(child_key)
                + r"\"|"
                + re.escape(child_key)
                + r")\s*=\s*)([^\n#]+)(.*)$",
                re.MULTILINE,
            )

            child_match = child_pattern.search(map_content)
            if child_match:
                prefix = child_match.group(1)
                comment = (
                    child_match.group(3) if child_match.group(3).strip().startswith("#") else ""
                )
                trailing = f" {comment.strip()}" if comment else ""
                replacement = f"{prefix}{formatted_val}{trailing}"
                updated_map = child_pattern.sub(lambda m: replacement, map_content, count=1)
            else:
                # Insert child inside map before map's closing brace
                map_close_idx = map_content.rfind("}")
                pfx = map_content[:map_close_idx]
                if not pfx.endswith("\n"):
                    pfx += "\n"
                sfx = map_content[map_close_idx:]
                updated_map = pfx + f"{child_indent}{child_key} = {formatted_val}\n" + sfx

            updated_block = block_text[:map_start] + updated_map + block_text[map_end:]
            return True, updated_block

        # Parent map doesn't exist — create it with child key
        map_block = (
            f"{attr_indent}{parent_key} = {{\n"
            f"{child_indent}{child_key} = {formatted_val}\n"
            f"{attr_indent}}}\n"
        )
        closing_brace_idx = block_text.rfind("}")
        if closing_brace_idx == -1:
            return False, block_text

        prefix = block_text[:closing_brace_idx]
        if not prefix.endswith("\n"):
            prefix += "\n"
        suffix = block_text[closing_brace_idx:]
        updated = prefix + map_block + suffix
        return True, updated

    @classmethod
    def format_hcl_value(cls, value: Any, indent_level: int = 2) -> str:
        """Format a Python value as an idiomatic HCL expression."""
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, str):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'
        if isinstance(value, list):
            if not value:
                return "[]"
            if all(isinstance(x, (str, int, float, bool)) for x in value):
                items = [cls.format_hcl_value(x) for x in value]
                return f"[{', '.join(items)}]"
            pad = " " * (indent_level + 2)
            items_str = ",\n".join(
                f"{pad}{cls.format_hcl_value(x, indent_level + 2)}" for x in value
            )
            return f"[\n{items_str}\n{' ' * indent_level}]"
        if isinstance(value, dict):
            if not value:
                return "{}"
            pad = " " * (indent_level + 2)
            lines: list[str] = []
            for k, v in value.items():
                key_str = f'"{k}"' if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_-]*$", str(k)) else str(k)
                lines.append(f"{pad}{key_str} = {cls.format_hcl_value(v, indent_level + 2)}")
            return "{\n" + "\n".join(lines) + f"\n{' ' * indent_level}}}"
        return f'"{value}"'

    def _run_formatter(self, file_path: Path) -> None:
        """Run terraform fmt or tofu fmt on the modified file if available."""
        cmd = None
        if shutil.which("terraform"):
            cmd = "terraform"
        elif shutil.which("tofu"):
            cmd = "tofu"

        if not cmd:
            return

        try:
            subprocess.run(
                [cmd, "fmt", str(file_path)],
                check=False,
                capture_output=True,
                timeout=5,
            )
        except Exception as e:
            logger.debug("Failed to run %s fmt: %s", cmd, e)
