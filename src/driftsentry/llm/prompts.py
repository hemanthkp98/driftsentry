"""Prompt templates and builders for LLM smart remediation."""

from __future__ import annotations

import json
from typing import Any

from driftsentry.core.models import DriftItem

# ─── System Prompts ─────────────────────────────────────────────

HCL_SYSTEM_PROMPT = """You are an expert Principal Cloud & Terraform / OpenTofu Infrastructure Engineer.
Your task is to generate idiomatic, clean, production-grade HCL code for unmanaged cloud resources detected during an infrastructure drift scan.

Rules for generating HCL:
1. Use standard Terraform / OpenTofu syntax and official provider resource block structures.
2. Structure complex attributes into native nested blocks where appropriate (e.g. ingress/egress blocks in aws_security_group, s3 bucket encryption/versioning blocks).
3. Do NOT include read-only, computed, or runtime-assigned attributes (e.g. arn, id, owner_id, unique_id, create_date, status, endpoints) inside the resource definition.
4. If noisy attributes change frequently without intent (e.g. tags_all, public_ip), add a `lifecycle { ignore_changes = [...] }` block.
5. Derive a clean, concise, snake_case resource name following Terraform best practices.
6. Provide an import command using the provided tool ('terraform' or 'opentofu').

Output Format:
You MUST respond with a valid JSON object matching this exact schema:
{
  "hcl_results": [
    {
      "resource_address": "aws_resource_type.resource_name",
      "resource_type": "aws_resource_type",
      "resource_id": "cloud-resource-id",
      "suggested_name": "resource_name",
      "hcl_code": "resource \\"aws_resource_type\\" \\"resource_name\\" {\\n  ...\\n}",
      "explanation": "Brief explanation of HCL structure and decisions",
      "import_command": "terraform import aws_resource_type.resource_name cloud-resource-id"
    }
  ]
}
Respond ONLY with valid JSON. No markdown backticks, no text outside JSON.
"""

ROOT_CAUSE_SYSTEM_PROMPT = """You are a senior DevSecOps and Infrastructure Security Engineer analyzing infrastructure drift.
Your task is to analyze drifted infrastructure resources (which have been modified or deleted out-of-band) along with their CloudTrail audit logs, and provide an actionable, security-conscious root cause narrative and risk assessment.

For each item:
1. Explain WHAT changed and WHO made the change (correlating user agent, principal, and CloudTrail event).
2. Note whether ClickOps (AWS Console) or automated CLI / CI was used.
3. Provide a clear risk assessment (Security impact, Compliance impact, Blast radius).
4. Recommend a concrete action: 'revert' (undo drift via IaC), 'accept' (import/update IaC to match new reality), or 'investigate' (suspicious/unknown actor).

Output Format:
You MUST respond with a valid JSON object matching this exact schema:
{
  "root_causes": [
    {
      "resource_address": "module.vpc.aws_security_group.web",
      "resource_type": "aws_security_group",
      "resource_id": "sg-12345",
      "narrative": "Port 22 was opened to 0.0.0.0/0 via AWS Console by user john.doe on 2026-08-20T14:30:00Z.",
      "risk_assessment": "CRITICAL: Direct SSH access exposed to public internet violates security baselines.",
      "recommended_action": "revert"
    }
  ]
}
Respond ONLY with valid JSON. No markdown backticks, no text outside JSON.
"""


# ─── Prompt Builders ────────────────────────────────────────────


def build_hcl_user_prompt(items: list[DriftItem], iac_tool: str = "terraform") -> str:
    """Build user prompt for HCL code generation from unmanaged drift items."""
    unmanaged_payload: list[dict[str, Any]] = []

    for item in items:
        attrs = {}
        tags = {}
        if item.cloud_resource:
            attrs = item.cloud_resource.attributes
            tags = item.cloud_resource.tags

        unmanaged_payload.append(
            {
                "resource_address": item.resource_address,
                "resource_type": item.resource_type,
                "resource_id": item.resource_id,
                "region": item.cloud_resource.region if item.cloud_resource else None,
                "tags": tags,
                "attributes": attrs,
            }
        )

    return (
        f"Generate idiomatic {iac_tool.capitalize()} HCL code and import commands for the following "
        f"{len(unmanaged_payload)} unmanaged cloud resource(s):\n\n"
        f"{json.dumps(unmanaged_payload, indent=2, default=str)}\n\n"
        f"IaC Tool to target: {iac_tool}"
    )


def build_root_cause_user_prompt(items: list[DriftItem]) -> str:
    """Build user prompt for root cause analysis from changed/deleted drift items."""
    drift_payload: list[dict[str, Any]] = []

    for item in items:
        diffs = [
            {
                "attribute": d.path,
                "desired_state": d.desired_value,
                "actual_cloud_state": d.actual_value,
                "is_sensitive": d.is_sensitive,
            }
            for d in item.attribute_diffs
        ]

        attribution_data = None
        if item.attribution:
            attribution_data = {
                "principal": item.attribution.principal,
                "event_name": item.attribution.event_name,
                "event_time": (
                    item.attribution.event_time.isoformat() if item.attribution.event_time else None
                ),
                "source_ip": item.attribution.source_ip,
                "user_agent": item.attribution.user_agent,
                "is_console_change": item.attribution.is_console_change,
            }

        drift_payload.append(
            {
                "resource_address": item.resource_address,
                "resource_type": item.resource_type,
                "resource_id": item.resource_id,
                "drift_type": item.drift_type.value,
                "severity": item.severity.value,
                "attribute_diffs": diffs,
                "attribution": attribution_data,
            }
        )

    return (
        f"Analyze the following {len(drift_payload)} drifted resource(s) and provide root cause narratives, "
        f"risk assessments, and recommended remediation actions:\n\n"
        f"{json.dumps(drift_payload, indent=2, default=str)}"
    )
