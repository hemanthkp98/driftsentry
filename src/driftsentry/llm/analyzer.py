"""LLM Analyzer — orchestrates AI-assisted drift analysis and remediation code generation."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from driftsentry.core.models import (
    AIHCLResult,
    AIRemediationResult,
    AIRootCause,
    DriftItem,
    DriftResult,
    DriftType,
)
from driftsentry.llm.base import BaseLLMProvider
from driftsentry.llm.prompts import (
    HCL_SYSTEM_PROMPT,
    ROOT_CAUSE_SYSTEM_PROMPT,
    build_hcl_user_prompt,
    build_root_cause_user_prompt,
)

logger = logging.getLogger(__name__)

BATCH_SIZE = 5


class LLMAnalyzer:
    """Orchestrates AI analysis of infrastructure drift using LLM providers."""

    def __init__(
        self,
        provider: BaseLLMProvider,
        max_items: int = 20,
        batch_size: int = BATCH_SIZE,
    ) -> None:
        self._provider = provider
        self._max_items = max_items
        self._batch_size = batch_size

    def analyze(self, result: DriftResult) -> AIRemediationResult:
        """Run AI analysis on a DriftResult.

        Generates:
        - Idiomatic HCL code blocks for unmanaged resources.
        - Root-cause narratives & risk assessments for changed/deleted resources.

        Args:
            result: The completed DriftResult.

        Returns:
            AIRemediationResult containing structured AI analysis.
        """
        ai_output = AIRemediationResult(
            provider_used=self._provider.provider_name,
            model_used=self._provider.model_name,
        )

        if not result.has_drift:
            return ai_output

        # Separate items by goal
        unmanaged_items = [d for d in result.drift_items if d.drift_type == DriftType.UNMANAGED][
            : self._max_items
        ]

        changed_or_deleted_items = [
            d for d in result.drift_items if d.drift_type in (DriftType.CHANGED, DriftType.DELETED)
        ][: self._max_items]

        # 1. Generate HCL for unmanaged resources
        if unmanaged_items:
            hcl_results = self._generate_hcl_batches(
                unmanaged_items, iac_tool=result.iac_tool.value
            )
            ai_output.hcl_results.extend(hcl_results)

        # 2. Generate root-cause narratives for changed/deleted resources
        if changed_or_deleted_items:
            root_causes = self._generate_root_cause_batches(changed_or_deleted_items)
            ai_output.root_causes.extend(root_causes)

        return ai_output

    def _generate_hcl_batches(self, items: list[DriftItem], iac_tool: str) -> list[AIHCLResult]:
        """Process unmanaged items in batches to generate idiomatic HCL."""
        results: list[AIHCLResult] = []

        for i in range(0, len(items), self._batch_size):
            batch = items[i : i + self._batch_size]
            user_prompt = build_hcl_user_prompt(batch, iac_tool=iac_tool)

            try:
                raw_response = self._provider.complete(
                    system_prompt=HCL_SYSTEM_PROMPT,
                    user_prompt=user_prompt,
                )
                parsed_json = self._extract_json(raw_response)
                for item_dict in parsed_json.get("hcl_results", []):
                    try:
                        results.append(AIHCLResult(**item_dict))
                    except Exception as e:
                        logger.warning(f"Failed to parse AI HCL item: {e}")
            except Exception as e:
                logger.error(f"AI HCL generation failed for batch: {e}")

        return results

    def _generate_root_cause_batches(self, items: list[DriftItem]) -> list[AIRootCause]:
        """Process changed/deleted items in batches to generate root cause narratives."""
        results: list[AIRootCause] = []

        for i in range(0, len(items), self._batch_size):
            batch = items[i : i + self._batch_size]
            user_prompt = build_root_cause_user_prompt(batch)

            try:
                raw_response = self._provider.complete(
                    system_prompt=ROOT_CAUSE_SYSTEM_PROMPT,
                    user_prompt=user_prompt,
                )
                parsed_json = self._extract_json(raw_response)
                for item_dict in parsed_json.get("root_causes", []):
                    try:
                        results.append(AIRootCause(**item_dict))
                    except Exception as e:
                        logger.warning(f"Failed to parse AI root cause item: {e}")
            except Exception as e:
                logger.error(f"AI root cause analysis failed for batch: {e}")

        return results

    @staticmethod
    def _extract_json(raw_text: str) -> dict[str, Any]:
        """Extract and parse JSON object from LLM response text."""
        cleaned = raw_text.strip()

        # Strip markdown json code blocks if present
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\n", "", cleaned)
            cleaned = re.sub(r"\n```$", "", cleaned)
            cleaned = cleaned.strip()

        try:
            parsed: Any = json.loads(cleaned)
            if isinstance(parsed, dict):
                return dict(parsed)
            return {}
        except json.JSONDecodeError:
            # Try finding first { and last }
            match = re.search(r"(\{.*\})", cleaned, re.DOTALL)
            if match:
                parsed_fallback: Any = json.loads(match.group(1))
                if isinstance(parsed_fallback, dict):
                    return dict(parsed_fallback)
            raise
