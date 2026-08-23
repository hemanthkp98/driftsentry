"""Unit tests for LLM analyzer and smart remediation orchestration."""

from __future__ import annotations

import json

from driftsentry.core.models import (
    AttributeDiff,
    CloudResource,
    DriftAttribution,
    DriftItem,
    DriftResult,
    DriftSeverity,
    DriftType,
    IaCTool,
    StateBackendType,
)
from driftsentry.llm.analyzer import LLMAnalyzer
from driftsentry.llm.base import BaseLLMProvider


class MockLLMProvider(BaseLLMProvider):
    """Mock LLM provider returning predetermined completions."""

    def __init__(
        self,
        hcl_response: str | None = None,
        root_cause_response: str | None = None,
    ) -> None:
        self.hcl_response = hcl_response or json.dumps(
            {
                "hcl_results": [
                    {
                        "resource_address": "aws_security_group.shadow_sg",
                        "resource_type": "aws_security_group",
                        "resource_id": "sg-99999",
                        "suggested_name": "shadow_sg",
                        "hcl_code": 'resource "aws_security_group" "shadow_sg" {\n  name = "shadow_sg"\n}',
                        "explanation": "Standard security group block with name attribute",
                        "import_command": "terraform import aws_security_group.shadow_sg sg-99999",
                    }
                ]
            }
        )
        self.root_cause_response = root_cause_response or json.dumps(
            {
                "root_causes": [
                    {
                        "resource_address": "aws_instance.web",
                        "resource_type": "aws_instance",
                        "resource_id": "i-12345",
                        "narrative": "Instance type was scaled up from t3.micro to t3.2xlarge via AWS Console by user admin.",
                        "risk_assessment": "MEDIUM: Increased compute costs without IaC tracking.",
                        "recommended_action": "revert",
                    }
                ]
            }
        )

    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> str:
        if "unmanaged" in user_prompt.lower():
            return self.hcl_response
        return self.root_cause_response

    @property
    def provider_name(self) -> str:
        return "mock-claude"

    @property
    def model_name(self) -> str:
        return "mock-claude-3-7-sonnet"


def test_llm_analyzer_full_workflow() -> None:
    # 1. Setup unmanaged item
    unmanaged_item = DriftItem(
        resource_address="[unmanaged] aws_security_group.sg-99999",
        resource_type="aws_security_group",
        resource_id="sg-99999",
        drift_type=DriftType.UNMANAGED,
        severity=DriftSeverity.HIGH,
        cloud_resource=CloudResource(
            resource_id="sg-99999",
            resource_type="aws_security_group",
            attributes={"name": "shadow_sg", "description": "test shadow"},
        ),
    )

    # 2. Setup changed item with attribution
    changed_item = DriftItem(
        resource_address="aws_instance.web",
        resource_type="aws_instance",
        resource_id="i-12345",
        drift_type=DriftType.CHANGED,
        severity=DriftSeverity.MEDIUM,
        attribute_diffs=[
            AttributeDiff(
                path="instance_type",
                desired_value="t3.micro",
                actual_value="t3.2xlarge",
            )
        ],
        attribution=DriftAttribution(
            principal="admin",
            event_name="ModifyInstanceAttribute",
            is_console_change=True,
        ),
    )

    drift_result = DriftResult(
        scan_id="scan-ai-1",
        provider="aws",
        state_backend=StateBackendType.LOCAL,
        state_source="terraform.tfstate",
        iac_tool=IaCTool.TERRAFORM,
        drift_items=[unmanaged_item, changed_item],
    )

    provider = MockLLMProvider()
    analyzer = LLMAnalyzer(provider=provider, max_items=10)

    ai_result = analyzer.analyze(drift_result)

    assert ai_result.provider_used == "mock-claude"
    assert ai_result.model_used == "mock-claude-3-7-sonnet"
    assert len(ai_result.hcl_results) == 1
    assert ai_result.hcl_results[0].suggested_name == "shadow_sg"
    assert 'resource "aws_security_group" "shadow_sg"' in ai_result.hcl_results[0].hcl_code

    assert len(ai_result.root_causes) == 1
    assert "t3.2xlarge" in ai_result.root_causes[0].narrative
    assert ai_result.root_causes[0].recommended_action == "revert"


def test_llm_analyzer_markdown_fence_stripping() -> None:
    fenced_json = (
        "```json\n"
        + json.dumps(
            {
                "hcl_results": [
                    {
                        "resource_address": "aws_s3_bucket.b1",
                        "resource_type": "aws_s3_bucket",
                        "resource_id": "b1",
                        "suggested_name": "b1",
                        "hcl_code": 'resource "aws_s3_bucket" "b1" {}',
                        "explanation": "Bucket block",
                        "import_command": "terraform import aws_s3_bucket.b1 b1",
                    }
                ]
            }
        )
        + "\n```"
    )

    provider = MockLLMProvider(hcl_response=fenced_json)
    analyzer = LLMAnalyzer(provider=provider)

    unmanaged_item = DriftItem(
        resource_address="[unmanaged] aws_s3_bucket.b1",
        resource_type="aws_s3_bucket",
        resource_id="b1",
        drift_type=DriftType.UNMANAGED,
        cloud_resource=CloudResource(resource_id="b1", resource_type="aws_s3_bucket"),
    )

    drift_result = DriftResult(
        scan_id="scan-ai-2",
        provider="aws",
        state_backend=StateBackendType.LOCAL,
        state_source="test",
        drift_items=[unmanaged_item],
    )

    ai_result = analyzer.analyze(drift_result)
    assert len(ai_result.hcl_results) == 1
    assert ai_result.hcl_results[0].suggested_name == "b1"


def test_llm_analyzer_no_drift() -> None:
    drift_result = DriftResult(
        scan_id="scan-no-drift",
        provider="aws",
        state_backend=StateBackendType.LOCAL,
        state_source="test",
        drift_items=[],
    )

    provider = MockLLMProvider()
    analyzer = LLMAnalyzer(provider=provider)
    ai_result = analyzer.analyze(drift_result)
    assert len(ai_result.hcl_results) == 0
    assert len(ai_result.root_causes) == 0


def test_llm_analyzer_graceful_on_malformed_json() -> None:
    provider = MockLLMProvider(hcl_response="This is not valid JSON at all!")
    analyzer = LLMAnalyzer(provider=provider)

    unmanaged_item = DriftItem(
        resource_address="[unmanaged] aws_s3_bucket.b1",
        resource_type="aws_s3_bucket",
        resource_id="b1",
        drift_type=DriftType.UNMANAGED,
        cloud_resource=CloudResource(resource_id="b1", resource_type="aws_s3_bucket"),
    )

    drift_result = DriftResult(
        scan_id="scan-ai-3",
        provider="aws",
        state_backend=StateBackendType.LOCAL,
        state_source="test",
        drift_items=[unmanaged_item],
    )

    # Should not raise an exception, returns empty list
    ai_result = analyzer.analyze(drift_result)
    assert len(ai_result.hcl_results) == 0
