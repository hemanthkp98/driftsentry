"""Unit tests for scanner registry and AWSProvider dynamic discovery."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from driftsentry.core.models import CloudResource
from driftsentry.providers.aws.provider import AWSProvider
from driftsentry.providers.base import (
    ResourceScanner,
    get_registered_scanners,
    register_scanner,
)


@register_scanner("aws")
class MockCustomScanner(ResourceScanner):
    @property
    def resource_types(self) -> list[str]:
        return ["aws_custom_plugin_type"]

    def list_all(self) -> list[CloudResource]:
        return [
            CloudResource(
                resource_id="plug-1",
                resource_type="aws_custom_plugin_type",
                attributes={"name": "plugin-test"},
            )
        ]

    def get_by_id(self, resource_id: str) -> CloudResource | None:
        return None

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return raw


def test_scanner_registry_contains_custom_and_builtin() -> None:
    scanners = get_registered_scanners("aws")
    assert MockCustomScanner in scanners


def test_aws_provider_loads_all_scanners() -> None:
    mock_session = MagicMock()
    with patch(
        "driftsentry.providers.aws.provider.AWSProvider._create_session", return_value=mock_session
    ):
        provider = AWSProvider(region="us-east-1")
        supported = provider.supported_resource_types()

        # Built-in Python scanners
        assert "aws_instance" in supported
        assert "aws_s3_bucket" in supported
        assert "aws_iam_role" in supported

        # Custom registry scanner
        assert "aws_custom_plugin_type" in supported

        # Declarative built-in YAML catalog
        assert "aws_sqs_queue" in supported
        assert "aws_dynamodb_table" in supported
        assert "aws_sns_topic" in supported
        assert "aws_kms_key" in supported
        assert "aws_route53_zone" in supported
