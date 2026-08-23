"""Unit tests for ResourceCatalog loader."""

from __future__ import annotations

from pathlib import Path

from driftsentry.attribution.cloudtrail import RESOURCE_EVENT_MAP
from driftsentry.providers.aws.catalog import ResourceCatalog
from driftsentry.providers.aws.mapping import get_mapping, is_security_critical


def test_catalog_loads_builtin_specs() -> None:
    catalog = ResourceCatalog()
    specs = catalog.load_all()

    # Built-in specs should be loaded
    assert "aws_sqs_queue" in specs
    assert "aws_sns_topic" in specs
    assert "aws_dynamodb_table" in specs
    assert "aws_kms_key" in specs
    assert "aws_route53_zone" in specs

    # Mappings should be registered
    mapping = get_mapping("aws_sqs_queue")
    assert mapping is not None
    assert mapping.aws_service == "sqs"
    assert is_security_critical("aws_sqs_queue", "kms_master_key_id")

    # CloudTrail event mappings should be registered
    assert "aws_sqs_queue" in RESOURCE_EVENT_MAP
    assert "CreateQueue" in RESOURCE_EVENT_MAP["aws_sqs_queue"]


def test_catalog_loads_inline_custom_specs() -> None:
    inline_custom = {
        "aws_my_custom_resource": {
            "service": "ec2",
            "description": "My Custom EC2 sub-resource",
            "discovery": {
                "list_operation": "describe_tags",
                "result_path": "Tags[]",
            },
            "security_critical": ["value"],
            "cloudtrail_events": ["CreateTags"],
        }
    }

    catalog = ResourceCatalog(inline_specs=inline_custom)
    specs = catalog.load_all()

    assert "aws_my_custom_resource" in specs
    assert is_security_critical("aws_my_custom_resource", "value")
    assert "CreateTags" in RESOURCE_EVENT_MAP["aws_my_custom_resource"]


def test_catalog_loads_directory_specs(tmp_path: Path) -> None:
    yaml_file = tmp_path / "custom_service.yaml"
    yaml_file.write_text(
        """
terraform_type: "aws_custom_queue"
service: "sqs"
discovery:
  list_operation: "list_queues"
  result_path: "QueueUrls[]"
"""
    )

    catalog = ResourceCatalog(custom_dirs=[tmp_path])
    specs = catalog.load_all()

    assert "aws_custom_queue" in specs
    assert specs["aws_custom_queue"].service == "sqs"
