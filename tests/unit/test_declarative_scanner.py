"""Unit tests for GenericAWSDeclarativeScanner."""

from __future__ import annotations

from unittest.mock import MagicMock

from driftsentry.providers.aws.declarative import GenericAWSDeclarativeScanner
from driftsentry.providers.base import DeclarativeResourceSpec, DiscoverySpec


def test_declarative_scanner_sqs_mock() -> None:
    spec = DeclarativeResourceSpec(
        terraform_type="aws_sqs_queue",
        service="sqs",
        description="Amazon SQS Queue",
        discovery=DiscoverySpec(
            list_operation="list_queues",
            result_path="QueueUrls[]",
            id_field="@",
            describe_operation="get_queue_attributes",
            describe_params={"QueueUrl": "{id}", "AttributeNames": ["All"]},
            attributes_path="Attributes",
        ),
        attributes={
            "name": "QueueName",
            "delay_seconds": "DelaySeconds",
            "visibility_timeout_seconds": "VisibilityTimeout",
            "kms_master_key_id": "KmsMasterKeyId",
        },
        security_critical=["kms_master_key_id", "policy"],
        noise_attributes=["approximate_number_of_messages"],
    )

    mock_session = MagicMock()
    mock_sqs_client = MagicMock()
    mock_session.client.return_value = mock_sqs_client

    # Mock list_queues
    mock_sqs_client.can_paginate.return_value = False
    mock_sqs_client.list_queues.return_value = {
        "QueueUrls": [
            "https://sqs.us-east-1.amazonaws.com/123456789012/my-test-queue",
        ]
    }

    # Mock get_queue_attributes
    mock_sqs_client.get_queue_attributes.return_value = {
        "Attributes": {
            "QueueName": "my-test-queue",
            "DelaySeconds": "10",
            "VisibilityTimeout": "30",
            "KmsMasterKeyId": "alias/aws/sqs",
        }
    }

    scanner = GenericAWSDeclarativeScanner(mock_session, "us-east-1", spec)
    assert scanner.resource_types == ["aws_sqs_queue"]

    resources = scanner.list_all()
    assert len(resources) == 1
    res = resources[0]
    assert res.resource_type == "aws_sqs_queue"
    assert res.resource_id == "https://sqs.us-east-1.amazonaws.com/123456789012/my-test-queue"
    assert res.attributes["name"] == "my-test-queue"
    assert res.attributes["delay_seconds"] == 10  # Coerced to int
    assert res.attributes["visibility_timeout_seconds"] == 30
    assert res.attributes["kms_master_key_id"] == "alias/aws/sqs"


def test_declarative_scanner_dynamodb_get_by_id() -> None:
    spec = DeclarativeResourceSpec(
        terraform_type="aws_dynamodb_table",
        service="dynamodb",
        description="DynamoDB Table",
        discovery=DiscoverySpec(
            list_operation="list_tables",
            result_path="TableNames[]",
            id_field="@",
            describe_operation="describe_table",
            describe_params={"TableName": "{id}"},
            attributes_path="Table",
        ),
        attributes={
            "name": "TableName",
            "billing_mode": "BillingModeSummary.BillingMode",
            "deletion_protection_enabled": "DeletionProtectionEnabled",
        },
    )

    mock_session = MagicMock()
    mock_dynamo_client = MagicMock()
    mock_session.client.return_value = mock_dynamo_client

    mock_dynamo_client.describe_table.return_value = {
        "Table": {
            "TableName": "orders-table",
            "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/orders-table",
            "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
            "DeletionProtectionEnabled": True,
        }
    }

    scanner = GenericAWSDeclarativeScanner(mock_session, "us-east-1", spec)
    res = scanner.get_by_id("orders-table")

    assert res is not None
    assert res.resource_id == "orders-table"
    assert res.attributes["name"] == "orders-table"
    assert res.attributes["billing_mode"] == "PAY_PER_REQUEST"
    assert res.attributes["deletion_protection_enabled"] is True
