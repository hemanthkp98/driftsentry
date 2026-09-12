"""Unit tests for the driftsentry discover command and engine."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from driftsentry.cli.main import app
from driftsentry.core.models import CloudResource
from driftsentry.discovery.engine import DiscoveryEngine
from driftsentry.discovery.models import DiscoveryResult
from driftsentry.discovery.table import DiscoveryTableFormatter
from driftsentry.providers.base import CloudProvider

runner = CliRunner()


@pytest.fixture
def mock_cloud_resources() -> list[CloudResource]:
    return [
        CloudResource(
            resource_id="i-0123456789abcdef0",
            resource_type="aws_instance",
            region="us-east-1",
            account_id="123456789012",
            account_name="production",
            tags={"Name": "web-server-1", "Env": "prod"},
            attributes={"instance_type": "t3.micro"},
        ),
        CloudResource(
            resource_id="my-data-bucket",
            resource_type="aws_s3_bucket",
            arn="arn:aws:s3:::my-data-bucket",
            region="us-east-1",
            account_id="123456789012",
            account_name="production",
            tags={"Name": "my-data-bucket"},
            attributes={"bucket": "my-data-bucket"},
        ),
    ]


def test_cli_discover_help() -> None:
    """Test that driftsentry discover --help displays proper command help."""
    result = runner.invoke(app, ["discover", "--help"])
    assert result.exit_code == 0
    assert "Discover and list live cloud resources" in result.stdout
    assert "--region" in result.stdout
    assert "--regions" in result.stdout
    assert "--accounts" in result.stdout
    assert "--include-types" in result.stdout
    assert "--exclude-types" in result.stdout
    assert "--output" in result.stdout
    assert "--save" in result.stdout


def test_cli_discover_table_output(mock_cloud_resources: list[CloudResource]) -> None:
    """Test running discover with mocked AWS provider returning resources."""
    mock_provider = MagicMock(spec=CloudProvider)
    mock_provider.provider_name = "aws"
    mock_provider.scanned_regions = ["us-east-1"]
    mock_provider.scanned_accounts = ["123456789012"]
    mock_provider.supported_resource_types.return_value = ["aws_instance", "aws_s3_bucket"]

    def list_side_effect(rtype: str) -> list[CloudResource]:
        return [r for r in mock_cloud_resources if r.resource_type == rtype]

    mock_provider.list_resources.side_effect = list_side_effect

    with patch("driftsentry.cli.discover.AWSProvider", return_value=mock_provider):
        result = runner.invoke(app, ["discover", "--region", "us-east-1"])
        assert result.exit_code == 0
        assert "Discovered: 2 resources" in result.stdout
        assert "aws_instance" in result.stdout
        assert "i-0123456789abcdef0" in result.stdout
        assert "my-data-bucket" in result.stdout


def test_cli_discover_json_and_save(
    tmp_path: Path, mock_cloud_resources: list[CloudResource]
) -> None:
    """Test JSON output format and saving to file."""
    mock_provider = MagicMock(spec=CloudProvider)
    mock_provider.provider_name = "aws"
    mock_provider.scanned_regions = ["us-east-1"]
    mock_provider.scanned_accounts = ["123456789012"]
    mock_provider.supported_resource_types.return_value = ["aws_instance"]
    mock_provider.list_resources.return_value = [mock_cloud_resources[0]]

    save_file = tmp_path / "discovered.json"

    with patch("driftsentry.cli.discover.AWSProvider", return_value=mock_provider):
        result = runner.invoke(
            app,
            [
                "discover",
                "--region",
                "us-east-1",
                "-o",
                "json",
                "--save",
                str(save_file),
            ],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.stdout)
        assert parsed["total_resources"] == 1
        assert "aws_instance" in parsed["resources_by_type"]

        assert save_file.exists()
        saved_data = json.loads(save_file.read_text())
        assert saved_data["total_resources"] == 1


def test_cli_discover_multi_region_and_account_flags() -> None:
    """Test that CLI passes multi-region and multi-account configurations to AWSProvider."""
    with patch("driftsentry.cli.discover.AWSProvider") as mock_cls:
        instance = MagicMock()
        instance.provider_name = "aws"
        instance.scanned_regions = ["us-east-1", "us-west-2"]
        instance.scanned_accounts = ["111122223333", "prod-profile"]
        instance.supported_resource_types.return_value = []
        mock_cls.return_value = instance

        result = runner.invoke(
            app,
            [
                "discover",
                "--regions",
                "us-east-1,us-west-2",
                "--accounts",
                "111122223333,prod-profile",
                "--role-arn-template",
                "arn:aws:iam::{account_id}:role/DriftSentryScan",
                "--concurrency",
                "8",
            ],
        )
        assert result.exit_code == 0
        mock_cls.assert_called_once()
        _, kwargs = mock_cls.call_args
        assert kwargs["regions"] == ["us-east-1", "us-west-2"]
        assert len(kwargs["accounts"]) == 2
        assert kwargs["accounts"][0].id == "111122223333"
        assert kwargs["accounts"][1].name == "prod-profile"
        assert kwargs["role_arn_template"] == "arn:aws:iam::{account_id}:role/DriftSentryScan"
        assert kwargs["concurrency"] == 8


def test_cli_discover_unsupported_provider() -> None:
    """Test error when specifying an unsupported provider."""
    result = runner.invoke(app, ["discover", "--provider", "gcp"])
    assert result.exit_code == 1
    assert "Unsupported provider: gcp" in result.stdout


def test_discovery_engine_type_filtering(mock_cloud_resources: list[CloudResource]) -> None:
    """Test filtering of resource types in DiscoveryEngine."""
    mock_provider = MagicMock(spec=CloudProvider)
    mock_provider.provider_name = "aws"
    mock_provider.supported_resource_types.return_value = [
        "aws_instance",
        "aws_s3_bucket",
        "aws_security_group",
    ]

    engine = DiscoveryEngine(
        provider=mock_provider,
        include_types=["aws_instance", "aws_s3_bucket"],
        exclude_types=["aws_instance"],
    )

    types = engine.get_scan_types()
    assert types == ["aws_s3_bucket"]


def test_discovery_engine_handles_errors() -> None:
    """Test that DiscoveryEngine records errors and continues scanning."""
    mock_provider = MagicMock(spec=CloudProvider)
    mock_provider.provider_name = "aws"
    mock_provider.supported_resource_types.return_value = ["aws_instance", "aws_s3_bucket"]

    def list_side_effect(rtype: str) -> list[CloudResource]:
        if rtype == "aws_instance":
            raise RuntimeError("AccessDenied for EC2")
        return [
            CloudResource(
                resource_id="bucket-1",
                resource_type="aws_s3_bucket",
            )
        ]

    mock_provider.list_resources.side_effect = list_side_effect

    engine = DiscoveryEngine(provider=mock_provider)
    result = engine.discover(show_progress=False)

    assert result.total_resources == 1
    assert len(result.errors) == 1
    assert "AccessDenied for EC2" in result.errors[0]
    assert "aws_s3_bucket" in result.resources_by_type


def test_discovery_table_formatter_verbose(mock_cloud_resources: list[CloudResource]) -> None:
    """Test rendering table formatter in verbose mode."""
    result = DiscoveryResult(
        scan_id="test-123",
        provider="aws",
        regions=["us-east-1"],
        accounts=["123456789012", "987654321098"],
        total_resources=len(mock_cloud_resources),
        resources_by_type={
            "aws_instance": [mock_cloud_resources[0]],
            "aws_s3_bucket": [mock_cloud_resources[1]],
        },
        duration_seconds=1.23,
        errors=["Minor warning"],
    )

    formatter = DiscoveryTableFormatter(verbose=True)
    # Should execute without errors
    formatter.render(result)
