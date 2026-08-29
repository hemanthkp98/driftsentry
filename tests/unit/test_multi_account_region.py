"""Unit tests for Multi-Account and Multi-Region support in DriftSentry."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from driftsentry.attribution.cloudtrail import CloudTrailAttributor
from driftsentry.core.config import AccountConfig, DriftSentryConfig, load_config
from driftsentry.core.models import (
    CloudResource,
    DriftItem,
    DriftResult,
    DriftSeverity,
    DriftType,
    ResourceState,
    StateBackendType,
)
from driftsentry.core.scanner import DriftScanner
from driftsentry.output.html import HTMLFormatter
from driftsentry.output.markdown import MarkdownFormatter
from driftsentry.output.table import TableFormatter
from driftsentry.providers.aws.provider import AWSProvider
from driftsentry.providers.aws.target import ScanTarget, TargetResolver


# ─── TargetResolver Tests ─────────────────────────────────────────


def test_target_resolver_single_default_region() -> None:
    """Test default single region and account resolution."""
    resolver = TargetResolver(region="us-east-1")
    with patch("driftsentry.providers.aws.provider.AWSProvider._create_session") as mock_sess:
        mock_instance = MagicMock()
        mock_instance.region_name = "us-east-1"
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_instance.client.return_value = mock_sts
        mock_sess.return_value = mock_instance

        targets = resolver.resolve_targets()
        assert len(targets) == 1
        assert targets[0].account_id == "123456789012"
        assert targets[0].region == "us-east-1"
        assert targets[0].target_id == "123456789012:us-east-1"


def test_target_resolver_multi_region() -> None:
    """Test multi-region resolution within a single account."""
    resolver = TargetResolver(
        regions=["us-east-1", "us-west-2", "eu-west-1"],
        profile="prod",
    )
    with patch("driftsentry.providers.aws.provider.AWSProvider._create_session") as mock_sess:
        mock_instance = MagicMock()
        mock_instance.profile_name = "prod"
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "111122223333"}
        mock_instance.client.return_value = mock_sts
        mock_sess.return_value = mock_instance

        targets = resolver.resolve_targets()
        assert len(targets) == 3
        assert [t.region for t in targets] == ["us-east-1", "us-west-2", "eu-west-1"]
        assert all(t.account_id == "111122223333" for t in targets)
        assert all(t.profile == "prod" for t in targets)


def test_target_resolver_all_regions_expansion() -> None:
    """Test '--regions all' expansion querying ec2.describe_regions."""
    resolver = TargetResolver(regions=["all"])
    with patch("driftsentry.providers.aws.provider.AWSProvider._create_session") as mock_sess:
        mock_instance = MagicMock()
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "us-west-2"},
                {"RegionName": "ap-southeast-1"},
            ]
        }
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "999988887777"}

        def client_side_effect(service: str, **kwargs: object) -> MagicMock:
            if service == "ec2":
                return mock_ec2
            return mock_sts

        mock_instance.client.side_effect = client_side_effect
        mock_sess.return_value = mock_instance

        targets = resolver.resolve_targets()
        assert len(targets) == 3
        assert [t.region for t in targets] == ["ap-southeast-1", "us-east-1", "us-west-2"]


def test_target_resolver_multi_account_and_template() -> None:
    """Test multi-account resolution with role_arn_template."""
    accounts = [
        AccountConfig(id="111111111111", name="prod", regions=["us-east-1", "us-west-2"]),
        AccountConfig(id="222222222222", name="staging", profile="staging-prof"),
    ]
    resolver = TargetResolver(
        region="us-east-1",
        accounts=accounts,
        role_arn_template="arn:aws:iam::{account_id}:role/DriftSentryScanRole",
    )
    with patch("driftsentry.providers.aws.provider.AWSProvider._create_session") as mock_sess:
        mock_instance = MagicMock()
        mock_sess.return_value = mock_instance

        targets = resolver.resolve_targets()
        # prod has 2 regions, staging inherits default us-east-1 (total 3 targets)
        assert len(targets) == 3

        prod_targets = [t for t in targets if t.account_name == "prod"]
        assert len(prod_targets) == 2
        assert {t.region for t in prod_targets} == {"us-east-1", "us-west-2"}
        assert all(
            t.role_arn == "arn:aws:iam::111111111111:role/DriftSentryScanRole" for t in prod_targets
        )

        staging_targets = [t for t in targets if t.account_name == "staging"]
        assert len(staging_targets) == 1
        assert staging_targets[0].region == "us-east-1"
        assert staging_targets[0].role_arn == "arn:aws:iam::222222222222:role/DriftSentryScanRole"
        assert staging_targets[0].profile == "staging-prof"


# ─── AWSProvider Multi-Target Scanning & Deduplication ────────────


def test_aws_provider_global_service_deduplication() -> None:
    """Verify global services like IAM are queried once per account, not per region."""
    targets = [
        ScanTarget(
            account_id="111111111111",
            account_name="prod",
            region="us-east-1",
            session=MagicMock(),
        ),
        ScanTarget(
            account_id="111111111111",
            account_name="prod",
            region="us-west-2",
            session=MagicMock(),
        ),
        ScanTarget(
            account_id="222222222222",
            account_name="staging",
            region="us-east-1",
            session=MagicMock(),
        ),
    ]

    with patch.object(TargetResolver, "resolve_targets", return_value=targets):
        provider = AWSProvider(
            regions=["us-east-1", "us-west-2"],
            accounts=[
                AccountConfig(id="111111111111", name="prod"),
                AccountConfig(id="222222222222", name="staging"),
            ],
        )

        assert provider.scanned_regions == ["us-east-1", "us-west-2"]
        assert provider.scanned_accounts == ["prod", "staging"]

        # Global types target filter should return 2 targets (1 per account), not 3
        global_targets = provider._get_targets_for_type("aws_iam_role")
        assert len(global_targets) == 2
        assert {t.account_key for t in global_targets} == {"prod", "staging"}

        # Regional types target filter should return all 3 targets
        regional_targets = provider._get_targets_for_type("aws_instance")
        assert len(regional_targets) == 3


def test_aws_provider_concurrent_listing_and_enrichment() -> None:
    """Verify parallel listing enriches resources with account and region metadata."""
    target1 = ScanTarget(
        account_id="111111111111",
        account_name="prod",
        region="us-east-1",
        session=MagicMock(),
    )
    target2 = ScanTarget(
        account_id="222222222222",
        account_name="dev",
        region="eu-west-1",
        session=MagicMock(),
    )

    with patch.object(TargetResolver, "resolve_targets", return_value=[target1, target2]):
        provider = AWSProvider(regions=["us-east-1", "eu-west-1"], concurrency=2)

        # Mock scanner responses per target
        mock_scanner1 = MagicMock()
        mock_scanner1.list_all.return_value = [
            CloudResource(
                resource_id="i-prod1",
                resource_type="aws_instance",
                attributes={"instance_type": "m5.large"},
            )
        ]
        mock_scanner2 = MagicMock()
        mock_scanner2.list_all.return_value = [
            CloudResource(
                resource_id="i-dev1",
                resource_type="aws_instance",
                attributes={"instance_type": "t3.micro"},
            )
        ]

        provider._target_scanners = {
            target1.target_id: {"aws_instance": mock_scanner1},
            target2.target_id: {"aws_instance": mock_scanner2},
        }

        resources = provider.list_resources("aws_instance")
        assert len(resources) == 2

        prod_res = next(r for r in resources if r.resource_id == "i-prod1")
        assert prod_res.account_id == "111111111111"
        assert prod_res.account_name == "prod"
        assert prod_res.region == "us-east-1"

        dev_res = next(r for r in resources if r.resource_id == "i-dev1")
        assert dev_res.account_id == "222222222222"
        assert dev_res.account_name == "dev"
        assert dev_res.region == "eu-west-1"


# ─── Drift Detection in Multi-Account / Multi-Region ──────────────


def test_drift_scanner_multi_target_orchestration() -> None:
    """Test full scanner pipeline with multi-account, multi-region drift."""
    config = DriftSentryConfig()
    config.provider.regions = ["us-east-1", "us-west-2"]
    config.accounts = [
        AccountConfig(id="111111111111", name="prod"),
        AccountConfig(id="222222222222", name="staging"),
    ]
    config.attribution.enabled = False

    mock_state_reader = MagicMock()
    mock_state_reader.source_description = "terraform.tfstate"
    # State has 1 resource in prod us-east-1 and 1 resource in staging us-west-2
    mock_state_reader.read_state.return_value = [
        ResourceState(
            address="aws_instance.prod_web",
            resource_type="aws_instance",
            resource_name="prod_web",
            provider="aws",
            resource_id="i-prodweb",
            attributes={
                "id": "i-prodweb",
                "arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-prodweb",
                "instance_type": "t3.micro",
            },
        ),
        ResourceState(
            address="aws_instance.staging_db",
            resource_type="aws_instance",
            resource_name="staging_db",
            provider="aws",
            resource_id="i-stagingdb",
            attributes={
                "id": "i-stagingdb",
                "arn": "arn:aws:ec2:us-west-2:222222222222:instance/i-stagingdb",
                "instance_type": "m5.large",
            },
        ),
    ]

    mock_provider = MagicMock()
    mock_provider.supported_resource_types.return_value = ["aws_instance"]
    mock_provider.scanned_regions = ["us-east-1", "us-west-2"]
    mock_provider.scanned_accounts = ["prod", "staging"]

    # Live cloud has:
    # 1. i-prodweb with drifted instance_type (CHANGED)
    # 2. i-stagingdb missing from cloud (DELETED)
    # 3. i-shadow unmanaged in dev/eu-west-1 (UNMANAGED)
    mock_provider.list_resources.return_value = [
        CloudResource(
            resource_id="i-prodweb",
            resource_type="aws_instance",
            region="us-east-1",
            account_id="111111111111",
            account_name="prod",
            attributes={"id": "i-prodweb", "instance_type": "t3.large"},
        ),
        CloudResource(
            resource_id="i-shadow",
            resource_type="aws_instance",
            region="us-west-2",
            account_id="222222222222",
            account_name="staging",
            attributes={"id": "i-shadow", "instance_type": "t2.nano"},
        ),
    ]

    scanner = DriftScanner(config, mock_state_reader, mock_provider)
    result = scanner.scan(show_progress=False)

    assert result.has_drift
    assert len(result.drift_items) == 3
    assert result.regions == ["us-east-1", "us-west-2"]
    assert result.accounts == ["prod", "staging"]

    # Check changed item
    changed = next(d for d in result.drift_items if d.drift_type == DriftType.CHANGED)
    assert changed.resource_id == "i-prodweb"
    assert changed.account_name == "prod"
    assert changed.region == "us-east-1"

    # Check deleted item
    deleted = next(d for d in result.drift_items if d.drift_type == DriftType.DELETED)
    assert deleted.resource_id == "i-stagingdb"
    assert deleted.account_id == "222222222222"
    assert deleted.region == "us-west-2"

    # Check unmanaged item
    unmanaged = next(d for d in result.drift_items if d.drift_type == DriftType.UNMANAGED)
    assert unmanaged.resource_id == "i-shadow"
    assert unmanaged.account_name == "staging"
    assert unmanaged.region == "us-west-2"


# ─── Multi-Target CloudTrail Attribution ──────────────────────────


def test_cloudtrail_attributor_multi_target_routing() -> None:
    """Verify CloudTrailAttributor routes lookups to appropriate target clients."""
    target1 = ScanTarget(
        account_id="111111111111",
        account_name="prod",
        region="us-east-1",
        session=MagicMock(),
    )
    target2 = ScanTarget(
        account_id="222222222222",
        account_name="staging",
        region="us-west-2",
        session=MagicMock(),
    )

    mock_client1 = MagicMock()
    mock_paginator1 = MagicMock()
    mock_paginator1.paginate.return_value = [
        {
            "Events": [
                {
                    "EventName": "ModifyInstanceAttribute",
                    "EventTime": "2026-08-20T10:00:00Z",
                    "sourceIPAddress": "1.2.3.4",
                    "userAgent": "console.amazonaws.com",
                    "userIdentity": {"type": "IAMUser", "userName": "alice-prod"},
                }
            ]
        }
    ]
    mock_client1.get_paginator.return_value = mock_paginator1

    mock_client2 = MagicMock()
    mock_paginator2 = MagicMock()
    mock_paginator2.paginate.return_value = [
        {
            "Events": [
                {
                    "EventName": "ModifyInstanceAttribute",
                    "EventTime": "2026-08-21T11:00:00Z",
                    "sourceIPAddress": "5.6.7.8",
                    "userAgent": "aws-cli/2.0",
                    "userIdentity": {"type": "IAMUser", "userName": "bob-staging"},
                }
            ]
        }
    ]
    mock_client2.get_paginator.return_value = mock_paginator2

    attributor = CloudTrailAttributor(targets=[target1, target2])
    attributor._clients = {
        ("prod", "us-east-1"): mock_client1,
        ("staging", "us-west-2"): mock_client2,
    }

    item1 = DriftItem(
        resource_address="aws_instance.web",
        resource_type="aws_instance",
        resource_id="i-111",
        drift_type=DriftType.CHANGED,
        account_name="prod",
        region="us-east-1",
    )
    attr1 = attributor.attribute(item1)
    assert attr1 is not None
    assert attr1.principal == "alice-prod"
    assert attr1.is_console_change is True

    item2 = DriftItem(
        resource_address="aws_instance.db",
        resource_type="aws_instance",
        resource_id="i-222",
        drift_type=DriftType.CHANGED,
        account_name="staging",
        region="us-west-2",
    )
    attr2 = attributor.attribute(item2)
    assert attr2 is not None
    assert attr2.principal == "bob-staging"
    assert attr2.is_console_change is False


# ─── Output Formatters Multi-Target Rendering ─────────────────────


def test_table_and_markdown_and_html_renderers_with_multi_target() -> None:
    """Verify Table, Markdown, and HTML formatters handle Account and Region."""
    result = DriftResult(
        scan_id="multi-123",
        provider="aws",
        regions=["us-east-1", "us-west-2"],
        accounts=["prod", "staging"],
        state_backend=StateBackendType.LOCAL,
        state_source="terraform.tfstate",
        total_resources=10,
        total_cloud_resources=10,
        drift_items=[
            DriftItem(
                resource_address="aws_security_group.web",
                resource_type="aws_security_group",
                resource_id="sg-12345",
                drift_type=DriftType.CHANGED,
                severity=DriftSeverity.CRITICAL,
                account_name="prod",
                region="us-east-1",
            ),
            DriftItem(
                resource_address="aws_instance.db",
                resource_type="aws_instance",
                resource_id="i-99999",
                drift_type=DriftType.UNMANAGED,
                severity=DriftSeverity.MEDIUM,
                account_name="staging",
                region="us-west-2",
            ),
        ],
    )

    # 1. TableFormatter
    mock_console = MagicMock()
    table_formatter = TableFormatter(console=mock_console)
    table_formatter.render(result)
    assert mock_console.print.called

    # 2. MarkdownFormatter
    md_formatter = MarkdownFormatter()
    md_output = md_formatter.render(result)
    assert "**Accounts:** prod, staging" in md_output
    assert "**Regions:** us-east-1, us-west-2" in md_output
    assert "| Account | Region | Resource |" in md_output
    assert "`prod`" in md_output
    assert "`us-east-1`" in md_output
    assert "`staging`" in md_output
    assert "`us-west-2`" in md_output

    # 3. HTMLFormatter
    html_formatter = HTMLFormatter()
    html_output = html_formatter.render(result)
    assert "Accounts: prod, staging" in html_output
    assert "Regions: us-east-1, us-west-2" in html_output
    assert "<th>Account</th>" in html_output
    assert "<th>Region</th>" in html_output
    assert "<code>prod</code>" in html_output
    assert "<code>us-east-1</code>" in html_output
