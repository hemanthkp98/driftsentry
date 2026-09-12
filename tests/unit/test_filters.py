from __future__ import annotations

from driftsentry.core.config import ScanFilters
from driftsentry.core.filter import is_resource_excluded, is_state_resource_excluded
from driftsentry.core.models import CloudResource, ResourceState


def test_is_resource_excluded_empty_filters() -> None:
    res = CloudResource(
        resource_id="vpc-123",
        resource_type="aws_vpc",
        tags={"Name": "main"},
    )
    assert not is_resource_excluded(res, None)
    assert not is_resource_excluded(res, ScanFilters())


def test_is_resource_excluded_tag_exact_and_list() -> None:
    filters = ScanFilters(
        exclude_tags={
            "managed-by": ["AFT", "ControlTower"],
            "Environment": "baseline",
        }
    )

    aft_res = CloudResource(
        resource_id="vpc-1",
        resource_type="aws_vpc",
        tags={"Managed-By": "aft"},  # case-insensitive key and value
    )
    assert is_resource_excluded(aft_res, filters)

    baseline_res = CloudResource(
        resource_id="sg-1",
        resource_type="aws_security_group",
        tags={"environment": "baseline"},
    )
    assert is_resource_excluded(baseline_res, filters)

    user_res = CloudResource(
        resource_id="vpc-2",
        resource_type="aws_vpc",
        tags={"Managed-By": "Terraform", "Environment": "production"},
    )
    assert not is_resource_excluded(user_res, filters)


def test_is_resource_excluded_tag_wildcard() -> None:
    filters = ScanFilters(exclude_tags={"CreatedByAFT": "*"})

    res = CloudResource(
        resource_id="subnet-1",
        resource_type="aws_subnet",
        tags={"createdbyaft": "true"},
    )
    assert is_resource_excluded(res, filters)

    other = CloudResource(
        resource_id="subnet-2",
        resource_type="aws_subnet",
        tags={"CreatedBy": "User"},
    )
    assert not is_resource_excluded(other, filters)


def test_is_resource_excluded_pattern_matching() -> None:
    filters = ScanFilters(
        exclude_patterns=[
            "*aft*",
            "vpc-default*",
            "arn:aws:iam::*:role/aws-service-role/*",
        ]
    )

    # Match by ID
    res1 = CloudResource(
        resource_id="vpc-default-12345",
        resource_type="aws_vpc",
    )
    assert is_resource_excluded(res1, filters)

    # Match by Name tag
    res2 = CloudResource(
        resource_id="vpc-999",
        resource_type="aws_vpc",
        tags={"Name": "my-aft-management-vpc"},
    )
    assert is_resource_excluded(res2, filters)

    # Match by ARN
    res3 = CloudResource(
        resource_id="role-1",
        resource_type="aws_iam_role",
        arn="arn:aws:iam::123456789012:role/aws-service-role/s3.amazonaws.com/AWSServiceRoleForS3",
    )
    assert is_resource_excluded(res3, filters)

    # Match by attribute name
    res4 = CloudResource(
        resource_id="sg-123",
        resource_type="aws_security_group",
        attributes={"name": "aft-account-customizations-sg"},
    )
    assert is_resource_excluded(res4, filters)

    # Non-matching user resource
    user_res = CloudResource(
        resource_id="vpc-0987654321",
        resource_type="aws_vpc",
        tags={"Name": "customer-app-vpc"},
    )
    assert not is_resource_excluded(user_res, filters)


def test_is_resource_excluded_regex_pattern() -> None:
    filters = ScanFilters(exclude_patterns=["re:^sg-[0-9a-f]{4}$"])

    matching = CloudResource(
        resource_id="sg-abcd",
        resource_type="aws_security_group",
    )
    assert is_resource_excluded(matching, filters)

    not_matching = CloudResource(
        resource_id="sg-abcdef123456",
        resource_type="aws_security_group",
    )
    assert not is_resource_excluded(not_matching, filters)


def test_is_state_resource_excluded() -> None:
    filters = ScanFilters(
        exclude_tags={"managed-by": "AFT"},
        exclude_patterns=["*default*"],
    )

    state1 = ResourceState(
        address="aws_vpc.default",
        resource_type="aws_vpc",
        resource_name="default",
        provider="aws",
    )
    assert is_state_resource_excluded(state1, filters)

    state2 = ResourceState(
        address="aws_subnet.app",
        resource_type="aws_subnet",
        resource_name="app",
        provider="aws",
        attributes={"tags": {"managed-by": "AFT"}},
    )
    assert is_state_resource_excluded(state2, filters)

    state3 = ResourceState(
        address="aws_instance.web",
        resource_type="aws_instance",
        resource_name="web",
        provider="aws",
        attributes={"tags": {"Environment": "prod"}},
    )
    assert not is_state_resource_excluded(state3, filters)
