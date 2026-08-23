"""AWS resource type mapping — maps Terraform types to AWS API concepts.

This module provides metadata about how Terraform resource types map to
AWS service APIs, including which boto3 client to use, how to list resources,
and which attributes are security-critical for severity classification.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ResourceTypeMapping:
    """Metadata for a Terraform → AWS resource type mapping."""

    terraform_type: str
    """Terraform resource type, e.g. 'aws_instance'."""

    aws_service: str
    """boto3 service name, e.g. 'ec2'."""

    description: str
    """Human-readable description."""

    security_critical_attributes: list[str] = field(default_factory=list)
    """Attributes whose changes should be flagged as critical severity."""

    noise_attributes: list[str] = field(default_factory=list)
    """Attributes that change frequently and should be ignored by default."""


# ─── AWS Resource Type Registry ─────────────────────────────────

RESOURCE_MAPPINGS: dict[str, ResourceTypeMapping] = {
    # ── EC2 ──────────────────────────────────────────────────
    "aws_instance": ResourceTypeMapping(
        terraform_type="aws_instance",
        aws_service="ec2",
        description="EC2 Instance",
        security_critical_attributes=[
            "security_groups",
            "vpc_security_group_ids",
            "iam_instance_profile",
            "user_data",
            "metadata_options",
        ],
        noise_attributes=[
            "private_dns",
            "public_dns",
            "public_ip",
            "private_ip",
            "instance_state",
        ],
    ),
    "aws_security_group": ResourceTypeMapping(
        terraform_type="aws_security_group",
        aws_service="ec2",
        description="Security Group",
        security_critical_attributes=[
            "ingress",
            "egress",
        ],
        noise_attributes=[
            "owner_id",
        ],
    ),
    "aws_security_group_rule": ResourceTypeMapping(
        terraform_type="aws_security_group_rule",
        aws_service="ec2",
        description="Security Group Rule",
        security_critical_attributes=[
            "cidr_blocks",
            "ipv6_cidr_blocks",
            "from_port",
            "to_port",
            "protocol",
            "type",
        ],
        noise_attributes=[],
    ),
    "aws_vpc": ResourceTypeMapping(
        terraform_type="aws_vpc",
        aws_service="ec2",
        description="VPC",
        security_critical_attributes=[
            "enable_dns_hostnames",
            "enable_dns_support",
        ],
        noise_attributes=["default_network_acl_id", "default_route_table_id"],
    ),
    "aws_subnet": ResourceTypeMapping(
        terraform_type="aws_subnet",
        aws_service="ec2",
        description="Subnet",
        security_critical_attributes=["map_public_ip_on_launch"],
        noise_attributes=["available_ip_address_count"],
    ),
    # ── S3 ───────────────────────────────────────────────────
    "aws_s3_bucket": ResourceTypeMapping(
        terraform_type="aws_s3_bucket",
        aws_service="s3",
        description="S3 Bucket",
        security_critical_attributes=[
            "acl",
            "policy",
            "server_side_encryption_configuration",
            "versioning",
            "logging",
        ],
        noise_attributes=[],
    ),
    # ── IAM ──────────────────────────────────────────────────
    "aws_iam_role": ResourceTypeMapping(
        terraform_type="aws_iam_role",
        aws_service="iam",
        description="IAM Role",
        security_critical_attributes=[
            "assume_role_policy",
            "managed_policy_arns",
            "inline_policy",
        ],
        noise_attributes=["create_date", "unique_id"],
    ),
    "aws_iam_policy": ResourceTypeMapping(
        terraform_type="aws_iam_policy",
        aws_service="iam",
        description="IAM Policy",
        security_critical_attributes=["policy"],
        noise_attributes=["create_date", "update_date", "attachment_count"],
    ),
    "aws_iam_user": ResourceTypeMapping(
        terraform_type="aws_iam_user",
        aws_service="iam",
        description="IAM User",
        security_critical_attributes=[],
        noise_attributes=["create_date", "unique_id"],
    ),
    # ── RDS ──────────────────────────────────────────────────
    "aws_db_instance": ResourceTypeMapping(
        terraform_type="aws_db_instance",
        aws_service="rds",
        description="RDS Instance",
        security_critical_attributes=[
            "publicly_accessible",
            "storage_encrypted",
            "iam_database_authentication_enabled",
            "vpc_security_group_ids",
            "deletion_protection",
        ],
        noise_attributes=[
            "endpoint",
            "hosted_zone_id",
            "latest_restorable_time",
            "status",
            "address",
        ],
    ),
    # ── Lambda ───────────────────────────────────────────────
    "aws_lambda_function": ResourceTypeMapping(
        terraform_type="aws_lambda_function",
        aws_service="lambda",
        description="Lambda Function",
        security_critical_attributes=[
            "role",
            "vpc_config",
            "environment",
        ],
        noise_attributes=[
            "last_modified",
            "version",
            "source_code_hash",
            "source_code_size",
        ],
    ),
    # ── ECS ──────────────────────────────────────────────────
    "aws_ecs_cluster": ResourceTypeMapping(
        terraform_type="aws_ecs_cluster",
        aws_service="ecs",
        description="ECS Cluster",
        security_critical_attributes=["configuration"],
        noise_attributes=["status"],
    ),
    "aws_ecs_service": ResourceTypeMapping(
        terraform_type="aws_ecs_service",
        aws_service="ecs",
        description="ECS Service",
        security_critical_attributes=[
            "network_configuration",
            "load_balancer",
            "task_definition",
        ],
        noise_attributes=["status", "running_count", "pending_count"],
    ),
}


def get_mapping(terraform_type: str) -> ResourceTypeMapping | None:
    """Get the mapping for a Terraform resource type."""
    return RESOURCE_MAPPINGS.get(terraform_type)


def register_mapping(mapping: ResourceTypeMapping) -> None:
    """Register a new resource mapping dynamically."""
    RESOURCE_MAPPINGS[mapping.terraform_type] = mapping


def is_security_critical(terraform_type: str, attribute: str) -> bool:
    """Check if an attribute change on a resource type is security-critical."""
    mapping = get_mapping(terraform_type)
    if mapping is None:
        return False
    return attribute in mapping.security_critical_attributes


def get_noise_attributes(terraform_type: str) -> list[str]:
    """Get attributes that should be ignored for a resource type (noisy/auto-generated)."""
    mapping = get_mapping(terraform_type)
    if mapping is None:
        return []
    return mapping.noise_attributes
