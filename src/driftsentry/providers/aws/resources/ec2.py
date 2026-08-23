"""EC2 resource scanner — instances, security groups, VPCs, subnets."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import boto3

from driftsentry.core.models import CloudResource
from driftsentry.providers.base import ResourceScanner, register_scanner

logger = logging.getLogger(__name__)


@register_scanner("aws")
class EC2Scanner(ResourceScanner):
    """Scans EC2 resources: instances, security groups, VPCs, and subnets."""

    def __init__(self, session: boto3.Session, region: str) -> None:
        self._ec2 = session.client("ec2", region_name=region)
        self._region = region

    @property
    def resource_types(self) -> list[str]:
        return ["aws_instance", "aws_security_group", "aws_vpc", "aws_subnet"]

    def list_all(self) -> list[CloudResource]:
        """List all EC2 resources across supported types."""
        resources: list[CloudResource] = []
        resources.extend(self._list_instances())
        resources.extend(self._list_security_groups())
        resources.extend(self._list_vpcs())
        resources.extend(self._list_subnets())
        return resources

    def get_by_id(self, resource_id: str) -> CloudResource | None:
        """Get an EC2 resource by its ID (auto-detects type from ID prefix)."""
        try:
            if resource_id.startswith("i-"):
                return self._get_instance(resource_id)
            elif resource_id.startswith("sg-"):
                return self._get_security_group(resource_id)
            elif resource_id.startswith("vpc-"):
                return self._get_vpc(resource_id)
            elif resource_id.startswith("subnet-"):
                return self._get_subnet(resource_id)
        except Exception as e:
            logger.error(f"Error getting EC2 resource {resource_id}: {e}")
        return None

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize EC2 API response to Terraform attribute format."""
        # Base normalization — keys that are common across EC2 resources
        normalized: dict[str, Any] = {}
        for key, value in raw.items():
            # Convert CamelCase to snake_case for common fields
            tf_key = self._to_snake_case(key)
            normalized[tf_key] = value
        return normalized

    # ── Instances ────────────────────────────────────────────

    def _list_instances(self) -> list[CloudResource]:
        """List all EC2 instances."""
        resources: list[CloudResource] = []
        paginator = self._ec2.get_paginator("describe_instances")

        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    if instance.get("State", {}).get("Name") == "terminated":
                        continue

                    resources.append(
                        CloudResource(
                            resource_id=instance["InstanceId"],
                            resource_type="aws_instance",
                            arn=self._build_arn("ec2", f"instance/{instance['InstanceId']}"),
                            region=self._region,
                            attributes=self._normalize_instance(instance),
                            tags=self._extract_tags(instance),
                        )
                    )

        return resources

    def _get_instance(self, instance_id: str) -> CloudResource | None:
        resp = self._ec2.describe_instances(InstanceIds=[instance_id])
        for reservation in resp.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                return CloudResource(
                    resource_id=instance["InstanceId"],
                    resource_type="aws_instance",
                    arn=self._build_arn("ec2", f"instance/{instance['InstanceId']}"),
                    region=self._region,
                    attributes=self._normalize_instance(instance),
                    tags=self._extract_tags(instance),
                )
        return None

    def _normalize_instance(self, instance: Mapping[str, Any]) -> dict[str, Any]:
        """Normalize EC2 instance response to Terraform attribute format."""
        sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]

        return {
            "id": instance.get("InstanceId"),
            "ami": instance.get("ImageId"),
            "instance_type": instance.get("InstanceType"),
            "availability_zone": instance.get("Placement", {}).get("AvailabilityZone"),
            "subnet_id": instance.get("SubnetId"),
            "vpc_security_group_ids": sorted(sg_ids),
            "key_name": instance.get("KeyName"),
            "iam_instance_profile": (
                instance.get("IamInstanceProfile", {}).get("Arn")
                if instance.get("IamInstanceProfile")
                else None
            ),
            "monitoring": instance.get("Monitoring", {}).get("State") == "enabled",
            "ebs_optimized": instance.get("EbsOptimized", False),
            "tenancy": instance.get("Placement", {}).get("Tenancy", "default"),
        }

    # ── Security Groups ──────────────────────────────────────

    def _list_security_groups(self) -> list[CloudResource]:
        resources: list[CloudResource] = []
        paginator = self._ec2.get_paginator("describe_security_groups")

        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                resources.append(
                    CloudResource(
                        resource_id=sg["GroupId"],
                        resource_type="aws_security_group",
                        arn=self._build_arn("ec2", f"security-group/{sg['GroupId']}"),
                        region=self._region,
                        attributes=self._normalize_security_group(sg),
                        tags=self._extract_tags(sg),
                    )
                )

        return resources

    def _get_security_group(self, sg_id: str) -> CloudResource | None:
        resp = self._ec2.describe_security_groups(GroupIds=[sg_id])
        for sg in resp.get("SecurityGroups", []):
            return CloudResource(
                resource_id=sg["GroupId"],
                resource_type="aws_security_group",
                arn=self._build_arn("ec2", f"security-group/{sg['GroupId']}"),
                region=self._region,
                attributes=self._normalize_security_group(sg),
                tags=self._extract_tags(sg),
            )
        return None

    def _normalize_security_group(self, sg: Mapping[str, Any]) -> dict[str, Any]:
        """Normalize security group to Terraform format."""
        return {
            "id": sg.get("GroupId"),
            "name": sg.get("GroupName"),
            "description": sg.get("Description"),
            "vpc_id": sg.get("VpcId"),
            "ingress": self._normalize_sg_rules(sg.get("IpPermissions", [])),
            "egress": self._normalize_sg_rules(sg.get("IpPermissionsEgress", [])),
        }

    def _normalize_sg_rules(self, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize security group rules to Terraform's ingress/egress format."""
        normalized: list[dict[str, Any]] = []
        for rule in rules:
            normalized.append(
                {
                    "from_port": rule.get("FromPort", 0),
                    "to_port": rule.get("ToPort", 0),
                    "protocol": rule.get("IpProtocol", "-1"),
                    "cidr_blocks": [r["CidrIp"] for r in rule.get("IpRanges", [])],
                    "ipv6_cidr_blocks": [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])],
                    "security_groups": [
                        g.get("GroupId", "") for g in rule.get("UserIdGroupPairs", [])
                    ],
                    "self": any(g.get("GroupId") == "" for g in rule.get("UserIdGroupPairs", [])),
                    "description": (
                        rule.get("IpRanges", [{}])[0].get("Description", "")
                        if rule.get("IpRanges")
                        else ""
                    ),
                }
            )
        return sorted(normalized, key=lambda r: (r["from_port"], r["to_port"], r["protocol"]))

    # ── VPCs ─────────────────────────────────────────────────

    def _list_vpcs(self) -> list[CloudResource]:
        resources: list[CloudResource] = []
        resp = self._ec2.describe_vpcs()

        for vpc in resp.get("Vpcs", []):
            resources.append(
                CloudResource(
                    resource_id=vpc["VpcId"],
                    resource_type="aws_vpc",
                    arn=self._build_arn("ec2", f"vpc/{vpc['VpcId']}"),
                    region=self._region,
                    attributes={
                        "id": vpc.get("VpcId"),
                        "cidr_block": vpc.get("CidrBlock"),
                        "instance_tenancy": vpc.get("InstanceTenancy", "default"),
                        "enable_dns_support": True,  # Needs separate API call
                        "enable_dns_hostnames": False,  # Needs separate API call
                        "is_default": vpc.get("IsDefault", False),
                    },
                    tags=self._extract_tags(vpc),
                )
            )

        return resources

    def _get_vpc(self, vpc_id: str) -> CloudResource | None:
        resp = self._ec2.describe_vpcs(VpcIds=[vpc_id])
        for vpc in resp.get("Vpcs", []):
            return CloudResource(
                resource_id=vpc["VpcId"],
                resource_type="aws_vpc",
                arn=self._build_arn("ec2", f"vpc/{vpc['VpcId']}"),
                region=self._region,
                attributes={
                    "id": vpc.get("VpcId"),
                    "cidr_block": vpc.get("CidrBlock"),
                    "instance_tenancy": vpc.get("InstanceTenancy", "default"),
                    "is_default": vpc.get("IsDefault", False),
                },
                tags=self._extract_tags(vpc),
            )
        return None

    # ── Subnets ──────────────────────────────────────────────

    def _list_subnets(self) -> list[CloudResource]:
        resources: list[CloudResource] = []
        resp = self._ec2.describe_subnets()

        for subnet in resp.get("Subnets", []):
            resources.append(
                CloudResource(
                    resource_id=subnet["SubnetId"],
                    resource_type="aws_subnet",
                    arn=subnet.get("SubnetArn"),
                    region=self._region,
                    attributes={
                        "id": subnet.get("SubnetId"),
                        "vpc_id": subnet.get("VpcId"),
                        "cidr_block": subnet.get("CidrBlock"),
                        "availability_zone": subnet.get("AvailabilityZone"),
                        "map_public_ip_on_launch": subnet.get("MapPublicIpOnLaunch", False),
                    },
                    tags=self._extract_tags(subnet),
                )
            )

        return resources

    def _get_subnet(self, subnet_id: str) -> CloudResource | None:
        resp = self._ec2.describe_subnets(SubnetIds=[subnet_id])
        for subnet in resp.get("Subnets", []):
            return CloudResource(
                resource_id=subnet["SubnetId"],
                resource_type="aws_subnet",
                arn=subnet.get("SubnetArn"),
                region=self._region,
                attributes={
                    "id": subnet.get("SubnetId"),
                    "vpc_id": subnet.get("VpcId"),
                    "cidr_block": subnet.get("CidrBlock"),
                    "availability_zone": subnet.get("AvailabilityZone"),
                    "map_public_ip_on_launch": subnet.get("MapPublicIpOnLaunch", False),
                },
                tags=self._extract_tags(subnet),
            )
        return None

    # ── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _extract_tags(resource: Mapping[str, Any]) -> dict[str, str]:
        """Extract tags from an AWS API response into a flat dict."""
        tags = resource.get("Tags", [])
        return {t["Key"]: t["Value"] for t in tags if "Key" in t and "Value" in t}

    def _build_arn(self, service: str, resource: str) -> str:
        """Build an ARN string."""
        return f"arn:aws:{service}:{self._region}::{resource}"

    @staticmethod
    def _to_snake_case(name: str) -> str:
        """Convert CamelCase to snake_case."""
        import re

        s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
        return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()
