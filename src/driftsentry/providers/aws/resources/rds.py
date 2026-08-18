"""RDS resource scanner — DB instances."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import boto3
from botocore.exceptions import ClientError

from driftsentry.core.models import CloudResource
from driftsentry.providers.base import ResourceScanner

logger = logging.getLogger(__name__)


class RDSScanner(ResourceScanner):
    """Scans RDS database instances."""

    def __init__(self, session: boto3.Session, region: str) -> None:
        self._rds = session.client("rds", region_name=region)
        self._region = region

    @property
    def resource_types(self) -> list[str]:
        return ["aws_db_instance"]

    def list_all(self) -> list[CloudResource]:
        resources: list[CloudResource] = []
        paginator = self._rds.get_paginator("describe_db_instances")

        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                resources.append(self._db_to_cloud_resource(db))

        return resources

    def get_by_id(self, resource_id: str) -> CloudResource | None:
        try:
            resp = self._rds.describe_db_instances(DBInstanceIdentifier=resource_id)
            instances = resp.get("DBInstances", [])
            if instances:
                return self._db_to_cloud_resource(instances[0])
        except ClientError:
            pass
        return None

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return raw

    def _db_to_cloud_resource(self, db: Mapping[str, Any]) -> CloudResource:
        sg_ids = [
            sg["VpcSecurityGroupId"]
            for sg in db.get("VpcSecurityGroups", [])
            if sg.get("Status") == "active"
        ]

        return CloudResource(
            resource_id=db["DBInstanceIdentifier"],
            resource_type="aws_db_instance",
            arn=db.get("DBInstanceArn"),
            region=self._region,
            attributes={
                "id": db.get("DBInstanceIdentifier"),
                "identifier": db.get("DBInstanceIdentifier"),
                "engine": db.get("Engine"),
                "engine_version": db.get("EngineVersion"),
                "instance_class": db.get("DBInstanceClass"),
                "allocated_storage": db.get("AllocatedStorage"),
                "storage_type": db.get("StorageType"),
                "storage_encrypted": db.get("StorageEncrypted", False),
                "kms_key_id": db.get("KmsKeyId"),
                "publicly_accessible": db.get("PubliclyAccessible", False),
                "multi_az": db.get("MultiAZ", False),
                "vpc_security_group_ids": sorted(sg_ids),
                "db_subnet_group_name": db.get("DBSubnetGroup", {}).get("DBSubnetGroupName"),
                "backup_retention_period": db.get("BackupRetentionPeriod", 0),
                "deletion_protection": db.get("DeletionProtection", False),
                "iam_database_authentication_enabled": db.get(
                    "IAMDatabaseAuthenticationEnabled", False
                ),
                "auto_minor_version_upgrade": db.get("AutoMinorVersionUpgrade", True),
                "copy_tags_to_snapshot": db.get("CopyTagsToSnapshot", False),
                "performance_insights_enabled": db.get("PerformanceInsightsEnabled", False),
            },
            tags=self._get_tags(db.get("DBInstanceArn", "")),
        )

    def _get_tags(self, arn: str) -> dict[str, str]:
        if not arn:
            return {}
        try:
            resp = self._rds.list_tags_for_resource(ResourceName=arn)
            return {t["Key"]: t["Value"] for t in resp.get("TagList", [])}
        except ClientError:
            return {}
