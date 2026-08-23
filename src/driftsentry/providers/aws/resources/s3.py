"""S3 resource scanner — S3 buckets."""

from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from driftsentry.core.models import CloudResource
from driftsentry.providers.base import ResourceScanner, register_scanner

logger = logging.getLogger(__name__)


@register_scanner("aws")
class S3Scanner(ResourceScanner):
    """Scans S3 buckets and their configurations."""

    def __init__(self, session: boto3.Session, region: str) -> None:
        self._s3 = session.client("s3", region_name=region)
        self._region = region

    @property
    def resource_types(self) -> list[str]:
        return ["aws_s3_bucket"]

    def list_all(self) -> list[CloudResource]:
        """List all S3 buckets in the account."""
        resources: list[CloudResource] = []

        try:
            resp = self._s3.list_buckets()
        except ClientError as e:
            logger.error(f"Error listing S3 buckets: {e}")
            return resources

        for bucket in resp.get("Buckets", []):
            bucket_name = bucket["Name"]

            # Check if bucket is in our region
            try:
                location = self._s3.get_bucket_location(Bucket=bucket_name)
                bucket_region = location.get("LocationConstraint") or "us-east-1"
                if bucket_region != self._region:
                    continue
            except ClientError:
                continue

            attrs = self._get_bucket_attributes(bucket_name)
            resources.append(
                CloudResource(
                    resource_id=bucket_name,
                    resource_type="aws_s3_bucket",
                    arn=f"arn:aws:s3:::{bucket_name}",
                    region=self._region,
                    attributes=attrs,
                    tags=self._get_bucket_tags(bucket_name),
                )
            )

        return resources

    def get_by_id(self, resource_id: str) -> CloudResource | None:
        """Get a specific S3 bucket by name."""
        try:
            self._s3.head_bucket(Bucket=resource_id)
        except ClientError:
            return None

        attrs = self._get_bucket_attributes(resource_id)
        return CloudResource(
            resource_id=resource_id,
            resource_type="aws_s3_bucket",
            arn=f"arn:aws:s3:::{resource_id}",
            region=self._region,
            attributes=attrs,
            tags=self._get_bucket_tags(resource_id),
        )

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize S3 API response to Terraform attribute format."""
        return raw  # Already normalized in _get_bucket_attributes

    def _get_bucket_attributes(self, bucket_name: str) -> dict[str, Any]:
        """Gather bucket configuration attributes matching Terraform's schema."""
        attrs: dict[str, Any] = {
            "id": bucket_name,
            "bucket": bucket_name,
        }

        # Versioning
        try:
            versioning = self._s3.get_bucket_versioning(Bucket=bucket_name)
            attrs["versioning"] = {
                "enabled": versioning.get("Status") == "Enabled",
                "mfa_delete": versioning.get("MFADelete") == "Enabled",
            }
        except ClientError:
            attrs["versioning"] = {"enabled": False, "mfa_delete": False}

        # Encryption
        try:
            encryption = self._s3.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                sse = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                attrs["server_side_encryption_configuration"] = {
                    "rule": {
                        "apply_server_side_encryption_by_default": {
                            "sse_algorithm": sse.get("SSEAlgorithm", ""),
                            "kms_master_key_id": sse.get("KMSMasterKeyID"),
                        },
                        "bucket_key_enabled": rules[0].get("BucketKeyEnabled", False),
                    }
                }
        except ClientError:
            pass

        # Logging
        try:
            logging_config = self._s3.get_bucket_logging(Bucket=bucket_name)
            log_config = logging_config.get("LoggingEnabled")
            if log_config:
                attrs["logging"] = {
                    "target_bucket": log_config.get("TargetBucket"),
                    "target_prefix": log_config.get("TargetPrefix", ""),
                }
        except ClientError:
            pass

        # Public access block
        try:
            public_access = self._s3.get_public_access_block(Bucket=bucket_name)
            config = public_access.get("PublicAccessBlockConfiguration", {})
            attrs["public_access_block"] = {
                "block_public_acls": config.get("BlockPublicAcls", False),
                "block_public_policy": config.get("BlockPublicPolicy", False),
                "ignore_public_acls": config.get("IgnorePublicAcls", False),
                "restrict_public_buckets": config.get("RestrictPublicBuckets", False),
            }
        except ClientError:
            pass

        return attrs

    def _get_bucket_tags(self, bucket_name: str) -> dict[str, str]:
        """Get tags for a bucket."""
        try:
            resp = self._s3.get_bucket_tagging(Bucket=bucket_name)
            return {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}
        except ClientError:
            return {}
