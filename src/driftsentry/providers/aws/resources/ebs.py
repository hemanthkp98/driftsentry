"""EBS and AMI resource scanner — volumes, snapshots, and images."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
from typing import Any

import boto3
from botocore.exceptions import ClientError

from driftsentry.core.models import CloudResource
from driftsentry.providers.base import ResourceScanner, register_scanner

logger = logging.getLogger(__name__)


@register_scanner("aws")
class EBSScanner(ResourceScanner):
    """Scans EBS volumes, EBS snapshots, and custom AMIs."""

    def __init__(self, session: boto3.Session, region: str) -> None:
        self._ec2 = session.client("ec2", region_name=region)
        self._region = region

    @property
    def resource_types(self) -> list[str]:
        return ["aws_ebs_volume", "aws_ebs_snapshot", "aws_ami"]

    def list_all(self) -> list[CloudResource]:
        """List all resources across supported EBS and AMI types."""
        resources: list[CloudResource] = []
        resources.extend(self._list_volumes())
        resources.extend(self._list_snapshots())
        resources.extend(self._list_images())
        return resources

    def get_by_id(self, resource_id: str) -> CloudResource | None:
        """Get an EBS/AMI resource by its ID (auto-detects type from ID prefix)."""
        try:
            if resource_id.startswith("vol-"):
                return self._get_volume(resource_id)
            elif resource_id.startswith("snap-"):
                return self._get_snapshot(resource_id)
            elif resource_id.startswith("ami-"):
                return self._get_image(resource_id)
        except Exception as e:
            logger.error(f"Error getting EBS/AMI resource {resource_id}: {e}")
        return None

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize EC2 API attributes to match Terraform attribute names."""
        normalized: dict[str, Any] = {}
        for key, value in raw.items():
            tf_key = self._to_snake_case(key)
            normalized[tf_key] = value
        return normalized

    # ─── Volumes ────────────────────────────────────────────────────────

    def _list_volumes(self) -> list[CloudResource]:
        resources: list[CloudResource] = []
        try:
            paginator = self._ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for vol in page.get("Volumes", []):
                    resources.append(self._volume_to_cloud_resource(vol))
        except Exception as e:
            logger.error(f"Error listing EBS volumes: {e}")
            raise
        return resources

    def _get_volume(self, volume_id: str) -> CloudResource | None:
        try:
            resp = self._ec2.describe_volumes(VolumeIds=[volume_id])
            vols = resp.get("Volumes", [])
            if vols:
                return self._volume_to_cloud_resource(vols[0])
        except ClientError:
            pass
        return None

    def _volume_to_cloud_resource(self, vol: Mapping[str, Any]) -> CloudResource:
        vol_id = vol["VolumeId"]
        tags = self._extract_tags(vol.get("Tags", []))
        attrs: dict[str, Any] = {
            "id": vol_id,
            "availability_zone": vol.get("AvailabilityZone"),
            "size": vol.get("Size"),
            "volume_type": vol.get("VolumeType"),
            "iops": vol.get("Iops"),
            "throughput": vol.get("Throughput"),
            "encrypted": vol.get("Encrypted", False),
            "kms_key_id": vol.get("KmsKeyId"),
            "snapshot_id": vol.get("SnapshotId"),
            "multi_attach_enabled": vol.get("MultiAttachEnabled", False),
            "tags": tags,
        }
        return CloudResource(
            resource_id=vol_id,
            resource_type="aws_ebs_volume",
            arn=f"arn:aws:ec2:{self._region}::volume/{vol_id}",
            region=self._region,
            attributes=attrs,
            tags=tags,
        )

    # ─── Snapshots ──────────────────────────────────────────────────────

    def _list_snapshots(self) -> list[CloudResource]:
        resources: list[CloudResource] = []
        try:
            paginator = self._ec2.get_paginator("describe_snapshots")
            for page in paginator.paginate(OwnerIds=["self"]):
                for snap in page.get("Snapshots", []):
                    resources.append(self._snapshot_to_cloud_resource(snap))
        except Exception as e:
            logger.error(f"Error listing EBS snapshots: {e}")
            raise
        return resources

    def _get_snapshot(self, snapshot_id: str) -> CloudResource | None:
        try:
            resp = self._ec2.describe_snapshots(SnapshotIds=[snapshot_id])
            snaps = resp.get("Snapshots", [])
            if snaps:
                return self._snapshot_to_cloud_resource(snaps[0])
        except ClientError:
            pass
        return None

    def _snapshot_to_cloud_resource(self, snap: Mapping[str, Any]) -> CloudResource:
        snap_id = snap["SnapshotId"]
        tags = self._extract_tags(snap.get("Tags", []))
        attrs: dict[str, Any] = {
            "id": snap_id,
            "volume_id": snap.get("VolumeId"),
            "volume_size": snap.get("VolumeSize"),
            "description": snap.get("Description"),
            "encrypted": snap.get("Encrypted", False),
            "kms_key_id": snap.get("KmsKeyId"),
            "owner_id": snap.get("OwnerId"),
            "tags": tags,
        }
        return CloudResource(
            resource_id=snap_id,
            resource_type="aws_ebs_snapshot",
            arn=f"arn:aws:ec2:{self._region}::snapshot/{snap_id}",
            region=self._region,
            attributes=attrs,
            tags=tags,
        )

    # ─── AMIs (Images) ──────────────────────────────────────────────────

    def _list_images(self) -> list[CloudResource]:
        resources: list[CloudResource] = []
        try:
            resp = self._ec2.describe_images(Owners=["self"])
            for img in resp.get("Images", []):
                resources.append(self._image_to_cloud_resource(img))
        except Exception as e:
            logger.error(f"Error listing AMIs: {e}")
            raise
        return resources

    def _get_image(self, image_id: str) -> CloudResource | None:
        try:
            resp = self._ec2.describe_images(ImageIds=[image_id])
            imgs = resp.get("Images", [])
            if imgs:
                return self._image_to_cloud_resource(imgs[0])
        except ClientError:
            pass
        return None

    def _image_to_cloud_resource(self, img: Mapping[str, Any]) -> CloudResource:
        img_id = img["ImageId"]
        tags = self._extract_tags(img.get("Tags", []))
        attrs: dict[str, Any] = {
            "id": img_id,
            "name": img.get("Name"),
            "description": img.get("Description"),
            "architecture": img.get("Architecture"),
            "image_type": img.get("ImageType"),
            "root_device_name": img.get("RootDeviceName"),
            "virtualization_type": img.get("VirtualizationType"),
            "hypervisor": img.get("Hypervisor"),
            "public": img.get("Public", False),
            "tags": tags,
        }
        return CloudResource(
            resource_id=img_id,
            resource_type="aws_ami",
            arn=f"arn:aws:ec2:{self._region}::image/{img_id}",
            region=self._region,
            attributes=attrs,
            tags=tags,
        )

    # ─── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _extract_tags(tags_list: Sequence[Mapping[str, Any]] | None) -> dict[str, str]:
        tags: dict[str, str] = {}
        if not tags_list:
            return tags
        for tag in tags_list:
            key = tag.get("Key")
            value = tag.get("Value")
            if key and value is not None:
                tags[str(key)] = str(value)
        return tags

    @staticmethod
    def _to_snake_case(s: str) -> str:
        s = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", s)
        return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s).lower()
