"""ECS resource scanner — ECS clusters and services."""

from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from driftsentry.core.models import CloudResource
from driftsentry.providers.base import ResourceScanner

logger = logging.getLogger(__name__)


class ECSScanner(ResourceScanner):
    """Scans ECS clusters and services."""

    def __init__(self, session: boto3.Session, region: str) -> None:
        self._ecs = session.client("ecs", region_name=region)
        self._region = region

    @property
    def resource_types(self) -> list[str]:
        return ["aws_ecs_cluster", "aws_ecs_service"]

    def list_all(self) -> list[CloudResource]:
        resources: list[CloudResource] = []
        resources.extend(self._list_clusters())
        resources.extend(self._list_services())
        return resources

    def get_by_id(self, resource_id: str) -> CloudResource | None:
        # Try cluster first, then service
        resource = self._get_cluster(resource_id)
        if resource:
            return resource
        return None

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return raw

    # ── Clusters ─────────────────────────────────────────────

    def _list_clusters(self) -> list[CloudResource]:
        resources: list[CloudResource] = []

        try:
            cluster_arns = self._ecs.list_clusters().get("clusterArns", [])
        except ClientError as e:
            logger.error(f"Error listing ECS clusters: {e}")
            return resources

        if not cluster_arns:
            return resources

        resp = self._ecs.describe_clusters(clusters=cluster_arns, include=["SETTINGS", "TAGS"])

        for cluster in resp.get("clusters", []):
            resources.append(
                CloudResource(
                    resource_id=cluster["clusterName"],
                    resource_type="aws_ecs_cluster",
                    arn=cluster.get("clusterArn"),
                    region=self._region,
                    attributes={
                        "id": cluster.get("clusterArn"),
                        "name": cluster.get("clusterName"),
                        "setting": [
                            {"name": s["name"], "value": s["value"]}
                            for s in cluster.get("settings", [])
                        ],
                    },
                    tags={t["key"]: t["value"] for t in cluster.get("tags", [])},
                )
            )

        return resources

    def _get_cluster(self, cluster_name: str) -> CloudResource | None:
        try:
            resp = self._ecs.describe_clusters(
                clusters=[cluster_name], include=["SETTINGS", "TAGS"]
            )
            clusters = resp.get("clusters", [])
            if clusters:
                cluster = clusters[0]
                return CloudResource(
                    resource_id=cluster["clusterName"],
                    resource_type="aws_ecs_cluster",
                    arn=cluster.get("clusterArn"),
                    region=self._region,
                    attributes={
                        "id": cluster.get("clusterArn"),
                        "name": cluster.get("clusterName"),
                    },
                    tags={t["key"]: t["value"] for t in cluster.get("tags", [])},
                )
        except ClientError:
            pass
        return None

    # ── Services ─────────────────────────────────────────────

    def _list_services(self) -> list[CloudResource]:
        resources: list[CloudResource] = []

        try:
            cluster_arns = self._ecs.list_clusters().get("clusterArns", [])
        except ClientError:
            return resources

        for cluster_arn in cluster_arns:
            try:
                paginator = self._ecs.get_paginator("list_services")
                for page in paginator.paginate(cluster=cluster_arn):
                    service_arns = page.get("serviceArns", [])
                    if not service_arns:
                        continue

                    svc_resp = self._ecs.describe_services(
                        cluster=cluster_arn, services=service_arns, include=["TAGS"]
                    )

                    for svc in svc_resp.get("services", []):
                        if svc.get("status") != "ACTIVE":
                            continue

                        net_config = svc.get("networkConfiguration", {}).get(
                            "awsvpcConfiguration", {}
                        )

                        resources.append(
                            CloudResource(
                                resource_id=svc["serviceName"],
                                resource_type="aws_ecs_service",
                                arn=svc.get("serviceArn"),
                                region=self._region,
                                attributes={
                                    "id": svc.get("serviceArn"),
                                    "name": svc.get("serviceName"),
                                    "cluster": cluster_arn,
                                    "task_definition": svc.get("taskDefinition"),
                                    "desired_count": svc.get("desiredCount", 0),
                                    "launch_type": svc.get("launchType"),
                                    "scheduling_strategy": svc.get("schedulingStrategy", "REPLICA"),
                                    "network_configuration": {
                                        "subnets": sorted(net_config.get("subnets", [])),
                                        "security_groups": sorted(
                                            net_config.get("securityGroups", [])
                                        ),
                                        "assign_public_ip": net_config.get(
                                            "assignPublicIp", "DISABLED"
                                        ),
                                    }
                                    if net_config
                                    else {},
                                },
                                tags={t["key"]: t["value"] for t in svc.get("tags", [])},
                            )
                        )
            except ClientError as e:
                logger.error(f"Error listing ECS services in {cluster_arn}: {e}")

        return resources
