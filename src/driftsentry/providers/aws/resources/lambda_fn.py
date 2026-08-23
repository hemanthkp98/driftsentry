"""Lambda resource scanner — Lambda functions."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import boto3
from botocore.exceptions import ClientError

from driftsentry.core.models import CloudResource
from driftsentry.providers.base import ResourceScanner, register_scanner

logger = logging.getLogger(__name__)


@register_scanner("aws")
class LambdaScanner(ResourceScanner):
    """Scans Lambda functions."""

    def __init__(self, session: boto3.Session, region: str) -> None:
        self._lambda = session.client("lambda", region_name=region)
        self._region = region

    @property
    def resource_types(self) -> list[str]:
        return ["aws_lambda_function"]

    def list_all(self) -> list[CloudResource]:
        resources: list[CloudResource] = []
        paginator = self._lambda.get_paginator("list_functions")

        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                resources.append(self._fn_to_cloud_resource(fn))

        return resources

    def get_by_id(self, resource_id: str) -> CloudResource | None:
        try:
            fn = self._lambda.get_function(FunctionName=resource_id)
            config = fn.get("Configuration", {})
            return self._fn_to_cloud_resource(config)
        except ClientError:
            return None

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return raw

    def _fn_to_cloud_resource(self, fn: Mapping[str, Any]) -> CloudResource:
        vpc_config = fn.get("VpcConfig", {})
        env_vars = fn.get("Environment", {}).get("Variables", {})

        return CloudResource(
            resource_id=fn["FunctionName"],
            resource_type="aws_lambda_function",
            arn=fn.get("FunctionArn"),
            region=self._region,
            attributes={
                "id": fn.get("FunctionName"),
                "function_name": fn.get("FunctionName"),
                "role": fn.get("Role"),
                "handler": fn.get("Handler"),
                "runtime": fn.get("Runtime"),
                "timeout": fn.get("Timeout", 3),
                "memory_size": fn.get("MemorySize", 128),
                "description": fn.get("Description", ""),
                "architectures": fn.get("Architectures", ["x86_64"]),
                "package_type": fn.get("PackageType", "Zip"),
                "vpc_config": {
                    "subnet_ids": sorted(vpc_config.get("SubnetIds", [])),
                    "security_group_ids": sorted(vpc_config.get("SecurityGroupIds", [])),
                }
                if vpc_config.get("SubnetIds")
                else {},
                "environment": {"variables": env_vars} if env_vars else {},
                "tracing_config": {
                    "mode": fn.get("TracingConfig", {}).get("Mode", "PassThrough"),
                },
                "ephemeral_storage": {
                    "size": fn.get("EphemeralStorage", {}).get("Size", 512),
                },
            },
            tags=fn.get("Tags", {}),
        )
