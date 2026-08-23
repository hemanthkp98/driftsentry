"""IAM resource scanner — roles, policies, users."""

from __future__ import annotations

import json
import logging
import urllib.parse
from typing import Any

import boto3
from botocore.exceptions import ClientError

from driftsentry.core.models import CloudResource
from driftsentry.providers.base import ResourceScanner, register_scanner

logger = logging.getLogger(__name__)


@register_scanner("aws")
class IAMScanner(ResourceScanner):
    """Scans IAM resources: roles, policies, and users."""

    def __init__(self, session: boto3.Session, region: str) -> None:
        self._iam = session.client("iam")  # IAM is global, no region needed
        self._region = region

    @property
    def resource_types(self) -> list[str]:
        return ["aws_iam_role", "aws_iam_policy", "aws_iam_user"]

    def list_all(self) -> list[CloudResource]:
        resources: list[CloudResource] = []
        resources.extend(self._list_roles())
        resources.extend(self._list_policies())
        resources.extend(self._list_users())
        return resources

    def get_by_id(self, resource_id: str) -> CloudResource | None:
        """Get IAM resource by name or ARN."""
        # Try as role name first, then policy ARN, then user name
        resource = self._get_role(resource_id)
        if resource:
            return resource
        resource = self._get_policy(resource_id)
        if resource:
            return resource
        return self._get_user(resource_id)

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return raw

    # ── Roles ────────────────────────────────────────────────

    def _list_roles(self) -> list[CloudResource]:
        resources: list[CloudResource] = []
        paginator = self._iam.get_paginator("list_roles")

        for page in paginator.paginate():
            for role in page.get("Roles", []):
                # Skip AWS service-linked roles
                if role.get("Path", "").startswith("/aws-service-role/"):
                    continue

                resources.append(self._role_to_cloud_resource(role))

        return resources

    def _get_role(self, role_name: str) -> CloudResource | None:
        try:
            resp = self._iam.get_role(RoleName=role_name)
            return self._role_to_cloud_resource(resp["Role"])
        except ClientError:
            return None

    def _role_to_cloud_resource(self, role: dict[str, Any]) -> CloudResource:
        assume_role_policy = role.get("AssumeRolePolicyDocument", {})
        if isinstance(assume_role_policy, str):
            assume_role_policy = json.loads(urllib.parse.unquote(assume_role_policy))

        # Get attached managed policies
        managed_policies: list[str] = []
        try:
            paginator = self._iam.get_paginator("list_attached_role_policies")
            for page in paginator.paginate(RoleName=role["RoleName"]):
                for policy in page.get("AttachedPolicies", []):
                    managed_policies.append(policy["PolicyArn"])
        except ClientError:
            pass

        return CloudResource(
            resource_id=role["RoleName"],
            resource_type="aws_iam_role",
            arn=role.get("Arn"),
            region="global",
            attributes={
                "id": role.get("RoleName"),
                "name": role.get("RoleName"),
                "path": role.get("Path", "/"),
                "assume_role_policy": json.dumps(assume_role_policy, sort_keys=True),
                "description": role.get("Description", ""),
                "max_session_duration": role.get("MaxSessionDuration", 3600),
                "managed_policy_arns": sorted(managed_policies),
            },
            tags=self._extract_tags(role),
        )

    # ── Policies ─────────────────────────────────────────────

    def _list_policies(self) -> list[CloudResource]:
        resources: list[CloudResource] = []
        paginator = self._iam.get_paginator("list_policies")

        for page in paginator.paginate(Scope="Local"):  # Only customer-managed policies
            for policy in page.get("Policies", []):
                resource = self._policy_to_cloud_resource(policy)
                if resource:
                    resources.append(resource)

        return resources

    def _get_policy(self, policy_arn: str) -> CloudResource | None:
        try:
            resp = self._iam.get_policy(PolicyArn=policy_arn)
            return self._policy_to_cloud_resource(resp["Policy"])
        except ClientError:
            return None

    def _policy_to_cloud_resource(self, policy: dict[str, Any]) -> CloudResource | None:
        policy_arn = policy.get("Arn", "")

        # Get the policy document
        policy_document: str = "{}"
        try:
            version_id = policy.get("DefaultVersionId", "v1")
            version_resp = self._iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id,
            )
            doc = version_resp.get("PolicyVersion", {}).get("Document", {})
            if isinstance(doc, str):
                doc = json.loads(urllib.parse.unquote(doc))
            policy_document = json.dumps(doc, sort_keys=True)
        except ClientError as e:
            logger.warning(f"Could not get policy document for {policy_arn}: {e}")

        return CloudResource(
            resource_id=policy_arn,
            resource_type="aws_iam_policy",
            arn=policy_arn,
            region="global",
            attributes={
                "id": policy_arn,
                "name": policy.get("PolicyName"),
                "path": policy.get("Path", "/"),
                "description": policy.get("Description", ""),
                "policy": policy_document,
            },
            tags=self._get_policy_tags(policy_arn),
        )

    def _get_policy_tags(self, policy_arn: str) -> dict[str, str]:
        try:
            resp = self._iam.list_policy_tags(PolicyArn=policy_arn)
            return {t["Key"]: t["Value"] for t in resp.get("Tags", [])}
        except ClientError:
            return {}

    # ── Users ────────────────────────────────────────────────

    def _list_users(self) -> list[CloudResource]:
        resources: list[CloudResource] = []
        paginator = self._iam.get_paginator("list_users")

        for page in paginator.paginate():
            for user in page.get("Users", []):
                resources.append(
                    CloudResource(
                        resource_id=user["UserName"],
                        resource_type="aws_iam_user",
                        arn=user.get("Arn"),
                        region="global",
                        attributes={
                            "id": user.get("UserName"),
                            "name": user.get("UserName"),
                            "path": user.get("Path", "/"),
                        },
                        tags=self._extract_tags(user),
                    )
                )

        return resources

    def _get_user(self, user_name: str) -> CloudResource | None:
        try:
            resp = self._iam.get_user(UserName=user_name)
            user = resp["User"]
            return CloudResource(
                resource_id=user["UserName"],
                resource_type="aws_iam_user",
                arn=user.get("Arn"),
                region="global",
                attributes={
                    "id": user.get("UserName"),
                    "name": user.get("UserName"),
                    "path": user.get("Path", "/"),
                },
                tags=self._extract_tags(user),
            )
        except ClientError:
            return None

    @staticmethod
    def _extract_tags(resource: dict[str, Any]) -> dict[str, str]:
        tags = resource.get("Tags", [])
        return {t["Key"]: t["Value"] for t in tags if "Key" in t and "Value" in t}
