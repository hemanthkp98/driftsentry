"""CloudTrail attributor — queries AWS CloudTrail to determine who caused drift.

Looks up recent CloudTrail events for drifted resources to identify
the IAM principal, API call, timestamp, and source IP.
"""

from __future__ import annotations

import datetime
import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from driftsentry.core.models import DriftAttribution, DriftItem

logger = logging.getLogger(__name__)

# ─── Resource type to CloudTrail event mapping ──────────────────

# Maps Terraform resource types to the CloudTrail event names that
# could modify them. This is a best-effort mapping.
RESOURCE_EVENT_MAP: dict[str, list[str]] = {
    "aws_instance": [
        "ModifyInstanceAttribute",
        "RunInstances",
        "TerminateInstances",
        "StopInstances",
        "StartInstances",
    ],
    "aws_security_group": [
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress",
        "ModifySecurityGroupRules",
        "UpdateSecurityGroupRuleDescriptionsIngress",
        "UpdateSecurityGroupRuleDescriptionsEgress",
        "CreateSecurityGroup",
        "DeleteSecurityGroup",
    ],
    "aws_s3_bucket": [
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketAcl",
        "PutBucketVersioning",
        "PutBucketEncryption",
        "DeleteBucketEncryption",
        "PutBucketLogging",
        "PutPublicAccessBlock",
        "DeletePublicAccessBlock",
    ],
    "aws_iam_role": [
        "UpdateAssumeRolePolicy",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "PutRolePolicy",
        "DeleteRolePolicy",
        "CreateRole",
        "DeleteRole",
    ],
    "aws_iam_policy": [
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion",
        "DeletePolicyVersion",
        "CreatePolicy",
        "DeletePolicy",
    ],
    "aws_iam_user": [
        "CreateUser",
        "DeleteUser",
        "AttachUserPolicy",
        "DetachUserPolicy",
    ],
    "aws_db_instance": [
        "ModifyDBInstance",
        "DeleteDBInstance",
        "CreateDBInstance",
    ],
    "aws_lambda_function": [
        "UpdateFunctionConfiguration",
        "UpdateFunctionCode",
        "CreateFunction",
        "DeleteFunction",
        "PublishVersion",
    ],
    "aws_ecs_cluster": [
        "CreateCluster",
        "DeleteCluster",
        "UpdateClusterSettings",
    ],
    "aws_ecs_service": [
        "CreateService",
        "UpdateService",
        "DeleteService",
    ],
}


def register_resource_events(resource_type: str, event_names: list[str]) -> None:
    """Register or extend CloudTrail event names for a resource type dynamically."""
    if resource_type not in RESOURCE_EVENT_MAP:
        RESOURCE_EVENT_MAP[resource_type] = []
    for evt in event_names:
        if evt not in RESOURCE_EVENT_MAP[resource_type]:
            RESOURCE_EVENT_MAP[resource_type].append(evt)


# Console user agents
CONSOLE_USER_AGENTS = [
    "console.amazonaws.com",
    "signin.amazonaws.com",
    "Coral/Jakarta",
    "Coral/Netty4",
]


class CloudTrailAttributor:
    """Queries CloudTrail to attribute drift to specific IAM principals.

    Supports multi-account and multi-region environments by dynamically
    routing event lookups to the appropriate regional and account client.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        profile: str | None = None,
        lookback_hours: int = 168,  # 7 days
        targets: list[Any] | None = None,
    ) -> None:
        self._default_region = region or "us-east-1"
        self._profile = profile
        self._lookback_hours = lookback_hours
        self._targets = targets or []

        # Cache of CloudTrail clients: key -> boto3 CloudTrail client
        self._clients: dict[tuple[str, str], Any] = {}

        # Pre-populate clients from targets if provided
        for target in self._targets:
            key = (getattr(target, "account_key", "default"), getattr(target, "region", "us-east-1"))
            try:
                session = getattr(target, "session", None)
                if session:
                    self._clients[key] = session.client("cloudtrail", region_name=target.region)
            except Exception as e:
                logger.debug(f"Failed to create CloudTrail client for target {key}: {e}")

        # Default fallback client
        if ("default", self._default_region) not in self._clients:
            session_kwargs: dict[str, Any] = {"region_name": self._default_region}
            if profile:
                session_kwargs["profile_name"] = profile
            try:
                session = boto3.Session(**session_kwargs)
                self._clients[("default", self._default_region)] = session.client("cloudtrail")
            except Exception as e:
                logger.debug(f"Failed to create default CloudTrail client: {e}")

    def attribute(self, drift_item: DriftItem) -> DriftAttribution | None:
        """Find who caused drift for a given drift item.

        Returns the most recent relevant CloudTrail event, or None
        if no attribution could be made.
        """
        resource_id = drift_item.resource_id
        resource_type = drift_item.resource_type

        if not resource_id:
            return None

        # Get relevant event names for this resource type
        event_names = RESOURCE_EVENT_MAP.get(resource_type, [])
        if not event_names:
            logger.debug(f"No event mapping for {resource_type}")
            return None

        client = self._get_client_for_item(drift_item)
        if client is None:
            return None

        # Query CloudTrail
        events = self._lookup_events_with_client(client, resource_id, event_names)

        if not events:
            return None

        # Return the most recent relevant event
        event = events[0]
        user_agent = event.get("userAgent", "")

        return DriftAttribution(
            principal=self._extract_principal(event),
            event_name=event.get("eventName"),
            event_time=event.get("eventTime"),
            source_ip=event.get("sourceIPAddress"),
            user_agent=user_agent,
            is_console_change=any(ua in user_agent for ua in CONSOLE_USER_AGENTS),
        )

    def _get_client_for_item(self, item: DriftItem) -> Any:
        """Get or create the CloudTrail client for an item's account and region."""
        region = item.region or self._default_region
        account_key = item.account_name or item.account_id or "default"

        key = (account_key, region)
        if key in self._clients:
            return self._clients[key]

        # Try match by account only
        for (acc, reg), client in self._clients.items():
            if acc == account_key:
                return client

        # Try match by region only
        for (acc, reg), client in self._clients.items():
            if reg == region:
                return client

        # Return default or first available client
        if ("default", self._default_region) in self._clients:
            return self._clients[("default", self._default_region)]

        if self._clients:
            return next(iter(self._clients.values()))

        return None

    def _lookup_events_with_client(
        self,
        client: Any,
        resource_id: str,
        event_names: list[str],
    ) -> list[dict[str, Any]]:
        """Query CloudTrail for events related to a resource using a specific client."""
        start_time = datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(
            hours=self._lookback_hours
        )

        all_events: list[dict[str, Any]] = []

        try:
            paginator = client.get_paginator("lookup_events")
            for page in paginator.paginate(
                LookupAttributes=[
                    {
                        "AttributeKey": "ResourceName",
                        "AttributeValue": resource_id,
                    }
                ],
                StartTime=start_time,
                MaxResults=50,
            ):
                for event in page.get("Events", []):
                    if event.get("EventName") in event_names:
                        all_events.append(self._parse_event(event))

        except ClientError as e:
            logger.warning(f"CloudTrail lookup failed for {resource_id}: {e}")
            return []
        except Exception as e:
            logger.debug(f"CloudTrail lookup error for {resource_id}: {e}")
            return []

        # Sort by time, most recent first
        all_events.sort(key=lambda e: e.get("eventTime", ""), reverse=True)
        return all_events

    def _lookup_events(
        self,
        resource_id: str,
        event_names: list[str],
    ) -> list[dict[str, Any]]:
        """Query CloudTrail for events related to a resource."""
        start_time = datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(
            hours=self._lookback_hours
        )

        all_events: list[dict[str, Any]] = []

        try:
            # Look up by resource name/ID
            paginator = self._cloudtrail.get_paginator("lookup_events")
            for page in paginator.paginate(
                LookupAttributes=[
                    {
                        "AttributeKey": "ResourceName",
                        "AttributeValue": resource_id,
                    }
                ],
                StartTime=start_time,
                MaxResults=50,
            ):
                for event in page.get("Events", []):
                    if event.get("EventName") in event_names:
                        all_events.append(self._parse_event(event))

        except ClientError as e:
            logger.warning(f"CloudTrail lookup failed for {resource_id}: {e}")
            return []

        # Sort by time, most recent first
        all_events.sort(key=lambda e: e.get("eventTime", ""), reverse=True)
        return all_events

    @staticmethod
    def _parse_event(event: dict[str, Any]) -> dict[str, Any]:
        """Parse a CloudTrail event into a standardized dict."""
        import json

        cloud_trail_event = event.get("CloudTrailEvent", "{}")
        if isinstance(cloud_trail_event, str):
            try:
                detail = json.loads(cloud_trail_event)
            except json.JSONDecodeError:
                detail = {}
        else:
            detail = cloud_trail_event or {}

        # Merge top-level lookup_events fields with parsed CloudTrailEvent JSON
        user_identity = detail.get("userIdentity") or event.get("userIdentity", {})
        username = event.get("Username")
        if username and not user_identity.get("userName"):
            user_identity["userName"] = username

        return {
            "eventName": event.get("EventName") or detail.get("eventName"),
            "eventTime": event.get("EventTime") or detail.get("eventTime"),
            "sourceIPAddress": detail.get("sourceIPAddress") or event.get("sourceIPAddress"),
            "userAgent": detail.get("userAgent") or event.get("userAgent", ""),
            "userIdentity": user_identity,
            "requestParameters": detail.get("requestParameters") or event.get("requestParameters", {}),
            "username": username,
        }

    @staticmethod
    def _extract_principal(event: dict[str, Any]) -> str:
        """Extract a human-readable principal name from CloudTrail event."""
        identity = event.get("userIdentity", {})

        # Check for assumed role with session name
        session_context = identity.get("sessionContext", {})
        session_issuer = session_context.get("sessionIssuer", {})

        arn = identity.get("arn", "")

        # If it's an assumed role, show the role name and session name
        if identity.get("type") == "AssumedRole":
            role_name = session_issuer.get("userName", "")
            # ARN format: arn:aws:sts::123456:assumed-role/RoleName/SessionName
            parts = arn.split("/")
            session_name = parts[-1] if len(parts) > 2 else ""
            if session_name and role_name:
                return f"{role_name}/{session_name}"
            return str(role_name or arn)

        # IAM user
        if identity.get("type") == "IAMUser" or identity.get("userName"):
            return str(identity.get("userName") or arn)

        # Root account
        if identity.get("type") == "Root":
            return "root"

        # AWS service
        if identity.get("type") == "AWSService":
            return str(identity.get("invokedBy") or "aws-service")

        if event.get("username"):
            return str(event["username"])

        return str(arn or "unknown")
