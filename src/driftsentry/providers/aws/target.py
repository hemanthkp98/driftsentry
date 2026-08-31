"""Scan targets and target resolution for multi-account and multi-region AWS scanning."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import ClientError

from driftsentry.core.config import AccountConfig

logger = logging.getLogger(__name__)


@dataclass
class ScanTarget:
    """Represents a specific (Account, Region) scan endpoint."""

    account_id: str
    account_name: str
    region: str
    session: boto3.Session
    role_arn: str | None = None
    profile: str | None = None

    @property
    def target_id(self) -> str:
        """Unique identifier for this scan target, e.g. 'production:us-east-1'."""
        name = self.account_name or self.account_id
        return f"{name}:{self.region}"

    @property
    def account_key(self) -> str:
        """Account identifier, e.g. 'production' or '123456789012'."""
        return self.account_name or self.account_id


class TargetResolver:
    """Resolves configuration and CLI options into concrete ScanTarget instances."""

    def __init__(
        self,
        region: str | None = None,
        regions: list[str] | None = None,
        profile: str | None = None,
        role_arn: str | None = None,
        accounts: list[AccountConfig] | None = None,
        role_arn_template: str | None = None,
    ) -> None:
        self._region = region
        self._regions = [r.strip() for r in (regions or []) if r and r.strip()]
        self._profile = profile
        self._role_arn = role_arn
        self._accounts = accounts or []
        self._role_arn_template = role_arn_template

    def resolve_targets(self) -> list[ScanTarget]:
        """Resolve and return all (Account, Region) scan targets."""
        targets: list[ScanTarget] = []

        if self._accounts:
            for acc in self._accounts:
                account_targets = self._resolve_account_targets(acc)
                targets.extend(account_targets)
        else:
            # Single or default account with single/multiple regions
            default_acc = AccountConfig(
                id=None,
                name=None,
                role_arn=self._role_arn,
                profile=self._profile,
                regions=self._regions or ([self._region] if self._region else []),
            )
            targets.extend(self._resolve_account_targets(default_acc))

        return targets

    def _resolve_account_targets(self, acc: AccountConfig) -> list[ScanTarget]:
        """Resolve targets for a single AccountConfig."""
        # 1. Determine role ARN if using template
        role_arn = acc.role_arn
        if not role_arn and self._role_arn_template and acc.id:
            role_arn = self._role_arn_template.format(account_id=acc.id)

        # 2. Build initial session for account identity discovery
        base_session = self._create_base_session(
            profile=acc.profile or self._profile,
            region=self._region or "us-east-1",
        )

        account_session = self._create_account_session(
            base_session=base_session,
            role_arn=role_arn,
            external_id=acc.external_id,
            region=self._region or "us-east-1",
        )

        # 3. Determine Account ID and Name
        account_id = acc.id
        account_name = acc.name or (acc.id if acc.id else "default")
        if not account_id:
            try:
                sts = account_session.client("sts")
                caller_identity = sts.get_caller_identity()
                account_id = caller_identity.get("Account", "unknown")
                if not acc.name:
                    account_name = account_id
            except Exception as e:
                logger.warning(f"Could not determine AWS caller identity: {e}")
                account_id = "default"
                account_name = acc.name or "default"

        # 4. Determine Regions for this account
        target_regions = self._resolve_regions(account_session, acc.regions)

        # 5. Create a ScanTarget per region
        targets: list[ScanTarget] = []
        for reg in target_regions:
            # Create a regional session for this specific target
            reg_session = self._create_account_session(
                base_session=base_session,
                role_arn=role_arn,
                external_id=acc.external_id,
                region=reg,
            )
            targets.append(
                ScanTarget(
                    account_id=account_id,
                    account_name=account_name,
                    region=reg,
                    session=reg_session,
                    role_arn=role_arn,
                    profile=acc.profile or self._profile,
                )
            )

        return targets

    def _resolve_regions(
        self,
        session: boto3.Session,
        account_regions: list[str] | None,
    ) -> list[str]:
        """Determine regions to scan, expanding 'all' if requested."""
        candidate_regions = (
            account_regions if (account_regions and len(account_regions) > 0) else self._regions
        )

        if not candidate_regions:
            if self._region:
                return [self._region]
            return [session.region_name or "us-east-1"]

        # Check if 'all' or 'all-regions' was requested
        if any(r.lower() in ("all", "all-regions") for r in candidate_regions):
            try:
                ec2 = session.client("ec2", region_name="us-east-1")
                resp = ec2.describe_regions()
                discovered = [r["RegionName"] for r in resp.get("Regions", [])]
                if discovered:
                    return sorted(discovered)
            except ClientError as e:
                logger.warning(f"Failed to describe AWS regions, falling back to defaults: {e}")
            except Exception as e:
                logger.warning(f"Error querying AWS regions: {e}")
            return ["us-east-1"]

        # Deduplicate while preserving order
        seen: set[str] = set()
        resolved: list[str] = []
        for r in candidate_regions:
            cleaned = r.strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                resolved.append(cleaned)

        return resolved or ["us-east-1"]

    @staticmethod
    def _create_base_session(
        profile: str | None,
        region: str | None,
    ) -> boto3.Session:
        """Create a base boto3 Session."""
        from driftsentry.providers.aws.provider import AWSProvider

        return AWSProvider._create_session(region=region, profile=profile)

    @staticmethod
    def _create_account_session(
        base_session: boto3.Session,
        role_arn: str | None,
        external_id: str | None,
        region: str | None,
    ) -> boto3.Session:
        """Create a boto3 session, assuming a role if specified."""
        if not role_arn:
            if region:
                from driftsentry.providers.aws.provider import AWSProvider

                profile = getattr(base_session, "profile_name", None)
                return AWSProvider._create_session(region=region, profile=profile)
            return base_session

        # If base_session was mocked to return a mock client or custom session
        try:
            sts = base_session.client("sts", region_name=region or "us-east-1")
            assume_kwargs: dict[str, Any] = {
                "RoleArn": role_arn,
                "RoleSessionName": "driftsentry-multitarget-scanner",
            }
            if external_id:
                assume_kwargs["ExternalId"] = external_id

            assumed = sts.assume_role(**assume_kwargs)
            creds = assumed["Credentials"]

            return boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
        except Exception as e:
            logger.warning(f"Role assumption failed for {role_arn}: {e}")
            return base_session
