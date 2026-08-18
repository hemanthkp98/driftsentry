"""S3 state reader — reads .tfstate files from AWS S3 backends."""

from __future__ import annotations

import json
from typing import Any

import boto3
from botocore.exceptions import ClientError

from driftsentry.core.models import ResourceState
from driftsentry.state.base import StateParseError, StateReader
from driftsentry.state.local import LocalStateReader


class S3StateReader(StateReader):
    """Reads Terraform/OpenTofu state from an S3 backend.

    Downloads the state file from the specified S3 bucket/key and
    parses it using the same logic as LocalStateReader.
    """

    def __init__(
        self,
        bucket: str,
        key: str,
        region: str | None = None,
        profile: str | None = None,
        role_arn: str | None = None,
    ) -> None:
        self._bucket = bucket
        self._key = key
        self._region = region
        self._profile = profile
        self._role_arn = role_arn
        self._raw_state: dict[str, Any] | None = None

    def read_state(self) -> list[ResourceState]:
        """Download state from S3 and extract all managed resources."""
        raw = self.get_raw_state()
        # Reuse LocalStateReader's extraction logic
        reader = LocalStateReader.__new__(LocalStateReader)
        return reader._extract_resources(raw)

    def get_raw_state(self) -> dict[str, Any]:
        """Download and cache the raw JSON state from S3."""
        if self._raw_state is not None:
            return self._raw_state

        session = self._create_session()
        s3_client = session.client("s3", region_name=self._region)

        try:
            response = s3_client.get_object(Bucket=self._bucket, Key=self._key)
            body = response["Body"].read().decode("utf-8")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "NoSuchBucket":
                raise FileNotFoundError(f"S3 bucket not found: {self._bucket}") from e
            if error_code == "NoSuchKey":
                raise FileNotFoundError(
                    f"State file not found: s3://{self._bucket}/{self._key}"
                ) from e
            if error_code in ("AccessDenied", "403"):
                raise PermissionError(
                    f"Access denied to s3://{self._bucket}/{self._key}. "
                    "Ensure your IAM credentials have s3:GetObject permission."
                ) from e
            raise StateParseError(
                f"S3 error ({error_code}): {e}",
                source=self.source_description,
            ) from e

        try:
            self._raw_state = json.loads(body)
        except json.JSONDecodeError as e:
            raise StateParseError(str(e), source=self.source_description) from e

        return self._raw_state

    @property
    def source_description(self) -> str:
        return f"s3://{self._bucket}/{self._key}"

    def _create_session(self) -> boto3.Session:
        """Create a boto3 session, optionally assuming a role."""
        session_kwargs: dict[str, Any] = {}
        if self._profile:
            session_kwargs["profile_name"] = self._profile
        if self._region:
            session_kwargs["region_name"] = self._region

        session = boto3.Session(**session_kwargs)

        if self._role_arn:
            sts_client = session.client("sts")
            assumed = sts_client.assume_role(
                RoleArn=self._role_arn,
                RoleSessionName="driftsentry-state-reader",
            )
            creds = assumed["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self._region,
            )

        return session
