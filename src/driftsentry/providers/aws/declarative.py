"""Generic AWS Declarative Resource Scanner.

Interprets DeclarativeResourceSpec definitions to dynamically scan AWS resources
using Boto3 and normalize attributes via JMESPath mapping without custom Python code.
"""

from __future__ import annotations

import logging
from typing import Any

import boto3
import jmespath  # type: ignore[import-untyped]
from botocore.exceptions import ClientError

from driftsentry.core.models import CloudResource
from driftsentry.providers.base import DeclarativeResourceSpec, ResourceScanner

logger = logging.getLogger(__name__)


class GenericAWSDeclarativeScanner(ResourceScanner):
    """Dynamically scans AWS services based on a DeclarativeResourceSpec."""

    def __init__(
        self,
        session: boto3.Session,
        region: str,
        spec: DeclarativeResourceSpec,
    ) -> None:
        super().__init__(session, region)
        self.spec = spec
        # Some global services like Route53 do not use region
        if spec.service in ("route53", "iam", "cloudfront"):
            self._client = session.client(spec.service)  # type: ignore[call-overload]
        else:
            self._client = session.client(spec.service, region_name=region)  # type: ignore[call-overload]

    @property
    def resource_types(self) -> list[str]:
        return [self.spec.terraform_type]

    def list_all(self) -> list[CloudResource]:
        """List all resources matching the declarative spec."""
        resources: list[CloudResource] = []
        disc = self.spec.discovery

        try:
            raw_items = self._fetch_list_items()
        except Exception as e:
            logger.warning(
                f"Failed to list {self.spec.terraform_type} via {disc.list_operation}: {e}"
            )
            raise

        for item in raw_items:
            try:
                # Extract resource ID
                if disc.id_field == "@":
                    resource_id = str(item)
                else:
                    extracted = jmespath.search(disc.id_field, item)
                    resource_id = str(extracted) if extracted is not None else ""

                if not resource_id:
                    continue

                # If describe_operation is configured, fetch detailed attributes
                if disc.describe_operation:
                    raw_attrs = self._describe_item(resource_id, item)
                    if raw_attrs is None:
                        continue
                else:
                    raw_attrs = item if isinstance(item, dict) else {"id": resource_id}

                # Normalize attributes
                norm_attrs = self.normalize(raw_attrs)
                norm_attrs["id"] = resource_id

                # Extract ARN if present
                arn = norm_attrs.get("arn") or raw_attrs.get("Arn") or raw_attrs.get("arn")

                resources.append(
                    CloudResource(
                        resource_id=resource_id,
                        resource_type=self.spec.terraform_type,
                        arn=str(arn) if arn else None,
                        region=self.region,
                        attributes=norm_attrs,
                        tags=self._extract_tags(raw_attrs),
                    )
                )
            except Exception as e:
                logger.debug(f"Error processing {self.spec.terraform_type} item: {e}")
                raise

        return resources

    def get_by_id(self, resource_id: str) -> CloudResource | None:
        """Get a specific resource by its ID."""
        disc = self.spec.discovery
        try:
            if disc.describe_operation:
                raw_attrs = self._describe_item(resource_id, {"id": resource_id})
                if raw_attrs is None:
                    return None
            else:
                # Fallback: scan all and find match
                for res in self.list_all():
                    if res.resource_id == resource_id:
                        return res
                return None

            norm_attrs = self.normalize(raw_attrs)
            norm_attrs["id"] = resource_id
            arn = norm_attrs.get("arn") or raw_attrs.get("Arn") or raw_attrs.get("arn")

            return CloudResource(
                resource_id=resource_id,
                resource_type=self.spec.terraform_type,
                arn=str(arn) if arn else None,
                region=self.region,
                attributes=norm_attrs,
                tags=self._extract_tags(raw_attrs),
            )
        except Exception as e:
            logger.debug(f"Failed to get {self.spec.terraform_type} {resource_id}: {e}")
            return None

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize raw Boto3 dictionary using the specification's attribute mappings."""
        disc = self.spec.discovery
        source_dict = raw
        if disc.attributes_path:
            nested = jmespath.search(disc.attributes_path, raw)
            if isinstance(nested, dict):
                source_dict = nested

        normalized: dict[str, Any] = {}

        # 1. Apply explicit mappings from spec
        for tf_attr, jmes_path in self.spec.attributes.items():
            val = jmespath.search(jmes_path, source_dict)
            if val is None and source_dict is not raw:
                # Fallback to searching the root dictionary
                val = jmespath.search(jmes_path, raw)
            if val is not None:
                normalized[tf_attr] = self._coerce_value(val)

        # 2. If no explicit mapping provided, pass through top-level keys in snake_case
        if not self.spec.attributes:
            for k, v in source_dict.items():
                snake_k = self._to_snake_case(k)
                normalized[snake_k] = self._coerce_value(v)

        return normalized

    def _fetch_list_items(self) -> list[Any]:
        """Fetch all items using either Boto3 paginator or direct list operation."""
        disc = self.spec.discovery
        items: list[Any] = []

        op_name = disc.paginator_operation or disc.list_operation

        if self._client.can_paginate(op_name):
            paginator = self._client.get_paginator(op_name)
            for page in paginator.paginate():
                page_items = jmespath.search(disc.result_path, page)
                if isinstance(page_items, list):
                    items.extend(page_items)
        else:
            method = getattr(self._client, disc.list_operation)
            response = method()
            res_items = jmespath.search(disc.result_path, response)
            if isinstance(res_items, list):
                items.extend(res_items)

        return items

    def _describe_item(self, resource_id: str, list_item: Any) -> dict[str, Any] | None:
        """Call describe_operation with templated parameters for a specific resource."""
        disc = self.spec.discovery
        if not disc.describe_operation:
            return None

        # Build parameters dictionary, substituting {id} and {name}
        params: dict[str, Any] = {}
        for k, v in disc.describe_params.items():
            if isinstance(v, str):
                name_val = ""
                if isinstance(list_item, dict):
                    name_val = list_item.get("Name") or list_item.get("name") or ""
                val = v.replace("{id}", resource_id).replace("{name}", str(name_val))
                params[k] = val
            else:
                params[k] = v

        try:
            method = getattr(self._client, disc.describe_operation)
            response: dict[str, Any] = method(**params)
            return response
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if "NotFound" in error_code or "NonExistent" in error_code:
                return None
            logger.debug(f"ClientError describing {resource_id}: {e}")
            return None

    @staticmethod
    def _extract_tags(raw: dict[str, Any]) -> dict[str, str]:
        """Extract resource tags from standard AWS formats."""
        tags_raw = raw.get("Tags") or raw.get("tags") or raw.get("TagList") or []
        if isinstance(tags_raw, dict):
            return {str(k): str(v) for k, v in tags_raw.items()}
        if isinstance(tags_raw, list):
            tags_dict: dict[str, str] = {}
            for item in tags_raw:
                if isinstance(item, dict):
                    k = item.get("Key") or item.get("key")
                    v = item.get("Value") or item.get("value")
                    if k is not None and v is not None:
                        tags_dict[str(k)] = str(v)
            return tags_dict
        return {}

    @staticmethod
    def _coerce_value(val: Any) -> Any:
        """Coerce boolean strings and numeric strings if standard."""
        if isinstance(val, str):
            if val.lower() == "true":
                return True
            if val.lower() == "false":
                return False
            # Check if integer
            if val.isdigit():
                return int(val)
        return val

    @staticmethod
    def _to_snake_case(name: str) -> str:
        """Convert CamelCase to snake_case."""
        import re

        s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
        return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()
