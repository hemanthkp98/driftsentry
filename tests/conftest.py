"""Shared test fixtures for DriftSentry tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from driftsentry.core.config import DriftSentryConfig
from driftsentry.core.models import CloudResource, ResourceState, StateBackendType
from driftsentry.state.local import LocalStateReader

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_STATE_PATH = FIXTURES_DIR / "sample_state.tfstate"


@pytest.fixture
def sample_state_file() -> Path:
    """Path to sample .tfstate test fixture."""
    return SAMPLE_STATE_PATH


@pytest.fixture
def sample_state_dict(sample_state_file: Path) -> dict[str, Any]:
    """Parsed sample .tfstate dictionary."""
    return json.loads(sample_state_file.read_text())


@pytest.fixture
def local_state_reader(sample_state_file: Path) -> LocalStateReader:
    """LocalStateReader initialized with sample state file."""
    return LocalStateReader(sample_state_file)


@pytest.fixture
def default_config(sample_state_file: Path) -> DriftSentryConfig:
    """Default test configuration pointing to sample state file."""
    config = DriftSentryConfig()
    config.state.backend = StateBackendType.LOCAL
    config.state.path = str(sample_state_file)
    config.attribution.enabled = False
    return config


@pytest.fixture
def mock_ec2_resource() -> ResourceState:
    """Mock EC2 instance ResourceState."""
    return ResourceState(
        address="aws_instance.web",
        resource_type="aws_instance",
        resource_name="web",
        provider='provider["registry.terraform.io/hashicorp/aws"]',
        resource_id="i-0abc123def456789",
        attributes={
            "id": "i-0abc123def456789",
            "ami": "ami-0abcdef1234567890",
            "instance_type": "t3.micro",
            "subnet_id": "subnet-0abc123",
            "vpc_security_group_ids": ["sg-0abc123"],
            "monitoring": False,
        },
    )


@pytest.fixture
def mock_cloud_ec2() -> CloudResource:
    """Mock EC2 instance CloudResource matching mock_ec2_resource."""
    return CloudResource(
        resource_id="i-0abc123def456789",
        resource_type="aws_instance",
        arn="arn:aws:ec2:us-east-1::instance/i-0abc123def456789",
        region="us-east-1",
        attributes={
            "id": "i-0abc123def456789",
            "ami": "ami-0abcdef1234567890",
            "instance_type": "t3.micro",
            "subnet_id": "subnet-0abc123",
            "vpc_security_group_ids": ["sg-0abc123"],
            "monitoring": False,
        },
        tags={"Name": "web-server", "Environment": "production"},
    )
