"""Unit tests for state reader implementations."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from driftsentry.core.config import DriftSentryConfig
from driftsentry.core.models import StateBackendType
from driftsentry.state.base import StateParseError
from driftsentry.state.factory import create_state_reader
from driftsentry.state.local import LocalStateReader


def test_local_state_reader_parses_sample_state(sample_state_file: Path) -> None:
    reader = LocalStateReader(sample_state_file)
    resources = reader.read_state()

    # 4 managed resources in sample_state.tfstate: aws_instance.web, aws_security_group.web, aws_s3_bucket.logs, aws_iam_role.app
    # Note: aws_caller_identity.current is mode="data" so it's skipped
    assert len(resources) == 4

    types = [r.resource_type for r in resources]
    assert "aws_instance" in types
    assert "aws_security_group" in types
    assert "aws_s3_bucket" in types
    assert "aws_iam_role" in types


def test_local_state_reader_extracts_attributes(local_state_reader: LocalStateReader) -> None:
    resources = local_state_reader.read_state()
    instance = next(r for r in resources if r.resource_type == "aws_instance")

    assert instance.address == "aws_instance.web"
    assert instance.resource_id == "i-0abc123def456789"
    assert instance.attributes.get("instance_type") == "t3.micro"
    assert instance.attributes.get("ami") == "ami-0abcdef1234567890"


def test_local_state_reader_file_not_found(tmp_path: Path) -> None:
    non_existent = tmp_path / "non_existent.tfstate"
    reader = LocalStateReader(non_existent)
    with pytest.raises(FileNotFoundError):
        reader.read_state()


def test_local_state_reader_invalid_json(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.tfstate"
    bad_file.write_text("{ this is not json }")
    reader = LocalStateReader(bad_file)
    with pytest.raises(StateParseError):
        reader.read_state()


def test_local_state_reader_unsupported_version(tmp_path: Path) -> None:
    old_version_file = tmp_path / "old.tfstate"
    old_version_file.write_text(json.dumps({"version": 3, "resources": []}))
    reader = LocalStateReader(old_version_file)
    with pytest.raises(StateParseError) as exc_info:
        reader.read_state()
    assert "Unsupported state format version 3" in str(exc_info.value)


def test_state_reader_factory_local(sample_state_file: Path) -> None:
    config = DriftSentryConfig()
    config.state.backend = StateBackendType.LOCAL
    config.state.path = str(sample_state_file)

    reader = create_state_reader(config)
    assert isinstance(reader, LocalStateReader)
    assert reader.read_state()


def test_state_reader_factory_missing_path() -> None:
    config = DriftSentryConfig()
    config.state.backend = StateBackendType.LOCAL
    config.state.path = None

    with pytest.raises(ValueError) as exc_info:
        create_state_reader(config)
    assert "no state file path was provided" in str(exc_info.value)
