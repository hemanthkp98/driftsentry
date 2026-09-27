"""Unit tests for Terraform state auto-discovery engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from driftsentry.core.config import DriftSentryConfig
from driftsentry.core.models import StateBackendType
from driftsentry.state.auto_discovery import (
    DEFAULT_REGION,
    DiscoveredState,
    StateDiscoveryError,
    apply_auto_discovered_state,
    discover_terraform_state,
    find_git_root,
    format_discovery_error,
    get_search_directories,
    resolve_aws_region,
)

# ─── AWS Region Resolution Tests ──────────────────────────────────────────


def test_resolve_aws_region_from_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-1")

    # Backend region takes precedence
    assert resolve_aws_region("eu-central-1") == "eu-central-1"
    assert resolve_aws_region("  ap-south-1  ") == "ap-south-1"


def test_resolve_aws_region_from_aws_region_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_REGION", "eu-west-2")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-2")

    assert resolve_aws_region(None) == "eu-west-2"
    assert resolve_aws_region("") == "eu-west-2"
    assert resolve_aws_region("   ") == "eu-west-2"


def test_resolve_aws_region_from_aws_default_region_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "sa-east-1")

    assert resolve_aws_region(None) == "sa-east-1"
    assert resolve_aws_region("") == "sa-east-1"


def test_resolve_aws_region_default_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)

    assert resolve_aws_region(None) == DEFAULT_REGION
    assert resolve_aws_region("") == DEFAULT_REGION


# ─── Git Root and Directory Traversal Tests ─────────────────────────────────


def test_find_git_root_and_search_directories(tmp_path: Path) -> None:
    # Set up repo structure: repo/.git, repo/envs/prod
    repo_root = tmp_path / "my-repo"
    git_dir = repo_root / ".git"
    git_dir.mkdir(parents=True)

    sub_dir = repo_root / "envs" / "prod"
    sub_dir.mkdir(parents=True)

    assert find_git_root(sub_dir) == repo_root
    assert find_git_root(repo_root) == repo_root

    search_dirs = get_search_directories(sub_dir)
    assert search_dirs == [sub_dir, repo_root / "envs", repo_root]

    # Non-git directory
    non_git = tmp_path / "standalone"
    non_git.mkdir()
    assert find_git_root(non_git) is None
    assert get_search_directories(non_git) == [non_git]


def test_find_git_root_with_gitfile(tmp_path: Path) -> None:
    # Git worktree / submodule with .git as file
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    git_file = worktree / ".git"
    git_file.write_text("gitdir: /path/to/main/.git/worktrees/worktree")

    assert find_git_root(worktree) == worktree


# ─── Local State Auto-Discovery Tests ──────────────────────────────────────


def test_discover_local_state_direct(tmp_path: Path) -> None:
    tfstate = tmp_path / "terraform.tfstate"
    tfstate.write_text(json.dumps({"version": 4, "resources": []}))

    discovered = discover_terraform_state(tmp_path)
    assert discovered.backend == StateBackendType.LOCAL
    assert discovered.path == tfstate
    assert discovered.workspace_dir == tmp_path
    assert "local" in discovered.summary


def test_discover_local_named_tfstate(tmp_path: Path) -> None:
    # When terraform.tfstate is not present, pick other *.tfstate
    prod_state = tmp_path / "prod.tfstate"
    prod_state.write_text(json.dumps({"version": 4, "resources": []}))

    discovered = discover_terraform_state(tmp_path)
    assert discovered.backend == StateBackendType.LOCAL
    assert discovered.path == prod_state


def test_discover_local_state_parent_traversal(tmp_path: Path) -> None:
    repo = tmp_path / "project"
    (repo / ".git").mkdir(parents=True)
    tfstate = repo / "terraform.tfstate"
    tfstate.write_text(json.dumps({"version": 4, "resources": []}))

    deep_dir = repo / "modules" / "vpc"
    deep_dir.mkdir(parents=True)

    discovered = discover_terraform_state(deep_dir)
    assert discovered.backend == StateBackendType.LOCAL
    assert discovered.path == tfstate
    assert discovered.workspace_dir == repo


def test_discover_ignores_backup_files(tmp_path: Path) -> None:
    # Backup file should not be picked up if no valid state exists
    backup_file = tmp_path / "terraform.tfstate.backup"
    backup_file.write_text(json.dumps({"version": 4, "resources": []}))

    with pytest.raises(StateDiscoveryError) as exc_info:
        discover_terraform_state(tmp_path)

    assert any("terraform.tfstate" in str(p) for p in exc_info.value.checked_paths)


# ─── Remote Backend Auto-Discovery Tests (.terraform) ──────────────────────


def test_discover_s3_backend_full_config(tmp_path: Path) -> None:
    tf_dir = tmp_path / ".terraform"
    tf_dir.mkdir()
    meta = tf_dir / "terraform.tfstate"
    meta.write_text(
        json.dumps(
            {
                "version": 3,
                "backend": {
                    "type": "s3",
                    "config": {
                        "bucket": "corp-tf-states-prod",
                        "key": "networking/vpc.tfstate",
                        "region": "eu-central-1",
                        "encrypt": True,
                    },
                },
            }
        )
    )

    discovered = discover_terraform_state(tmp_path)
    assert discovered.backend == StateBackendType.S3
    assert discovered.s3_bucket == "corp-tf-states-prod"
    assert discovered.s3_key == "networking/vpc.tfstate"
    assert discovered.s3_region == "eu-central-1"
    assert discovered.region == "eu-central-1"
    assert "s3://corp-tf-states-prod/networking/vpc.tfstate" in discovered.summary


def test_discover_s3_backend_region_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_REGION", "ap-southeast-1")

    tf_dir = tmp_path / ".terraform"
    tf_dir.mkdir()
    meta = tf_dir / "terraform.tfstate"
    # Backend config without region
    meta.write_text(
        json.dumps(
            {
                "version": 3,
                "backend": {
                    "type": "s3",
                    "config": {
                        "bucket": "corp-states",
                        "key": "app/terraform.tfstate",
                    },
                },
            }
        )
    )

    discovered = discover_terraform_state(tmp_path)
    assert discovered.backend == StateBackendType.S3
    assert discovered.s3_bucket == "corp-states"
    assert discovered.s3_key == "app/terraform.tfstate"
    assert discovered.region == "ap-southeast-1"


def test_discover_s3_backend_precedence_over_local(tmp_path: Path) -> None:
    # If S3 backend is configured in .terraform, it should be chosen even if stale terraform.tfstate exists
    tf_dir = tmp_path / ".terraform"
    tf_dir.mkdir()
    (tf_dir / "terraform.tfstate").write_text(
        json.dumps(
            {
                "backend": {
                    "type": "s3",
                    "config": {"bucket": "b", "key": "k", "region": "us-east-1"},
                }
            }
        )
    )
    (tmp_path / "terraform.tfstate").write_text(json.dumps({"version": 4}))

    discovered = discover_terraform_state(tmp_path)
    assert discovered.backend == StateBackendType.S3
    assert discovered.s3_bucket == "b"


def test_discover_handles_malformed_terraform_meta(tmp_path: Path) -> None:
    tf_dir = tmp_path / ".terraform"
    tf_dir.mkdir()
    (tf_dir / "terraform.tfstate").write_text("invalid json content")

    # Also have local state in same directory
    local_state = tmp_path / "terraform.tfstate"
    local_state.write_text(json.dumps({"version": 4}))

    discovered = discover_terraform_state(tmp_path)
    assert discovered.backend == StateBackendType.LOCAL
    assert discovered.path == local_state


def test_discover_local_backend_with_custom_path(tmp_path: Path) -> None:
    custom_state = tmp_path / "custom" / "state.tfstate"
    custom_state.parent.mkdir()
    custom_state.write_text(json.dumps({"version": 4}))

    tf_dir = tmp_path / ".terraform"
    tf_dir.mkdir()
    (tf_dir / "terraform.tfstate").write_text(
        json.dumps(
            {
                "backend": {
                    "type": "local",
                    "config": {"path": "custom/state.tfstate"},
                }
            }
        )
    )

    discovered = discover_terraform_state(tmp_path)
    assert discovered.backend == StateBackendType.LOCAL
    assert discovered.path == custom_state.resolve()


# ─── Failure and Error Formatting Tests ────────────────────────────────────


def test_discover_raises_when_no_state_found(tmp_path: Path) -> None:
    repo = tmp_path / "empty-repo"
    (repo / ".git").mkdir(parents=True)
    nested = repo / "deep" / "dir"
    nested.mkdir(parents=True)

    with pytest.raises(StateDiscoveryError) as exc_info:
        discover_terraform_state(nested)

    err = exc_info.value
    assert len(err.checked_paths) >= 2
    msg = format_discovery_error(err)
    assert "No Terraform state file or remote backend configuration discovered" in msg
    assert "Checked paths" in msg
    assert "--state-file" in msg


# ─── Config Mutation Tests ─────────────────────────────────────────────────


def test_apply_auto_discovered_state_local() -> None:
    config = DriftSentryConfig()
    discovered = DiscoveredState(
        backend=StateBackendType.LOCAL,
        path=Path("/tmp/test/terraform.tfstate"),
        region="us-west-2",
    )

    apply_auto_discovered_state(config, discovered)
    assert config.state.backend == StateBackendType.LOCAL
    assert config.state.path == "/tmp/test/terraform.tfstate"
    assert config.provider.region == "us-west-2"


def test_apply_auto_discovered_state_s3() -> None:
    config = DriftSentryConfig()
    discovered = DiscoveredState(
        backend=StateBackendType.S3,
        s3_bucket="my-bucket",
        s3_key="my-key",
        s3_region="eu-west-1",
        region="eu-west-1",
    )

    apply_auto_discovered_state(config, discovered)
    assert config.state.backend == StateBackendType.S3
    assert config.state.s3_bucket == "my-bucket"
    assert config.state.s3_key == "my-key"
    assert config.state.s3_region == "eu-west-1"
    assert config.provider.region == "eu-west-1"


def test_apply_auto_discovered_state_preserves_explicit_provider_region() -> None:
    config = DriftSentryConfig()
    config.provider.region = "ap-south-1"  # explicitly set
    discovered = DiscoveredState(
        backend=StateBackendType.LOCAL,
        path=Path("/tmp/terraform.tfstate"),
        region="us-east-1",
    )

    apply_auto_discovered_state(config, discovered)
    assert config.provider.region == "ap-south-1"
