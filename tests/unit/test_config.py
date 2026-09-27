from pathlib import Path

from driftsentry.core.config import DriftSentryConfig, load_config


def test_scan_filters_exclusion_defaults() -> None:
    config = DriftSentryConfig()
    assert config.filters.exclude_tags == {}
    assert config.filters.exclude_patterns == []


def test_scan_filters_exclusion_custom_yaml(tmp_path: Path) -> None:
    yaml_content = """
filters:
  exclude_tags:
    managed-by:
      - "AFT"
      - "ControlTower"
    Environment: "baseline"
  exclude_patterns:
    - "*aft*"
    - "vpc-default"
"""
    config_file = tmp_path / ".driftsentry.yaml"
    config_file.write_text(yaml_content)

    config = load_config(config_file)

    assert config.filters.exclude_tags["managed-by"] == ["AFT", "ControlTower"]
    assert config.filters.exclude_tags["Environment"] == "baseline"
    assert config.filters.exclude_patterns == ["*aft*", "vpc-default"]
