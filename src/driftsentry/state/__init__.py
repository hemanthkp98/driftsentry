"""State reading — parse Terraform/OpenTofu state from various backends."""

from driftsentry.state.base import StateReader
from driftsentry.state.factory import create_state_reader
from driftsentry.state.local import LocalStateReader
from driftsentry.state.s3 import S3StateReader

__all__ = [
    "LocalStateReader",
    "S3StateReader",
    "StateReader",
    "create_state_reader",
]
