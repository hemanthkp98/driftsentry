"""Remediation engine — generates import commands, HCL code, and PRs."""

from driftsentry.remediation.generator import RemediationGenerator, RemediationOutput
from driftsentry.remediation.hcl_patcher import HCLPatcher, HCLPatchResult
from driftsentry.remediation.pr_creator import PRCreator

__all__ = [
    "HCLPatchResult",
    "HCLPatcher",
    "PRCreator",
    "RemediationGenerator",
    "RemediationOutput",
]
