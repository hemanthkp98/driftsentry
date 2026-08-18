"""PR creator — creates GitHub/GitLab pull requests with remediation code."""

from __future__ import annotations

import logging
from pathlib import Path

from driftsentry.core.models import DriftResult
from driftsentry.output.markdown import MarkdownFormatter
from driftsentry.remediation.generator import RemediationOutput

logger = logging.getLogger(__name__)


class PRCreator:
    """Creates GitHub pull requests with remediation code and drift summary.

    Requires a GitHub personal access token with repo permissions.
    """

    def __init__(
        self,
        github_token: str,
        repo: str,
        base_branch: str = "main",
    ) -> None:
        """Initialize the PR creator.

        Args:
            github_token: GitHub personal access token.
            repo: Repository in 'owner/name' format.
            base_branch: Base branch for the PR.
        """
        self._token = github_token
        self._repo = repo
        self._base_branch = base_branch

    def create_pr(
        self,
        result: DriftResult,
        remediation: RemediationOutput,
        branch_name: str | None = None,
    ) -> str:
        """Create a GitHub PR with remediation artifacts.

        Args:
            result: The drift scan result.
            remediation: The remediation output with files to include.
            branch_name: Git branch name. Auto-generated if None.

        Returns:
            URL of the created pull request.
        """
        from github import Github, InputGitTreeElement

        branch_name = branch_name or f"driftsentry/remediate-{result.scan_id}"

        g = Github(self._token)
        repo = g.get_repo(self._repo)

        # Get the base branch SHA
        base_ref = repo.get_branch(self._base_branch)
        base_sha = base_ref.commit.sha

        # Build the tree with remediation files
        tree_elements: list[InputGitTreeElement] = []

        for file_path in remediation.files_created:
            rel_path = Path(file_path).name
            content = Path(file_path).read_text()
            tree_elements.append(
                InputGitTreeElement(
                    path=f"driftsentry-remediation/{rel_path}",
                    mode="100644",
                    type="blob",
                    content=content,
                )
            )

        if not tree_elements:
            raise ValueError("No remediation files to include in PR")

        # Create the tree and commit
        tree = repo.create_git_tree(tree_elements, base_tree=repo.get_git_tree(base_sha))

        commit_message = (
            f"fix: Remediate {result.total_drifted} drifted resources "
            f"detected by DriftSentry\n\n"
            f"Scan ID: {result.scan_id}\n"
            f"Changed: {result.changed_count} | "
            f"Deleted: {result.deleted_count} | "
            f"Unmanaged: {result.unmanaged_count}"
        )

        commit = repo.create_git_commit(
            message=commit_message,
            tree=tree,
            parents=[repo.get_git_commit(base_sha)],
        )

        # Create the branch
        repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=commit.sha)

        # Generate PR body
        formatter = MarkdownFormatter()
        pr_body = formatter.render(result)

        # Truncate if too long for GitHub (max 65536 chars)
        if len(pr_body) > 60000:
            pr_body = (
                pr_body[:60000]
                + "\n\n---\n*Report truncated. See full details in the remediation files.*"
            )

        # Create the PR
        pr = repo.create_pull(
            title=f"fix: Remediate {result.total_drifted} drifted resources — DriftSentry",
            body=pr_body,
            head=branch_name,
            base=self._base_branch,
        )

        logger.info(f"Created PR #{pr.number}: {pr.html_url}")
        return pr.html_url
