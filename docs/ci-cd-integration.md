# CI/CD & GitHub Actions Integration (`driftsentry check`)

DriftSentry provides a dedicated, non-interactive CI command (`driftsentry check`) designed specifically for CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins, CircleCI). It provides deterministic exit codes, automatic GitHub Step Summary rendering, and customizable failure policies.

---

## Key Capabilities

1. **Deterministic Exit Codes**:
   - `0`: Infrastructure is clean (no drift detected) or drift detected is below the `--fail-on` threshold.
   - `2`: Drift detected matching failure policy criteria (e.g. security-critical drift).
   - `1`: Operational, configuration, or state scanning error.
2. **Native GitHub Actions Step Summaries (`$GITHUB_STEP_SUMMARY`)**:
   - Automatically detects the `$GITHUB_STEP_SUMMARY` environment variable in GitHub Actions.
   - Renders rich GitHub-flavored markdown with status badges, summary count tables, and drifted resource matrices.
   - Embeds collapsible `<details><summary>` blocks for granular attribute diffs and CloudTrail attribution culprits to keep job summaries clean and readable.
3. **PR & Issue Comment Export (`--output-markdown`)**:
   - Exports PR-ready markdown files for posting drift comments directly to Pull Requests via `gh pr comment` or `actions/github-script`.
4. **Zero-Config State Auto-Discovery**:
   - Automatically discovers local or remote S3 Terraform/OpenTofu state in the repository directory hierarchy by default.
5. **Configurable Failure Policies (`--fail-on`)**:
   - Control exactly when a CI job should fail (blocking vs. non-blocking).

---

## Exit Code Specification

| Exit Code | Status | Meaning |
| :---: | :--- | :--- |
| **`0`** | `SUCCESS` | Clean scan (no drift detected) OR detected drift does not breach the `--fail-on` threshold. |
| **`2`** | `DRIFT DETECTED` | Drift was found that matches the `--fail-on` threshold (e.g. any drift on `--fail-on any`, or critical drift on `--fail-on critical`). |
| **`1`** | `ERROR` | Scan failed due to operational issues (state file not found, AWS credentials expired, invalid configuration). |

---

## `--fail-on` Policy Modes

The `--fail-on` option controls when DriftSentry exits with code `2`:

| Mode | Behavior | Use Case |
| :--- | :--- | :--- |
| `any` *(default)* | Exits `2` if **any** drift (changed, deleted, unmanaged) is detected. | Strict enforcement pipelines, pre-deployment gates. |
| `critical` | Exits `2` **only** if one or more `CRITICAL` severity items are found (e.g., security groups open to 0.0.0.0/0, public S3 buckets, IAM privilege escalation). Exits `0` for lower-severity drift. | Security-focused gates that avoid failing builds on minor tag drift. |
| `high` | Exits `2` if any `HIGH` or `CRITICAL` drift items are found. Exits `0` for medium/low/info drift. | Production balance between security/outage prevention and pipeline noise. |
| `none` / `never` | **Always exits `0`** on drift. Only exits `1` on operational scanning errors. | Scheduled audit runs, non-blocking drift reporting, and PR notification bots. |

---

## Native GitHub Actions Step Summary

When executed inside GitHub Actions, DriftSentry automatically inspects `$GITHUB_STEP_SUMMARY`. If present, it writes a formatted executive summary directly to the job summary page:

- **Status Banner**: Visual indicators (`Clean ✅`, `Drift Detected ❌`, `Non-Blocking ⚠️`).
- **Run Overview**: Scan ID, IaC tool, target regions, AWS accounts, and duration.
- **Summary Metrics**: High-level counts for managed resources, changed resources, deleted resources, unmanaged (shadow IT) resources, and critical severity items.
- **Drifted Resource Table**: Address, type, severity emoji, diff counts, and attributed culprits.
- **Collapsible `<details>`**: Expandable blocks containing attribute diff tables and CloudTrail audit log culprits (IAM actor, API event, ClickOps console detection, source IP, user agent).

You can also explicitly pass `--github-step-summary <file>` to output or append the summary to a custom path.

---

## Example 1: Scheduled Nightly Drift Detection Workflow

Create `.github/workflows/drift-detection.yml`:

```yaml
name: "Scheduled Infrastructure Drift Detection"

on:
  schedule:
    # Run every morning at 06:00 UTC
    - cron: "0 6 * * *"
  workflow_dispatch:

permissions:
  id-token: write  # For AWS OIDC authentication
  contents: read
  issues: write    # For creating drift alert issues

jobs:
  drift-check:
    name: "DriftSentry CI Check"
    runs-on: ubuntu-latest

    steps:
      - name: Checkout infrastructure code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: "pip"

      - name: Install DriftSentry
        run: pip install driftsentry

      - name: Configure AWS Credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_DRIFTSENTRY_ROLE_ARN }}
          aws-region: us-east-1

      # Runs zero-config check; automatically writes to $GITHUB_STEP_SUMMARY
      - name: Run Drift Check
        id: drift_check
        run: |
          driftsentry check \
            --fail-on critical \
            --output-markdown drift-summary.md \
            --save scan-result.json

      - name: Upload Drift Artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: driftsentry-scan-result
          path: |
            scan-result.json
            drift-summary.md
```

---

## Example 2: Pull Request Drift Comment Workflow

Post live infrastructure drift diffs directly as PR comments when reviewing infrastructure pull requests:

```yaml
name: "PR Infrastructure Drift Audit"

on:
  pull_request:
    paths:
      - "terraform/**"
      - "*.tf"

permissions:
  id-token: write
  contents: read
  pull-requests: write

jobs:
  pr-drift-audit:
    name: "Audit PR Drift"
    runs-on: ubuntu-latest

    steps:
      - name: Checkout PR branch
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install DriftSentry
        run: pip install driftsentry

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_DRIFTSENTRY_ROLE_ARN }}
          aws-region: us-east-1

      # Use --fail-on none so the job completes and publishes the comment
      - name: Check Drift
        run: |
          driftsentry check \
            --fail-on none \
            --output-markdown pr-drift-comment.md

      - name: Comment Drift Summary on PR
        uses: actions/github-script@v7
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          script: |
            const fs = require('fs');
            const markdown = fs.readFileSync('pr-drift-comment.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: markdown
            });
```

---

## Example 3: GitLab CI Pipeline

In `.gitlab-ci.yml`:

```yaml
stages:
  - drift

driftsentry_check:
  stage: drift
  image: python:3.12-slim
  before_script:
    - pip install driftsentry
  script:
    # Zero-config auto-discovery; exits 2 if critical drift is detected
    - driftsentry check --fail-on critical --output-markdown gitlab-drift-summary.md
  artifacts:
    when: always
    paths:
      - gitlab-drift-summary.md
  rules:
    - if: '$CI_PIPELINE_SOURCE == "schedule"'
```
