# Deployment & CI/CD Integration

Automate scheduled infrastructure drift scans, generate report artifacts, and enable automatic remediation Pull Requests in CI/CD pipelines.

---

## Overview

DriftSentry is designed for headless automation in CI/CD environments (GitHub Actions, GitLab CI) to continuously detect configuration drift, attribute live changes to specific IAM actors via CloudTrail, and automatically open Pull Requests with corrective HCL code.

---

## GitHub Actions Workflow

Create `.github/workflows/driftsentry.yml` in your infrastructure repository:

```yaml
name: "DriftSentry IaC Drift Detection"

on:
  schedule:
    # Run every morning at 06:00 UTC
    - cron: "0 6 * * *"
  workflow_dispatch: # Allow manual trigger

permissions:
  id-token: write # Required for AWS OIDC authentication
  contents: write # Required for committing remediation branch
  pull-requests: write # Required for opening auto-remediation PRs

jobs:
  drift-detection:
    name: "Scan Infrastructure Drift"
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: "pip"

      - name: Install DriftSentry with AI support
        run: |
          pip install "driftsentry[ai]"

      - name: Configure AWS Credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_DRIFTSENTRY_ROLE_ARN }}
          aws-region: us-east-1

      - name: Run Drift Scan
        run: |
          driftsentry scan \
            --state-backend s3 \
            --s3-bucket ${{ secrets.TF_STATE_BUCKET }} \
            --s3-key production/terraform.tfstate \
            --region us-east-1 \
            --save scan-result.json

      - name: Generate HTML Drift Report
        if: always()
        run: |
          driftsentry report \
            --input scan-result.json \
            --format html \
            --output drift-report.html

      - name: Upload Drift Report Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: drift-report
          path: drift-report.html

      - name: Auto-Remediate with AI and Create PR
        if: failure() || success()
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          driftsentry remediate \
            --input scan-result.json \
            --ai \
            --create-pr \
            --repo "${{ github.repository }}" \
            --base-branch "main"
```

---

## GitLab CI Pipeline

Create a `.gitlab-ci.yml` entry:

```yaml
stages:
  - drift-check

drift_scan:
  stage: drift-check
  image: python:3.12-slim
  rules:
    - if: '$CI_PIPELINE_SOURCE == "schedule"'
    - if: '$CI_PIPELINE_SOURCE == "web"'
  before_script:
    - pip install "driftsentry[ai]"
  script:
    - driftsentry scan --state-file terraform.tfstate --save scan-result.json
    - driftsentry report --input scan-result.json --format html --output public/drift-report.html
  artifacts:
    paths:
      - public/drift-report.html
      - scan-result.json
    expire_in: 30 days
```

---

## Multi-Account & Multi-Region CI/CD

To automate drift detection across multiple member accounts in an AWS Organization using a central GitHub Actions runner or AWS OIDC authentication, see the dedicated [Multi-Account & Multi-Region Guide](multi-account-multi-region.md#cicd-example-github-actions-with-aws-oidc).
