# Multi-Account & Multi-Region Scanning

Guide for configuring, authenticating, and running DriftSentry across enterprise AWS Organizations, multi-account landing zones, and multiple AWS regions.

---

## Overview

Modern cloud architectures span multiple AWS accounts (e.g., Core, Security, Production, Staging, Shared Services) and geographic regions. Detecting infrastructure drift across these environments traditionally required executing separate scan scripts for every account and region.

DriftSentry provides a native, high-performance **Multi-Account and Multi-Region scanning engine** that:
- **Parallelizes Scans**: Concurrently inspects all account/region targets using a configurable worker pool (`ThreadPoolExecutor`).
- **Eliminates Redundant Calls**: Automatically deduplicates global services (IAM, Route 53, CloudFront) to query only once per account, preventing AWS API throttling.
- **Routes CloudTrail Attribution**: Dynamically queries the exact target account session and region where a resource was modified to identify ClickOps actors.
- **Unified Multi-Tenant Reporting**: Displays account IDs/names and regions in CLI tables, PR Markdown summaries, and dark-mode HTML dashboards.

```
                                  ┌───────────────────────────┐
                                  │      TargetResolver       │
                                  │ (Accounts, Roles, Regions)│
                                  └─────────────┬─────────────┘
                                                │
                 ┌──────────────────────────────┼──────────────────────────────┐
                 ▼                              ▼                              ▼
     ┌───────────────────────┐      ┌───────────────────────┐      ┌───────────────────────┐
     │ Target: Prod / us-east-1│     │Target: Prod / us-west-2│     │Target: Dev / us-east-1 │
     │  (Assumed Role + Sess)│      │  (Assumed Role + Sess)│      │  (Named Profile Sess) │
     └───────────┬───────────┘      └───────────┬───────────┘      └───────────┬───────────┘
                 │                              │                              │
                 └──────────────────────────────┼──────────────────────────────┘
                                                ▼
                                  ┌───────────────────────────┐
                                  │  Parallel AWSProvider     │
                                  │  (Global Service Dedup)   │
                                  └─────────────┬─────────────┘
                                                │ Enriched CloudResources
                                                ▼
                                  ┌───────────────────────────┐
                                  │    Unified Drift Engine   │
                                  └───────────────────────────┘
```

---

## AWS Multi-Account Authentication Patterns

DriftSentry supports four authentication patterns to suit different organizational structures.

### Pattern 1: Central Role Delegation (Hub-and-Spoke)

The recommended pattern for enterprise AWS Organizations and AWS Control Tower. A central scanning runner (Hub / Security Account) assumes an IAM role in each member account (Spoke).

```yaml
# .driftsentry.yaml
provider:
  name: "aws"
  region: "us-east-1"

accounts:
  - id: "111122223333"
    name: "production"
    role_arn: "arn:aws:iam::111122223333:role/DriftSentryScanRole"
    regions: ["us-east-1", "us-west-2"]
  - id: "444455556666"
    name: "staging"
    role_arn: "arn:aws:iam::444455556666:role/DriftSentryScanRole"
    regions: ["us-east-1"]
  - id: "777788889999"
    name: "security"
    role_arn: "arn:aws:iam::777788889999:role/DriftSentryScanRole"
```

### Pattern 2: Dynamic Role ARN Templating

For organizations with dozens or hundreds of accounts using standardized IAM role names, use `role_arn_template` instead of writing individual `role_arn` strings for each account:

```yaml
# .driftsentry.yaml
role_arn_template: "arn:aws:iam::{account_id}:role/DriftSentryScanRole"

accounts:
  - id: "111122223333"
    name: "core-networking"
  - id: "222233334444"
    name: "data-platform"
  - id: "333344445555"
    name: "analytics"
  - id: "444455556666"
    name: "identity-prod"
```

### Pattern 3: Named AWS CLI Profiles

For local developer workstations or multi-account setups configured in `~/.aws/config`:

```yaml
# .driftsentry.yaml
accounts:
  - name: "prod"
    profile: "aws-prod-profile"
    regions: ["us-east-1", "us-west-2"]
  - name: "staging"
    profile: "aws-staging-profile"
    regions: ["us-east-1"]
  - name: "dev"
    profile: "aws-dev-profile"
```

### Pattern 4: External ID (Multi-Tenant & Third-Party)

If your cross-account IAM roles require an `ExternalId` condition to prevent the confused deputy problem:

```yaml
# .driftsentry.yaml
accounts:
  - id: "111122223333"
    name: "client-prod"
    role_arn: "arn:aws:iam::111122223333:role/DriftSentryAuditor"
    external_id: "UniqueSecuritySecret-12345"
```

---

## Multi-Region Scanning Configurations

### 1. Static Region List

Specify multiple regions globally under `provider.regions`:

```yaml
provider:
  name: "aws"
  regions:
    - "us-east-1"
    - "us-west-2"
    - "eu-west-1"
    - "ap-southeast-1"
```

### 2. Dynamic Region Discovery (`--regions all`)

To automatically scan all active, enabled regions in your AWS account without hardcoding:

```bash
driftsentry scan --state-file terraform.tfstate --regions all
```

Or in `.driftsentry.yaml`:

```yaml
provider:
  name: "aws"
  regions:
    - "all"
```

DriftSentry queries `ec2:DescribeRegions` to discover all accessible regions in the account.

### 3. Per-Account Region Overrides

Different accounts frequently operate in different subsets of regions. You can configure global default regions and override them on specific accounts:

```yaml
provider:
  name: "aws"
  region: "us-east-1"
  regions:
    - "us-east-1"
    - "us-west-2"

accounts:
  # Uses default regions (us-east-1, us-west-2)
  - id: "111122223333"
    name: "staging"

  # Scans global primary + European disaster recovery region
  - id: "444455556666"
    name: "production"
    regions: ["us-east-1", "us-west-2", "eu-west-1"]

  # Global/IAM-only account
  - id: "777788889999"
    name: "shared-identity"
    regions: ["us-east-1"]
```

---

## Performance Tuning & Concurrency

DriftSentry scans all `(Account, Region)` combinations concurrently using a Python `ThreadPoolExecutor`.

You can adjust the worker concurrency to balance speed and AWS API rate limits:

```yaml
# .driftsentry.yaml
concurrency: 8  # Default is 4
```

Or via CLI flag:

```bash
driftsentry scan --state-file terraform.tfstate --regions all --concurrency 8
```

### Global Service Deduplication
When scanning across multiple regions within the same account, resources that exist globally in AWS (such as `aws_iam_role`, `aws_iam_policy`, `aws_iam_user`, `aws_route53_zone`, and `aws_cloudfront_distribution`) are automatically scanned **only once per account**. This eliminates duplicate API calls, speeds up scans, and prevents AWS rate limiting.

---

## CLI Usage Examples

### Ad-Hoc Multi-Region Scan
```bash
driftsentry scan \
  --state-file ./terraform.tfstate \
  --regions us-east-1,us-west-2,eu-west-1 \
  --verbose
```

### Ad-Hoc Multi-Account Scan with Dynamic Template
```bash
driftsentry scan \
  --state-file ./terraform.tfstate \
  --accounts 111122223333,444455556666,777788889999 \
  --role-arn-template "arn:aws:iam::{account_id}:role/DriftSentryScanRole" \
  --regions us-east-1,us-west-2 \
  --concurrency 6
```

### Combined with Remote S3 State
```bash
driftsentry scan \
  --state-backend s3 \
  --s3-bucket corp-terraform-states \
  --s3-key prod/terraform.tfstate \
  --accounts 111122223333,444455556666 \
  --role-arn-template "arn:aws:iam::{account_id}:role/DriftSentryScanRole" \
  --regions us-east-1,us-west-2 \
  --save multi-scan.json
```

---

## IAM Setup for Multi-Account Scanning

### 1. Hub / Runner Account Policy

Attach this policy to the IAM identity (or GitHub Actions OIDC role) running DriftSentry in your central account:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAssumeSpokeRoles",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/DriftSentryScanRole"
    },
    {
      "Sid": "AllowDescribeRegions",
      "Effect": "Allow",
      "Action": "ec2:DescribeRegions",
      "Resource": "*"
    }
  ]
}
```

### 2. Spoke / Member Account Role & Trust Policy

In each target AWS account, create the IAM role `DriftSentryScanRole`:

**Trust Relationship (Trust Policy):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::CENTRAL_HUB_ACCOUNT_ID:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

**Permission Policy (Read-Only Scan + CloudTrail):**
Attach the AWS managed `SecurityAudit` or `ReadOnlyAccess` policy, plus CloudTrail permissions:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudTrailLookup",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents",
        "cloudtrail:DescribeTrails"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## CI/CD Example (GitHub Actions with AWS OIDC)

Automate scheduled scans across all production accounts in GitHub Actions:

```yaml
name: "Scheduled Multi-Account Drift Scan"

on:
  schedule:
    - cron: "0 4 * * *" # Daily at 04:00 UTC
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  multi-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: "pip"

      - run: pip install "driftsentry[ai]"

      # Authenticate to Hub / Security Account via OIDC
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::100000000000:role/DriftSentryCentralRunner
          aws-region: us-east-1

      # Run scan across member accounts
      - name: Scan Multi-Account Infrastructure
        run: |
          driftsentry scan \
            --state-backend s3 \
            --s3-bucket corp-terraform-states \
            --s3-key core-infra/terraform.tfstate \
            --accounts 111122223333,444455556666,777788889999 \
            --role-arn-template "arn:aws:iam::{account_id}:role/DriftSentryScanRole" \
            --regions us-east-1,us-west-2 \
            --concurrency 6 \
            --save scan-result.json

      - name: Generate Reports
        if: always()
        run: |
          driftsentry report --input scan-result.json --format html --output report.html
          driftsentry report --input scan-result.json --format markdown --output report.md

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: drift-reports
          path: |
            report.html
            report.md
```

---

## Multi-Target Report Visibility

When multiple accounts or regions are scanned, DriftSentry automatically enhances output formats:

### Terminal (Rich Table)
```
╭────────────────── Terraform Drift Scan — DriftSentry ───────────────────╮
│ 📊 Scanned: 42 resources  │  ⏱ Duration: 3.42s  │  🌍 Provider: aws     │
│ 🏢 Accounts (3): production, staging, security                          │
│ 📍 Regions (2): us-east-1, us-west-2                                    │
│                                                                         │
│ 🔴 CRITICAL: 1  │  📝 Changed: 3  │  🗑️ Deleted: 0  │  👻 Unmanaged: 2  │
╰─────────────────────────────────────────────────────────────────────────╯

Drifted Resources:
┌────────────┬───────────┬──────────────────────────┬────────────┬──────────┬─────────┬──────────────┐
│ Account    │ Region    │ Resource                 │ Drift Type │ Severity │ Changes │ Changed By   │
├────────────┼───────────┼──────────────────────────┼────────────┼──────────┼─────────┼──────────────┤
│ production │ us-east-1 │ aws_security_group.web   │ CHANGED    │ 🔴 CRIT  │ 2       │ alice (cons) │
│ staging    │ us-west-2 │ aws_instance.dev_worker  │ UNMANAGED  │ 🟡 MED   │ -       │ bob (cli)    │
└────────────┴───────────┴──────────────────────────┴────────────┴──────────┴─────────┴──────────────┘
```

### HTML & Markdown Reports
- **Header Metadata**: Summarizes total scanned accounts and regions.
- **Account & Region Columns**: Group and contextualize every detected drift item.
