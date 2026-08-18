# 🛡️ DriftSentry

<p align="center">
  <strong>Your infrastructure's immune system.</strong><br>
  Detect IaC drift, attribute blame with audit logs, and auto-remediate with Pull Requests.<br>
  Built for <strong>Terraform</strong> and <strong>OpenTofu</strong>.
</p>

<p align="center">
  <a href="https://github.com/hemanthkp98/driftsentry/actions/workflows/ci.yml"><img src="https://github.com/hemanthkp98/driftsentry/actions/workflows/ci.yml/badge.svg" alt="CI Status"></a>
  <a href="https://pypi.org/project/driftsentry/"><img src="https://img.shields.io/pypi/v/driftsentry.svg" alt="PyPI version"></a>
  <a href="https://pypi.org/project/driftsentry/"><img src="https://img.shields.io/pypi/pyversions/driftsentry.svg" alt="Python Versions"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/hemanthkp98/driftsentry/stargazers"><img src="https://img.shields.io/github/stars/hemanthkp98/driftsentry" alt="GitHub Stars"></a>
</p>

---

## 💡 Why DriftSentry?

Infrastructure drift happens when real-world cloud resources diverge from your Infrastructure as Code (IaC) definitions. When **driftctl** was archived in 2023, the open-source community was left without a complete drift management solution:

- ❌ `terraform plan -refresh-only` only sees resources **already in state** — it cannot find **unmanaged** shadow IT resources.
- ❌ No open-source tool answers **who** caused the drift (ClickOps vs automated tools).
- ❌ Reconciling drift requires manual, error-prone `terraform import` commands or manual code writing.

**DriftSentry is the modern open-source solution that bridges this gap.**

```
                         ┌─────────────────────────┐
                         │   Terraform / OpenTofu  │
                         │    State (Local / S3)   │
                         └────────────┬────────────┘
                                      │
                                      ▼
┌──────────────────┐           ┌──────────────┐           ┌──────────────────┐
│   Live Cloud     │ ────────► │ DriftSentry  │ ◄──────── │ AWS CloudTrail   │
│   Environment    │           │  Diff Engine │           │  (Attribution)   │
│   (AWS APIs)     │           └──────┬───────┘           └──────────────────┘
└──────────────────┘                  │
                                      ▼
           ┌──────────────────────────┼──────────────────────────┐
           ▼                          ▼                          ▼
 ┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐
 │   Rich Terminal   │      │   Interactive     │      │  Auto-Remediation │
 │   & JSON Output   │      │   HTML Reports    │      │  PRs & Import HCL │
 └───────────────────┘      └───────────────────┘      └───────────────────┘
```

---

## ✨ Features

- 🔍 **Full Drift Detection**: Detects modified (`CHANGED`), deleted (`DELETED`), and shadow IT (`UNMANAGED`) resources.
- 🕵️ **Drift Attribution**: Correlates drifted resources with AWS CloudTrail events to identify **who** made the change, when, and whether it was via Console (ClickOps) or CLI.
- 🔧 **Dual-Mode Auto-Remediation**:
  - **Import Mode**: Automatically generates `terraform import` / `tofu import` scripts and skeleton HCL resource blocks for unmanaged resources.
  - **Revert Mode**: Generates actionable plans to revert out-of-band changes back to your repository's code.
  - **Both Mode**: Combine both approaches with full granular control.
- 🤖 **Auto-PR Creation**: Directly open pull requests on GitHub containing generated remediation code and a rich markdown drift report.
- 🥋 **OpenTofu & Terraform**: Native, first-class support for both OpenTofu and Terraform state files.
- 📊 **Multi-Format Reporting**: Beautiful Rich CLI tables, structured JSON (for pipelines), self-contained dark-theme HTML reports, and PR-ready Markdown.
- 📜 **Policy as Code**: Configurable policy rules to ignore benign drift (e.g., tag updates) or escalate security-critical changes (e.g., public S3 buckets, open security group rules).
- 🔒 **Read-Only Cloud Access**: Requires only read-only IAM permissions for scanning.

---

## 🚀 Quick Start

### 1. Installation

```bash
# Via pip
pip install driftsentry

# Or install from source
git clone https://github.com/hemanthkp98/driftsentry.git
cd driftsentry
pip install -e .
```

### 2. Configure AWS Credentials

Ensure your AWS credentials are configured (standard environment variables or AWS profile):

```bash
export AWS_REGION="us-east-1"
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
```

### 3. Run Your First Scan

```bash
# Scan using a local Terraform state file
driftsentry scan --state-file ./terraform.tfstate

# Or scan an OpenTofu state file
driftsentry scan --state-file ./terraform.tfstate --iac-tool opentofu

# Scan using an S3 remote state backend
driftsentry scan --state-backend s3 --s3-bucket my-tf-state --s3-key prod/terraform.tfstate
```

---

## 🖥️ CLI Usage Reference

### `driftsentry scan`

Scans live cloud infrastructure against an IaC state file.

```bash
driftsentry scan [OPTIONS]
```

| Option | Flag | Description | Default |
|--------|------|-------------|---------|
| `--state-file` | `-s` | Path to local `.tfstate` file | None |
| `--state-backend` | | State backend type (`local` or `s3`) | `local` |
| `--s3-bucket` | | S3 bucket for remote state | None |
| `--s3-key` | | S3 object key (path) for remote state | None |
| `--provider` | `-p` | Cloud provider (`aws`) | `aws` |
| `--region` | `-r` | AWS region to scan | `us-east-1` |
| `--profile` | | AWS CLI profile name | Default profile |
| `--iac-tool` | | IaC engine (`terraform` or `opentofu`) | `terraform` |
| `--output` | `-o` | Output format (`table`, `json`) | `table` |
| `--include-types` | | Comma-separated resource types to include | All supported |
| `--exclude-types` | | Comma-separated resource types to exclude | None |
| `--config` | `-c` | Path to `.driftsentry.yaml` config | Auto-discovered |
| `--no-attribution`| | Skip CloudTrail attribution for faster scans| `false` |
| `--no-policy` | | Skip policy evaluation | `false` |
| `--verbose` | `-v` | Show detailed attribute-level diff table | `false` |
| `--save` | | Save scan result to a JSON file | None |

#### Example Output

```text
╭──────────────────────── Terraform Drift Scan — DriftSentry ────────────────────────╮
│                                                                                     │
│  📊 Scanned: 47 resources  │  ⏱  Duration: 8.4s  │  🌍 Provider: aws  │  📍 Region: us-east-1 │
│                                                                                     │
│  🔴 CRITICAL: 1  │  📝 Changed: 2  │  🗑️ Deleted: 1  │  👻 Unmanaged: 1  │  ✅ OK: 44     │
│                                                                                     │
╰──────────────────────────────────────── scan_id: a8f9c2d1 ──────────────────────────╯

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ Resource                       ┃ Drift Type ┃ Severity  ┃ Changes ┃ Changed By         ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ aws_security_group.web         │  CHANGED   │ 🔴 CRIT   │    1    │ john.doe (console) ┃
│ aws_instance.api_server        │  CHANGED   │ 🟡 MEDIUM │    1    │ ci-deployer-role   ┃
│ aws_s3_bucket.old_logs         │  DELETED   │ 🟠 HIGH   │    -    │ admin@company.com  ┃
│ [unmanaged] aws_iam_role.test  │ UNMANAGED  │ 🔴 CRIT   │    -    │ -                  ┃
└────────────────────────────────┴────────────┴───────────┴─────────┴────────────────────┘
```

---

### `driftsentry report`

Generates reports from the last scan or an exported scan JSON file.

```bash
# Generate an interactive HTML report
driftsentry report --format html --output drift-report.html

# Generate a PR-ready Markdown report
driftsentry report --format markdown --output report.md

# Load from a saved JSON scan
driftsentry report --input scan-result.json --format html --output report.html
```

---

### `driftsentry remediate`

Generates remediation scripts, Terraform/OpenTofu HCL code, or directly opens GitHub Pull Requests.

```bash
# Generate both import scripts and revert plans
driftsentry remediate --mode both --output-dir ./remediation

# Generate import commands for OpenTofu
driftsentry remediate --mode import --iac-tool opentofu

# Automatically create a GitHub PR with remediation code
export GITHUB_TOKEN="ghp_..."
driftsentry remediate --create-pr --repo "myorg/terraform-infrastructure" --base-branch "main"
```

Generated folder structure:
```
driftsentry-remediation/
├── import.sh                  # Executable shell script with import commands
├── imported_shadow_sg.tf      # Auto-generated HCL resource block
├── revert_plan.json           # Detailed JSON diff plan
├── revert_instructions.md     # Step-by-step instructions to revert
└── REMEDIATION_SUMMARY.md     # Comprehensive remediation summary
```

---

## ⚙️ Configuration File (`.driftsentry.yaml`)

You can customize DriftSentry's behavior using a `.driftsentry.yaml` file in your repository root or home directory:

```yaml
# IaC tool: terraform or opentofu
iac_tool: "terraform"

# State backend
state:
  backend: "local"
  path: "./terraform.tfstate"
  # For S3:
  # backend: "s3"
  # s3_bucket: "my-terraform-state-bucket"
  # s3_key: "prod/terraform.tfstate"
  # s3_region: "us-east-1"

# Cloud provider
provider:
  name: "aws"
  region: "us-east-1"
  # profile: "production"
  # role_arn: "arn:aws:iam::123456789012:role/DriftSentryScanRole"

# Drift attribution (CloudTrail)
attribution:
  enabled: true
  lookback_hours: 168  # 7 days

# Policy configuration
policy:
  enabled: true
  fail_on_critical: true

# Remediation options
remediation:
  mode: "both"
  output_dir: "./driftsentry-remediation"
  create_pr: false
  github_repo: "myorg/infra-repo"

# Notifications
notifications:
  slack_webhook_url: "${DRIFTSENTRY_SLACK_WEBHOOK}"
  notify_on:
    - "critical"
    - "high"

# Filter noise
filters:
  ignore_attributes:
    - "tags_all"
    - "arn"
    - "id"
    - "owner_id"
    - "unique_id"
    - "create_date"
    - "last_modified"
```

---

## 🔒 Recommended AWS IAM Policy

DriftSentry requires **only read-only access** to scan your infrastructure and query CloudTrail:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DriftSentryReadOnlyScan",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketVersioning",
        "s3:GetBucketEncryption",
        "s3:GetBucketLogging",
        "s3:GetBucketTagging",
        "s3:GetBucketPolicy",
        "s3:GetAccountPublicAccessBlock",
        "iam:ListRoles",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListUsers",
        "iam:GetUser",
        "rds:DescribeDBInstances",
        "rds:ListTagsForResource",
        "lambda:ListFunctions",
        "lambda:GetFunction",
        "ecs:ListClusters",
        "ecs:DescribeClusters",
        "ecs:ListServices",
        "ecs:DescribeServices",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DriftSentryReadStateBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::your-terraform-state-bucket/*"
    }
  ]
}
```

---

## 🔄 GitHub Actions CI/CD Integration

Run scheduled drift detection in GitHub Actions and automatically receive Slack alerts or PRs:

```yaml
name: Daily Infrastructure Drift Scan

on:
  schedule:
    - cron: '0 6 * * *'  # Run daily at 06:00 UTC
  workflow_dispatch:

jobs:
  drift-scan:
    name: Scan for Drift
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: write
      pull-requests: write

    steps:
      - name: Checkout Code
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
          role-to-assume: arn:aws:iam::123456789012:role/DriftSentryGitHubRole
          aws-region: us-east-1

      - name: Run DriftSentry Scan
        run: |
          driftsentry scan \
            --state-backend s3 \
            --s3-bucket my-company-tfstate \
            --s3-key prod/terraform.tfstate \
            --save ./scan-results.json \
            --verbose

      - name: Generate HTML Drift Report
        if: always()
        run: |
          driftsentry report \
            --input ./scan-results.json \
            --format html \
            --output ./drift-report.html

      - name: Upload Report Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: drift-report
          path: ./drift-report.html

      - name: Auto-Remediate via PR on Drift
        if: failure()
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          driftsentry remediate \
            --input ./scan-results.json \
            --mode both \
            --create-pr \
            --repo ${{ github.repository }}
```

---

## 🐳 Docker Usage

```bash
# Build Docker image
docker build -t driftsentry:latest .

# Run scan using mounted AWS credentials and state file
docker run --rm \
  -v ~/.aws:/home/driftsentry/.aws:ro \
  -v $(pwd)/terraform.tfstate:/data/terraform.tfstate:ro \
  driftsentry:latest scan --state-file /data/terraform.tfstate
```

---

## 🗺️ Supported AWS Resource Types

| Service | Terraform / OpenTofu Resource Type | Description |
|---------|------------------------------------|-------------|
| **EC2** | `aws_instance` | EC2 compute instances |
| **EC2** | `aws_security_group` | VPC security groups & rules |
| **EC2** | `aws_vpc` | Virtual Private Clouds |
| **EC2** | `aws_subnet` | VPC Subnets |
| **S3** | `aws_s3_bucket` | S3 Buckets (versioning, SSE, logging, ACLs) |
| **IAM** | `aws_iam_role` | IAM Roles & assume role policies |
| **IAM** | `aws_iam_policy` | Customer-managed IAM Policies |
| **IAM** | `aws_iam_user` | IAM Users |
| **RDS** | `aws_db_instance` | RDS database instances |
| **Lambda** | `aws_lambda_function` | Lambda serverless functions |
| **ECS** | `aws_ecs_cluster` | Elastic Container Service Clusters |
| **ECS** | `aws_ecs_service` | ECS Services & network configurations |

*Support for GCP and Azure resources is planned in upcoming releases.*

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on setting up a local development environment.

```bash
# Setup development environment
git clone https://github.com/hemanthkp98/driftsentry.git
cd driftsentry
make dev

# Run test suite
make test

# Run linter and type checker
make lint
```

---

## 📄 License

DriftSentry is licensed under the [Apache License 2.0](LICENSE).
