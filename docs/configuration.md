# Configuration

Configure `.driftsentry.yaml` settings, environment variables, IAM permissions, and resource filters for DriftSentry.

---

## Configuration File (`.driftsentry.yaml`)

DriftSentry loads configuration from a `.driftsentry.yaml` file located in the current working directory or your home directory (`~/.driftsentry.yaml`).

### Example Configuration

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
  region: "us-east-1"           # Primary fallback region
  regions:                      # Multi-region: list of regions to scan (or use CLI --regions)
    - "us-east-1"
    - "us-west-2"
    - "eu-west-1"
  # profile: "production"
  # role_arn: "arn:aws:iam::123456789012:role/DriftSentryScanRole"

# Multi-account configuration (AWS Organizations / multi-tenant)
accounts:
  - id: "111122223333"
    name: "production"
    role_arn: "arn:aws:iam::111122223333:role/DriftSentryScanRole"
    regions: ["us-east-1", "us-west-2"]
  - id: "444455556666"
    name: "staging"
    role_arn: "arn:aws:iam::444455556666:role/DriftSentryScanRole"
    profile: "staging-profile"

# Optional cross-account role template
role_arn_template: "arn:aws:iam::{account_id}:role/DriftSentryScanRole"

# Concurrency for parallel multi-target scans
concurrency: 4

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

# AI Smart Remediation (Claude or Gemini)
llm:
  enabled: false
  provider: "claude"            # "claude" or "gemini"
  # model: "claude-sonnet-4-6"  # Override default model
  max_items: 20

# Scan history persistence
history:
  enabled: true
  db_path: "~/.driftsentry/history.db"
  retention_days: 90

# Continuous monitoring daemon
monitor:
  enabled: true
  interval_minutes: 60
  max_scans: null
  smart_alerts_only: true

# Notifications
notifications:
  slack_webhook_url: "${DRIFTSENTRY_SLACK_WEBHOOK}"
  notify_on:
    - "critical"
    - "high"

# Filter noise and exclude baseline resources
filters:
  # exclude_tags:
  #   managed-by: ["AFT", "AWSControlTower"]
  #   Environment: "baseline"
  # exclude_patterns:
  #   - "*aft*"
  #   - "vpc-default"
  #   - "*-default-sg"
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

## Configuration Options Reference

| Option | Type | Default | Description |
|---|---|---|---|
| `iac_tool` | `string` | `terraform` | IaC engine: `terraform` or `opentofu`. |
| `state.backend` | `string` | `local` | State backend type: `local`, `s3`, or `gcs`. |
| `state.path` | `string` | `./terraform.tfstate` | Path to local state file when `backend: local`. |
| `state.s3_bucket` | `string` | — | S3 bucket name holding the remote state file. |
| `state.s3_key` | `string` | — | Object key of the remote state file in S3. |
| `state.s3_region` | `string` | `us-east-1` | AWS region where the S3 state bucket resides. |
| `provider.name` | `string` | `aws` | Cloud provider (`aws`). |
| `provider.region` | `string` | `us-east-1` | AWS target region to scan live infrastructure. |
| `provider.regions` | `list[string]` | `[]` | List of AWS regions to scan in parallel, or `["all"]`. |
| `provider.profile` | `string` | `default` | Named AWS credentials profile to use. |
| `provider.role_arn` | `string` | — | IAM Role ARN to assume before scanning. |
| `accounts` | `list[AccountConfig]` | `[]` | List of accounts (`id`, `name`, `role_arn`, `profile`, `regions`). |
| `role_arn_template` | `string` | — | Template for assuming cross-account roles, e.g. `arn:aws:iam::{account_id}:role/DriftSentryScanRole`. |
| `concurrency` | `integer` | `4` | Maximum worker threads for parallel scanning across targets. |
| `attribution.enabled` | `boolean` | `true` | Enable CloudTrail event lookup to identify who made the drift change. |
| `attribution.lookback_hours` | `integer` | `168` | CloudTrail history search window in hours (168h = 7 days). |
| `policy.enabled` | `boolean` | `true` | Enable policy engine severity classification. |
| `policy.fail_on_critical` | `boolean` | `true` | Exit with code 2 if any CRITICAL severity drift is detected. |
| `remediation.mode` | `string` | `both` | Remediation output mode: `import`, `revert`, or `both`. |
| `remediation.output_dir` | `string` | `./driftsentry-remediation` | Output directory for remediation scripts and plans. |
| `remediation.create_pr` | `boolean` | `false` | Automatically open a GitHub Pull Request with remediation artifacts. |
| `remediation.github_repo` | `string` | — | GitHub repository in `owner/repo` format for PR creation. |
| `llm.enabled` | `boolean` | `false` | Enable AI-powered smart remediation and root-cause analysis. |
| `llm.provider` | `string` | `claude` | LLM backend: `claude` or `gemini`. |
| `llm.model` | `string` | Provider default | Custom model identifier override. |
| `llm.max_items` | `integer` | `20` | Maximum number of drifted resources to send to LLM. |
| `history.enabled` | `boolean` | `true` | Whether to persist scan results to the SQLite history store. |
| `history.db_path` | `string` | `~/.driftsentry/history.db` | Override the default path to the history database. |
| `history.retention_days`| `integer` | `90` | Auto-prune scan history older than this many days. |
| `monitor.enabled` | `boolean` | `true` | Enable continuous drift monitoring daemon. |
| `monitor.interval_minutes`| `integer` | `60` | Default interval between continuous scans in minutes. |
| `monitor.max_scans` | `integer` | `null` | Stop continuous monitoring after this many scans (null = infinite). |
| `monitor.smart_alerts_only`| `boolean`| `true` | Only dispatch notifications (e.g. Slack) for NEW, REGRESSION, or WORSENED drift. |
| `notifications.slack_webhook_url` | `string` | — | Slack Incoming Webhook URL (supports `${ENV_VAR}` expansion). |
| `notifications.notify_on` | `list` | `["critical", "high"]` | Drift severity levels that trigger Slack notifications. |
| `filters.include_types` | `list[string]` | `[]` | Only scan these specific resource types (empty = all). |
| `filters.exclude_types` | `list[string]` | `[]` | Skip scanning these resource types completely. |
| `filters.exclude_tags` | `dict[string, string \| list[string]]` | `{}` | Exclude resources matching tag key-values (supports lists and `'*'`). |
| `filters.exclude_patterns` | `list[string]` | `[]` | Exclude resources matching ID, Name, or ARN glob patterns. |
| `filters.ignore_attributes` | `list` | `["arn", "id", ...]` | Top-level or nested attributes ignored during diff evaluation. |
| `filters.ignore_unmanaged_types` | `list[string]` | `[]` | Cloud resource types to exclude from UNMANAGED detection. |

---

### Excluding Account Vending Baselines (AFT / Control Tower)

When scanning or discovering resources in accounts provisioned by AWS Control Tower or Account Factory for Terraform (AFT), baseline infrastructure (default VPCs, AFT management VPCs, baseline IAM roles) can pollute scan results. You can suppress these baseline resources declaratively:

```yaml
filters:
  # Exclude by tag
  exclude_tags:
    managed-by:
      - "AFT"
      - "aft"
      - "AWSControlTower"
    Environment: "baseline"
    Terraform: "*"

  # Exclude by ID, Name tag, or ARN glob pattern
  exclude_patterns:
    - "*aft*"
    - "*control-tower*"
    - "vpc-default"
    - "*-default-sg"
    - "arn:aws:iam::*:role/aws-service-role/*"
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Optional | API key for Anthropic Claude LLM remediation. |
| `GEMINI_API_KEY` | Optional | API key for Google Gemini LLM remediation. |
| `AWS_REGION` | Optional | Default AWS region for scanning and CloudTrail lookups. |
| `AWS_PROFILE` | Optional | Named AWS CLI profile for credentials. |
| `DRIFTSENTRY_SLACK_WEBHOOK` | Optional | Slack webhook URL for automated alerts. |
| `GITHUB_TOKEN` | Optional | GitHub token with `repo` scope for auto-opening PRs. |

---

## Recommended AWS IAM Policy

DriftSentry requires **only read-only permissions** to scan live infrastructure and query CloudTrail:

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

## Supported AWS Resource Types

| Service | Terraform / OpenTofu Resource Type | Description |
|---|---|---|
| **EC2** | `aws_instance` | EC2 compute instances |
| **EC2** | `aws_security_group` | VPC security groups & ingress/egress rules |
| **EC2** | `aws_vpc` | Virtual Private Clouds |
| **EC2** | `aws_subnet` | VPC Subnets |
| **S3** | `aws_s3_bucket` | S3 Buckets (versioning, SSE, logging, ACLs) |
| **IAM** | `aws_iam_role` | IAM Roles & assume role policies |
| **IAM** | `aws_iam_policy` | Customer-managed IAM Policies |
| **IAM** | `aws_iam_user` | IAM Users |
| **RDS** | `aws_db_instance` | RDS relational database instances |
| **Lambda** | `aws_lambda_function` | Lambda serverless functions |
| **ECS** | `aws_ecs_cluster` | Elastic Container Service Clusters |
| **ECS** | `aws_ecs_service` | ECS Services & task configurations |

> [!NOTE]
> To add support for new AWS resource types without modifying Python source code, see [Custom Resources](custom-resources.md).
