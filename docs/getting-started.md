# Getting Started

Install DriftSentry, configure AWS credentials, and run your first drift scan in under two minutes.

---

## Prerequisites

- **Python**: Version 3.11, 3.12, or 3.13
- **IaC State**: A Terraform (`.tfstate`) or OpenTofu state file (local or remote in AWS S3)
- **AWS Permissions**: Read-only AWS credentials (see [Recommended IAM Policy](configuration.md#recommended-aws-iam-policy))

---

## Installation

### Standard Installation

```bash
pip install driftsentry
```

### With AI Smart Remediation (Claude & Gemini)

```bash
pip install "driftsentry[ai]"
```

### Install from Source

```bash
git clone https://github.com/hemanthkp98/driftsentry.git
cd driftsentry
pip install -e ".[dev,ai]"
```

Verify your installation:

```bash
driftsentry version
```

---

## Running with Docker

Run DriftSentry via container without local Python dependencies:

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

## Configure AWS Credentials

DriftSentry uses standard AWS SDK credential discovery:

### Option A: Environment Variables
```bash
export AWS_REGION="us-east-1"
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

### Option B: AWS CLI Profile
```bash
export AWS_PROFILE="production"
# Or pass --profile production in CLI commands
```

### Option C: IAM Role Assumption
```bash
driftsentry scan \
  --state-file ./terraform.tfstate \
  --role-arn "arn:aws:iam::123456789012:role/DriftSentryReadOnlyRole"
```

---

## Run Your First Scan

### Local Terraform State File
```bash
driftsentry scan --state-file ./terraform.tfstate
```

### Local OpenTofu State File
```bash
driftsentry scan --state-file ./terraform.tfstate --iac-tool opentofu
```

### Remote State in AWS S3 Bucket
```bash
driftsentry scan \
  --state-backend s3 \
  --s3-bucket my-terraform-state-bucket \
  --s3-key production/terraform.tfstate \
  --region us-east-1
```

---

## Reviewing Results

When drift is detected, DriftSentry displays a summary box and an actionable table in your terminal:

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
│ [unmanaged] aws_sqs_queue.demo │ UNMANAGED  │ 🟡 MEDIUM │    -    │ -                  ┃
└────────────────────────────────┴────────────┴───────────┴─────────┴────────────────────┘
```

---

## Next Steps

- 📊 **Generate Reports**: See [CLI Reference](api.md) to output HTML and Markdown reports.
- 🧠 **Auto-Remediate**: Read [AI Smart Remediation](ai-remediation.md) to generate HCL code and open GitHub PRs.
- 🧩 **Add Services**: Check [Custom Resources](custom-resources.md) to define new cloud services.
- ⚙️ **Configuration**: See [Configuration](configuration.md) for complete `.driftsentry.yaml` settings.
