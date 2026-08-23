# 🚀 Getting Started with DriftSentry

This guide will walk you through installing DriftSentry, configuring your cloud credentials, and running your first drift scan in under 2 minutes.

---

## 1. Prerequisites

- **Python**: Version 3.11, 3.12, or 3.13
- **IaC State**: A Terraform (`.tfstate`) or OpenTofu state file (local or remote in AWS S3)
- **AWS Permissions**: Read-only AWS credentials

---

## 2. Installation

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

## 3. Configure AWS Credentials

DriftSentry uses standard AWS SDK credential discovery. You can configure credentials using any of the standard methods:

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
If you use cross-account roles:
```bash
driftsentry scan \
  --state-file ./terraform.tfstate \
  --role-arn "arn:aws:iam::123456789012:role/DriftSentryReadOnlyRole"
```

---

## 4. Run Your First Scan

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

## 5. Reviewing the Results

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

## 6. Next Steps

- 📊 **Generate Reports**: See [CLI Usage Reference](cli-reference.md) to output HTML and Markdown reports.
- 🧠 **Auto-Remediate**: Read [AI Smart Remediation](ai-remediation.md) to generate HCL code and open GitHub PRs.
- 🧩 **Add Services**: Check [Custom & Declarative Resources](custom-resources.md) to define new cloud services.
