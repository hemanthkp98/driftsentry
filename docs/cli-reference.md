# 🖥️ CLI Usage Reference

DriftSentry provides three primary subcommands:
1. `driftsentry scan` — Scan live infrastructure and compare against IaC state.
2. `driftsentry report` — Render multi-format reports from scan results.
3. `driftsentry remediate` — Generate import scripts, idiomatic HCL blocks, revert plans, or open PRs.

---

## 1. `driftsentry scan`

Scans live cloud infrastructure against a Terraform or OpenTofu state file.

```bash
driftsentry scan [OPTIONS]
```

### Options

| Option | Flag | Description | Default |
|---|---|---|---|
| `--state-file` | `-s` | Path to local `.tfstate` file | None |
| `--state-backend` | | State backend type (`local` or `s3`) | `local` |
| `--s3-bucket` | | S3 bucket for remote state | None |
| `--s3-key` | | S3 object key (path) for remote state | None |
| `--provider` | `-p` | Cloud provider (`aws`) | `aws` |
| `--region` | `-r` | AWS region to scan | `us-east-1` |
| `--profile` | | AWS CLI profile name | Default profile |
| `--role-arn` | | AWS IAM Role ARN to assume | None |
| `--iac-tool` | | IaC engine (`terraform` or `opentofu`) | `terraform` |
| `--output` | `-o` | Output format (`table`, `json`) | `table` |
| `--include-types` | | Comma-separated resource types to include (e.g. `aws_instance,aws_sqs_queue`) | All supported |
| `--exclude-types` | | Comma-separated resource types to exclude | None |
| `--config` | `-c` | Path to `.driftsentry.yaml` configuration file | Auto-discovered |
| `--no-attribution`| | Skip CloudTrail attribution lookups for faster scan | `false` |
| `--no-policy` | | Skip policy evaluation rules | `false` |
| `--verbose` | `-v` | Show detailed attribute-level diff table | `false` |
| `--save` | | Save scan result to a JSON file | None |

### Examples

```bash
# Basic scan with verbose attribute diff table
driftsentry scan --state-file terraform.tfstate --verbose

# Scan S3 remote state and save result to JSON
driftsentry scan \
  --state-backend s3 \
  --s3-bucket prod-tf-state \
  --s3-key vpc/terraform.tfstate \
  --save scan-result.json

# Scan only compute and database resources
driftsentry scan \
  --state-file terraform.tfstate \
  --include-types aws_instance,aws_db_instance
```

---

## 2. `driftsentry report`

Renders reports from the last scan in memory or from a saved scan JSON file.

```bash
driftsentry report [OPTIONS]
```

### Options

| Option | Flag | Description | Default |
|---|---|---|---|
| `--input` | `-i` | Path to saved scan JSON file (defaults to last scan) | Last scan |
| `--format` | `-f` | Report format: `table`, `json`, `html`, `markdown` | `table` |
| `--output` | `-o` | Output file path (prints to stdout if omitted) | stdout |
| `--config` | `-c` | Path to `.driftsentry.yaml` config file | Auto-discovered |

### Examples

```bash
# Generate self-contained dark-theme HTML report
driftsentry report --format html --output drift-report.html

# Generate PR-ready Markdown report
driftsentry report --format markdown --output drift-report.md

# Convert saved scan JSON to formatted HTML
driftsentry report --input scan-result.json --format html --output report.html
```

---

## 3. `driftsentry remediate`

Generates import commands, HCL resource code, revert instructions, or opens automated pull requests.

```bash
driftsentry remediate [OPTIONS]
```

### Options

| Option | Flag | Description | Default |
|---|---|---|---|
| `--input` | `-i` | Path to saved scan JSON file | Last scan |
| `--mode` | `-m` | Remediation mode: `both`, `import`, `revert` | `both` |
| `--output-dir`| `-o` | Directory to write remediation artifacts | `./driftsentry-remediation` |
| `--iac-tool` | | Target IaC tool: `terraform` or `opentofu` | `terraform` |
| `--dry-run` | | Preview remediation summary without writing files | `false` |
| `--ai` | | Enable AI-powered smart HCL generation & root-cause analysis | `false` |
| `--ai-provider`| | LLM provider: `claude` or `gemini` | `claude` |
| `--ai-model` | | Override default LLM model name | Auto |
| `--ai-max-items`| | Maximum drift items to analyze with AI | `20` |
| `--create-pr` | | Automatically create a GitHub PR with remediation code | `false` |
| `--repo` | | Target GitHub repository (`owner/repo`) | None |
| `--github-token`| | GitHub Personal Access Token | `GITHUB_TOKEN` env |
| `--base-branch`| | Base branch for the Pull Request | `main` |
| `--config` | `-c` | Path to `.driftsentry.yaml` config file | Auto-discovered |

### Examples

```bash
# Standard dual-mode remediation
driftsentry remediate --mode both --output-dir ./remediation

# AI-powered smart remediation with Claude
export ANTHROPIC_API_KEY="sk-ant-..."
driftsentry remediate --ai --ai-provider claude

# AI-powered smart remediation with Gemini
export GEMINI_API_KEY="AIza..."
driftsentry remediate --ai --ai-provider gemini

# Automatically create a GitHub PR with AI-enriched descriptions
export GITHUB_TOKEN="ghp_..."
driftsentry remediate --ai --create-pr --repo "myorg/infra-repo" --base-branch "main"
```
