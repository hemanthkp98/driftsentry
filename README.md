# DriftSentry

Infrastructure-as-Code (IaC) drift detection, CloudTrail actor attribution, and AI-powered automated remediation engine for Terraform and OpenTofu.

[![CI](https://github.com/hemanthkp98/driftsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/hemanthkp98/driftsentry/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/driftsentry.svg)](https://pypi.org/project/driftsentry/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

---

## Why It Exists

Cloud environments continuously drift away from committed Terraform code due to emergency console hotfixes, uncoordinated script executions, and out-of-band updates. DriftSentry detects configuration discrepancies between live AWS infrastructure and your state files, pinpoints the exact IAM identity responsible using CloudTrail history, and generates production-ready HCL patches or Pull Requests with zero human intervention.

---

## Quickstart

```bash
# 1. Install DriftSentry with AI smart remediation
pip install "driftsentry[ai]"

# 2. Scan live AWS infrastructure against your state file
driftsentry scan --state-file ./terraform.tfstate

# 3. Generate an interactive HTML drift report
driftsentry report --format html --output drift-report.html

# 4. Auto-remediate and open a Pull Request with AI root-cause analysis
driftsentry remediate --ai --create-pr --repo "myorg/infra-repo"
```

---

## Documentation

- [Getting Started](docs/getting-started.md) — Installation options, AWS credentials setup, running first scans, and Docker usage.
- [Configuration](docs/configuration.md) — `.driftsentry.yaml` schema, environment variables, and recommended read-only IAM policy.
- [CLI Reference](docs/api.md) — Complete command options, flags, and exit codes for `scan`, `report`, and `remediate`.
- [Architecture & Internals](docs/architecture.md) — 5-stage pipeline design, diff engine algorithms, and CloudTrail correlation.
- [AI Smart Remediation](docs/ai-remediation.md) — Claude and Gemini LLM setup, prompt guardrails, and auto-generated HCL blocks.
- [Policy as Code](docs/policy-as-code.md) — Severity classification rules, noise suppression, and CI/CD threshold controls.
- [Deployment & CI/CD](docs/deployment.md) — Scheduled scans in GitHub Actions and GitLab CI with automated Slack alerting.
- [Custom Resources](docs/custom-resources.md) — Pluggable zero-code YAML schema and Python collector plugins for AWS resources.
- [Development](docs/development.md) — Local development workflow, running test suites, and linting.

---

## Architecture

DriftSentry processes infrastructure drift through an automated 5-stage pipeline:

```
IaC State (.tfstate) ──┐
                       ├──► Deep Diff Engine ──► CloudTrail Attribution ──► LLM Remediation & PR
Live AWS Cloud API  ───┘
```

For complete state reader abstractions, attribution lookups, and sequence diagrams, see [Architecture](docs/architecture.md).

---

## Contributing & License

- Development setup and PR checklists are in [CONTRIBUTING.md](CONTRIBUTING.md).
- Distributed under the [Apache License 2.0](LICENSE).
