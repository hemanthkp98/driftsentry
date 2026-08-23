# 📚 DriftSentry Documentation

Welcome to the **DriftSentry** documentation. DriftSentry is an open-source Infrastructure-as-Code (IaC) drift detection, CloudTrail attribution, and AI-powered auto-remediation engine for **Terraform** and **OpenTofu**.

---

## 🗺️ Documentation Map

| Guide | Description | Target Audience |
|---|---|---|
| [🚀 Getting Started](getting-started.md) | Installation, AWS credentials setup, running your first scan in under 2 minutes. | New Users |
| [🖥️ CLI Usage Reference](cli-reference.md) | Complete reference for all CLI commands (`scan`, `report`, `remediate`) and options. | Everyone |
| [🧠 AI Smart Remediation](ai-remediation.md) | LLM-powered idiomatic HCL generation, root-cause narratives, and automated PRs (Claude & Gemini). | DevOps / Platform Engineers |
| [🧩 Custom & Declarative Resources](custom-resources.md) | How to add any AWS service using zero-code Declarative YAML or Python plugins. | Platform Engineers & Contributors |
| [📜 Policy as Code](policy-as-code.md) | Security rules, severity classification, ignoring benign changes, and exit code thresholds. | Security & Compliance Teams |
| [🔄 CI/CD Automation](ci-cd-integration.md) | Integrating DriftSentry into GitHub Actions and GitLab CI for scheduled drift scans. | DevOps Engineers |
| [🏗️ Architecture & Internals](architecture.md) | Deep dive into the Diff Engine, CloudTrail Attribution, and State Reader abstractions. | Contributors & Architects |

---

## ⚡ Quick Links & Cheatsheet

```bash
# 1. Install DriftSentry (with AI extras)
pip install "driftsentry[ai]"

# 2. Scan live AWS infrastructure against state
driftsentry scan --state-file ./terraform.tfstate

# 3. Generate interactive HTML drift report
driftsentry report --format html --output drift-report.html

# 4. Auto-remediate with AI-generated HCL and create GitHub PR
driftsentry remediate --ai --create-pr --repo "org/infrastructure"
```
