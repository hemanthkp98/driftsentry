# 🏗️ Architecture & Internal Design

This document details the architectural design and execution flow of DriftSentry.

---

## 🏛️ High-Level Architecture

```
                               ┌───────────────────────────┐
                               │  Terraform / OpenTofu     │
                               │  State Reader (Local/S3)  │
                               └─────────────┬─────────────┘
                                             │ Desired State
                                             ▼
┌───────────────────────────┐     ┌─────────────────────┐     ┌───────────────────────────┐
│  Cloud Provider Engine    │────▶│   Drift Differ      │◀────│  AWS CloudTrail           │
│  (Declarative & Python)   │     │   (Deep Diff)       │     │  Attribution Engine       │
└───────────────────────────┘     └──────────┬──────────┘     └───────────────────────────┘
       Actual State                          │
                                             ▼
                                  ┌─────────────────────┐
                                  │   Policy Engine     │
                                  │   (Severity & Rules)│
                                  └──────────┬──────────┘
                                             │
                                             ▼
                                  ┌─────────────────────┐
                                  │  Remediation Engine │
                                  │  (AI HCL & Auto-PR) │
                                  └─────────────────────┘
```

---

## 🔄 The 5-Stage Scan Pipeline

### Stage 1: State Ingestion
- `StateReader` (`LocalStateReader` or `S3StateReader`) parses Terraform format v4 JSON.
- Filters non-cloud metadata and builds an in-memory index of `ResourceState` objects.

### Stage 2: Live Cloud Discovery (Multi-Account & Multi-Region)
- `TargetResolver` inspects configuration and CLI options to resolve all `(Account, Region)` `ScanTarget` instances:
  - Supports default local profile/role, explicit multi-accounts list, or dynamic role ARN templates (`arn:aws:iam::{account_id}:role/DriftSentryScanRole`).
  - Supports explicit region lists or dynamic expansion with `--regions all` via `ec2.describe_regions()`.
- `AWSProvider` spins up a concurrent worker pool (`ThreadPoolExecutor`) with configurable `concurrency`:
  - Scans multiple target accounts and regions concurrently.
  - **Global Service Deduplication**: Resources that are global in AWS (e.g. `aws_iam_role`, `aws_iam_policy`, `aws_route53_zone`, `aws_cloudfront_distribution`) are queried only once per unique account, preventing redundant API calls and rate-limiting.
  - Scanned `CloudResource` objects are automatically enriched with target `account_id`, `account_name`, and `region`.

### Stage 3: Deep Diffing & Classification
- `DriftDiffer` performs recursive attribute comparisons between state and cloud.
- Supports cross-target ID and ARN matching.
- Categorizes each resource as:
  - `CHANGED`: Exists in state and cloud, but attribute values differ.
  - `DELETED`: Exists in state, but is missing in the cloud.
  - `UNMANAGED`: Exists in the cloud, but is absent from IaC state (Shadow IT).

### Stage 4: CloudTrail Attribution
- If drift is found on a resource, `CloudTrailAttributor` dynamically routes audit log lookups to the specific AWS account session and region where the resource resides.
- Identifies the principal (IAM user/role), timestamp, source IP, user agent, and whether the modification was made via AWS Console ClickOps.

### Stage 5: Policy Evaluation & Remediation
- `PolicyEngine` evaluates rule triggers, suppresses ignored noise attributes, and sets severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- `RemediationGenerator` (with optional `LLMAnalyzer`) produces executable import scripts, idiomatic HCL code, revert plans, and opens GitHub Pull Requests.

---

## 🛡️ Drift Baseline Ledger & Fingerprinting

DriftSentry includes an acknowledged-drift ledger system designed to prevent alert fatigue from known, intentional drift (such as approved emergency hotfixes or manual out-of-band updates) without permanently ignoring entire resources:

```
┌─────────────────┐       ┌────────────────────────┐       ┌─────────────────────────┐
│   DriftDiffer   │──────▶│     DriftResult        │──────▶│     BaselineFilter      │
└─────────────────┘       │ (Raw Detected Drift)   │       └────────────┬────────────┘
                                                                        │
                                                          .driftsentry-baseline.json
                                                                        │
                                  ┌─────────────────────────────────────┴─────────────────────────────────────┐
                                  ▼                                     ▼                                     ▼
                      ┌──────────────────────┐              ┌──────────────────────┐              ┌──────────────────────┐
                      │    Active Items      │              │  Acknowledged Items  │              │   Regression Items   │
                      │ (Net-new Drift Items)│              │(Exact Fingerprint)   │              │(Re-drifted in Cloud) │
                      └──────────┬───────────┘              └──────────┬───────────┘              └──────────┬───────────┘
                                 │                                     │                                     │
                                 ▼                                     ▼                                     ▼
                      Unfiltered in Reports/CI               Suppressed from Noise                Flagged in Reports/CI
```

### Deterministic SHA-256 Fingerprinting

Every detected drift item is hashed into a platform-agnostic, canonical fingerprint:

$$\text{Fingerprint} = \text{SHA256}(\text{normalized\_address} \mid \text{drift\_type} \mid \text{attribute\_path} \mid \text{canonical\_json\_actual\_value})$$

- **Dictionary Normalization**: JSON serialization recursively sorts all dictionary keys and applies stable separators (`","`, `":"`).
- **Granular Attribute Attribution**: For `CHANGED` resources, each modified attribute receives its own fingerprint. A resource can have one attribute acknowledged while newly modified attributes remain active.
- **Regression Detection**: If an acknowledged resource attribute is modified again in the cloud to a different value, the new fingerprint does not match the baseline entry and the item is classified as a `REGRESSION` rather than being silently suppressed.

