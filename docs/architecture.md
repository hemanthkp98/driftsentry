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

### Stage 2: Live Cloud Discovery
- `AWSProvider` enumerates live resources in the cloud account using:
  - **Specialized Scanners** (e.g. `EC2Scanner`, `S3Scanner`, `IAMScanner`).
  - **Declarative Scanners** (`GenericAWSDeclarativeScanner` using Boto3 + JMESPath).
- Resources are normalized to match the Terraform attribute schema.

### Stage 3: Deep Diffing & Classification
- `DriftDiffer` performs recursive attribute comparisons between state and cloud.
- Categorizes each resource as:
  - `CHANGED`: Exists in state and cloud, but attribute values differ.
  - `DELETED`: Exists in state, but is missing in the cloud.
  - `UNMANAGED`: Exists in the cloud, but is absent from IaC state (Shadow IT).

### Stage 4: CloudTrail Attribution
- If drift is found on a resource, `CloudTrailAttributor` queries AWS CloudTrail audit logs matching the resource ID/ARN within the lookback window.
- Identifies the principal (IAM user/role), timestamp, source IP, user agent, and whether the modification was made via AWS Console ClickOps.

### Stage 5: Policy Evaluation & Remediation
- `PolicyEngine` evaluates rule triggers, suppresses ignored noise attributes, and sets severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- `RemediationGenerator` (with optional `LLMAnalyzer`) produces executable import scripts, idiomatic HCL code, revert plans, and opens GitHub Pull Requests.
