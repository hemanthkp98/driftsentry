# 📜 Policy as Code & Severity Classification

DriftSentry includes a Policy Engine that classifies the severity of configuration drift, suppresses benign changes (noise reduction), and controls CI/CD pipeline failure thresholds.

---

## 🚦 Severity Levels

| Severity | Color | Meaning | Examples |
|---|---|---|---|
| `CRITICAL` | 🔴 Red | High security risk or public exposure | Security group ingress `0.0.0.0/0`, IAM policy changes, public S3 bucket |
| `HIGH` | 🟠 Orange | Operational risk or potential outage | Database deletion protection disabled, instance stopped |
| `MEDIUM` | 🟡 Yellow | Functional configuration drift | Instance size modified, retention period changed |
| `LOW` | 🟢 Green | Low impact operational drift | CloudWatch alarm threshold tweak |
| `INFO` | 🔵 Blue | Benign drift or auto-generated fields | Tag updates, metadata changes |

---

## ⚙️ Configuration in `.driftsentry.yaml`

```yaml
policy:
  enabled: true
  # Exit with non-zero exit code if any CRITICAL drift is detected
  fail_on_critical: true
  
  # Optional custom policy rules file
  policy_file: "./driftsentry-policy.yaml"

filters:
  # Attributes to ignore across all resources during diff
  ignore_attributes:
    - "tags_all"
    - "arn"
    - "id"
    - "owner_id"
    - "unique_id"
    - "create_date"
    - "last_modified"

  # Resource types to completely skip from unmanaged shadow IT detection
  ignore_unmanaged_types:
    - "aws_iam_user"
```

---

## 📝 Custom Policy Rules (`driftsentry-policy.yaml`)

You can define custom rule overrides in a dedicated policy file:

```yaml
rules:
  # Rule 1: Always escalate SSH port 22 openings to CRITICAL
  - name: "open_ssh_port_critical"
    resource_type: "aws_security_group"
    attribute_path: "ingress.*.from_port"
    equals: 22
    set_severity: "critical"

  # Rule 2: Ignore tag changes on staging environment
  - name: "ignore_staging_tags"
    resource_type: "*"
    attribute_path: "tags.*"
    action: "ignore"

  # Rule 3: Escalate RDS deletion protection changes
  - name: "rds_deletion_protection_high"
    resource_type: "aws_db_instance"
    attribute_path: "deletion_protection"
    set_severity: "high"
```

---

## 🚫 CI/CD Pipeline Control

By default, when `fail_on_critical: true`:
- If **0 critical drift** is found: Exit code `0` (Pipeline passes).
- If **1+ critical drift** is found: Exit code `2` (Pipeline fails, triggering alert/PR).
- If general errors occur: Exit code `1`.

You can disable failure on critical drift in dev/testing environments by passing `--no-policy` or setting `policy.fail_on_critical: false`.
