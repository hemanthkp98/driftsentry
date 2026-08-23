# 🧩 Adding Custom & Declarative AWS Resource Types

DriftSentry provides a **pluggable, data-driven resource engine**. You can add support for any AWS service without waiting for a new release or modifying core Python code.

---

## 🎯 Two Ways to Add Resources

| Method | Best For | Effort |
|---|---|---|
| **1. Declarative YAML Specs** | 80% of standard AWS services that use standard Boto3 list/describe calls | 5 minutes, 0 Python code |
| **2. Python Plugin Scanners** | Complex services requiring multi-call aggregation or custom API logic | Python class with `@register_scanner` |

---

## Method 1: Declarative YAML Specifications (Zero-Code)

You can define a new resource in a `.yaml` file or inline in your `.driftsentry.yaml` configuration.

### Example 1: Defining Amazon SQS Queue

Create a file `custom_resources/aws_sqs_queue.yaml`:

```yaml
terraform_type: "aws_sqs_queue"
service: "sqs"
description: "Amazon SQS Queue"

# 1. API Discovery
discovery:
  list_operation: "list_queues"
  result_path: "QueueUrls[]"
  id_field: "@"
  describe_operation: "get_queue_attributes"
  describe_params:
    QueueUrl: "{id}"
    AttributeNames: ["All"]
  attributes_path: "Attributes"

# 2. Attribute Mapping (Terraform Attribute -> API Field / JMESPath)
attributes:
  name: "QueueName"
  delay_seconds: "DelaySeconds"
  max_message_size: "MaximumMessageSize"
  visibility_timeout_seconds: "VisibilityTimeout"
  kms_master_key_id: "KmsMasterKeyId"
  policy: "Policy"

# 3. Policy & Noise Filtering
security_critical:
  - "policy"
  - "kms_master_key_id"

noise_attributes:
  - "approximate_number_of_messages"
  - "created_timestamp"
  - "last_modified_timestamp"

# 4. CloudTrail Events for Attribution
cloudtrail_events:
  - "CreateQueue"
  - "DeleteQueue"
  - "SetQueueAttributes"
```

### Loading Your Custom YAML Definitions

In your `.driftsentry.yaml`:

```yaml
provider:
  name: "aws"
  region: "us-east-1"
  resource_definitions_dirs:
    - "./custom_resources"
    - "~/.driftsentry/resources"
```

Now run your scan:
```bash
driftsentry scan --state-file terraform.tfstate --include-types aws_sqs_queue
```

---

## Method 2: Inline Configuration in `.driftsentry.yaml`

For quick one-off resource additions, define them directly under `provider.custom_resources`:

```yaml
provider:
  name: "aws"
  region: "us-east-1"
  custom_resources:
    aws_sns_topic:
      service: "sns"
      description: "Amazon SNS Topic"
      discovery:
        list_operation: "list_topics"
        result_path: "Topics[].TopicArn"
        id_field: "@"
        describe_operation: "get_topic_attributes"
        describe_params:
          TopicArn: "{id}"
        attributes_path: "Attributes"
      attributes:
        name: "DisplayName"
        policy: "Policy"
        kms_master_key_id: "KmsMasterKeyId"
      security_critical:
        - "policy"
      cloudtrail_events:
        - "CreateTopic"
        - "DeleteTopic"
        - "SetTopicAttributes"
```

---

## Method 3: Python Plugin Scanners (Code-Level Extension)

For complex resources that require custom multi-step logic:

1. Create a Python file (e.g. `my_plugins/custom_scanner.py`):

```python
from typing import Any
import boto3
from driftsentry.core.models import CloudResource
from driftsentry.providers.base import ResourceScanner, register_scanner

@register_scanner("aws")
class CustomDynamoScanner(ResourceScanner):
    def __init__(self, session: boto3.Session, region: str) -> None:
        super().__init__(session, region)
        self._client = session.client("dynamodb", region_name=region)

    @property
    def resource_types(self) -> list[str]:
        return ["aws_dynamodb_table"]

    def list_all(self) -> list[CloudResource]:
        response = self._client.list_tables()
        resources = []
        for name in response.get("TableNames", []):
            detail = self._client.describe_table(TableName=name).get("Table", {})
            resources.append(
                CloudResource(
                    resource_id=name,
                    resource_type="aws_dynamodb_table",
                    region=self.region,
                    attributes={"name": name, "billing_mode": detail.get("BillingModeSummary", {}).get("BillingMode")},
                )
            )
        return resources

    def get_by_id(self, resource_id: str) -> CloudResource | None:
        detail = self._client.describe_table(TableName=resource_id).get("Table", {})
        return CloudResource(
            resource_id=resource_id,
            resource_type="aws_dynamodb_table",
            region=self.region,
            attributes={"name": resource_id},
        )

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return raw
```

2. Register the plugin in `.driftsentry.yaml`:

```yaml
provider:
  name: "aws"
  plugins:
    - "my_plugins.custom_scanner"
```
