# Example assessment report

This is a fully synthetic demonstration. Account, resource, assessment, and evidence identifiers are fictional; no live account data or credentials are included.

The JSON report uses the stable top-level schema emitted by `aegis report --format json`:

```json
{
  "schema_version": "1.0",
  "report_type": "aegis-assessment",
  "assessment": {
    "id": "00000000-0000-4000-8000-000000000001",
    "started_at": "2026-01-01T12:00:00+00:00",
    "completed_at": "2026-01-01T12:00:03+00:00",
    "endpoint": "http://127.0.0.1:4566",
    "region": "us-east-1",
    "status": "PARTIAL",
    "tool_version": "0.1.0"
  },
  "scope": {
    "endpoint": "http://127.0.0.1:4566",
    "region": "us-east-1",
    "resource_count": 2,
    "cloud_resource_count": 2,
    "resource_types": [
      "cloudwatch_log_group",
      "iam_policy"
    ]
  },
  "coverage": {
    "operation_count": 3,
    "by_status": {
      "SUCCESS": 3
    },
    "unsupported_checks": [],
    "errors": [],
    "limitations": [
      "AEGIS-LOGS-001 on cloudwatch_log_group:/example/application is NOT_SUPPORTED: retentionInDays was not returned.",
      "One or more discovery operations or rule checks have incomplete evidence; the assessment is not a security pass.",
      "AEGIS did not apply remediation; rule guidance is advisory and is not evidence that a change was made."
    ]
  },
  "summary": {
    "finding_count": 2,
    "by_outcome": {
      "PASS": 0,
      "FAIL": 1,
      "NOT_APPLICABLE": 0,
      "NOT_SUPPORTED": 1,
      "ERROR": 0
    },
    "by_severity": {
      "CRITICAL": 0,
      "HIGH": 1,
      "MEDIUM": 0,
      "LOW": 0,
      "INFO": 0
    }
  },
  "findings": [
    {
      "rule_id": "AEGIS-IAM-001",
      "resource_type": "iam_policy",
      "resource_id": "arn:aws:iam::000000000000:policy/example-read-policy",
      "outcome": "FAIL",
      "severity": "HIGH",
      "title": "Avoid wildcard IAM permissions",
      "description": "Detect Allow statements that use wildcard action or resource patterns. Conditions and effective permissions are not evaluated.",
      "reason": "statement 0 has wildcard Action; statement 0 has wildcard Resource pattern",
      "remediation": "Replace broad action/resource patterns with the smallest explicit permissions required.",
      "evidence_refs": [
        {
          "operation_id": 1,
          "service": "iam",
          "operation": "ListPolicies",
          "subject_resource_id": null,
          "status": "SUCCESS",
          "evidence_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
        },
        {
          "operation_id": 2,
          "service": "iam",
          "operation": "GetPolicyVersion",
          "subject_resource_id": "arn:aws:iam::000000000000:policy/example-read-policy#v1",
          "status": "SUCCESS",
          "evidence_sha256": "2222222222222222222222222222222222222222222222222222222222222222"
        }
      ],
      "assessed_at": "2026-01-01T12:00:03+00:00",
      "previous_outcome": null,
      "change_state": "FIRST_SEEN"
    },
    {
      "rule_id": "AEGIS-LOGS-001",
      "resource_type": "cloudwatch_log_group",
      "resource_id": "/example/application",
      "outcome": "NOT_SUPPORTED",
      "severity": "MEDIUM",
      "title": "Use at least 30 days of log retention",
      "description": "Compare an explicitly returned CloudWatch log retention value with the AEGIS local 30-day assessment baseline.",
      "reason": "Required configuration evidence was not returned by the API.",
      "remediation": "Set and periodically review a retention period based on organizational requirements.",
      "evidence_refs": [
        {
          "operation_id": 3,
          "service": "logs",
          "operation": "DescribeLogGroups",
          "subject_resource_id": null,
          "status": "SUCCESS",
          "evidence_sha256": "1111111111111111111111111111111111111111111111111111111111111111"
        }
      ],
      "assessed_at": "2026-01-01T12:00:03+00:00",
      "previous_outcome": null,
      "change_state": "FIRST_SEEN"
    }
  ]
}
```

The Markdown report labels severity totals as confirmed `FAIL` only and keeps evidence gaps separate. The excerpt follows the renderer's headings and reference style:

```markdown
# AEGIS Assessment Report

- Assessment ID: `00000000-0000-4000-8000-000000000001`
- Started: `2026-01-01T12:00:00+00:00`
- Completed: `2026-01-01T12:00:03+00:00`
- Status: **PARTIAL**
- Scope: `http://127.0.0.1:4566` / region `us-east-1`
- Inventory: 2 records; 2 cloud resources

> **Assessment coverage is incomplete:** one or more discovery operations or rule checks did not provide complete evidence.

## Summary

Findings: 2

### By severity (confirmed FAIL only)

| Severity | Count |
|---|---:|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 0 |
| LOW | 0 |
| INFO | 0 |

### By outcome

| Outcome | Count |
|---|---:|
| PASS | 0 |
| FAIL | 1 |
| NOT_APPLICABLE | 0 |
| NOT_SUPPORTED | 1 |
| ERROR | 0 |

## Findings

### FAIL — Avoid wildcard IAM permissions

- Rule: `AEGIS-IAM-001`
- Severity: HIGH (severity counts include FAIL only)
- Resource: `iam_policy` / `arn:aws:iam::000000000000:policy/example-read-policy`
- Reason: statement 0 has wildcard Action; statement 0 has wildcard Resource pattern
- Description: Detect Allow statements that use wildcard action or resource patterns. Conditions and effective permissions are not evaluated.
- Evidence references:
  - Operation record 1: iam:ListPolicies; status SUCCESS; subject null; evidence SHA-256 "0000000000000000000000000000000000000000000000000000000000000000".
  - Operation record 2: iam:GetPolicyVersion; status SUCCESS; subject "arn:aws:iam::000000000000:policy/example-read-policy#v1"; evidence SHA-256 "2222222222222222222222222222222222222222222222222222222222222222".
- Remediation guidance for this confirmed failure: Replace broad action/resource patterns with the smallest explicit permissions required.

### NOT_SUPPORTED — Use at least 30 days of log retention

- Rule: `AEGIS-LOGS-001`
- Severity: MEDIUM (severity counts include FAIL only)
- Resource: `cloudwatch_log_group` / `/example/application`
- Reason: Required configuration evidence was not returned by the API.
- Description: Compare an explicitly returned CloudWatch log retention value with the AEGIS local 30-day assessment baseline.
- Evidence references:
  - Operation record 3: logs:DescribeLogGroups; status SUCCESS; subject null; evidence SHA-256 "1111111111111111111111111111111111111111111111111111111111111111".
- Evidence status: required evidence is unavailable; this is not a pass or confirmed failure.
- General rule guidance (not a determination that changes are needed): Set and periodically review a retention period based on organizational requirements.

## Discovery coverage

Operations recorded: 3

- SUCCESS: 3

### Unsupported checks and errors

None recorded.

### Coverage limitations

- AEGIS-LOGS-001 on cloudwatch_log_group:/example/application is NOT_SUPPORTED: retentionInDays was not returned.
- One or more discovery operations or rule checks have incomplete evidence; the assessment is not a security pass.
- AEGIS did not apply remediation; rule guidance is advisory and is not evidence that a change was made.
```

The example does not imply framework compliance, effective-permission analysis, or full discovery coverage.
