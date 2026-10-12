# Phase 3 Rules and Evidence

AEGIS evaluates only directly observed API configuration and records one explicit outcome per resource/rule when a resource was discovered. The evaluator has no cloud client and cannot make changes. When a resource type is absent or its inventory operation fails before resources are observed, AEGIS emits no synthetic `scope:*` resource finding; operation errors and unsupported states remain in the assessment's operation records and report coverage.

## Outcome meanings

- `PASS`: the required response fields were present, structurally valid, and did not meet the rule's failure condition.
- `FAIL`: complete observed evidence met the rule's failure condition.
- `NOT_APPLICABLE`: the required inventory operation succeeded but returned no resources of the rule's type.
- `NOT_SUPPORTED`: the operation or required response field/document was unavailable or omitted. An absent field never implies insecure configuration.
- `ERROR`: malformed response data or a failed required API operation prevented a sound evaluation.

The persisted schema allows `NOT_APPLICABLE`, but the current assessment runner represents an empty resource type as zero resource-level findings. This avoids presenting a placeholder scope identifier as a cloud resource. Zero findings must not be read as a security pass. Operation errors with no response payload have `evidence_sha256: null`; their persisted operation ID and sanitized error text are the evidence reference, while no response hash is available.

## Rule catalog

### AEGIS-IAM-001 — Avoid wildcard IAM permissions

**Severity:** High. **Resource:** local IAM managed policies. **Required operations:** IAM `ListPolicies(Scope=Local)` and `GetPolicyVersion` for each listed policy's `DefaultVersionId`.

The rule examines the returned policy `Document.Statement`. It reports `FAIL` when any `Effect: Allow` statement has an action string containing `*` or a resource string containing `*`. Thus `s3:*` and `bucket/*` both match the simple detector; a wildcard in a resource path can still be intentionally narrow, so this is a policy-pattern warning, not proof that access is globally exploitable. It reports `PASS` only if every statement is valid and no wildcard is present. Missing default version/document is `NOT_SUPPORTED`; malformed statements, effects, actions, or resources are `ERROR`. `Deny` statements are not treated as broad grants. This does not resolve groups, inline policies, permission boundaries, SCPs, conditions, or effective permissions.

**Remediation:** Replace broad action/resource patterns with the minimum explicit permissions required and validate dependent workloads before rollout.

### AEGIS-EC2-001 — Restrict public SSH and RDP ingress

**Severity:** High. **Resource:** EC2 security groups. **Required operation:** EC2 `DescribeSecurityGroups`.

The rule checks observed `IpPermissions`. It reports `FAIL` for protocol `-1`, or TCP port ranges overlapping 22 or 3389, when an IPv4 range is `0.0.0.0/0` or an IPv6 range is `::/0`. Complete observed rules without these conditions are `PASS`. Missing `IpPermissions`, `IpRanges`, or `Ipv6Ranges` evidence is `NOT_SUPPORTED`; malformed protocols, port bounds, ranges, or CIDRs are `ERROR`. This identifies security-group configuration and does not prove that a resource is attached, routed from the internet, or reachable.

**Remediation:** Restrict management ingress to narrow approved source ranges or use a controlled administrative access path.

### AEGIS-LOGS-001 — Use at least 30 days of log retention

**Severity:** Medium. **Resource:** CloudWatch log groups. **Required operation:** Logs `DescribeLogGroups`.

This project-local baseline reports `FAIL` for a valid explicit `retentionInDays` value below 30 and `PASS` for values of 30 or more. Omitted retention is `NOT_SUPPORTED`, not proof that retention is unlimited. Zero has unverified semantics in this adapter and is `NOT_SUPPORTED`; invalid values are `ERROR`. The 30-day threshold is not mapped to a benchmark and may not meet organizational requirements.

**Remediation:** Set and periodically review a retention period based on approved operational, legal, and incident-response requirements.

## Evidence, persistence, and comparisons

Each assessment stores normalized inventory, sanitized source operation responses and SHA-256 hashes. Findings retain the IDs, statuses, subject resource where available, and hashes of supporting operation evidence. Assessment UUID and UTC collection/evaluation timestamps make runs traceable. A later finding records `FIRST_SEEN`, `UNCHANGED`, or `CHANGED` compared with the most recent prior finding for the same endpoint, rule, and resource. These hashes are local integrity checks, not tamper-proof audit storage.

Before detector logic runs, the assessment runner requires a successful operation record for every declared `required_evidence` entry, scoped to that resource where the adapter provides a subject ID (notably IAM policy versions). A failed or unsupported required operation yields a resource-specific `ERROR` or `NOT_SUPPORTED` result, never a detector-derived `FAIL` or `PASS`.

Discovery status is `COMPLETED` when all recorded operations succeed, `PARTIAL` when at least one succeeds and another fails, is unsupported, or is incomplete, and `FAILED` when none succeeds. Assessment status is also changed from `COMPLETED` to `PARTIAL` if any resource rule returns `NOT_SUPPORTED` or `ERROR`; it remains `FAILED` when discovery had no successful operation. Only confirmed resource-specific `FAIL` outcomes contribute to severity counts; operation/evaluation errors and incomplete pagination are reported separately.

No finding maps to CIS, NIST, or another framework in this phase. No finding represents exploit validation or effective authorization analysis.
