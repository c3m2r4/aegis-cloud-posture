# AEGIS Discovery Audit

**Live Floci verification:** 2026-10-12 · AWS region `us-east-1` · AWS-compatible API `http://127.0.0.1:4566` · Floci console proxy `http://127.0.0.1:4500`

This audit records what AEGIS actually enumerated from the local Floci runtime. It is not an AWS compatibility or account-wide coverage claim. Discovery uses the read-only boto3 allowlist in `src/aegis/adapters.py`; it does not import the Floci lab bootstrap or call the console's create/update/delete routes.

## Root cause and result

The previous AEGIS adapter called only six top-level read operations (STS identity, S3 buckets, EC2 instances and security groups, IAM local policies, and CloudWatch log groups), then fetched one IAM default policy version per listed policy. Those calls succeeded, but the allowlist never asked the other AWS services for their inventory. SQLite retained each assessment snapshot and its operations; the resources were not discarded by the dashboard or overwritten by a later run.

The pre-change project database had 12 saved assessments. Its latest snapshot had 7 successful operation records and 15 resource records: 13 cloud inventory objects plus the `aws_identity` and `iam_policy_version` evidence records. Its cloud inventory types were S3 buckets (5), EC2 instances (1), EC2 security groups (3), log groups (3), and IAM policies (1). The identity and policy-version rows are useful evidence, but are not counted as independent cloud assets.

After extending discovery, a fresh read-only scan against the same local endpoint made 46 API calls; all 46 returned successfully, and none returned a continuation token. This comprised 42 fixed allowlisted calls plus dependent calls for the returned local IAM policy, additional EventBridge bus, and EKS cluster. AEGIS persisted 56 resource records in the isolated assessment: **54 unique cloud inventory objects** plus the `aws_identity` and `iam_policy_version` evidence records. A new scan is required for an existing database to show the extended inventory; historic snapshots remain unchanged.

## Service coverage matrix

“Enumerated” means the AEGIS allowlisted operation or operations for that category returned successfully for this Floci snapshot. It does not mean AEGIS covers every AWS resource kind or every operation in that service. A successful empty list is recorded as an empty result, not as an unsupported service.

| Category | Verified read operations | Floci result in this run | AEGIS resources |
|---|---|---:|---:|
| Compute | `ec2:DescribeInstances`, `ec2:DescribeImages` | 1 instance, 10 images | 11 |
| EKS | `eks:ListClusters`; `eks:ListNodegroups` and `eks:ListFargateProfiles` for each returned cluster | 1 cluster; related lists empty | 1 |
| Serverless | `lambda:ListFunctions`, `lambda:ListLayers` | 1 function; layers empty | 1 |
| Containers | `ecs:ListClusters`, `ecr:DescribeRepositories` | Both succeeded; empty | 0 |
| Storage | `s3:ListBuckets`, `ec2:DescribeVolumes` | 5 buckets, 1 volume | 6 |
| Database | `rds:DescribeDBInstances`, `rds:DescribeDBClusters`, `rds:DescribeDBSubnetGroups`, `rds:DescribeDBSnapshots` | 1 instance, 1 subnet group; clusters and snapshots empty | 2 |
| DynamoDB | `dynamodb:ListTables` | 1 table | 1 |
| Networking | `ec2:DescribeVpcs`, `DescribeSubnets`, `DescribeNetworkInterfaces`, `DescribeSecurityGroups`, `DescribeRouteTables`, `DescribeInternetGateways`, `DescribeNatGateways` | 2 VPCs, 5 subnets, 1 interface, 3 security groups, 2 route tables, 1 internet gateway, no NAT gateways | 14 |
| ELB | `elb:DescribeLoadBalancers`, `elbv2:DescribeLoadBalancers` (each with `PageSize=100`) | Classic list empty; 1 v2 load balancer | 1 |
| SQS | `sqs:ListQueues` | 1 queue | 1 |
| API Gateway | `apigateway:GetRestApis`, `apigatewayv2:GetApis` | 1 REST API; v2 APIs empty | 1 |
| EventBridge | `events:ListEventBuses`; `events:ListRules` for the default and each named bus | 2 buses; no rules | 2 |
| SES identity | `ses:ListIdentities` for email identities | 1 identity | 1 |
| Cloud Scheduler | `scheduler:ListSchedules` | Succeeded; empty | 0 |
| Step Functions | `stepfunctions:ListStateMachines` | 1 state machine | 1 |
| CloudFormation | `cloudformation:ListStacks` (summary metadata only) | 1 stack | 1 |
| Identity | `iam:ListPolicies` (`Scope=Local`), `iam:ListUsers`, `iam:ListRoles`, `iam:ListGroups`, `iam:ListInstanceProfiles`; `iam:GetPolicyVersion` for each listed default version | 1 policy, 1 user, 1 role; groups and profiles empty; 1 policy-version evidence record | 3 |
| Secrets Manager | `secretsmanager:ListSecrets` (metadata only) | 1 secret | 1 |
| KMS | `kms:ListKeys` | 1 key | 1 |
| Parameter Store | `ssm:DescribeParameters` (metadata only) | 1 parameter | 1 |
| CloudWatch Logs | `logs:DescribeLogGroups` | 4 log groups | 4 |

The operation result was `46 SUCCESS`, including the additional `ListRules` call for the named event bus, the two EKS cluster-scoped calls, and the IAM policy-version call. The 54 inventory objects were unique by `(resource_type, resource_id)` in this assessment. The database enforces the same key within each assessment; endpoint and region are scoped by the parent assessment, with account identity recorded as a separate evidence resource, so historical runs remain separate snapshots.

## Floci console comparison

The current Floci console proxy returned 38 rows across its service resource-list endpoints, and all 38 `(service, type, id)` tuples were distinct. The direct AWS-compatible API scan returned 54 cloud resources. Using a mapping between console display types and AEGIS normalized resource types, 28 rows matched on identifier and 9 more matched on display name. One console “SES Mailbox” row had no AWS-resource match; the other 37 rows matched. AEGIS had 17 additional resources outside the console's normalized rows. This is a different inventory definition from direct AWS API discovery:

- 28 console rows had an identifier that exactly matched the corresponding direct API identifier.
- 9 more rows matched by normalized resource type and display name; the console often uses short names while AWS responses use ARNs or queue URLs.
- One console “SES Mailbox” row had no corresponding AWS resource match. The console record is a mailbox/message object, whereas `ses:ListIdentities` enumerates an AWS SES identity. AEGIS does not collect mailbox messages or their content.
- AEGIS's 17 additional cloud inventory objects comprise lower-level EC2 networking resources, EC2 images, an EBS volume, IAM roles/policies, and other API objects not included in the console's normalized category counts.

The current comparison is **38 Floci console rows versus 54 AEGIS cloud inventory objects**, with 37 matched console resources and one console-only mailbox object. The totals should not be forced to match. In particular, the console shows 19 of 21 categories available and marks Containers and Cloud Scheduler “coming soon”; the direct ECS/ECR and Scheduler list APIs responded successfully but returned empty results in this probe. The console label alone is not evidence that those AWS-compatible APIs are unsupported.

## Bounds, evidence, and status handling

- Client connect/read timeouts are explicit and SDK retries are disabled. Where a list API accepts a page-size parameter, AEGIS supplies a cap (typically 50 or 100; SQS uses 1,000). IAM default policy versions and EventBridge rules are requested only for at most the first 100 returned policies/buses.
- AEGIS detects common continuation fields, including `NextToken`, `nextToken`, `NextMarker`, IAM/KMS truncation flags, and DynamoDB continuation keys. It does not follow a cursor until that operation's Floci behavior is verified. A response with a continuation marker is stored with status `INCOMPLETE`; its resources are retained as partial observations, the assessment is partial, and rule evaluation cannot treat that response as complete evidence.
- Both classic ELB and ELBv2 `DescribeLoadBalancers` accept a caller-specified page size; AEGIS sends `PageSize=100`, verified successfully against Floci. CloudFormation `ListStacks` has no caller-specified page-size field in the SDK model, but the CloudFormation API bounds an individual response to 1 MB and returns `NextToken` if more data remains. AEGIS records such a marker as `INCOMPLETE` and does not fetch another page ([AWS `ListStacks` API](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ListStacks.html)). Pagination has not been verified by forcing a multi-page fixture against Floci.
- EC2 `DescribeKeyPairs` and `DescribeAddresses` were probed successfully, but are deferred: their current botocore operations expose no request-side page-size bound. They are not classified as unsupported. The `DescribeKeyPairs` probe returned one key pair, which is a known remaining inventory gap; `DescribeAddresses` returned an empty list.
- SES discovery is limited to `IdentityType=EmailAddress`; Floci's console mailbox object is not enumerated as an SES API resource. IAM policy enumeration is deliberately `Scope=Local`, matching the managed-policy assessment rule, and does not claim to inventory AWS-managed policies.
- `ListStacks` stores summary fields only. AEGIS never calls `GetSecretValue`, `GetParameter`, Lambda `GetFunction`, or a stack template/parameter operation. Lambda environment variables and CloudFormation parameters/outputs are not persisted. Secret metadata is limited to the `ListSecrets` response's normalized fields; secret values are never requested.
- Cloud resource identity uses the stable AWS identifier returned by each operation (ARNs where available; IDs/names for global or name-keyed APIs). Resource type distinguishes otherwise overlapping IDs. Since each assessment uses one configured endpoint and region, that scope is stored on the assessment rather than copied into each resource row.
- Discovery coverage, rule assessment coverage, and evidence-reference coverage are separate report fields. In this live run, 54 cloud resources were discovered, 8 resources had rule evaluations, and 46 discovered resources had no rule evaluation. Compute and Networking are marked `PARTIAL` in the service coverage view because verified EC2 listing operations are deferred for lack of a request-side page bound. No rule currently covers most of the newly inventoried types; they remain inventory-only and are not security passes.
- The current rules remain limited to IAM wildcard policy statements, public SSH/RDP security-group ingress, and CloudWatch retention where the returned field supports a conclusion. The live assessment was `PARTIAL`: 3 `PASS`, 1 confirmed `FAIL` (high severity), and 4 `NOT_SUPPORTED` log-retention evaluations because `retentionInDays` was absent. Discovery coverage success does not imply assessment coverage or compliance.

## Reproduction

The following requests use the local Floci endpoint and dummy emulator credentials only. They do not contact AWS when the endpoint is kept at loopback.

```bash
cd /home/camara/Aegis
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 \
  AEGIS_ENDPOINT_URL=http://127.0.0.1:4566 AEGIS_RUN_INTEGRATION=1 \
  .venv/bin/pytest -q tests/integration/test_floci.py
```

To create a new local assessment in the configured database, explicitly run `aegis assess --yes` or confirm the dashboard workflow. `aegis report` and the dashboard's ordinary GET routes read only the assessment already persisted.
