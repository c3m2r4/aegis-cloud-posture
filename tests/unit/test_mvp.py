from __future__ import annotations

import json

from typer.testing import CliRunner

from aegis.adapters import FlociAdapter, OperationResult, specifications
from aegis.cli import app
from aegis.config import Settings
from aegis.evidence import canonical_json, evidence_hash, sanitize
from aegis.service import export_assessment, run_discovery


class FakeClient:
    DEFAULTS = {
        "get_caller_identity": {"Account": "000000000000"}, "list_buckets": {"Buckets": []},
        "describe_instances": {"Reservations": []}, "describe_images": {"Images": []},
        "describe_vpcs": {"Vpcs": []}, "describe_volumes": {"Volumes": []},
        "describe_subnets": {"Subnets": []}, "describe_network_interfaces": {"NetworkInterfaces": []},
        "describe_route_tables": {"RouteTables": []}, "describe_internet_gateways": {"InternetGateways": []},
        "describe_nat_gateways": {"NatGateways": []},
        "list_policies": {"Policies": []}, "list_users": {"Users": []}, "list_roles": {"Roles": []},
        "list_groups": {"Groups": []}, "list_instance_profiles": {"InstanceProfiles": []},
        "describe_log_groups": {"logGroups": []},
        "describe_security_groups": {"SecurityGroups": []}, "list_functions": {"Functions": []},
        "list_layers": {"Layers": []}, "get_apis": {"Items": []},
        "list_clusters": {"clusters": [], "clusterArns": []}, "list_nodegroups": {"nodegroups": []},
        "list_fargate_profiles": {"fargateProfileNames": []}, "describe_db_instances": {"DBInstances": []},
        "describe_db_clusters": {"DBClusters": []},
        "describe_db_subnet_groups": {"DBSubnetGroups": []}, "describe_db_snapshots": {"DBSnapshots": []},
        "list_tables": {"TableNames": []}, "describe_load_balancers": {"LoadBalancers": [], "LoadBalancerDescriptions": []},
        "list_queues": {"QueueUrls": []}, "get_rest_apis": {"items": []},
        "list_event_buses": {"EventBuses": []}, "list_rules": {"Rules": []}, "list_identities": {"Identities": []},
        "list_state_machines": {"stateMachines": []}, "list_stacks": {"StackSummaries": []},
        "list_secrets": {"SecretList": []}, "list_keys": {"Keys": []},
        "describe_parameters": {"Parameters": []}, "list_schedules": {"Schedules": []},
        "describe_repositories": {"repositories": []},
    }

    def __init__(self, responses, service):
        self.responses = responses
        self.service = service

    def __getattr__(self, name):
        if name == "get_policy_version":
            return lambda **_kwargs: self.responses.get("VersionResponse", {"PolicyVersion": {"Document": {"Statement": []}}})
        if name not in self.DEFAULTS:
            raise AttributeError(name)
        if name == "describe_load_balancers":
            key = "LoadBalancerDescriptions" if self.service == "elb" else "LoadBalancers"
            return lambda **_kwargs: self.responses.get(name, {key: []})
        return lambda **_kwargs: self.responses.get({
            "get_caller_identity": "GetCallerIdentity", "list_buckets": "ListBuckets",
            "describe_instances": "DescribeInstances", "describe_log_groups": "DescribeLogGroups",
            "list_policies": "ListPolicies", "list_event_buses": "ListEventBuses",
            "list_rules": "ListRules", "list_stacks": "ListStacks",
            "list_clusters": "ListClusters",
            "list_instance_profiles": "ListInstanceProfiles", "list_layers": "ListLayers",
            "get_apis": "GetApis", "describe_db_clusters": "DescribeDBClusters",
            "list_nodegroups": "ListNodegroups", "list_fargate_profiles": "ListFargateProfiles",
        }.get(name, name), self.DEFAULTS[name])


class FakeSession:
    def __init__(self, responses):
        self.responses = responses

    def client(self, service, **_kwargs):
        return FakeClient(self.responses, service)


def test_sanitization_redacts_sensitive_fields_and_tokens():
    value = {"SecretString": "nope", "Authorization": "Bearer " + "unit-test-token-value", "note": "key " + "AKIA" + "ABCDEFGHIJKLMNOP"}
    safe = sanitize(value)
    assert safe["SecretString"] == "[REDACTED]"
    assert safe["Authorization"] == "[REDACTED]"
    assert ("AKIA" + "ABCDEFGHIJKLMNOP") not in safe["note"]
    assert evidence_hash(value) == evidence_hash(safe)


def test_discovery_persists_normalized_resources_and_cloudwatch_stored_bytes(tmp_path):
    responses = {
        "GetCallerIdentity": {"Account": "000000000000", "Arn": "arn:aws:iam::000000000000:root"},
        "ListBuckets": {"Buckets": [{"Name": "alpha", "CreationDate": "2026-01-01"}]},
        "DescribeInstances": {"Reservations": [{"Instances": [{"InstanceId": "i-1", "State": {"Name": "running"}}]}]},
        "ListPolicies": {"Policies": [{"Arn": "arn:aws:iam::000000000000:policy/test", "PolicyName": "test", "DefaultVersionId": "v1"}],
            "VersionResponse": {"PolicyVersion": {"VersionId": "v1", "Document": {"Statement": []}}}},
        "DescribeLogGroups": {"logGroups": [
            {"logGroupName": "empty", "storedBytes": 0},
            {"logGroupName": "used", "storedBytes": 128},
            {"logGroupName": "legacy"},
        ]},
    }
    settings = Settings(database=tmp_path / "aegis.sqlite")
    adapter = FlociAdapter(settings, session=FakeSession(responses))
    assessment_id = run_discovery(settings, adapter=adapter)
    export = export_assessment(settings, assessment_id)
    assert export["assessment"]["status"] == "COMPLETED"
    assert len(export["operations"]) >= 6
    assert {r["resource_type"] for r in export["resources"]} >= {"s3_bucket", "ec2_instance", "iam_policy", "cloudwatch_log_group", "aws_identity"}
    groups = {r["resource_id"]: r["attributes"] for r in export["resources"] if r["resource_type"] == "cloudwatch_log_group"}
    assert groups["empty"]["storedBytes"] == 0
    assert groups["used"]["storedBytes"] == 128
    assert "storedBytes" not in groups["legacy"]
    assert all(item["evidence_sha256"] for item in export["operations"])


def test_empty_service_lists_are_success_not_invented_resources(tmp_path):
    responses = {"GetCallerIdentity": {"Account": "000000000000"}, "ListBuckets": {"Buckets": []}, "DescribeInstances": {"Reservations": []},
                 "ListPolicies": {"Policies": []}, "DescribeLogGroups": {"logGroups": []}}
    settings = Settings(database=tmp_path / "empty.sqlite")
    assessment_id = run_discovery(settings, FlociAdapter(settings, session=FakeSession(responses)))
    export = export_assessment(settings, assessment_id)
    assert {item["resource_type"] for item in export["resources"]} <= {"aws_identity"}
    assert all(op["status"] == "SUCCESS" for op in export["operations"])


def test_partial_unsupported_is_separate_from_api_error(tmp_path):
    class PartialAdapter:
        def collect(self):
            return [
                OperationResult("s3", "ListBuckets", "SUPPORTED_AND_TESTED", "SUCCESS", response={"Buckets": []}, resources=[], observed_at="now"),
                OperationResult("iam", "ListPolicies", "UNSUPPORTED", "UNSUPPORTED", error="NotImplemented", observed_at="now"),
                OperationResult("logs", "DescribeLogGroups", "SUPPORTED_BUT_UNVERIFIED", "ERROR", error="timeout", observed_at="now"),
            ]
    settings = Settings(database=tmp_path / "partial.sqlite")
    assessment_id = run_discovery(settings, PartialAdapter())
    data = export_assessment(settings, assessment_id)
    assert data["assessment"]["status"] == "PARTIAL"
    assert [op["status"] for op in data["operations"]] == ["SUCCESS", "UNSUPPORTED", "ERROR"]
    assert [op["capability"] for op in data["operations"]] == ["SUPPORTED_AND_TESTED", "UNSUPPORTED", "SUPPORTED_BUT_UNVERIFIED"]


def test_cli_discover_json_with_mocked_adapters(monkeypatch, tmp_path):
    import aegis.cli as cli
    responses = {"GetCallerIdentity": {"Account": "000000000000"}, "ListBuckets": {"Buckets": []},
                 "DescribeInstances": {"Reservations": []}, "ListPolicies": {"Policies": []}, "DescribeLogGroups": {"logGroups": []}}
    settings = Settings(database=tmp_path / "cli.sqlite")
    monkeypatch.setattr(cli, "_settings", lambda: settings)
    monkeypatch.setattr(cli, "run_discovery", lambda s: run_discovery(s, FlociAdapter(s, session=FakeSession(responses))))
    result = CliRunner().invoke(app, ["discover", "--json"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert parsed["assessment"]["status"] == "COMPLETED"


def test_secret_values_are_redacted_before_database_and_export(tmp_path):
    import sqlite3
    responses = {
        "GetCallerIdentity": {"Account": "000000000000"},
        "ListBuckets": {"Buckets": [{"Name": "example", "SecretAccessKey": "unit-test-secret"}]},
        "DescribeInstances": {"Reservations": []},
        "ListPolicies": {"Policies": []},
        "DescribeLogGroups": {"logGroups": []},
    }
    settings = Settings(database=tmp_path / "redacted.sqlite")
    assessment_id = run_discovery(settings, FlociAdapter(settings, session=FakeSession(responses)))
    with sqlite3.connect(settings.database) as db:
        persisted = " ".join(str(row) for row in db.execute("SELECT evidence_json FROM operations"))
        persisted += " " + " ".join(str(row) for row in db.execute("SELECT attributes_json FROM resources"))
    exported = json.dumps(export_assessment(settings, assessment_id))
    assert "unit-test-secret" not in persisted
    assert "unit-test-secret" not in exported
    assert "[REDACTED]" in persisted


def test_malformed_service_list_response_is_error_not_empty_inventory():
    from aegis.adapters import specifications
    settings = Settings()
    adapter = FlociAdapter(settings, session=FakeSession({"ListBuckets": {"Unexpected": []}}))
    spec = next(item for item in specifications() if item.operation == "ListBuckets")
    result = adapter.collect_one(spec)
    assert result.status == "ERROR"
    assert result.capability == "SUPPORTED_AND_TESTED"
    assert result.resources == []
    assert result.response is None
    assert result.error.startswith("MalformedResponse:")


def test_new_discovery_normalizers_preserve_resource_identity_and_type():
    cases = [
        (("ec2", "DescribeImages"), {"Images": [{"ImageId": "ami-1", "Name": "image", "Description": "free-form marker"}]}, "ec2_image", "ami-1"),
        (("ec2", "DescribeVpcs"), {"Vpcs": [{"VpcId": "vpc-1", "Description": "free-form marker", "Tags": [{"Key": "Name", "Value": "net"}]}]}, "ec2_vpc", "vpc-1"),
        (("ec2", "DescribeVolumes"), {"Volumes": [{"VolumeId": "vol-1", "Encrypted": True}]}, "ec2_volume", "vol-1"),
        (("ec2", "DescribeSubnets"), {"Subnets": [{"SubnetId": "subnet-1"}]}, "ec2_subnet", "subnet-1"),
        (("ec2", "DescribeNetworkInterfaces"), {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1"}]}, "ec2_network_interface", "eni-1"),
        (("ec2", "DescribeRouteTables"), {"RouteTables": [{"RouteTableId": "rtb-1"}]}, "ec2_route_table", "rtb-1"),
        (("ec2", "DescribeInternetGateways"), {"InternetGateways": [{"InternetGatewayId": "igw-1"}]}, "ec2_internet_gateway", "igw-1"),
        (("ec2", "DescribeNatGateways"), {"NatGateways": [{"NatGatewayId": "nat-1"}]}, "ec2_nat_gateway", "nat-1"),
        (("iam", "ListUsers"), {"Users": [{"Arn": "arn:user:1", "UserName": "u"}]}, "iam_user", "arn:user:1"),
        (("iam", "ListRoles"), {"Roles": [{"Arn": "arn:role:1", "RoleName": "r"}]}, "iam_role", "arn:role:1"),
        (("iam", "ListGroups"), {"Groups": [{"Arn": "arn:group:1", "GroupName": "g"}]}, "iam_group", "arn:group:1"),
        (("iam", "ListInstanceProfiles"), {"InstanceProfiles": [{"Arn": "arn:profile:1", "InstanceProfileName": "profile", "Roles": [{"RoleName": "nested"}]}]}, "iam_instance_profile", "arn:profile:1"),
        (("lambda", "ListFunctions"), {"Functions": [{"FunctionArn": "arn:lambda:1", "FunctionName": "fn", "Environment": {"Variables": {"TOKEN": "do-not-store"}}}]}, "lambda_function", "arn:lambda:1"),
        (("lambda", "ListLayers"), {"Layers": [{"LayerArn": "arn:layer:1", "LayerName": "layer"}]}, "lambda_layer", "arn:layer:1"),
        (("eks", "ListClusters"), {"clusters": ["cluster"]}, "eks_cluster", "cluster"),
        (("ecs", "ListClusters"), {"clusterArns": ["arn:ecs:1"]}, "ecs_cluster", "arn:ecs:1"),
        (("ecr", "DescribeRepositories"), {"repositories": [{"repositoryArn": "arn:ecr:1", "repositoryName": "repo"}]}, "ecr_repository", "arn:ecr:1"),
        (("rds", "DescribeDBInstances"), {"DBInstances": [{"DBInstanceArn": "arn:rds:1", "DBInstanceIdentifier": "db"}]}, "rds_db_instance", "arn:rds:1"),
        (("rds", "DescribeDBClusters"), {"DBClusters": [{"DBClusterArn": "arn:rds:cluster:1", "DBClusterIdentifier": "cluster"}]}, "rds_db_cluster", "arn:rds:cluster:1"),
        (("rds", "DescribeDBSubnetGroups"), {"DBSubnetGroups": [{"DBSubnetGroupArn": "arn:rds:subnet:1", "DBSubnetGroupName": "subnets"}]}, "rds_db_subnet_group", "arn:rds:subnet:1"),
        (("rds", "DescribeDBSnapshots"), {"DBSnapshots": [{"DBSnapshotArn": "arn:rds:snap:1", "DBSnapshotIdentifier": "snap"}]}, "rds_db_snapshot", "arn:rds:snap:1"),
        (("dynamodb", "ListTables"), {"TableNames": ["table"]}, "dynamodb_table", "table"),
        (("elbv2", "DescribeLoadBalancers"), {"LoadBalancers": [{"LoadBalancerArn": "arn:lb:1", "LoadBalancerName": "lb"}]}, "elbv2_load_balancer", "arn:lb:1"),
        (("elb", "DescribeLoadBalancers"), {"LoadBalancerDescriptions": [{"LoadBalancerName": "classic-lb", "DNSName": "lb.local"}]}, "elb_load_balancer", "classic-lb"),
        (("sqs", "ListQueues"), {"QueueUrls": ["http://local/123/queue"]}, "sqs_queue", "http://local/123/queue"),
        (("apigateway", "GetRestApis"), {"items": [{"id": "api-1", "name": "api"}]}, "apigateway_rest_api", "api-1"),
        (("apigatewayv2", "GetApis"), {"Items": [{"ApiId": "api-v2-1", "Name": "api v2"}]}, "apigatewayv2_api", "api-v2-1"),
        (("events", "ListEventBuses"), {"EventBuses": [{"Arn": "arn:events:1", "Name": "bus"}]}, "eventbridge_event_bus", "arn:events:1"),
        (("events", "ListRules"), {"Rules": [{"Arn": "arn:rule:1", "Name": "rule"}]}, "eventbridge_rule", "arn:rule:1"),
        (("ses", "ListIdentities"), {"Identities": ["example.test"]}, "ses_identity", "example.test"),
        (("stepfunctions", "ListStateMachines"), {"stateMachines": [{"stateMachineArn": "arn:sfn:1", "name": "flow"}]}, "stepfunctions_state_machine", "arn:sfn:1"),
        (("cloudformation", "ListStacks"), {"StackSummaries": [{"StackId": "arn:stack:1", "StackName": "stack"}]}, "cloudformation_stack", "arn:stack:1"),
        (("secretsmanager", "ListSecrets"), {"SecretList": [{"ARN": "arn:secret:1", "Name": "metadata"}]}, "secretsmanager_secret", "arn:secret:1"),
        (("kms", "ListKeys"), {"Keys": [{"KeyArn": "arn:kms:1", "KeyId": "key-id"}]}, "kms_key", "arn:kms:1"),
        (("ssm", "DescribeParameters"), {"Parameters": [{"Name": "/app/config", "Type": "SecureString", "LastModifiedUser": "free-form marker"}]}, "ssm_parameter", "/app/config"),
        (("scheduler", "ListSchedules"), {"Schedules": [{"Arn": "arn:scheduler:1", "Name": "schedule"}]}, "scheduler_schedule", "arn:scheduler:1"),
    ]
    specs = {(spec.service, spec.operation): spec for spec in specifications()}
    for key, response, resource_type, resource_id in cases:
        resource, = specs[key].normalize(response)
        assert resource["resource_type"] == resource_type
        assert resource["resource_id"] == resource_id
        assert resource["name"]
    case_responses = {key: response for key, response, _type, _id in cases}
    assert "Environment" not in specs[("lambda", "ListFunctions")].normalize(case_responses[("lambda", "ListFunctions")])[0]["attributes"]
    assert "Parameters" not in specs[("cloudformation", "ListStacks")].normalize(case_responses[("cloudformation", "ListStacks")])[0]["attributes"]
    assert "Description" not in specs[("ec2", "DescribeImages")].normalize(case_responses[("ec2", "DescribeImages")])[0]["attributes"]
    assert "Description" not in specs[("ec2", "DescribeVpcs")].normalize(case_responses[("ec2", "DescribeVpcs")])[0]["attributes"]
    assert "Roles" not in specs[("iam", "ListInstanceProfiles")].normalize(case_responses[("iam", "ListInstanceProfiles")])[0]["attributes"]
    assert "LastModifiedUser" not in specs[("ssm", "DescribeParameters")].normalize(case_responses[("ssm", "DescribeParameters")])[0]["attributes"]


def test_unverified_continuation_marker_is_incomplete_not_empty_or_success():
    settings = Settings()
    spec = next(item for item in specifications() if (item.service, item.operation) == ("s3", "ListBuckets"))
    adapter = FlociAdapter(settings, session=FakeSession({"ListBuckets": {
        "Buckets": [{"Name": "first"}], "NextToken": "next-page"}}))
    result = adapter.collect_one(spec)
    assert result.status == "INCOMPLETE"
    assert result.resources[0]["resource_id"] == "first"
    assert "Pagination" in result.error


def test_lambda_and_cloudformation_persistence_payloads_exclude_secret_bearing_fields():
    from aegis.config import Settings
    responses = {
        "ListFunctions": {"Functions": [{"FunctionArn": "arn:lambda:1", "FunctionName": "fn",
                         "Environment": {"Variables": {"TOKEN": "sensitive-value"}}}]},
        "ListStacks": {"StackSummaries": [{"StackId": "arn:stack:1", "StackName": "stack"}]},
    }
    collected = FlociAdapter(Settings(), session=FakeSession(responses)).collect()
    stored_payloads = [item.response for item in collected if item.operation in {"ListFunctions", "ListStacks"}]
    assert "sensitive-value" not in json.dumps(stored_payloads)


def test_sensitive_cloud_tag_values_are_redacted():
    safe = sanitize({"Tags": [{"Key": "API_TOKEN", "Value": "sensitive-value"},
                              {"Key": "Name", "Value": "ordinary"}]})
    assert safe["Tags"][0]["Value"] == "[REDACTED]"
    assert safe["Tags"][1]["Value"] == "ordinary"


def test_eventbridge_rules_are_listed_once_for_default_and_each_named_bus():
    adapter = FlociAdapter(Settings(), session=FakeSession({
        "ListEventBuses": {"EventBuses": [{"Name": "default", "Arn": "arn:bus:default"},
                                           {"Name": "custom", "Arn": "arn:bus:custom"}]},
        "ListRules": {"Rules": [{"Arn": "arn:rule:test", "Name": "rule", "EventBusName": "custom"}]},
    }))
    results = adapter.collect()
    rule_calls = [result for result in results if result.service == "events" and result.operation == "ListRules"]
    assert len(rule_calls) == 2
    assert all(result.status == "SUCCESS" for result in rule_calls)
    assert {result.subject_resource_id for result in rule_calls} == {"default", "custom"}
    assert all(result.resources for result in rule_calls)


def test_eks_cluster_scoped_inventory_calls_are_bounded_and_normalized():
    class CapturingClient(FakeClient):
        def __getattr__(self, name):
            if name in {"list_nodegroups", "list_fargate_profiles"}:
                def call(**kwargs):
                    calls.append((name, kwargs))
                    key = "ListNodegroups" if name == "list_nodegroups" else "ListFargateProfiles"
                    return self.responses[key]
                return call
            return super().__getattr__(name)

    calls = []

    class CapturingSession(FakeSession):
        def client(self, service, **_kwargs):
            if service == "eks":
                return CapturingClient(self.responses, service)
            return super().client(service)

    adapter = FlociAdapter(Settings(), session=CapturingSession({
        "ListClusters": {"clusters": ["cluster-a"], "clusterArns": []},
        "ListNodegroups": {"nodegroups": ["workers"]},
        "ListFargateProfiles": {"fargateProfileNames": ["serverless"]},
    }))
    results = adapter.collect()
    related = [result for result in results if result.operation in {"ListNodegroups", "ListFargateProfiles"}]
    assert len(related) == 2
    assert all(result.status == "SUCCESS" for result in related)
    assert {result.resources[0]["resource_type"] for result in related} == {"eks_nodegroup", "eks_fargate_profile"}
    assert {result.resources[0]["resource_id"] for result in related} == {"cluster-a/workers", "cluster-a/serverless"}
    assert calls == [("list_nodegroups", {"clusterName": "cluster-a", "maxResults": 100}),
                     ("list_fargate_profiles", {"clusterName": "cluster-a", "maxResults": 100})]


def test_classic_and_v2_load_balancer_calls_use_verified_bounded_page_size():
    # These operations share the SDK method name but use distinct service clients.
    class Client:
        def describe_load_balancers(self, **kwargs):
            calls.append(kwargs)
            return {}

    calls = []
    for service in ("elb", "elbv2"):
        spec = next(item for item in specifications()
                    if item.service == service and item.operation == "DescribeLoadBalancers")
        spec.invoke(Client())
    assert calls == [{"PageSize": 100}, {"PageSize": 100}]
