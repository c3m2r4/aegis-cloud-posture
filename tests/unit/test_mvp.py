from __future__ import annotations

import json

from typer.testing import CliRunner

from aegis.adapters import FlociAdapter, OperationResult, specifications
from aegis.cli import app
from aegis.config import Settings
from aegis.evidence import canonical_json, evidence_hash, sanitize
from aegis.service import export_assessment, run_discovery


class FakeClient:
    def __init__(self, payload):
        self.payload = payload

    def get_caller_identity(self):
        return self.payload

    def list_buckets(self):
        return self.payload

    def describe_instances(self):
        return self.payload

    def list_policies(self, **_kwargs):
        return self.payload

    def describe_log_groups(self):
        return self.payload

    def describe_security_groups(self):
        return {"SecurityGroups": []}

    def get_policy_version(self, **_kwargs):
        return self.payload.get("VersionResponse", {"PolicyVersion": {"Document": {"Statement": []}}})


class FakeSession:
    def __init__(self, responses):
        self.responses = responses

    def client(self, service, **_kwargs):
        key = {"sts": "GetCallerIdentity", "s3": "ListBuckets", "ec2": "DescribeInstances",
               "iam": "ListPolicies", "logs": "DescribeLogGroups"}[service]
        return FakeClient(self.responses[key])


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
    assert result.response == {"Unexpected": []}
    assert result.error.startswith("MalformedResponse:")
