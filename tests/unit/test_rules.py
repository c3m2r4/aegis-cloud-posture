from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from aegis.adapters import FlociAdapter, OperationResult
from aegis.cli import app
from aegis.config import Settings
from aegis.rules import RULES, evaluate
from aegis.service import export_assessment, run_assessment


RULE_BY_ID = {rule.rule_id: rule for rule in RULES}


def iam_resource(document=None, include=True):
    attrs = {"PolicyVersion": {"Document": document}} if include else {}
    return {"resource_type": "iam_policy", "resource_id": "arn:policy:test", "attributes": attrs}


def sg_resource(permissions=None, include=True):
    attrs = {"IpPermissions": permissions} if include else {}
    return {"resource_type": "ec2_security_group", "resource_id": "sg-1", "attributes": attrs}


def log_resource(retention="MISSING"):
    attrs = {"logGroupName": "app"}
    if retention != "MISSING":
        attrs["retentionInDays"] = retention
    return {"resource_type": "cloudwatch_log_group", "resource_id": "app", "attributes": attrs}


@pytest.mark.parametrize("document", [
    {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::specific"}},
    {"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::specific"}},
    {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}},
    {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}},
])
def test_iam_wildcard_rule_fails_positive_cases(document):
    result = evaluate(RULE_BY_ID["AEGIS-IAM-001"], iam_resource(document))
    assert result.outcome == "FAIL"
    assert result.reason


def test_iam_wildcard_rule_passes_narrow_policy():
    document = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::private/object"]}]}
    assert evaluate(RULE_BY_ID["AEGIS-IAM-001"], iam_resource(document)).outcome == "PASS"


@pytest.mark.parametrize("resource", [iam_resource(include=False), {"attributes": []},
                                      iam_resource({"Statement": [{"Effect": "Allow", "Action": "*"}]})])
def test_iam_rule_handles_incomplete_and_malformed_evidence(resource):
    outcome = evaluate(RULE_BY_ID["AEGIS-IAM-001"], resource).outcome
    assert outcome in {"NOT_SUPPORTED", "ERROR"}


@pytest.mark.parametrize("permission", [
    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []},
    {"IpProtocol": "tcp", "FromPort": 3300, "ToPort": 3400, "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
    {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []},
])
def test_security_group_rule_fails_public_management_exposure(permission):
    assert evaluate(RULE_BY_ID["AEGIS-EC2-001"], sg_resource([permission])).outcome == "FAIL"


@pytest.mark.parametrize("permission", [
    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": []},
    {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []},
    {"IpProtocol": "udp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [], "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/32"}]},
])
def test_security_group_rule_passes_non_public_management(permission):
    assert evaluate(RULE_BY_ID["AEGIS-EC2-001"], sg_resource([permission])).outcome == "PASS"


@pytest.mark.parametrize("resource", [sg_resource(include=False), {"attributes": []},
                                      sg_resource([{"IpProtocol": "tcp", "FromPort": "22", "ToPort": 22}])])
def test_security_group_rule_handles_incomplete_and_malformed_evidence(resource):
    result = evaluate(RULE_BY_ID["AEGIS-EC2-001"], resource)
    assert result.outcome in {"NOT_SUPPORTED", "ERROR"}


@pytest.mark.parametrize("days,outcome", [(7, "FAIL"), (30, "PASS"), (365, "PASS")])
def test_log_retention_rule_positive_and_negative(days, outcome):
    assert evaluate(RULE_BY_ID["AEGIS-LOGS-001"], log_resource(days)).outcome == outcome


@pytest.mark.parametrize("resource,outcome", [(log_resource(), "NOT_SUPPORTED"),
                                               (log_resource("bad"), "ERROR"),
                                               (log_resource(-1), "ERROR"),
                                               (log_resource(0), "NOT_SUPPORTED")])
def test_log_retention_incomplete_and_malformed(resource, outcome):
    assert evaluate(RULE_BY_ID["AEGIS-LOGS-001"], resource).outcome == outcome


class FakeClient:
    def __init__(self, service, payloads):
        self.service, self.payloads = service, payloads

    def get_caller_identity(self): return self.payloads["sts"]
    def list_buckets(self): return self.payloads["s3"]
    def describe_instances(self): return self.payloads["ec2"]
    def list_policies(self, **kwargs): return self.payloads["iam"]
    def describe_log_groups(self): return self.payloads["logs"]
    def describe_security_groups(self): return self.payloads["security_groups"]
    def get_policy_version(self, **kwargs): return self.payloads["policy_version"]


class FakeSession:
    def __init__(self, payloads): self.payloads = payloads
    def client(self, service, **kwargs): return FakeClient(service, self.payloads)


def payloads(policy_document):
    return {
        "sts": {"Account": "000000000000"}, "s3": {"Buckets": []},
        "ec2": {"Reservations": []},
        "iam": {"Policies": [{"Arn": "arn:aws:iam::000000000000:policy/test", "PolicyName": "test", "DefaultVersionId": "v1"}]},
        "policy_version": {"PolicyVersion": {"VersionId": "v1", "Document": policy_document}},
        "logs": {"logGroups": [{"logGroupName": "app", "storedBytes": 1}]},
        "security_groups": {"SecurityGroups": [{"GroupId": "sg-1", "GroupName": "test", "IpPermissions": []}]},
    }


def test_findings_persist_evidence_references_and_compare_runs(tmp_path):
    settings = Settings(database=tmp_path / "assessment.sqlite")
    adapter = FlociAdapter(settings, session=FakeSession(payloads({"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})))
    first = run_assessment(settings, adapter)
    first_data = export_assessment(settings, first)
    assert first_data["summary"]["by_outcome"]["FAIL"] == 1
    fail = next(item for item in first_data["findings"] if item["rule_id"] == "AEGIS-IAM-001")
    assert fail["change_state"] == "FIRST_SEEN"
    assert {ref["operation"] for ref in fail["evidence_refs"]} == {"ListPolicies", "GetPolicyVersion"}

    second = run_assessment(settings, adapter)
    second_data = export_assessment(settings, second)
    second_fail = next(item for item in second_data["findings"] if item["rule_id"] == "AEGIS-IAM-001")
    assert second_fail["previous_outcome"] == "FAIL"
    assert second_fail["change_state"] == "UNCHANGED"

    safe_adapter = FlociAdapter(settings, session=FakeSession(payloads({"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/key"}})))
    third = run_assessment(settings, safe_adapter)
    third_data = export_assessment(settings, third)
    changed = next(item for item in third_data["findings"] if item["rule_id"] == "AEGIS-IAM-001")
    assert changed["previous_outcome"] == "FAIL"
    assert changed["change_state"] == "CHANGED"
    assert changed["outcome"] == "PASS"


def test_assess_cli_reports_summary_as_json(monkeypatch, tmp_path):
    import aegis.cli as cli
    settings = Settings(database=tmp_path / "cli-assess.sqlite")
    adapter = FlociAdapter(settings, session=FakeSession(payloads({"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})))
    monkeypatch.setattr(cli, "_settings", lambda: settings)
    monkeypatch.setattr(cli, "run_assessment", lambda _settings: run_assessment(_settings, adapter))
    result = CliRunner().invoke(app, ["assess", "--yes", "--json"])
    assert result.exit_code == 1, result.output
    data = json.loads(result.stdout)
    assert data["assessment"]["status"] == "PARTIAL"
    assert "by_outcome" in data["summary"] and "by_severity" in data["summary"]
    assert data["findings"]


def test_security_group_missing_cidr_array_is_not_supported():
    result = evaluate(RULE_BY_ID["AEGIS-EC2-001"], sg_resource([
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": []}
    ]))
    assert result.outcome == "NOT_SUPPORTED"


def test_security_group_invalid_cidr_is_error():
    result = evaluate(RULE_BY_ID["AEGIS-EC2-001"], sg_resource([
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
         "IpRanges": [{"CidrIp": "not-a-cidr"}], "Ipv6Ranges": []}
    ]))
    assert result.outcome == "ERROR"


def test_security_group_numeric_tcp_protocol_is_checked():
    permission = {"IpProtocol": "6", "FromPort": 22, "ToPort": 22,
                  "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}
    assert evaluate(RULE_BY_ID["AEGIS-EC2-001"], sg_resource([permission])).outcome == "FAIL"


@pytest.mark.parametrize("rule_id,resource", [
    ("AEGIS-IAM-001", {"resource_type": "iam_policy"}),
    ("AEGIS-EC2-001", {"resource_type": "ec2_security_group"}),
    ("AEGIS-LOGS-001", {"resource_type": "cloudwatch_log_group"}),
])
def test_absent_normalized_attributes_are_not_supported(rule_id, resource):
    assert evaluate(RULE_BY_ID[rule_id], resource).outcome == "NOT_SUPPORTED"
