import threading

from aegis.adapters import OperationResult
from aegis.config import Settings
from aegis.reporting import build_report
from aegis.service import export_assessment, run_assessment
from aegis.web_db import read_only_connect


class StaticAdapter:
    def __init__(self, results):
        self.results = results

    def collect(self):
        return self.results


def operation(service, name, status="SUCCESS", resources=None, response=None, error=None, subject=None):
    return OperationResult(service, name, "SUPPORTED_AND_TESTED", status, response=response,
                           resources=resources or [], error=error, subject_resource_id=subject)


def base_success():
    return [
        operation("sts", "GetCallerIdentity", resources=[{"resource_type": "aws_identity", "resource_id": "account-1", "attributes": {}}]),
        operation("s3", "ListBuckets"),
        operation("ec2", "DescribeInstances"),
        operation("ec2", "DescribeSecurityGroups"),
        operation("iam", "ListPolicies"),
        operation("logs", "DescribeLogGroups"),
    ]


def assess(tmp_path, results):
    settings = Settings(database=tmp_path / "assessments.sqlite")
    assessment_id = run_assessment(settings, StaticAdapter(results))
    return export_assessment(settings, assessment_id)


def test_all_discovery_operations_fail_produces_no_scope_findings(tmp_path):
    results = [operation(service, name, "ERROR", error="NoCredentialsError") for service, name in [
        ("sts", "GetCallerIdentity"), ("s3", "ListBuckets"), ("ec2", "DescribeInstances"),
        ("ec2", "DescribeSecurityGroups"), ("iam", "ListPolicies"), ("logs", "DescribeLogGroups")]]
    result = assess(tmp_path, results)
    assert result["assessment"]["status"] == "FAILED"
    assert result["resources"] == []
    assert result["findings"] == []
    assert all(op["status"] == "ERROR" and op["evidence_sha256"] is None for op in result["operations"])
    report = build_report(result)
    assert report["summary"]["by_severity"]["HIGH"] == 0
    assert len(report["coverage"]["errors"]) == 6
    assert "No resources were discovered" in " ".join(report["coverage"]["limitations"])


def test_mixed_discovery_failures_are_partial_and_not_vulnerability_findings(tmp_path):
    results = base_success()
    results[2] = operation("ec2", "DescribeInstances", "ERROR", error="TimeoutError")
    results[3] = operation("ec2", "DescribeSecurityGroups", "UNSUPPORTED", error="NotImplemented")
    result = assess(tmp_path, results)
    assert result["assessment"]["status"] == "PARTIAL"
    assert result["findings"] == []
    report = build_report(result)
    assert len(report["coverage"]["errors"]) == 1
    assert len(report["coverage"]["unsupported_checks"]) == 1
    assert report["summary"]["by_severity"]["HIGH"] == 0


def test_successful_empty_discovery_has_no_scope_resource_or_pass_claim(tmp_path):
    results = base_success()
    result = assess(tmp_path, results)
    assert result["assessment"]["status"] == "COMPLETED"
    assert [resource["resource_type"] for resource in result["resources"]] == ["aws_identity"]
    assert result["findings"] == []
    report = build_report(result)
    assert report["scope"]["cloud_resource_count"] == 0
    markdown = __import__("aegis.reporting", fromlist=["render_markdown"]).render_markdown(report)
    assert "No resources were discovered" in markdown
    assert "not a security pass" in markdown


def test_resource_specific_failure_and_pass_are_persisted(tmp_path):
    results = base_success()
    group = {"GroupId": "sg-public", "IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                                        "Ipv6Ranges": []}]}
    results[3] = operation("ec2", "DescribeSecurityGroups", resources=[{
        "resource_type": "ec2_security_group", "resource_id": "sg-public", "name": "public", "attributes": group}])
    failed = assess(tmp_path, results)
    finding = next(f for f in failed["findings"] if f["rule_id"] == "AEGIS-EC2-001")
    assert finding["resource_id"] == "sg-public"
    assert finding["outcome"] == "FAIL"
    assert failed["summary"]["by_severity"]["HIGH"] == 1

    results[3] = operation("ec2", "DescribeSecurityGroups", resources=[{
        "resource_type": "ec2_security_group", "resource_id": "sg-private", "name": "private",
        "attributes": {"GroupId": "sg-private", "IpPermissions": []}}])
    passed = assess(tmp_path, results)
    finding = next(f for f in passed["findings"] if f["rule_id"] == "AEGIS-EC2-001")
    assert finding["resource_id"] == "sg-private"
    assert finding["outcome"] == "PASS"


def test_missing_policy_version_and_missing_or_malformed_security_evidence_are_not_passes(tmp_path):
    results = base_success()
    arn = "arn:aws:iam::000000000000:policy/incomplete"
    results[4] = operation("iam", "ListPolicies", resources=[{
        "resource_type": "iam_policy", "resource_id": arn, "attributes": {"Arn": arn}}])
    results.append(operation("iam", "GetPolicyVersion", "ERROR", error="NoCredentialsError", subject=f"{arn}#v1"))
    results[3] = operation("ec2", "DescribeSecurityGroups", resources=[
        {"resource_type": "ec2_security_group", "resource_id": "sg-missing", "attributes": {}},
        {"resource_type": "ec2_security_group", "resource_id": "sg-bad", "attributes": {"IpPermissions": "malformed"}},
    ])
    result = assess(tmp_path, results)
    iam = next(f for f in result["findings"] if f["rule_id"] == "AEGIS-IAM-001")
    assert iam["resource_id"] == arn and iam["outcome"] == "ERROR"
    sg_findings = {f["resource_id"]: f["outcome"] for f in result["findings"] if f["rule_id"] == "AEGIS-EC2-001"}
    assert sg_findings == {"sg-missing": "NOT_SUPPORTED", "sg-bad": "ERROR"}


def test_rule_does_not_use_policy_document_when_required_version_call_failed(tmp_path):
    results = base_success()
    arn = "arn:aws:iam::000000000000:policy/possibly-stale-document"
    wildcard_document = {"PolicyVersion": {"Document": {"Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"}]}}}
    results[4] = operation("iam", "ListPolicies", resources=[{
        "resource_type": "iam_policy", "resource_id": arn, "attributes": {"Arn": arn, **wildcard_document}}])
    results.append(operation("iam", "GetPolicyVersion", "ERROR", error="NoCredentialsError", subject=f"{arn}#v1"))
    result = assess(tmp_path, results)
    finding = next(item for item in result["findings"] if item["rule_id"] == "AEGIS-IAM-001")
    assert finding["resource_id"] == arn
    assert finding["outcome"] == "ERROR"
    assert "NoCredentialsError" in finding["reason"]
    assert result["summary"]["by_severity"]["HIGH"] == 0


def test_assessment_errors_and_real_failures_are_separated_in_summary(tmp_path):
    results = base_success()
    results[2] = operation("ec2", "DescribeInstances", "ERROR", error="TimeoutError")
    results[3] = operation("ec2", "DescribeSecurityGroups", resources=[{
        "resource_type": "ec2_security_group", "resource_id": "sg-risk", "attributes": {
            "IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}]}}])
    result = assess(tmp_path, results)
    report = build_report(result)
    assert result["assessment"]["status"] == "PARTIAL"
    assert report["summary"]["by_severity"]["HIGH"] == 1
    assert report["summary"]["by_outcome"]["ERROR"] == 0
    assert len(report["coverage"]["errors"]) == 1


def test_assessment_remains_running_until_rule_evaluation_commits(tmp_path, monkeypatch):
    import aegis.service as service

    settings = Settings(database=tmp_path / "status.sqlite")
    results = base_success()
    results[3] = operation("ec2", "DescribeSecurityGroups", resources=[{
        "resource_type": "ec2_security_group", "resource_id": "sg-safe", "name": "safe",
        "attributes": {"GroupId": "sg-safe", "IpPermissions": []}}])
    entered, release = threading.Event(), threading.Event()
    original_evaluate = service.evaluate

    def paused_evaluate(rule, resource):
        entered.set()
        assert release.wait(3)
        return original_evaluate(rule, resource)

    monkeypatch.setattr(service, "evaluate", paused_evaluate)
    ids, errors = [], []

    def run():
        try:
            ids.append(run_assessment(settings, StaticAdapter(results)))
        except Exception as exc:  # surfaced below with the captured exception category
            errors.append(type(exc).__name__)

    worker = threading.Thread(target=run)
    worker.start()
    assert entered.wait(2)
    with read_only_connect(settings.database) as db:
        row = db.execute("SELECT id,status,completed_at FROM assessments").fetchone()
        assert row["status"] == "RUNNING" and row["completed_at"] is None
        snapshot = export_assessment(settings, row["id"])
    report = build_report(snapshot)
    assert any("still running" in item for item in report["coverage"]["limitations"])
    assert "not a security pass" in " ".join(report["coverage"]["limitations"])
    release.set()
    worker.join(3)
    assert not worker.is_alive() and not errors
    finished = export_assessment(settings, ids[0])
    assert finished["assessment"]["status"] == "COMPLETED"
    assert finished["assessment"]["completed_at"] is not None
