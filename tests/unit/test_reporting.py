import copy
import json

from aegis.reporting import build_report, compare_assessments, render_markdown


def finding(outcome="FAIL", severity="HIGH", resource_id="bucket-1", **extra):
    return {"rule_id": "AEGIS-TEST-001", "resource_type": "s3:bucket", "resource_id": resource_id,
            "outcome": outcome, "severity": severity, "title": "Test check", "description": "Description",
            "reason": "Observed condition", "evidence_refs": [{"operation_id": 1, "status": "SUCCESS",
                                                                    "evidence_sha256": "0" * 64}], **extra}


def snapshot(assessment_id, findings=(), resources=(), operations=()):
    return {"assessment": {"id": assessment_id, "started_at": "2026-01-01T00:00:00Z",
                            "completed_at": "2026-01-01T00:00:01Z", "status": "COMPLETED",
                            "endpoint": "http://127.0.0.1:4566", "region": "us-east-1"},
            "findings": list(findings), "resources": list(resources), "operations": list(operations)}


def test_compare_new_resolved_unchanged_and_changed_and_inventory_changes():
    old = snapshot("old", [finding(resource_id="resolved"), finding("FAIL", "HIGH", "same"),
                            finding("PASS", "HIGH", "changed")],
                   [{"resource_type": "s3:bucket", "resource_id": "kept"},
                    {"resource_type": "s3:bucket", "resource_id": "gone"}])
    new = snapshot("new", [finding("PASS", "HIGH", "resolved"), finding("FAIL", "HIGH", "same"),
                            finding("FAIL", "HIGH", "changed"), finding("FAIL", "MEDIUM", "new")],
                   [{"resource_type": "s3:bucket", "resource_id": "kept"},
                    {"resource_type": "s3:bucket", "resource_id": "added"}])
    result = compare_assessments(old, new)
    assert [x["finding"]["resource_id"] for x in result["findings"]["new"]] == ["new"]
    assert [x["finding"]["resource_id"] for x in result["findings"]["resolved"]] == ["resolved"]
    assert [x["finding"]["resource_id"] for x in result["findings"]["unchanged"]] == ["same"]
    assert [x["finding"]["resource_id"] for x in result["findings"]["changed"]] == ["changed"]
    assert result["summary"]["inventory"] == {"added": 1, "removed": 1, "modified": 0, "unchanged": 1}


def test_inventory_attribute_change_is_reported_as_modified():
    before = {"resource_type": "s3:bucket", "resource_id": "bucket-a", "name": "a", "attributes": {"region": "east"}}
    after = {"resource_type": "s3:bucket", "resource_id": "bucket-a", "name": "a", "attributes": {"region": "west"}}
    result = compare_assessments(snapshot("a", resources=[before]), snapshot("b", resources=[after]))
    assert result["inventory"]["modified"] == [{"previous": before, "current": after}]
    assert result["inventory"]["unchanged"] == []


def test_compare_severity_change_is_changed():
    result = compare_assessments(snapshot("a", [finding("FAIL", "LOW")]),
                                 snapshot("b", [finding("FAIL", "HIGH")]))
    assert len(result["findings"]["changed"]) == 1
    assert result["findings"]["changed"][0]["previous"]["severity"] == "LOW"


def test_pass_to_fail_is_changed_outcome():
    result = compare_assessments(snapshot("a", [finding("PASS")]), snapshot("b", [finding("FAIL")]))
    assert result["findings"]["new"] == []
    assert len(result["findings"]["changed"]) == 1


def test_unsupported_transitions_are_not_passes_or_resolutions():
    old = snapshot("a", [finding("NOT_SUPPORTED", "HIGH")])
    passed = compare_assessments(old, snapshot("b", [finding("PASS", "HIGH")]))
    failed = compare_assessments(old, snapshot("c", [finding("FAIL", "HIGH")]))
    assert not passed["findings"]["resolved"] and len(passed["findings"]["changed"]) == 1
    assert not failed["findings"]["new"] and len(failed["findings"]["changed"]) == 1


def test_error_transitions_are_not_remediation_or_new_confirmed_failures():
    failed_to_error = compare_assessments(snapshot("a", [finding("FAIL")]),
                                          snapshot("b", [finding("ERROR")]))
    error_to_pass = compare_assessments(snapshot("a", [finding("ERROR")]),
                                        snapshot("b", [finding("PASS")]))
    error_to_fail = compare_assessments(snapshot("a", [finding("ERROR")]),
                                        snapshot("b", [finding("FAIL")]))
    assert not failed_to_error["findings"]["resolved"]
    assert len(failed_to_error["findings"]["changed"]) == 1
    assert not error_to_pass["findings"]["resolved"]
    assert len(error_to_pass["findings"]["changed"]) == 1
    assert not error_to_fail["findings"]["new"]
    assert len(error_to_fail["findings"]["changed"]) == 1


def test_missing_evidence_and_identity_are_not_classified_as_resolution():
    old = snapshot("a", [finding("FAIL")])
    no_evidence = finding("PASS")
    no_evidence["evidence_refs"] = []
    result = compare_assessments(old, snapshot("b", [no_evidence]))
    assert result["findings"]["resolved"] == []
    assert len(result["findings"]["changed"]) == 1
    identity_missing = finding("FAIL")
    identity_missing.pop("resource_id")
    result = compare_assessments(old, snapshot("b", [identity_missing]))
    assert result["findings"]["resolved"] == []
    assert result["findings"]["uncomparable"][0]["assessment"] == "current"


def test_non_successful_or_unhashed_evidence_cannot_confirm_new_or_resolved_findings():
    new_finding = finding("FAIL")
    new_finding["evidence_refs"] = [{"operation_id": 2, "status": "ERROR", "evidence_sha256": None}]
    new_result = compare_assessments(snapshot("old"), snapshot("new", [new_finding]))
    assert new_result["findings"]["new"] == []
    assert len(new_result["findings"]["changed"]) == 1

    prior = finding("FAIL")
    current = finding("PASS")
    current["evidence_refs"] = [{"operation_id": 3, "status": "SUCCESS", "evidence_sha256": None}]
    result = compare_assessments(snapshot("prior", [prior]), snapshot("current", [current]))
    assert result["findings"]["resolved"] == []
    assert len(result["findings"]["changed"]) == 1


def test_evidence_reference_without_explicit_success_is_not_resolution():
    prior = finding("FAIL")
    current = finding("PASS")
    current["evidence_refs"] = [{"operation_id": 3, "evidence_sha256": "0" * 64}]
    result = compare_assessments(snapshot("prior", [prior]), snapshot("current", [current]))
    assert result["findings"]["resolved"] == []
    assert len(result["findings"]["changed"]) == 1


def test_supported_evidence_confirms_resolution():
    old = snapshot("a", [finding("FAIL")])
    passed = finding("PASS")
    passed["evidence_refs"] = [{"operation_id": 2, "status": "SUCCESS", "evidence_sha256": "2" * 64}]
    result = compare_assessments(old, snapshot("b", [passed]))
    assert len(result["findings"]["resolved"]) == 1


def test_missing_current_finding_is_not_resolved():
    result = compare_assessments(snapshot("a", [finding()]), snapshot("b"))
    assert len(result["findings"]["not_reassessed"]) == 1
    assert result["findings"]["resolved"] == []


def test_empty_and_error_report_json_schema_and_markdown():
    empty = build_report(snapshot("empty"))
    assert set(empty) == {"schema_version", "report_type", "assessment", "scope", "coverage", "summary", "findings"}
    assert empty["summary"]["by_outcome"] == {"PASS": 0, "FAIL": 0, "NOT_APPLICABLE": 0, "NOT_SUPPORTED": 0, "ERROR": 0}
    error_finding = finding("ERROR")
    error_finding["evidence_refs"] = [{"operation_id": 1, "service": "iam", "operation": "ListPolicies",
                                       "status": "SUCCESS", "subject_resource_id": None, "evidence_sha256": None}]
    report = build_report(snapshot("partial", [error_finding], operations=[
        {"service": "iam", "operation": "ListPolicies", "status": "ERROR", "error": "timeout"},
        {"service": "s3", "operation": "ListBuckets", "status": "UNSUPPORTED"}]))
    encoded = json.dumps(report, sort_keys=True)
    assert json.loads(encoded)["assessment"]["id"] == "partial"
    markdown = render_markdown(report)
    assert markdown.startswith("# AEGIS Assessment Report\n")
    assert "confirmed FAIL only" in markdown
    assert "unsupported" in markdown.lower() and "ERROR" in markdown
    assert "Operation record 1: iam:ListPolicies" in markdown
    assert "no response evidence hash" in markdown


def test_failed_zero_resource_report_is_prominent_and_not_compliance_claim():
    stored = snapshot("failed", operations=[{"id": 8, "service": "sts", "operation": "GetCallerIdentity",
                                             "status": "ERROR", "error": "NoCredentialsError",
                                             "evidence_sha256": None}])
    stored["assessment"]["status"] = "FAILED"
    report = build_report(stored)
    markdown = render_markdown(report)
    assert "Assessment coverage is incomplete" in markdown
    assert "No resources were discovered" in markdown
    assert "> **No resources were discovered.**" in markdown
    assert "No resource findings were recorded. This is not a security pass" in markdown
    assert report["summary"]["by_severity"]["HIGH"] == 0
    assert report["coverage"]["errors"][0]["evidence_sha256"] is None


def test_evidence_absence_is_reported_and_does_not_make_failed_finding_invisible():
    item = finding("NOT_SUPPORTED")
    item["evidence_refs"] = []
    report = build_report(snapshot("x", [item]))
    assert report["findings"][0]["evidence_refs"] == []
    assert "not a pass or confirmed failure" in render_markdown(report)


def test_incomplete_results_do_not_claim_remediation_is_required_or_performed():
    item = finding("NOT_SUPPORTED")
    item["remediation"] = "Set retention to at least 30 days."
    markdown = render_markdown(build_report(snapshot("partial", [item])))
    assert "General rule guidance (not a determination that changes are needed)" in markdown
    assert "Remediation guidance for this confirmed failure" not in markdown
    assert "AEGIS did not apply remediation" in markdown

    failed = finding("FAIL")
    failed["remediation"] = "Replace wildcard permissions."
    markdown = render_markdown(build_report(snapshot("failure", [failed])))
    assert "Remediation guidance for this confirmed failure: Replace wildcard permissions." in markdown


def test_completed_api_discovery_with_unsupported_rule_evidence_is_still_limited():
    result = snapshot("complete-operations", [finding("NOT_SUPPORTED")])
    result["resources"] = [{"resource_type": "cloudwatch_log_group", "resource_id": "group-a"}]
    report = build_report(result)
    assert any("AEGIS-TEST-001" in item and "NOT_SUPPORTED" in item for item in report["coverage"]["limitations"])
    assert "Assessment coverage is incomplete" in render_markdown(report)


def test_comparison_schema_repeatable():
    old, new = snapshot("a", [finding()]), snapshot("b", [finding("FAIL")])
    first = compare_assessments(old, new)
    second = compare_assessments(copy.deepcopy(old), copy.deepcopy(new))
    assert first == second
    assert first["schema_version"] == "1.0"


def test_comparing_an_assessment_with_itself_is_stable():
    data = snapshot("same", [finding("FAIL")], resources=[
        {"resource_type": "s3_bucket", "resource_id": "bucket-1", "name": "bucket-1", "attributes": {}}])
    result = compare_assessments(data, copy.deepcopy(data))
    assert len(result["findings"]["unchanged"]) == 1
    assert result["summary"]["inventory"]["unchanged"] == 1


def test_discovery_and_assessment_coverage_are_separate_and_services_require_all_expected_calls():
    stored = snapshot("inventory", resources=[
        {"resource_type": "ec2_instance", "resource_id": "i-1"},
        {"resource_type": "aws_identity", "resource_id": "account"},
        {"resource_type": "iam_policy_version", "resource_id": "policy#v1"},
        {"resource_type": "s3_bucket", "resource_id": "bucket"},
    ], operations=[{"service": "ec2", "operation": "DescribeInstances", "status": "SUCCESS", "observed_at": "2026-01-01T00:00:00Z"}])
    report = build_report(stored)
    assert report["scope"]["resource_count"] == 2
    assert report["scope"]["evidence_record_types"] == ["aws_identity", "iam_policy_version"]
    assert report["scope"]["resources_by_service"] == {"Compute": 1, "Storage": 1}
    compute = next(item for item in report["coverage"]["discovery"]["services"] if item["service"] == "Compute")
    assert compute["state"] == "PARTIAL"
    assert compute["missing_operations"]
    assert "Compute" in report["coverage"]["discovery"]["services_partially_enumerated"]
    assert report["coverage"]["assessment"]["resources_without_evaluations"] == 2


def test_verified_but_unbounded_operations_are_reported_as_deferred_coverage_gaps():
    from aegis.reporting import RESOURCE_SERVICE
    from aegis.adapters import specifications

    operations = [{"service": spec.service, "operation": spec.operation, "status": "SUCCESS"}
                  for spec in specifications()
                  if RESOURCE_SERVICE.get(spec.resource_type) in {"Compute", "Networking"}]
    report = build_report(snapshot("deferred", operations=operations))
    by_service = {item["service"]: item for item in report["coverage"]["discovery"]["services"]}
    assert by_service["Compute"]["state"] == "PARTIAL"
    assert by_service["Networking"]["state"] == "PARTIAL"
    deferred = report["coverage"]["discovery"]["deferred_operations"]
    assert {(item["service"], item["operation"]) for item in deferred} == {
        ("ec2", "DescribeKeyPairs"), ("ec2", "DescribeAddresses")
    }
    deferred_limitations = [item for item in report["coverage"]["limitations"] if "verified but deferred" in item]
    assert len(deferred_limitations) == 2
    assert all("no request-side page-size bound" in item for item in deferred_limitations)


def test_continuation_marker_is_reported_as_incomplete_enumeration():
    stored = snapshot("partial", resources=[{"resource_type": "s3_bucket", "resource_id": "bucket"}], operations=[
        {"id": 4, "service": "s3", "operation": "ListBuckets", "status": "INCOMPLETE",
         "capability": "SUPPORTED_BUT_UNVERIFIED", "error": "PaginationIncomplete", "observed_at": "2026-01-01"},
    ])
    stored["assessment"]["status"] = "PARTIAL"
    report = build_report(stored)
    assert report["coverage"]["incomplete_operations"][0]["status"] == "INCOMPLETE"
    assert "s3:ListBuckets" in " ".join(report["coverage"]["limitations"])
    assert "INCOMPLETE" in render_markdown(report)
