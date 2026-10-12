"""Opt-in read-only assessment integration tests against configured Floci."""
import os

import boto3
import pytest

from aegis.adapters import FlociAdapter
from aegis.config import Settings, credential_status
from aegis.service import export_assessment, run_assessment


pytestmark = pytest.mark.skipif(os.getenv("AEGIS_RUN_INTEGRATION") != "1",
                                reason="set AEGIS_RUN_INTEGRATION=1 to probe a real Floci endpoint")


def test_verified_read_operations_and_rules_against_floci(tmp_path):
    settings = Settings.from_env()
    assert credential_status(boto3.Session(region_name=settings.region))[0] == "AVAILABLE", \
        "opt-in Floci integration requires explicitly configured local credentials"
    results = FlociAdapter(settings).collect()
    operations = {result.operation for result in results}
    assert {"GetCallerIdentity", "ListBuckets", "DescribeInstances", "ListPolicies",
            "DescribeLogGroups", "DescribeSecurityGroups"} <= operations
    assert operations <= {"GetCallerIdentity", "ListBuckets", "DescribeInstances", "ListPolicies",
                          "DescribeLogGroups", "DescribeSecurityGroups", "GetPolicyVersion"}
    assert all(result.status in {"SUCCESS", "UNSUPPORTED", "ERROR"} for result in results)

    assessment_settings = Settings(endpoint_url=settings.endpoint_url, region=settings.region,
                                   database=tmp_path / "floci-assessment.sqlite",
                                   connect_timeout=settings.connect_timeout, read_timeout=settings.read_timeout)
    assessment_id = run_assessment(assessment_settings)
    exported = export_assessment(assessment_settings, assessment_id)
    assert exported["assessment"]["id"] == assessment_id
    assert exported["findings"]
    assert {finding["outcome"] for finding in exported["findings"]} <= {
        "PASS", "FAIL", "NOT_APPLICABLE", "NOT_SUPPORTED", "ERROR"
    }
