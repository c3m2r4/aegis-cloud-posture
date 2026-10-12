"""Opt-in read-only assessment integration tests against configured Floci."""
import os
from urllib.parse import urlsplit

import boto3
import pytest

from aegis.adapters import FlociAdapter, specifications
from aegis.config import Settings, credential_status
from aegis.service import export_assessment, run_assessment


pytestmark = pytest.mark.skipif(os.getenv("AEGIS_RUN_INTEGRATION") != "1",
                                reason="set AEGIS_RUN_INTEGRATION=1 to probe a real Floci endpoint")


def test_verified_read_operations_and_rules_against_floci(tmp_path):
    settings = Settings.from_env()
    endpoint = urlsplit(settings.endpoint_url)
    assert endpoint.hostname in {"127.0.0.1", "localhost", "::1"} and endpoint.port == 4566, \
        "integration tests are restricted to local Floci on port 4566"
    assert credential_status(boto3.Session(region_name=settings.region))[0] == "AVAILABLE", \
        "opt-in Floci integration requires explicitly configured local credentials"
    results = FlociAdapter(settings).collect()
    operations = {(result.service, result.operation) for result in results}
    expected = {(spec.service, spec.operation) for spec in specifications()}
    assert expected <= operations
    assert operations <= expected | {("iam", "GetPolicyVersion"), ("eks", "ListNodegroups"),
                                     ("eks", "ListFargateProfiles")}
    assert all(result.status in {"SUCCESS", "UNSUPPORTED", "ERROR", "INCOMPLETE"} for result in results)
    assert all(result.resources is not None for result in results if result.status in {"SUCCESS", "INCOMPLETE"})
    for item in results:
        if item.operation in {"ListFunctions", "ListStacks"} and item.response:
            assert "Environment" not in str(item.response)
            assert "ParameterValue" not in str(item.response)

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
