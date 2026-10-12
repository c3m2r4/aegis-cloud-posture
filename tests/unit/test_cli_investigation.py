import json
import uuid

from typer.testing import CliRunner

from aegis.cli import app
from aegis.config import Settings
from aegis.db import connect


def test_saved_investigation_commands_are_read_only_and_hide_raw_operation_data(tmp_path, monkeypatch):
    database = tmp_path / "history.sqlite"
    settings = Settings(database=database)
    assessment_id = str(uuid.uuid4())
    with connect(database) as db:
        db.execute("INSERT INTO assessments(id,started_at,completed_at,endpoint,region,status,tool_version) VALUES(?,?,?,?,?,?,?)",
                   (assessment_id, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z", settings.endpoint_url,
                    settings.region, "PARTIAL", "test"))
        db.execute("INSERT INTO operations(assessment_id,service,operation,capability,status,error,evidence_json,evidence_sha256,observed_at) VALUES(?,?,?,?,?,?,?,?,?)",
                   (assessment_id, "s3", "ListBuckets", "SUPPORTED_AND_TESTED", "ERROR",
                    "password=raw-secret at /private/trace.py", json.dumps({"secretAccessKey": "raw-secret"}),
                    "a" * 64, "2026-01-01T00:00:00Z"))
        db.execute("INSERT INTO resources(assessment_id,resource_type,resource_id,name,source_service,source_operation,observed_at,attributes_json) VALUES(?,?,?,?,?,?,?,?)",
                   (assessment_id, "s3_bucket", "bucket-a", "bucket-a", "s3", "ListBuckets",
                    "2026-01-01T00:00:00Z", json.dumps({"password": "raw-secret", "Region": "us-east-1"})))
        db.execute("INSERT INTO findings(assessment_id,rule_id,resource_type,resource_id,outcome,severity,title,description,reason,remediation,evidence_refs_json,assessed_at,change_state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (assessment_id, "AEGIS-LOGS-001", "cloudwatch_log_group", "/logs/a", "NOT_SUPPORTED", "MEDIUM",
                    "Retention", "Description", "Field was not observed", "Review retention", "[]",
                    "2026-01-01T00:00:00Z", "FIRST_SEEN"))
    monkeypatch.setattr("aegis.cli._settings", lambda: settings)
    runner = CliRunner()
    commands = [
        ["history", "--json"], ["show", assessment_id, "--json"],
        ["findings", assessment_id, "--outcome", "NOT_SUPPORTED", "--json"],
        ["resources", assessment_id, "--json"], ["operations", assessment_id, "--json"],
    ]
    for command in commands:
        result = runner.invoke(app, command)
        assert result.exit_code == 0, (command, result.output)
        assert "raw-secret" not in result.output
        assert "/private/trace.py" not in result.output
    with connect(database) as db:
        assert db.execute("SELECT COUNT(*) FROM assessments").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM operations").fetchone()[0] == 1


def test_config_json_never_reads_or_prints_credential_values(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "access-marker")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret-marker")
    monkeypatch.setattr("aegis.cli._settings", lambda: Settings(database=tmp_path / "unused.sqlite"))
    result = CliRunner().invoke(app, ["config", "--json"])
    assert result.exit_code == 0
    assert "boto3 standard provider chain" in result.output
    assert "access-marker" not in result.output and "secret-marker" not in result.output
