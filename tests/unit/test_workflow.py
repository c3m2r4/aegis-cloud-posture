import pytest

from aegis.adapters import OperationResult, specifications
from aegis.config import Settings
from aegis.db import connect
from aegis.workflow import assessment_preview, run_preflight


class StaticAdapter:
    def __init__(self, results):
        self.results = results
        self.calls = 0

    def collect(self):
        self.calls += 1
        return self.results


def results_all(status="SUCCESS"):
    values = []
    for spec in specifications():
        response = {"Account": "000000000000", "Arn": "arn:aws:iam::000000000000:user/demo", "UserId": "demo"} if spec.service == "sts" else {}
        values.append(OperationResult(spec.service, spec.operation, "SUPPORTED_AND_TESTED", status,
                                      response=response if status == "SUCCESS" else None,
                                      resources=[], error=None if status == "SUCCESS" else "password=secret: /home/private"))
    return values


def fake_environment(monkeypatch, *, credentials="AVAILABLE", tcp=True):
    monkeypatch.setattr("aegis.workflow.boto3.Session", lambda **_kwargs: object())
    monkeypatch.setattr("aegis.workflow.credential_status", lambda _session: (
        credentials, "Credentials resolved through test provider; values hidden."))
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
    def connect(*_args, **_kwargs):
        if not tcp:
            raise OSError("password=secret-value")
        return Connection()
    monkeypatch.setattr("aegis.workflow.socket.create_connection", connect)


def test_assessment_preview_uses_static_allowlist_and_does_not_create_database(tmp_path):
    settings = Settings(database=tmp_path / "absent" / "aegis.sqlite")
    preview = assessment_preview(settings)
    assert preview["database"]["state"] == "not_created"
    assert len(preview["operations"]) == len(specifications()) + 1
    assert preview["operations"][-1]["operation"] == "GetPolicyVersion"
    assert {rule["id"] for rule in preview["rules"]} == {"AEGIS-IAM-001", "AEGIS-EC2-001", "AEGIS-LOGS-001"}
    assert preview["pagination_supported"] is False
    assert not settings.database.exists() and not settings.database.parent.exists()


def test_preflight_ready_uses_actual_successful_read_results_without_persisting(tmp_path, monkeypatch):
    database = tmp_path / "ready.sqlite"
    with connect(database):
        pass
    settings = Settings(database=database)
    fake_environment(monkeypatch)
    adapter = StaticAdapter(results_all())
    result = run_preflight(settings, adapter)
    assert result["readiness"] == "READY"
    assert adapter.calls == 1
    assert result["identity"] == "000000000000"
    assert all(item["state"] == "SUCCESS" for item in result["operations"])
    assert all(check["state"] in {"PASS", "WARN"} for check in result["checks"])
    with connect(database) as db:
        assert db.execute("SELECT COUNT(*) FROM assessments").fetchone()[0] == 0
    assert list(tmp_path.glob(".aegis-write-check-*")) == []


def test_preflight_reports_limitations_for_missing_database_and_unsupported_operation(tmp_path, monkeypatch):
    settings = Settings(database=tmp_path / "not-yet-created.sqlite")
    fake_environment(monkeypatch)
    results = results_all()
    results[1].status = "UNSUPPORTED"
    results[1].capability = "UNSUPPORTED"
    result = run_preflight(settings, StaticAdapter(results))
    assert result["readiness"] == "READY WITH LIMITATIONS"
    assert next(check for check in result["checks"] if check["id"] == "required_read_operations")["state"] == "WARN"
    assert not settings.database.exists()


def test_preflight_does_not_treat_missing_operation_result_as_success(tmp_path, monkeypatch):
    database = tmp_path / "ready.sqlite"
    with connect(database):
        pass
    fake_environment(monkeypatch)
    adapter = StaticAdapter([results_all()[0]])
    result = run_preflight(Settings(database=database), adapter)
    assert result["readiness"] == "READY WITH LIMITATIONS"  # identity succeeded but collection is incomplete
    assert next(check for check in result["checks"] if check["id"] == "required_read_operations")["state"] == "WARN"
    missing = next(item for item in result["operations"] if item["operation"] == "ListBuckets")
    assert missing["state"] == "NOT_RETURNED"


@pytest.mark.parametrize("credentials", ["MISSING", "INVALID", "ERROR"])
def test_preflight_blocks_without_credentials_and_does_not_call_cloud_adapter(tmp_path, monkeypatch, credentials):
    settings = Settings(database=tmp_path / "aegis.sqlite")
    fake_environment(monkeypatch, credentials=credentials)
    adapter = StaticAdapter(results_all())
    result = run_preflight(settings, adapter)
    assert result["readiness"] == "BLOCKED"
    assert adapter.calls == 0
    assert "secret-value" not in str(result)
    assert next(check for check in result["checks"] if check["id"] == "required_read_operations")["state"] == "BLOCKED"


def test_preflight_identity_failure_blocks_even_when_credentials_are_present(tmp_path, monkeypatch):
    database = tmp_path / "ready.sqlite"
    with connect(database):
        pass
    fake_environment(monkeypatch)
    results = results_all()
    results[0].status = "ERROR"
    results[0].error = "password=secret-value: AccessDenied: /home/private/file"
    result = run_preflight(Settings(database=database), StaticAdapter(results))
    assert result["readiness"] == "BLOCKED"
    assert next(check for check in result["checks"] if check["id"] == "identity")["state"] == "FAIL"
    assert "secret-value" not in str(result) and "/home/private" not in str(result)


def test_preflight_endpoint_failure_is_limited_when_identity_succeeds(tmp_path, monkeypatch):
    database = tmp_path / "ready.sqlite"
    with connect(database):
        pass
    fake_environment(monkeypatch, tcp=False)
    result = run_preflight(Settings(database=database), StaticAdapter(results_all()))
    assert result["readiness"] == "READY WITH LIMITATIONS"
    endpoint = next(check for check in result["checks"] if check["id"] == "endpoint")
    assert endpoint["state"] == "FAIL"
    assert "secret-value" not in str(result)


def test_incompatible_database_blocks_preflight_without_migrating_it(tmp_path, monkeypatch):
    import sqlite3
    database = tmp_path / "old.sqlite"
    with sqlite3.connect(database) as db:
        db.executescript("CREATE TABLE assessments(id TEXT); CREATE TABLE operations(id INTEGER, assessment_id TEXT);")
        before = [row[1] for row in db.execute("PRAGMA table_info(operations)")]
    fake_environment(monkeypatch)
    result = run_preflight(Settings(database=database), StaticAdapter(results_all()))
    with sqlite3.connect(database) as db:
        after = [row[1] for row in db.execute("PRAGMA table_info(operations)")]
    assert result["readiness"] == "BLOCKED"
    assert next(check for check in result["checks"] if check["id"] == "database")["state"] == "FAIL"
    assert before == after
