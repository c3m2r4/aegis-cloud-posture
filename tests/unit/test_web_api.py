"""Read-only dashboard API tests use only temporary persisted SQLite snapshots."""
import json
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from aegis.config import Settings
from aegis.db import connect
from aegis.web_api import create_app
from aegis.web_db import read_only_connect


NOW = "2026-01-01T00:00:00+00:00"
ENDPOINT = "http://127.0.0.1:4566"
OUTCOMES = ("PASS", "FAIL", "NOT_APPLICABLE", "NOT_SUPPORTED", "ERROR")


@pytest.fixture
def setup_api(tmp_path, monkeypatch):
    database = tmp_path / "records.sqlite"
    settings = Settings(database=database)
    app = create_app(settings, allowed_hosts=["testserver", "127.0.0.1", "localhost"])
    client = TestClient(app)
    first, second = str(uuid.uuid4()), str(uuid.uuid4())
    with connect(database) as db:
        for assessment_id, timestamp, status in ((first, NOW, "COMPLETED"),
                                                   (second, "2026-01-02T00:00:00+00:00", "PARTIAL")):
            db.execute("INSERT INTO assessments(id,started_at,completed_at,endpoint,region,status,tool_version) "
                       "VALUES(?,?,?,?,?,?,?)", (assessment_id, timestamp, timestamp, ENDPOINT,
                       "us-east-1", status, "test"))
        db.execute("UPDATE assessments SET endpoint=?", ("http://user:credential-marker@127.0.0.1:4566/?token=query-marker",))
        op_ids = {}
        for assessment_id in (first, second):
            cursor = db.execute("INSERT INTO operations(assessment_id,service,operation,capability,status,error,"
                                "evidence_json,evidence_sha256,observed_at) VALUES(?,?,?,?,?,?,?,?,?)",
                                (assessment_id, "ec2", "DescribeSecurityGroups", "SUPPORTED_AND_TESTED", "SUCCESS",
                                 None, json.dumps({"secretAccessKey": "do-not-return"}), "a" * 64, NOW))
            op_ids[assessment_id] = cursor.lastrowid
            db.execute("INSERT INTO operations(assessment_id,service,operation,capability,status,error,"
                       "evidence_json,evidence_sha256,observed_at) VALUES(?,?,?,?,?,?,?,?,?)",
                       (assessment_id, "logs", "DescribeLogGroups", "UNSUPPORTED", "UNSUPPORTED",
                        "unsupported test operation", json.dumps({"secretAccessKey": "do-not-return"}),
                        "c" * 64, NOW))
            db.execute("INSERT INTO operations(assessment_id,service,operation,capability,status,error,"
                       "evidence_json,evidence_sha256,observed_at) VALUES(?,?,?,?,?,?,?,?,?)",
                       (assessment_id, "ec2", "DescribeInstances", "SUPPORTED_AND_TESTED", "ERROR",
                        "password=dashboard-secret at /home/private/traceback.txt", None, None, NOW))
            db.execute("INSERT INTO resources(assessment_id,resource_type,resource_id,name,source_service,"
                        "source_operation,observed_at,attributes_json) VALUES(?,?,?,?,?,?,?,?)",
                       (assessment_id, "ec2_security_group", "sg-shared", "sample group",
                        "ec2", "DescribeSecurityGroups", NOW, json.dumps({"GroupId": "sg-shared"})))
        for index, outcome in enumerate(OUTCOMES):
            refs = [{"operation_id": op_ids[first], "service": "ec2", "operation": "DescribeSecurityGroups",
                     "status": "SUCCESS", "evidence_sha256": "a" * 64}]
            db.execute("INSERT INTO findings(assessment_id,rule_id,resource_type,resource_id,outcome,severity,title,"
                       "description,reason,remediation,evidence_refs_json,assessed_at,previous_outcome,change_state) "
                       "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (first, f"AEGIS-EC2-{index + 1:03d}", "ec2_security_group", "sg-shared", outcome,
                        "HIGH", f"Finding {outcome}", "Description", "Observed reason", "Guidance",
                        json.dumps(refs), NOW, None, "FIRST_SEEN"))
        stale_refs = [{"operation_id": op_ids[first], "service": "ec2", "operation": "DescribeSecurityGroups",
                       "status": "SUCCESS", "evidence_sha256": "a" * 64}]
        db.execute("INSERT INTO findings(assessment_id,rule_id,resource_type,resource_id,outcome,severity,title,"
                   "description,reason,remediation,evidence_refs_json,assessed_at,previous_outcome,change_state) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (first, "AEGIS-IAM-999", "iam_policy", "policy-old", "FAIL", "HIGH",
                    "Historical failure", "Description", "Observed reason", "Guidance",
                    json.dumps(stale_refs), NOW, None, "FIRST_SEEN"))
        # The first finding resolves only with evidence on the later assessment.
        later_refs = [{"operation_id": op_ids[second], "service": "ec2", "operation": "DescribeSecurityGroups",
                       "status": "SUCCESS", "evidence_sha256": "b" * 64}]
        db.execute("INSERT INTO findings(assessment_id,rule_id,resource_type,resource_id,outcome,severity,title,"
                   "description,reason,remediation,evidence_refs_json,assessed_at,previous_outcome,change_state) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (second, "AEGIS-EC2-002", "ec2_security_group", "sg-shared", "PASS", "HIGH",
                    "Resolved candidate", "Description", "Observed safe state", "Guidance",
                    json.dumps(later_refs), "2026-01-02T00:00:00+00:00", "FAIL", "CHANGED"))
    return client, database, first, second


def test_missing_database_is_empty_and_never_created(tmp_path):
    database = tmp_path / "missing" / "aegis.sqlite"
    client = TestClient(create_app(Settings(database=database), allowed_hosts=["testserver"]))
    assert client.get("/api/health").json() == {
        "status": "ok", "database": {"available": False, "state": "not_created"}}
    overview = client.get("/api/overview").json()
    assert overview["latest_assessment"] is None
    assert overview["resource_types"] == []
    assert overview["coverage"]["discovery"]["deferred_operations"] == []
    assert overview["summary"]["by_outcome"] == {outcome: 0 for outcome in OUTCOMES}
    missing_id, other_id = str(uuid.uuid4()), str(uuid.uuid4())
    paths = [
        "/api/assessments",
        f"/api/assessments/{missing_id}",
        f"/api/assessments/{missing_id}/findings",
        f"/api/assessments/{missing_id}/resources",
        f"/api/assessments/{missing_id}/operations",
        f"/api/assessments/{missing_id}/reports/json",
        f"/api/comparisons/{missing_id}/{other_id}",
        "/", "/assessments", f"/assessments/{missing_id}", "/compare",
        "/static/dashboard.js", "/static/dashboard.css",
    ]
    expected_statuses = [200, 404, 404, 404, 404, 404, 404, 200, 200, 200, 200, 200, 200]
    assert [client.get(path).status_code for path in paths] == expected_statuses
    assert not database.exists()
    assert not database.parent.exists()


def test_read_only_connection_cannot_write_or_migrate(tmp_path):
    database = tmp_path / "existing.sqlite"
    with connect(database) as db:
        before = {row[1] for row in db.execute("PRAGMA table_info(operations)")}
    with read_only_connect(database) as db:
        with pytest.raises(sqlite3.OperationalError):
            db.execute("CREATE TABLE should_not_exist (id INT)")
        with pytest.raises(sqlite3.OperationalError):
            db.execute("INSERT INTO assessments(id,started_at,endpoint,region,status,tool_version) "
                       "VALUES('x','x','x','x','x','x')")
        after = {row[1] for row in db.execute("PRAGMA table_info(operations)")}
    assert before == after
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT name FROM sqlite_master WHERE name='should_not_exist'").fetchone() is None


def test_old_schema_health_does_not_migrate_it(tmp_path):
    database = tmp_path / "old.sqlite"
    with sqlite3.connect(database) as db:
        db.executescript("CREATE TABLE assessments(id TEXT); CREATE TABLE operations(id INTEGER, assessment_id TEXT);")
    with sqlite3.connect(database) as db:
        before = [row[1] for row in db.execute("PRAGMA table_info(operations)")]
    client = TestClient(create_app(Settings(database=database), allowed_hosts=["testserver"]))
    response = client.get("/api/health")
    assert response.status_code == 503
    with sqlite3.connect(database) as db:
        after = [row[1] for row in db.execute("PRAGMA table_info(operations)")]
    assert before == after


def test_overview_and_all_outcomes_preserve_partial_state(setup_api):
    client, _database, first, second = setup_api
    overview = client.get("/api/overview").json()
    assert overview["latest_assessment"]["id"] == second
    assert overview["latest_assessment"]["status"] == "PARTIAL"
    assert overview["resource_types"] == ["ec2_security_group"]
    deferred = overview["coverage"]["discovery"]["deferred_operations"]
    assert {(item["service"], item["operation"]) for item in deferred} == {
        ("ec2", "DescribeKeyPairs"), ("ec2", "DescribeAddresses")}
    assert "do-not-return" not in json.dumps(overview)
    assert "credential-marker" not in json.dumps(overview)
    assert "query-marker" not in json.dumps(overview)
    detail = client.get(f"/api/assessments/{first}").json()
    assert "do-not-return" not in json.dumps(detail)
    assert detail["summary"]["by_outcome"] == {**{outcome: 1 for outcome in OUTCOMES}, "FAIL": 2}
    assert detail["summary"]["by_severity"]["HIGH"] == 2
    assert detail["scope"]["cloud_resource_count"] == 1
    response = client.get(f"/api/assessments/{first}/findings?outcome=NOT_SUPPORTED")
    assert response.status_code == 200
    assert [row["outcome"] for row in response.json()["items"]] == ["NOT_SUPPORTED"]
    assert response.json()["items"][0]["evidence_refs"][0]["evidence_sha256"] == "a" * 64


def test_lists_filters_bounds_and_missing_assessments(setup_api):
    client, _database, first, _second = setup_api
    assessments = client.get("/api/assessments?limit=1&offset=0").json()
    assert assessments["total"] == 2 and len(assessments["items"]) == 1
    resources = client.get(f"/api/assessments/{first}/resources?limit=1").json()
    assert resources["total"] == 1 and resources["items"][0]["attributes"]["GroupId"] == "sg-shared"
    searched = client.get(f"/api/assessments/{first}/findings?resource=sample%20group")
    assert searched.status_code == 200 and searched.json()["total"] == 5
    operations = client.get(f"/api/assessments/{first}/operations").json()
    assert "evidence" not in operations["items"][0]
    assert "evidence_sha256" in operations["items"][0]
    assert "error" not in operations["items"][0]
    assert any(item["status"] == "ERROR" for item in operations["items"])
    assert "dashboard-secret" not in json.dumps(operations)
    assert "/home/private" not in json.dumps(operations)
    assert client.get("/api/assessments?limit=101").status_code == 422
    assert client.get("/api/assessments?offset=100001").status_code == 422
    assert client.get(f"/api/assessments/{first}/findings?outcome=MADE_UP").status_code == 422
    assert client.get(f"/api/assessments/{first}/findings?severity=EXTREME").status_code == 422
    assert client.get(f"/api/assessments/{first}/findings?rule_id=bad%27%20OR%201%3D1").status_code == 422
    assert client.get("/api/assessments/not-a-uuid").status_code == 422
    assert client.get(f"/api/assessments/{uuid.uuid4()}").status_code == 404
    assert client.get(f"/api/assessments/{first}/resources?limit=0").status_code == 422
    missing = str(uuid.uuid4())
    assert client.get(f"/api/assessments/{missing}/reports/json").status_code == 404
    assert client.get(f"/api/assessments/{first}/reports/html").status_code == 422


def test_resource_inventory_service_and_type_filters_use_persisted_fields(setup_api):
    client, database, first, _second = setup_api
    with connect(database) as db:
        db.execute("INSERT INTO resources(assessment_id,resource_type,resource_id,name,source_service,"
                   "source_operation,observed_at,attributes_json) VALUES(?,?,?,?,?,?,?,?)",
                   (first, "s3_bucket", "bucket-1", "bucket", "s3", "ListBuckets", NOW, "{}"))
    all_items = client.get(f"/api/assessments/{first}/resources").json()
    assert all_items["total"] == 2
    assert all_items["available_filters"] == {
        "services": ["ec2", "s3"], "resource_types": ["ec2_security_group", "s3_bucket"]}
    filtered_service = client.get(f"/api/assessments/{first}/resources?service=s3").json()
    assert [item["resource_type"] for item in filtered_service["items"]] == ["s3_bucket"]
    filtered_type = client.get(f"/api/assessments/{first}/resources?resource_type=ec2_security_group").json()
    assert [item["source_service"] for item in filtered_type["items"]] == ["ec2"]
    assert client.get(f"/api/assessments/{first}/resources?service=ec2%27%20OR%201%3D1").status_code == 422
    assert client.get(f"/api/assessments/{first}/resources?resource_type=bad.type").status_code == 422


def test_reports_are_persisted_sanitized_and_use_safe_names(setup_api):
    client, _database, first, _second = setup_api
    report = client.get(f"/api/assessments/{first}/reports/json")
    assert report.status_code == 200
    assert report.headers["content-disposition"] == f'attachment; filename="aegis-assessment-{first}.json"'
    assert report.headers["x-content-type-options"] == "nosniff"
    assert "do-not-return" not in report.text
    assert "credential-marker" not in report.text and "query-marker" not in report.text
    assert "dashboard-secret" not in report.text and "/home/private" not in report.text
    payload = report.json()
    assert payload["summary"]["by_outcome"] == {**{outcome: 1 for outcome in OUTCOMES}, "FAIL": 2}
    assert payload["coverage"]["errors"][0]["status"] == "ERROR"
    assert "error" not in payload["coverage"]["errors"][0]
    markdown = client.get(f"/api/assessments/{first}/reports/markdown")
    assert markdown.status_code == 200 and "# AEGIS Assessment Report" in markdown.text
    assert "do-not-return" not in markdown.text
    assert "dashboard-secret" not in markdown.text and "/home/private" not in markdown.text
    assert client.get(f"/api/assessments/{first}/reports/../../etc/passwd").status_code in {404, 422}


def test_comparison_uses_existing_conservative_engine(setup_api):
    client, _database, first, second = setup_api
    response = client.get(f"/api/comparisons/{first}/{second}")
    assert response.status_code == 200
    comparison = response.json()
    assert comparison["findings"]["resolved"][0]["finding"]["rule_id"] == "AEGIS-EC2-002"
    assert comparison["findings"]["not_reassessed"]
    assert client.get(f"/api/comparisons/{second}/{first}").status_code == 422
    assert client.get(f"/api/comparisons/{first}/{first}").status_code == 422


def test_comparison_rejects_an_assessment_still_running(setup_api):
    client, database, first, _second = setup_api
    running = str(uuid.uuid4())
    with connect(database) as db:
        db.execute("INSERT INTO assessments(id,started_at,endpoint,region,status,tool_version) VALUES(?,?,?,?,?,?)",
                   (running, "2026-01-03T00:00:00+00:00", ENDPOINT, "us-east-1", "RUNNING", "test"))
    response = client.get(f"/api/comparisons/{first}/{running}")
    assert response.status_code == 409
    assert response.json()["detail"] == "Assessments can be compared after both runs have finished"


def test_get_routes_never_invoke_cloud_adapter(setup_api, monkeypatch):
    client, _database, first, second = setup_api

    def forbidden(*_args, **_kwargs):
        raise AssertionError("cloud access or write attempted from GET route")

    monkeypatch.setattr("aegis.adapters.FlociAdapter.collect", forbidden)
    monkeypatch.setattr("aegis.service.run_assessment", forbidden)
    monkeypatch.setattr("aegis.service.run_discovery", forbidden)
    monkeypatch.setattr("aegis.db.connect", forbidden)
    paths = ["/api/health", "/api/overview", "/api/assessments",
             f"/api/assessments/{first}", f"/api/assessments/{first}/findings",
             f"/api/assessments/{first}/resources", f"/api/assessments/{first}/operations",
             f"/api/assessments/{first}/reports/json", f"/api/comparisons/{first}/{second}",
             "/", "/assessments", f"/assessments/{first}", "/compare", "/static/dashboard.js", "/static/dashboard.css"]
    assert all(client.get(path).status_code == 200 for path in paths)


def test_dashboard_shell_api_and_static_assets_disable_caching(setup_api):
    client, _database, _first, _second = setup_api
    for path in ("/", "/api/overview", "/static/dashboard.js", "/static/dashboard.css"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"


def test_host_validation_and_request_errors_do_not_disclose_internal_values(setup_api):
    client, _database, first, _second = setup_api
    assert client.get("/api/health", headers={"host": "attacker.example"}).status_code == 400
    invalid = client.get(f"/api/assessments/{first}/findings?limit=credential-secret")
    assert invalid.status_code == 422
    assert "credential-secret" not in invalid.text


def test_preview_and_run_status_gets_never_start_cloud_work_or_write_database(tmp_path, monkeypatch):
    database = tmp_path / "missing" / "aegis.sqlite"
    client = TestClient(create_app(Settings(database=database), allowed_hosts=["testserver"]))
    monkeypatch.setattr("aegis.web_api.run_preflight", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("preflight ran from GET")))
    monkeypatch.setattr("aegis.web_api.run_assessment", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("assessment ran from GET")))
    preview = client.get("/api/assessment-preview")
    assert preview.status_code == 200
    assert preview.json()["endpoint"] == "http://127.0.0.1:4566"
    assert client.get(f"/api/assessment-runs/{uuid.uuid4()}").status_code == 404
    assert not database.exists() and not database.parent.exists()


def test_preflight_and_start_require_same_origin_json_and_explicit_confirmation(tmp_path, monkeypatch):
    client = TestClient(create_app(Settings(database=tmp_path / "flow.sqlite"), allowed_hosts=["testserver"]))
    called = {"preflight": 0, "assessment": 0}
    def preflight(*_args, **_kwargs):
        called["preflight"] += 1
        return {"readiness": "READY WITH LIMITATIONS", "checks": [], "operations": [], "identity": None, "limitations": []}
    monkeypatch.setattr("aegis.web_api.run_preflight", preflight)
    monkeypatch.setattr("aegis.web_api.run_assessment", lambda *_args, **_kwargs: called.__setitem__("assessment", called["assessment"] + 1))
    bad_origin = client.post("/api/preflight", json={}, headers={"Origin": "http://attacker.example"})
    assert bad_origin.status_code == 403 and called["preflight"] == 0
    missing_origin = client.post("/api/preflight", json={})
    assert missing_origin.status_code == 403 and called["preflight"] == 0
    too_large = client.post("/api/preflight", content=json.dumps({"padding": "x" * 2000}),
                            headers={"Origin": "http://testserver", "Content-Type": "application/json"})
    assert too_large.status_code == 413 and called["preflight"] == 0
    wrong_type = client.post("/api/preflight", content="{}", headers={"Origin": "http://testserver", "Content-Type": "text/plain"})
    assert wrong_type.status_code == 415
    preflight_response = client.post("/api/preflight", json={}, headers={"Origin": "http://testserver"})
    assert preflight_response.status_code == 200 and called["preflight"] == 1
    no_confirmation = client.post("/api/assessment-runs", json={"confirmation": False}, headers={"Origin": "http://testserver"})
    assert no_confirmation.status_code == 422 and called["assessment"] == 0
    accepted = client.post("/api/assessment-runs", json={"confirmation": True}, headers={"Origin": "http://testserver"})
    assert accepted.status_code == 200
    assert called["assessment"] == 1


def test_preflight_is_one_time_and_blocked_preflight_cannot_launch_scan(tmp_path, monkeypatch):
    client = TestClient(create_app(Settings(database=tmp_path / "one-time.sqlite"), allowed_hosts=["testserver"]))
    calls = {"assessment": 0}
    monkeypatch.setattr("aegis.web_api.run_preflight", lambda *_args, **_kwargs: {"readiness": "BLOCKED"})
    monkeypatch.setattr("aegis.web_api.run_assessment", lambda *_args, **_kwargs: calls.__setitem__("assessment", calls["assessment"] + 1))
    headers = {"Origin": "http://testserver"}
    assert client.post("/api/assessment-runs", json={"confirmation": True}, headers=headers).status_code == 409
    assert client.post("/api/preflight", json={}, headers=headers).status_code == 200
    assert client.post("/api/assessment-runs", json={"confirmation": True}, headers=headers).status_code == 409
    assert calls["assessment"] == 0


@pytest.mark.parametrize("assessment_status", ["COMPLETED", "PARTIAL"])
def test_running_assessment_is_serialized_and_status_returns_actual_saved_result(tmp_path, monkeypatch, assessment_status):
    database = tmp_path / "runs.sqlite"
    client = TestClient(create_app(Settings(database=database), allowed_hosts=["testserver"]))
    client.app.state.latest_preflight = {"readiness": "READY", "checked_at": datetime.now(timezone.utc).isoformat()}
    entered, release = threading.Event(), threading.Event()
    def blocked_run(settings, *, lock=None, assessment_id=None):
        with lock:
            entered.set()
            assert release.wait(3)
            with connect(settings.database) as db:
                db.execute("INSERT INTO assessments(id,started_at,completed_at,endpoint,region,status,tool_version) VALUES(?,?,?,?,?,?,?)",
                           (assessment_id, NOW, NOW, ENDPOINT, "us-east-1", assessment_status, "test"))
        return assessment_id

    monkeypatch.setattr("aegis.web_api.run_assessment", blocked_run)
    headers = {"Origin": "http://testserver"}
    started = client.post("/api/assessment-runs", json={"confirmation": True}, headers=headers)
    assert started.status_code == 200
    run_id = started.json()["run_id"]
    assert entered.wait(2)
    duplicate = client.post("/api/assessment-runs", json={"confirmation": True}, headers=headers)
    assert duplicate.status_code == 409
    during = client.get(f"/api/assessment-runs/{run_id}").json()
    assert during["state"] == "RUNNING"
    release.set()
    terminal = None
    for _ in range(100):
        terminal = client.get(f"/api/assessment-runs/{run_id}").json()
        if terminal["state"] in {"COMPLETED", "PARTIAL", "FAILED"}:
            break
        time.sleep(0.01)
    assert terminal["state"] == assessment_status
    assert terminal["assessment_id"] == run_id
    assert terminal["assessment_status"] == assessment_status
    assert client.get(f"/api/assessments/{run_id}").json()["assessment"]["status"] == assessment_status


@pytest.mark.parametrize("saved_status,expected_state", [("COMPLETED", "COMPLETED"),
                                                           ("PARTIAL", "PARTIAL"),
                                                           ("FAILED", "FAILED"),
                                                           ("RUNNING", "UNKNOWN")])
def test_run_status_recovers_from_database_after_web_process_restart(tmp_path, saved_status, expected_state):
    database = tmp_path / "recovery.sqlite"
    run_id = str(uuid.uuid4())
    with connect(database) as db:
        db.execute("INSERT INTO assessments(id,started_at,completed_at,endpoint,region,status,tool_version) "
                   "VALUES(?,?,?,?,?,?,?)", (run_id, NOW, None if saved_status == "RUNNING" else NOW,
                   ENDPOINT, "us-east-1", saved_status, "test"))
    # This new app has no in-memory job map, as after an API process restart.
    client = TestClient(create_app(Settings(database=database), allowed_hosts=["testserver"]))
    response = client.get(f"/api/assessment-runs/{run_id}")
    assert response.status_code == 200
    status = response.json()
    assert status["state"] == expected_state
    assert status["assessment_id"] == run_id
    if expected_state == "UNKNOWN":
        assert status["assessment_status"] == "RUNNING"
        assert "unknown" in status["message"].lower()
    else:
        assert status["completed_at"] == NOW
        assert status["assessment_url"] == f"/assessments/{run_id}"


def test_worker_failure_is_safe_and_does_not_expose_exception_details(tmp_path, monkeypatch):
    client = TestClient(create_app(Settings(database=tmp_path / "worker-error.sqlite"), allowed_hosts=["testserver"]))
    client.app.state.latest_preflight = {"readiness": "READY", "checked_at": datetime.now(timezone.utc).isoformat()}
    calls = {"assessment": 0}
    def failed_run(*_args, **_kwargs):
        calls["assessment"] += 1
        raise RuntimeError("password=worker-secret at /home/private/traceback.py")
    monkeypatch.setattr("aegis.web_api.run_assessment", failed_run)
    started = client.post("/api/assessment-runs", json={"confirmation": True}, headers={"Origin": "http://testserver"})
    assert started.status_code == 200
    status = None
    for _ in range(100):
        status = client.get(started.json()["status_url"]).json()
        if status["state"] == "FAILED":
            break
        time.sleep(0.01)
    assert status["state"] == "FAILED" and status["error_type"] == "RuntimeError"
    assert "worker-secret" not in json.dumps(status) and "/home/private" not in json.dumps(status)
    assert calls["assessment"] == 1


def test_preflight_then_cancel_does_not_start_assessment(tmp_path, monkeypatch):
    client = TestClient(create_app(Settings(database=tmp_path / "cancel.sqlite"), allowed_hosts=["testserver"]))
    calls = {"preflight": 0, "assessment": 0}
    def preflight(*_args, **_kwargs):
        calls["preflight"] += 1
        return {"readiness": "READY", "checks": [], "operations": [], "limitations": []}
    monkeypatch.setattr("aegis.web_api.run_preflight", preflight)
    monkeypatch.setattr("aegis.web_api.run_assessment", lambda *_args, **_kwargs: calls.__setitem__("assessment", calls["assessment"] + 1))
    headers = {"Origin": "http://testserver"}
    assert client.get("/api/assessment-preview").status_code == 200
    assert client.post("/api/preflight", json={}, headers=headers).status_code == 200
    # Closing/cancelling the preview has no endpoint call; only the dedicated
    # confirmed start route can invoke the assessment service.
    assert calls == {"preflight": 1, "assessment": 0}
