import json

from typer.testing import CliRunner

from aegis.cli import app
from aegis.config import Settings
from aegis.db import connect


def test_report_cli_reads_persisted_assessment_only(tmp_path, monkeypatch):
    database = tmp_path / "stored.db"
    settings = Settings("http://127.0.0.1:4566", "us-east-1", database, 1, 1)
    monkeypatch.setattr("aegis.cli._settings", lambda: settings)
    with connect(database) as db:
        db.execute("INSERT INTO assessments(id,started_at,completed_at,endpoint,region,status,tool_version) VALUES(?,?,?,?,?,?,?)",
                   ("assessment-1", "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z",
                    settings.endpoint_url, settings.region, "COMPLETED", "test"))
    # If report accidentally starts a fresh collection, this stub makes the test fail.
    monkeypatch.setattr("aegis.cli.run_discovery", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("discovery called")))
    runner = CliRunner()
    result = runner.invoke(app, ["report", "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["assessment"]["id"] == "assessment-1"
    assert payload["summary"]["finding_count"] == 0
    markdown = runner.invoke(app, ["report", "--assessment", "assessment-1"])
    assert markdown.exit_code == 0, markdown.output
    assert "# AEGIS Assessment Report" in markdown.output


def test_compare_cli_loads_both_saved_assessments(tmp_path, monkeypatch):
    database = tmp_path / "stored.db"
    settings = Settings("http://127.0.0.1:4566", "us-east-1", database, 1, 1)
    monkeypatch.setattr("aegis.cli._settings", lambda: settings)
    with connect(database) as db:
        for assessment_id, started_at in (("older", "2026-01-01T00:00:00Z"), ("newer", "2026-01-02T00:00:00Z")):
            db.execute("INSERT INTO assessments(id,started_at,completed_at,endpoint,region,status,tool_version) VALUES(?,?,?,?,?,?,?)",
                       (assessment_id, started_at, "2026-01-03T00:00:00Z",
                        settings.endpoint_url, settings.region, "COMPLETED", "test"))
    monkeypatch.setattr("aegis.cli.run_discovery", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("discovery called")))
    result = CliRunner().invoke(app, ["compare", "older", "newer"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["comparison"] == {"previous_assessment_id": "older", "current_assessment_id": "newer"}


def test_compare_missing_id_returns_concise_nonzero_error(tmp_path, monkeypatch):
    settings = Settings("http://127.0.0.1:4566", "us-east-1", tmp_path / "missing.sqlite", 1, 1)
    monkeypatch.setattr("aegis.cli._settings", lambda: settings)
    result = CliRunner().invoke(app, ["compare", "not-persisted-a", "not-persisted-b"])
    assert result.exit_code == 1
    assert result.output.strip() == "No matching assessment was found"


def test_compare_rejects_reversed_assessment_order(tmp_path, monkeypatch):
    database = tmp_path / "order.sqlite"
    settings = Settings("http://127.0.0.1:4566", "us-east-1", database, 1, 1)
    monkeypatch.setattr("aegis.cli._settings", lambda: settings)
    with connect(database) as db:
        for assessment_id, started_at in (("later", "2026-01-02T00:00:00Z"), ("earlier", "2026-01-01T00:00:00Z")):
            db.execute("INSERT INTO assessments(id,started_at,completed_at,endpoint,region,status,tool_version) VALUES(?,?,?,?,?,?,?)",
                       (assessment_id, started_at, started_at, settings.endpoint_url, settings.region, "COMPLETED", "test"))
    result = CliRunner().invoke(app, ["compare", "later", "earlier"])
    assert result.exit_code == 2
    assert "must have a later start timestamp" in result.output


def test_export_and_report_do_not_create_missing_database(tmp_path, monkeypatch):
    database = tmp_path / "missing" / "stored.db"
    settings = Settings("http://127.0.0.1:4566", "us-east-1", database, 1, 1)
    monkeypatch.setattr("aegis.cli._settings", lambda: settings)
    runner = CliRunner()
    exported = runner.invoke(app, ["export"])
    reported = runner.invoke(app, ["report"])
    assert exported.exit_code == 1
    assert reported.exit_code == 1
    assert not database.exists() and not database.parent.exists()


def test_export_service_uses_read_only_query_connection(tmp_path, monkeypatch):
    database = tmp_path / "saved.db"
    settings = Settings("http://127.0.0.1:4566", "us-east-1", database, 1, 1)
    with connect(database) as db:
        db.execute("INSERT INTO assessments(id,started_at,completed_at,endpoint,region,status,tool_version) VALUES(?,?,?,?,?,?,?)",
                   ("saved", "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z", settings.endpoint_url,
                    settings.region, "COMPLETED", "test"))
    monkeypatch.setattr("aegis.service.connect", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("writer connection opened")))
    from aegis.service import export_assessment
    assert export_assessment(settings, "saved")["assessment"]["id"] == "saved"
