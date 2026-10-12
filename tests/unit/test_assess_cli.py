from typer.testing import CliRunner

from aegis.cli import app
from aegis.config import Settings


def snapshot(status):
    return {"assessment": {"id": "persisted-id", "status": status}, "resources": [],
            "findings": [], "operations": [{"service": "sts", "operation": "GetCallerIdentity",
                                               "status": "ERROR", "error": "NoCredentialsError"}],
            "summary": {"finding_count": 0,
                        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                        "by_outcome": {"PASS": 0, "FAIL": 0, "NOT_APPLICABLE": 0, "NOT_SUPPORTED": 0, "ERROR": 0}}}


def invoke_assess(monkeypatch, tmp_path, data):
    monkeypatch.setattr("aegis.cli._settings", lambda: Settings(database=tmp_path / "unused.sqlite"))
    monkeypatch.setattr("aegis.cli.run_assessment", lambda _settings: "persisted-id")
    monkeypatch.setattr("aegis.cli.export_assessment", lambda _settings, _assessment_id: data)
    return CliRunner().invoke(app, ["assess", "--yes"])


def test_assess_cli_returns_nonzero_and_explains_empty_failed_assessment(monkeypatch, tmp_path):
    result = invoke_assess(monkeypatch, tmp_path, snapshot("FAILED"))
    assert result.exit_code == 1
    assert "Assessment persisted-id: FAILED" in result.output
    assert "Resources discovered: 0" in result.output
    assert "no resource-level security conclusions" in result.output
    assert "ERROR       sts:GetCallerIdentity: failure category NoCredentialsError" in result.output
    assert "By severity (FAIL outcomes)" in result.output


def test_assess_cli_success_requires_completed_status(monkeypatch, tmp_path):
    data = snapshot("COMPLETED")
    data["operations"] = []
    result = invoke_assess(monkeypatch, tmp_path, data)
    assert result.exit_code == 0
    assert "Assessment persisted-id: COMPLETED" in result.output
    assert "No resources discovered" in result.output


def test_assess_noninteractive_requires_explicit_yes_and_makes_no_calls(monkeypatch, tmp_path):
    monkeypatch.setattr("aegis.cli._settings", lambda: Settings(database=tmp_path / "unused.sqlite"))
    monkeypatch.setattr("aegis.cli.run_assessment", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("scan started")))
    result = CliRunner().invoke(app, ["assess", "--json"])
    assert result.exit_code == 2
    assert "Use --yes" in result.output
    assert "scan started" not in result.output


def test_assess_preview_is_local_and_lists_supported_scope(monkeypatch, tmp_path):
    monkeypatch.setattr("aegis.cli._settings", lambda: Settings(database=tmp_path / "unused.sqlite"))
    monkeypatch.setattr("aegis.cli.run_assessment", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("scan started")))
    result = CliRunner().invoke(app, ["assess", "--preview", "--json"])
    assert result.exit_code == 0
    assert '"pagination_supported": false' in result.output
    assert "DescribeSecurityGroups" in result.output


def test_preflight_prints_readiness_and_hides_all_secret_values(monkeypatch, tmp_path):
    from aegis.config import Settings
    monkeypatch.setattr("aegis.cli._settings", lambda: Settings(database=tmp_path / "unused.sqlite"))
    monkeypatch.setattr("aegis.cli.run_preflight", lambda *_args, **_kwargs: {
        "readiness": "READY WITH LIMITATIONS",
        "checks": [{"id": "credentials", "state": "PASS", "message": "Credentials are available."}],
        "operations": [{"service": "s3", "operation": "ListBuckets", "state": "UNSUPPORTED",
                        "capability": "UNSUPPORTED", "error_code": "NotImplemented"}],
        "secret": "credential-secret-marker",
    })
    human = CliRunner().invoke(app, ["preflight"])
    assert human.exit_code == 0
    assert "Overall readiness: READY WITH LIMITATIONS" in human.output
    assert "credential-secret-marker" not in human.output
    structured = CliRunner().invoke(app, ["preflight", "--json"])
    assert structured.exit_code == 0
    assert "credential-secret-marker" not in structured.output
    assert "ListBuckets" in structured.output


def test_preflight_blocked_uses_nonzero_exit(monkeypatch, tmp_path):
    monkeypatch.setattr("aegis.cli._settings", lambda: Settings(database=tmp_path / "unused.sqlite"))
    monkeypatch.setattr("aegis.cli.run_preflight", lambda *_args, **_kwargs: {
        "readiness": "BLOCKED", "checks": [], "operations": []})
    result = CliRunner().invoke(app, ["preflight"])
    assert result.exit_code == 1
    assert "Overall readiness: BLOCKED" in result.output
