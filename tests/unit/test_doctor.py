from types import SimpleNamespace

from botocore.exceptions import ClientError
from typer.testing import CliRunner

from aegis.cli import app
from aegis.config import Settings


class FakeSession:
    def __init__(self, available=True, error=None):
        self.available = available
        self.error = error

    def get_credentials(self):
        if not self.available:
            return None
        return SimpleNamespace(method="env", get_frozen_credentials=lambda: SimpleNamespace(
            access_key="hidden-access-value", secret_key="hidden-secret-value"))

    def client(self, service, **kwargs):
        assert service == "sts"
        assert kwargs["endpoint_url"] == "http://127.0.0.1:4566"
        if self.error:
            raise self.error
        return SimpleNamespace(get_caller_identity=lambda: {"Account": "000000000000"})


def setup_doctor(monkeypatch, tmp_path, session):
    monkeypatch.setattr("aegis.cli._settings", lambda: Settings(database=tmp_path / "doctor.sqlite"))
    monkeypatch.setattr("aegis.cli.boto3.Session", lambda region_name: session)
    class Connected:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
    monkeypatch.setattr("aegis.cli.socket.create_connection", lambda *_args, **_kwargs: Connected())


def test_doctor_missing_credentials_is_not_ready_and_has_remediation(monkeypatch, tmp_path):
    setup_doctor(monkeypatch, tmp_path, FakeSession(available=False))
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "FAIL credentials: MISSING" in result.output
    assert "not attempted because credentials are unavailable" in result.output
    assert "Overall readiness: NOT READY" in result.output
    assert "AWS profile configured with the emulator's local-only credentials" in result.output
    assert "Never reuse emulator credentials" in result.output


def test_doctor_success_hides_secrets_and_reports_ready(monkeypatch, tmp_path):
    setup_doctor(monkeypatch, tmp_path, FakeSession())
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "PASS credentials: AVAILABLE" in result.output
    assert "PASS sts:GetCallerIdentity" in result.output
    assert "Overall readiness: READY" in result.output
    assert "hidden-access-value" not in result.output
    assert "hidden-secret-value" not in result.output


def test_doctor_authentication_failure_is_distinct_from_missing_credentials(monkeypatch, tmp_path):
    failure = ClientError({"Error": {"Code": "InvalidClientTokenId", "Message": "invalid"}}, "GetCallerIdentity")
    setup_doctor(monkeypatch, tmp_path, FakeSession(error=failure))
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "PASS credentials: AVAILABLE" in result.output
    assert "authentication/API failure InvalidClientTokenId" in result.output
    assert "Overall readiness: NOT READY" in result.output


def test_doctor_network_failure_is_distinct_from_authentication_failure(monkeypatch, tmp_path):
    setup_doctor(monkeypatch, tmp_path, FakeSession(error=OSError("connection refused")))
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "PASS credentials: AVAILABLE" in result.output
    assert "network/SDK failure OSError" in result.output
    assert "connection refused" not in result.output


def test_doctor_invalid_configuration_exits_two_without_leaking_url_details(monkeypatch):
    monkeypatch.setenv("AEGIS_ENDPOINT_URL", "http://user:secret@host/?token=hidden")
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 2
    assert "Configuration error: AEGIS_ENDPOINT_URL must not contain credentials" in result.output
    assert "secret" not in result.output and "hidden" not in result.output
