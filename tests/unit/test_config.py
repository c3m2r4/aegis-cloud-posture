import pytest
import boto3

from aegis.config import Settings, credential_status, load_local_dotenv


@pytest.mark.parametrize("endpoint", [
    "http://user:password@127.0.0.1:4566",
    "http://127.0.0.1:4566/?token=secret",
    "http://127.0.0.1:4566/#secret",
    "http://127.0.0.1:4566/secret-path",
])
def test_endpoint_rejects_embedded_secrets(endpoint):
    with pytest.raises(ValueError):
        Settings(endpoint_url=endpoint)


def test_endpoint_allows_localhost_default():
    assert Settings().endpoint_url == "http://127.0.0.1:4566"


def test_process_environment_overrides_settings_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_ENDPOINT_URL", "http://127.0.0.1:9999/")
    monkeypatch.setenv("AEGIS_REGION", "test-region-1")
    monkeypatch.setenv("AEGIS_DATABASE", str(tmp_path / "configured.sqlite"))
    monkeypatch.setenv("AEGIS_CONNECT_TIMEOUT", "1.25")
    monkeypatch.setenv("AEGIS_READ_TIMEOUT", "2.5")

    settings = Settings.from_env()
    assert settings.endpoint_url == "http://127.0.0.1:9999"
    assert settings.region == "test-region-1"
    assert settings.database == tmp_path / "configured.sqlite"
    assert settings.connect_timeout == 1.25
    assert settings.read_timeout == 2.5


def test_dotenv_loader_respects_process_environment_precedence(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("AEGIS_ENDPOINT_URL=http://should-not-load:4566\n")
    monkeypatch.setenv("AEGIS_ENDPOINT_URL", "http://shell-wins:4566")
    assert load_local_dotenv()
    assert Settings.from_env().endpoint_url == "http://shell-wins:4566"


def test_dotenv_loader_supplies_configuration_when_shell_value_is_absent(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("AEGIS_ENDPOINT_URL=http://dotenv-local:4566\n")
    monkeypatch.delenv("AEGIS_ENDPOINT_URL", raising=False)
    assert load_local_dotenv()
    assert Settings.from_env().endpoint_url == "http://dotenv-local:4566"


def _isolate_credential_chain(monkeypatch):
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/dev/null")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)


def test_standard_aws_environment_credentials_are_resolved_without_disclosure(monkeypatch):
    _isolate_credential_chain(monkeypatch)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "local-test-access")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "local-test-secret")
    status, message = credential_status(boto3.Session(region_name="us-east-1"))
    assert status == "AVAILABLE"
    assert "env" in message
    assert "local-test-access" not in message and "local-test-secret" not in message


def test_absent_credentials_are_reported_as_missing(monkeypatch):
    _isolate_credential_chain(monkeypatch)
    assert credential_status(boto3.Session()) == (
        "MISSING", "No credentials were found in the AWS provider chain.")


@pytest.mark.parametrize("access,secret,expected", [
    ("only-access-key", None, "INVALID"),
    (None, "only-secret-key", "MISSING"),
])
def test_partial_environment_credentials_are_never_reported_as_available(monkeypatch, access, secret, expected):
    _isolate_credential_chain(monkeypatch)
    if access:
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", access)
    if secret:
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", secret)
    status, message = credential_status(boto3.Session())
    assert status == expected
    assert status != "AVAILABLE"
    assert access not in message if access else True
    assert secret not in message if secret else True


@pytest.mark.parametrize("name,value", [
    ("AEGIS_ENDPOINT_URL", "not-a-url"),
    ("AEGIS_REGION", "   "),
    ("AEGIS_DATABASE", "  "),
    ("AEGIS_CONNECT_TIMEOUT", "nan"),
    ("AEGIS_READ_TIMEOUT", "0"),
])
def test_malformed_environment_configuration_is_rejected(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        Settings.from_env()


def test_boto_client_uses_local_endpoint_and_standard_environment_credentials(monkeypatch, tmp_path):
    _isolate_credential_chain(monkeypatch)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "local-test-access")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "local-test-secret")
    from aegis.adapters import FlociAdapter

    settings = Settings(endpoint_url="http://127.0.0.1:4566", database=tmp_path / "offline.sqlite")
    client = FlociAdapter(settings, session=boto3.Session(region_name=settings.region))._client("sts")
    assert client.meta.endpoint_url == settings.endpoint_url
    assert client._request_signer._credentials.access_key == "local-test-access"
    assert client._request_signer._credentials.secret_key == "local-test-secret"
