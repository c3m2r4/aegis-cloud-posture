"""Configuration with safe localhost defaults."""
from __future__ import annotations

import os
import math
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from botocore.exceptions import BotoCoreError, PartialCredentialsError
from dotenv import find_dotenv, load_dotenv

_DOTENV_LOADED = False


def load_local_dotenv() -> bool:
    """Load an optional local env file without overriding exported variables."""
    global _DOTENV_LOADED
    explicit_env_file = os.getenv("AEGIS_ENV_FILE")
    dotenv_path = explicit_env_file or find_dotenv(usecwd=True)
    if not dotenv_path:
        return False
    load_dotenv(dotenv_path=dotenv_path, override=False)
    _DOTENV_LOADED = True
    return True


def dotenv_loaded() -> bool:
    return _DOTENV_LOADED


@dataclass(frozen=True)
class Settings:
    endpoint_url: str = "http://127.0.0.1:4566"
    region: str = "us-east-1"
    database: Path = Path("./aegis.db")
    connect_timeout: float = 3.0
    read_timeout: float = 8.0

    def __post_init__(self) -> None:
        parsed = urlparse(self.endpoint_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("endpoint_url must be an absolute http(s) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("endpoint_url must not contain credentials, query parameters, or fragments")
        if parsed.path not in {"", "/"}:
            raise ValueError("endpoint_url must not contain a path")
        if not self.region.strip():
            raise ValueError("region must not be empty")
        if not math.isfinite(self.connect_timeout) or not math.isfinite(self.read_timeout) or self.connect_timeout <= 0 or self.read_timeout <= 0:
            raise ValueError("timeouts must be greater than zero")

    @classmethod
    def from_env(cls) -> "Settings":
        endpoint = os.getenv("AEGIS_ENDPOINT_URL", "http://127.0.0.1:4566").strip()
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("AEGIS_ENDPOINT_URL must be an absolute http(s) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("AEGIS_ENDPOINT_URL must not contain credentials, query parameters, or fragments")
        if parsed.path not in {"", "/"}:
            raise ValueError("AEGIS_ENDPOINT_URL must not contain a path")
        try:
            connect_timeout = float(os.getenv("AEGIS_CONNECT_TIMEOUT", "3"))
            read_timeout = float(os.getenv("AEGIS_READ_TIMEOUT", "8"))
        except ValueError as exc:
            raise ValueError("AEGIS timeouts must be numbers") from exc
        if not math.isfinite(connect_timeout) or not math.isfinite(read_timeout) or connect_timeout <= 0 or read_timeout <= 0:
            raise ValueError("AEGIS timeouts must be greater than zero")
        region = os.getenv("AEGIS_REGION", "us-east-1").strip()
        if not region:
            raise ValueError("AEGIS_REGION must not be empty")
        database_value = os.getenv("AEGIS_DATABASE", "./aegis.db").strip()
        if not database_value:
            raise ValueError("AEGIS_DATABASE must not be empty")
        return cls(
            endpoint_url=endpoint.rstrip("/"),
            region=region,
            database=Path(database_value).expanduser(),
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )


def credential_status(session: object) -> tuple[str, str]:
    """Resolve the standard botocore provider chain without exposing credential data."""
    try:
        credentials = session.get_credentials()  # type: ignore[attr-defined]
    except PartialCredentialsError:
        return "INVALID", "Credential provider returned an incomplete credential pair."
    except BotoCoreError as exc:
        return "ERROR", f"Credential provider failed ({type(exc).__name__})."
    if credentials is None:
        return "MISSING", "No credentials were found in the AWS provider chain."
    try:
        frozen = credentials.get_frozen_credentials()
    except PartialCredentialsError:
        return "INVALID", "Credential provider returned an incomplete credential pair."
    except BotoCoreError as exc:
        return "ERROR", f"Credential provider failed ({type(exc).__name__})."
    if not frozen.access_key or not frozen.secret_key:
        return "INVALID", "Credential provider returned an incomplete credential pair."
    return "AVAILABLE", f"Credentials resolved via {credentials.method}; values are hidden."
