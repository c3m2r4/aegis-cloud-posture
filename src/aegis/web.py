"""Local dashboard API runner. The initial release binds to loopback only."""
from __future__ import annotations

import os

import uvicorn

from aegis.config import Settings, load_local_dotenv
from aegis.web_api import create_app


def main() -> None:
    load_local_dotenv()
    try:
        port = int(os.getenv("AEGIS_WEB_PORT", "8000"))
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise SystemExit("AEGIS_WEB_PORT must be an integer from 1 to 65535") from None
    try:
        settings = Settings.from_env()
    except ValueError as exc:
        raise SystemExit(f"Configuration error: {exc}") from None
    uvicorn.run(create_app(settings), host="127.0.0.1", port=port, access_log=False)
