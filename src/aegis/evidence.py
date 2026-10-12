"""Sanitize cloud responses before evidence is persisted or exported."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit


SENSITIVE_KEY = re.compile(
    r"(secret|password|credential|token|authorization|private.?key|access.?key|user.?data|session.?key)",
    re.IGNORECASE,
)
AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")


def sanitize(value: Any, key: str | None = None) -> Any:
    """Recursively redact likely secrets and sanitize strings."""
    if key and SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): sanitize(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        value = AWS_ACCESS_KEY.sub("[REDACTED]", value)
        return BEARER.sub("Bearer [REDACTED]", value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def safe_endpoint_url(value: Any) -> str:
    """Render only endpoint scheme/host/port, removing user info and path data."""
    if not isinstance(value, str):
        return "[REDACTED]"
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return "[REDACTED]"
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        if parsed.port:
            host += f":{parsed.port}"
        path = ""
        if parsed.path not in {"", "/"}:
            path = "/[path-sha256-" + hashlib.sha256(parsed.path.encode("utf-8")).hexdigest()[:16] + "]"
        return urlunsplit((parsed.scheme, host, path, "", ""))
    except ValueError:
        return "[REDACTED]"


def canonical_json(value: Any) -> str:
    return json.dumps(sanitize(value), sort_keys=True, separators=(",", ":"), default=str)


def evidence_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
