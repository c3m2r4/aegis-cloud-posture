"""Non-persistent guided setup checks used only after an explicit preflight action."""
from __future__ import annotations

import re
import os
import sqlite3
import socket
import tempfile
from urllib.parse import urlsplit
from urllib.parse import quote

import boto3

from aegis.adapters import FlociAdapter, OperationResult, specifications
from aegis.config import Settings, credential_status
from aegis.locking import ScanLock, acquire_scan_lock
from aegis.rules import RULES
from aegis.web_db import read_only_connect, schema_available


def assessment_preview(settings: Settings) -> dict:
    """Return configured scope and verified implementation metadata without cloud calls."""
    with read_only_connect(settings.database) as db:
        database = "not_created" if db is None else ("available" if schema_available(db) else "incompatible")
    return {
        "endpoint": settings.endpoint_url,
        "region": settings.region,
        "database": {"state": database},
        "operations": [{"service": spec.service, "operation": spec.operation,
                        "resource_type": spec.resource_type}
                       for spec in specifications()] + [
                           {"service": "iam", "operation": "GetPolicyVersion", "resource_type": "iam_policy_version",
                            "scope": "Default version for each local policy returned by ListPolicies"}],
        "rules": [{"id": rule.rule_id, "title": rule.title, "severity": rule.severity,
                   "resource_type": rule.resource_type, "required_evidence": list(rule.required_evidence),
                   "description": rule.description}
                  for rule in RULES],
        "pagination_supported": False,
        "unsupported_capabilities": [
            "Pagination is disabled because Floci behavior has not been verified.",
            "Log retention remains NOT_SUPPORTED when retentionInDays is absent.",
        ],
        "expected_outputs": ["Persisted sanitized evidence", "Inventory", "Rule outcomes", "JSON and Markdown reports"],
        "network_notice": "Read-only API requests still create network activity and may incur provider charges.",
    }


def _safe_operation_error(result: OperationResult) -> str | None:
    if result.status == "SUCCESS":
        return None
    raw = result.error or ""
    match = re.match(r"([A-Za-z][A-Za-z0-9_.-]{0,79}):", raw)
    return match.group(1) if match else "details_hidden"


def _database_write_ready(path) -> bool:
    """Check write access without creating the configured DB or changing rows."""
    path = path.expanduser().resolve()
    if path.exists():
        if not os.access(path, os.W_OK):
            return False
        uri = f"file:{quote(str(path), safe='/')}?mode=rw"
        try:
            connection = sqlite3.connect(uri, uri=True, timeout=1)
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.rollback()
            finally:
                connection.close()
            return True
        except sqlite3.Error:
            return False
    parent = path.parent
    while not parent.exists() and parent.parent != parent:
        parent = parent.parent
    if not parent.is_dir() or not os.access(parent, os.W_OK):
        return False
    try:
        with tempfile.NamedTemporaryFile(prefix=".aegis-write-check-", dir=parent):
            pass
        return True
    except OSError:
        return False


def _run_preflight_locked(settings: Settings, adapter: FlociAdapter | None = None) -> dict:
    """Check credential resolution, endpoint reachability, schema, identity and operations.

    This action deliberately does not persist discovery output or raw responses.
    It may create the configured database parent and a temporary write probe to
    test local storage access; the probe is removed before the response. It must
    be requested explicitly; ordinary page/API reads never call it.
    """
    checks: list[dict] = []
    try:
        parsed = urlsplit(settings.endpoint_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        with socket.create_connection((parsed.hostname, port), timeout=settings.connect_timeout):
            tcp_ok = True
    except (OSError, ValueError):
        tcp_ok = False
    checks.append({"id": "endpoint", "state": "PASS" if tcp_ok else "FAIL",
                   "message": "Configured endpoint accepted a TCP connection." if tcp_ok else
                              "The configured endpoint could not be reached.",
                   "next_step": "Check AEGIS_ENDPOINT_URL and start the endpoint service, then run `aegis doctor` or choose Run preflight again."})

    session = boto3.Session(region_name=settings.region)
    credentials, credential_detail = credential_status(session)
    credential_ok = credentials == "AVAILABLE"
    checks.append({"id": "credentials", "state": "PASS" if credential_ok else "FAIL",
                   "message": "Credentials are available through the boto3 provider chain." if credential_ok else
                              f"Credentials are {credentials.lower()}: {credential_detail}",
                   "next_step": "Select a configured profile with AWS_PROFILE, then run `aegis doctor` or choose Run preflight again; never paste secret values here."})

    try:
        with read_only_connect(settings.database) as db:
            database_state = "not_created" if db is None else ("available" if schema_available(db) else "incompatible")
    except Exception:
        database_state = "unavailable"
    if database_state in {"available", "not_created"} and not _database_write_ready(settings.database):
        database_state = "unavailable"
    database_ok = database_state in {"available", "not_created"}
    database_check_state = "FAIL" if not database_ok else "WARN" if database_state == "not_created" else "PASS"
    checks.append({"id": "database", "state": database_check_state,
                   "message": ("The assessment database is available." if database_state == "available" else
                               "The database will be initialized when a confirmed assessment starts." if database_state == "not_created" else
                               "The existing database schema is incompatible." if database_state == "incompatible" else
                               "The database could not be read."),
                   "next_step": "Check database permissions/schema or set AEGIS_DATABASE to a compatible path, then run `aegis preflight` again."})

    results: list[OperationResult] = []
    if credential_ok:
        try:
            results = (adapter or FlociAdapter(settings, session=session)).collect()
        except Exception as exc:
            # Do not surface exception strings, response bodies, paths, or credentials.
            results = [OperationResult("aegis", "preflight", "SUPPORTED_BUT_UNVERIFIED", "ERROR",
                                       error=type(exc).__name__)]
    identity = next((item for item in results if item.service == "sts" and item.operation == "GetCallerIdentity"), None)
    identity_ok = bool(identity and identity.status == "SUCCESS")
    account = None
    if identity_ok and identity and identity.response:
        candidate = identity.response.get("Account")
        account = str(candidate) if isinstance(candidate, (str, int)) else None
    checks.append({"id": "identity", "state": "PASS" if identity_ok else ("FAIL" if credential_ok else "BLOCKED"),
                   "message": ("Cloud identity verified." if identity_ok else
                               "Identity verification was not attempted because credentials are unavailable." if not credential_ok else
                               "Cloud identity could not be verified."),
                   "identity": account,
                   "next_step": "Check endpoint access, credential validity, and permission for sts:GetCallerIdentity, then run `aegis preflight` again."})
    operation_checks = [{"service": item.service, "operation": item.operation,
                         "capability": item.capability, "state": item.status,
                         "error_code": _safe_operation_error(item),
                         "resource_count": len(item.resources or [])}
                        for item in results]
    observed = {(item.service, item.operation) for item in results}
    for spec in specifications():
        if (spec.service, spec.operation) not in observed:
            operation_checks.append({"service": spec.service, "operation": spec.operation,
                                     "capability": "NOT_CHECKED",
                                     "state": "NOT_ATTEMPTED" if not credential_ok else "NOT_RETURNED",
                                     "error_code": None, "resource_count": 0})
    failures = [item for item in operation_checks if item["state"] != "SUCCESS"]
    if not credential_ok:
        checks.append({"id": "required_read_operations", "state": "BLOCKED",
                       "message": "Read operations were not attempted because credentials are unavailable.",
                       "next_step": "Resolve credentials, then run preflight again."})
    else:
        checks.append({"id": "required_read_operations", "state": "PASS" if not failures else "WARN",
                       "message": ("Verified read operations completed." if not failures else
                                   f"{len(failures)} read operation(s) were unsupported or errored."),
                       "next_step": "Review operation availability in this checklist. You may continue for a partial result or fix the provider and run preflight again."})
    checks.append({"id": "scope", "state": "PASS" if identity_ok else "WARN",
                   "message": "Scope is limited to the configured endpoint and region and the resource types shown in the preview.",
                   "next_step": "Review the preview’s resource types, rules, and evidence limitations before confirming or canceling."})
    blocked = not credential_ok or not identity_ok or not database_ok
    limited = (not tcp_ok) or database_state == "not_created" or bool(failures)
    readiness = "BLOCKED" if blocked else ("READY WITH LIMITATIONS" if limited else "READY")
    return {"readiness": readiness, "checks": checks, "operations": operation_checks,
            "identity": account, "limitations": [
                "This verifies only the listed read operations; it is not comprehensive cloud coverage.",
                "List operations are not paginated; additional pages may be omitted.",
                "A scan performs a fresh collection after confirmation, so its results can differ from preflight.",
            ]}


def run_preflight(settings: Settings, adapter: FlociAdapter | None = None, *,
                  lock: ScanLock | None = None) -> dict:
    """Run explicit readiness checks without overlapping discovery/assessment."""
    if lock is not None:
        with lock:
            return _run_preflight_locked(settings, adapter=adapter)
    with acquire_scan_lock(settings.database):
        return _run_preflight_locked(settings, adapter=adapter)
