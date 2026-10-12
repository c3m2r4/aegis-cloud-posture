"""Read-only queries for the local dashboard.

Unlike :mod:`aegis.db`, this module never creates a database, initializes schema,
runs migrations, or commits changes. A missing database is represented as empty
data by the API layer.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from urllib.parse import quote


@contextmanager
def read_only_connect(path: Path) -> Iterator[sqlite3.Connection | None]:
    """Open an existing database with SQLite ``mode=ro``, or yield None if absent."""
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        yield None
        return
    uri = f"file:{quote(str(resolved), safe='/')}?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=2)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        yield connection
    finally:
        connection.close()


def schema_available(connection: sqlite3.Connection) -> bool:
    """Check the dashboard's required schema without creating or migrating it."""
    required = {"assessments", "operations", "resources", "findings"}
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not required <= tables:
        return False
    expected = {
        "assessments": {"id", "started_at", "completed_at", "endpoint", "region", "status", "tool_version"},
        "operations": {"id", "assessment_id", "service", "operation", "subject_resource_id", "capability",
                       "status", "error", "evidence_json", "evidence_sha256", "observed_at"},
        "resources": {"assessment_id", "resource_type", "resource_id", "name", "source_service",
                       "source_operation", "observed_at", "attributes_json"},
        "findings": {"assessment_id", "rule_id", "resource_type", "resource_id", "outcome", "severity", "title",
                     "description", "reason", "remediation", "evidence_refs_json", "assessed_at",
                     "previous_outcome", "change_state"},
    }
    return all(columns <= {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
               for table, columns in expected.items())


def _decode_rows(rows: list[sqlite3.Row], json_columns: tuple[str, ...] = ()) -> list[dict]:
    decoded = []
    for row in rows:
        item = dict(row)
        for column in json_columns:
            raw = item.pop(column, None)
            item[column.removesuffix("_json")] = json.loads(raw) if raw else ([] if column.endswith("refs_json") else None)
        decoded.append(item)
    return decoded


def load_assessment(connection: sqlite3.Connection, assessment_id: str) -> dict | None:
    row = connection.execute("SELECT * FROM assessments WHERE id=?", (assessment_id,)).fetchone()
    if row is None:
        return None
    assessment = dict(row)
    operations = _decode_rows(connection.execute(
        "SELECT id,service,operation,subject_resource_id,capability,status,error,evidence_json,evidence_sha256,observed_at "
        "FROM operations WHERE assessment_id=? ORDER BY id", (assessment_id,)).fetchall(), ("evidence_json",))
    resources = _decode_rows(connection.execute(
        "SELECT resource_type,resource_id,name,source_service,source_operation,observed_at,attributes_json "
        "FROM resources WHERE assessment_id=? ORDER BY resource_type,resource_id", (assessment_id,)).fetchall(),
        ("attributes_json",))
    findings = _decode_rows(connection.execute(
        "SELECT rule_id,resource_type,resource_id,outcome,severity,title,description,reason,remediation,evidence_refs_json,"
        "assessed_at,previous_outcome,change_state FROM findings WHERE assessment_id=? ORDER BY severity,rule_id,resource_id",
        (assessment_id,)).fetchall(), ("evidence_refs_json",))
    return {"assessment": assessment, "operations": operations, "resources": resources, "findings": findings}


def list_assessments(connection: sqlite3.Connection, limit: int, offset: int) -> list[dict]:
    return [dict(row) for row in connection.execute(
        "SELECT id,started_at,completed_at,endpoint,region,status,tool_version FROM assessments "
        "ORDER BY started_at DESC,id DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()]


def list_findings(connection: sqlite3.Connection, assessment_id: str, limit: int, offset: int,
                  outcome: str | None, severity: str | None, rule_id: str | None,
                  resource: str | None) -> tuple[list[dict], int]:
    clauses, params = ["assessment_id=?"], [assessment_id]
    for column, value in (("outcome", outcome), ("severity", severity), ("rule_id", rule_id)):
        if value is not None:
            clauses.append(f"{column}=?")
            params.append(value)
    if resource is not None:
        clauses.append("(resource_id LIKE ? OR resource_type LIKE ? OR EXISTS (SELECT 1 FROM resources r "
                       "WHERE r.assessment_id=findings.assessment_id AND r.resource_type=findings.resource_type "
                       "AND r.resource_id=findings.resource_id AND r.name LIKE ?))")
        pattern = f"%{resource}%"
        params.extend((pattern, pattern, pattern))
    where = " AND ".join(clauses)
    total = connection.execute(f"SELECT COUNT(*) FROM findings WHERE {where}", params).fetchone()[0]
    rows = connection.execute(
        "SELECT rule_id,resource_type,resource_id,outcome,severity,title,description,reason,remediation,"
        "evidence_refs_json,assessed_at,previous_outcome,change_state FROM findings WHERE " + where +
        " ORDER BY severity,rule_id,resource_id LIMIT ? OFFSET ?", (*params, limit, offset)).fetchall()
    return _decode_rows(rows, ("evidence_refs_json",)), total


def list_resources(connection: sqlite3.Connection, assessment_id: str, limit: int,
                   offset: int, service: str | None = None,
                   resource_type: str | None = None) -> tuple[list[dict], int]:
    clauses, params = ["assessment_id=?"], [assessment_id]
    if service is not None:
        clauses.append("source_service=?")
        params.append(service)
    if resource_type is not None:
        clauses.append("resource_type=?")
        params.append(resource_type)
    where = " AND ".join(clauses)
    total = connection.execute("SELECT COUNT(*) FROM resources WHERE " + where, params).fetchone()[0]
    rows = connection.execute(
        "SELECT resource_type,resource_id,name,source_service,source_operation,observed_at,attributes_json "
        "FROM resources WHERE " + where + " ORDER BY resource_type,resource_id LIMIT ? OFFSET ?",
        (*params, limit, offset)).fetchall()
    return _decode_rows(rows, ("attributes_json",)), total


def resource_filter_options(connection: sqlite3.Connection, assessment_id: str) -> dict[str, list[str]]:
    services = [row[0] for row in connection.execute(
        "SELECT DISTINCT source_service FROM resources WHERE assessment_id=? ORDER BY source_service",
        (assessment_id,)).fetchall()]
    resource_types = [row[0] for row in connection.execute(
        "SELECT DISTINCT resource_type FROM resources WHERE assessment_id=? ORDER BY resource_type",
        (assessment_id,)).fetchall()]
    return {"services": services, "resource_types": resource_types}


def list_operations(connection: sqlite3.Connection, assessment_id: str, limit: int,
                    offset: int) -> tuple[list[dict], int]:
    total = connection.execute("SELECT COUNT(*) FROM operations WHERE assessment_id=?", (assessment_id,)).fetchone()[0]
    rows = connection.execute(
        "SELECT id,service,operation,subject_resource_id,capability,status,evidence_sha256,observed_at "
        "FROM operations WHERE assessment_id=? ORDER BY id LIMIT ? OFFSET ?", (assessment_id, limit, offset)).fetchall()
    return [dict(row) for row in rows], total
