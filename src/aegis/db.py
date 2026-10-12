"""Small SQLite persistence layer for assessment records and inventory."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS assessments (
  id TEXT PRIMARY KEY, started_at TEXT NOT NULL, completed_at TEXT,
  endpoint TEXT NOT NULL, region TEXT NOT NULL, status TEXT NOT NULL,
  tool_version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operations (
  id INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id TEXT NOT NULL REFERENCES assessments(id),
  service TEXT NOT NULL, operation TEXT NOT NULL, subject_resource_id TEXT,
  capability TEXT NOT NULL,
  status TEXT NOT NULL, error TEXT, evidence_json TEXT, evidence_sha256 TEXT,
  observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS resources (
  id INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id TEXT NOT NULL REFERENCES assessments(id),
  resource_type TEXT NOT NULL, resource_id TEXT NOT NULL, name TEXT,
  source_service TEXT NOT NULL, source_operation TEXT NOT NULL,
  observed_at TEXT NOT NULL, attributes_json TEXT NOT NULL,
  UNIQUE(assessment_id, resource_type, resource_id)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id TEXT NOT NULL REFERENCES assessments(id),
  rule_id TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK(outcome IN ('PASS','FAIL','NOT_APPLICABLE','NOT_SUPPORTED','ERROR')),
  severity TEXT NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
  title TEXT NOT NULL, description TEXT NOT NULL, reason TEXT NOT NULL,
  remediation TEXT NOT NULL, evidence_refs_json TEXT NOT NULL,
  assessed_at TEXT NOT NULL, previous_outcome TEXT, change_state TEXT NOT NULL,
  UNIQUE(assessment_id, rule_id, resource_type, resource_id)
);
CREATE INDEX IF NOT EXISTS idx_resources_assessment ON resources(assessment_id);
CREATE INDEX IF NOT EXISTS idx_operations_assessment ON operations(assessment_id);
CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(assessment_id);
CREATE INDEX IF NOT EXISTS idx_findings_identity ON findings(rule_id, resource_type, resource_id);
"""


@contextmanager
def connect(path: Path) -> Iterator[sqlite3.Connection]:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(SCHEMA)
        operation_columns = {row[1] for row in connection.execute("PRAGMA table_info(operations)")}
        if "subject_resource_id" not in operation_columns:
            connection.execute("ALTER TABLE operations ADD COLUMN subject_resource_id TEXT")
        yield connection
        connection.commit()
    finally:
        connection.close()
