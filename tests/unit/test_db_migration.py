import sqlite3

from aegis.db import connect


def test_phase2_database_migrates_with_findings_and_operation_subject(tmp_path):
    path = tmp_path / "existing.sqlite"
    connection = sqlite3.connect(path)
    connection.executescript("""
    CREATE TABLE assessments (
      id TEXT PRIMARY KEY, started_at TEXT NOT NULL, completed_at TEXT,
      endpoint TEXT NOT NULL, region TEXT NOT NULL, status TEXT NOT NULL,
      tool_version TEXT NOT NULL
    );
    CREATE TABLE operations (
      id INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id TEXT NOT NULL REFERENCES assessments(id),
      service TEXT NOT NULL, operation TEXT NOT NULL, capability TEXT NOT NULL,
      status TEXT NOT NULL, error TEXT, evidence_json TEXT, evidence_sha256 TEXT,
      observed_at TEXT NOT NULL
    );
    """)
    connection.close()

    with connect(path) as migrated:
        columns = {row[1] for row in migrated.execute("PRAGMA table_info(operations)")}
        assert "subject_resource_id" in columns
        assert migrated.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'").fetchone()

    # Reopening an already migrated database must be idempotent.
    with connect(path) as migrated_again:
        columns = [row[1] for row in migrated_again.execute("PRAGMA table_info(operations)")]
        assert columns.count("subject_resource_id") == 1
        assert migrated_again.execute("SELECT COUNT(*) FROM assessments").fetchone()[0] == 0
