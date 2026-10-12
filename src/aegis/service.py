"""Assessment orchestration, sanitized persistence, and comparison history."""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from aegis import __version__
from aegis.adapters import FlociAdapter, OperationResult
from aegis.config import Settings
from aegis.db import connect
from aegis.evidence import canonical_json, evidence_hash, safe_endpoint_url, sanitize
from aegis.locking import ScanLock, acquire_scan_lock
from aegis.rules import RULES, RuleResult, evaluate
from aegis.web_db import read_only_connect, schema_available


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_discovery(settings: Settings, adapter: FlociAdapter | None = None, *, in_progress: bool = False,
                   assessment_id: str | None = None) -> str:
    assessment_id = assessment_id or str(uuid.uuid4())
    started = utcnow()
    adapter = adapter or FlociAdapter(settings)
    results = adapter.collect()
    terminal = {result.status for result in results}
    successful = sum(result.status == "SUCCESS" for result in results)
    if terminal <= {"SUCCESS"}:
        status = "COMPLETED"
    elif successful:
        status = "PARTIAL"
    else:
        status = "FAILED"
    with connect(settings.database) as db:
        db.execute("INSERT INTO assessments(id,started_at,endpoint,region,status,tool_version) VALUES(?,?,?,?,?,?)",
                   (assessment_id, started, settings.endpoint_url, settings.region,
                    "RUNNING" if in_progress else status, __version__))
        for result in results:
            _persist_result(db, assessment_id, result)
        if not in_progress:
            db.execute("UPDATE assessments SET completed_at=? WHERE id=?", (utcnow(), assessment_id))
    return assessment_id


def run_discovery(settings: Settings, adapter: FlociAdapter | None = None) -> str:
    """Collect and persist inventory while excluding overlapping local runs."""
    with acquire_scan_lock(settings.database):
        return _run_discovery(settings, adapter=adapter)


def _persist_result(db: Any, assessment_id: str, result: OperationResult) -> None:
    safe_response = sanitize(result.response) if result.response is not None else None
    response_json = canonical_json(safe_response) if safe_response is not None else None
    digest = evidence_hash(safe_response) if safe_response is not None else None
    safe_error = _error_category(result.error)
    db.execute("""INSERT INTO operations(assessment_id,service,operation,subject_resource_id,capability,status,error,evidence_json,evidence_sha256,observed_at)
                  VALUES(?,?,?,?,?,?,?,?,?,?)""",
               (assessment_id, result.service, result.operation, result.subject_resource_id, result.capability, result.status,
                safe_error, response_json, digest, result.observed_at or utcnow()))
    for resource in result.resources or []:
        attrs = sanitize(resource.get("attributes", {}))
        db.execute("""INSERT OR IGNORE INTO resources(assessment_id,resource_type,resource_id,name,source_service,source_operation,observed_at,attributes_json)
                      VALUES(?,?,?,?,?,?,?,?)""",
                   (assessment_id, resource["resource_type"], resource["resource_id"], resource.get("name"),
                    result.service, result.operation, result.observed_at or utcnow(), canonical_json(attrs)))


def _error_category(value: str | None) -> str | None:
    """Persist a short provider/SDK error code, not an untrusted message body."""
    if not value:
        return None
    if value.startswith("Pagination is required"):
        return "PaginationIncomplete"
    candidate = value.split(":", 1)[0].strip()
    return candidate if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,79}", candidate) else "OperationError"


def _evaluate_assessment(settings: Settings, assessment_id: str) -> None:
    """Evaluate one collected assessment and commit its actual terminal state."""
    with connect(settings.database) as db:
        resources = [dict(row) for row in db.execute(
            "SELECT * FROM resources WHERE assessment_id=? ORDER BY resource_type,resource_id", (assessment_id,)).fetchall()]
        operations = [dict(row) for row in db.execute(
            "SELECT * FROM operations WHERE assessment_id=? ORDER BY id", (assessment_id,)).fetchall()]
        now = utcnow()
        for rule in RULES:
            targets = [resource for resource in resources if resource["resource_type"] == rule.resource_type]
            required = set(rule.required_evidence)
            matching_ops = [op for op in operations if f"{op['service']}:{op['operation']}" in required]
            if not targets:
                # Operation status already records a failed/unsupported check. An
                # empty inventory has no resource identity and must not become a
                # synthetic scope finding or a security conclusion.
                continue
            for resource in targets:
                attrs = json.loads(resource["attributes_json"])
                normalized = {"resource_type": resource["resource_type"], "resource_id": resource["resource_id"],
                              "name": resource["name"], "attributes": attrs}
                evidence_ops = []
                for op in matching_ops:
                    subject = op.get("subject_resource_id")
                    if op["operation"] == "GetPolicyVersion" and subject and subject != resource["resource_id"] and not subject.startswith(resource["resource_id"] + "#"):
                        continue
                    evidence_ops.append(op)
                missing_evidence = None
                for required_operation in rule.required_evidence:
                    service, operation = required_operation.split(":", 1)
                    candidates = [op for op in evidence_ops if op["service"] == service and op["operation"] == operation]
                    if operation == "GetPolicyVersion":
                        candidates = [op for op in candidates if op.get("subject_resource_id") and
                                      (op["subject_resource_id"] == resource["resource_id"] or
                                       op["subject_resource_id"].startswith(resource["resource_id"] + "#"))]
                    if not candidates or not any(op["status"] == "SUCCESS" for op in candidates):
                        failed = next((op for op in candidates if op["status"] == "ERROR"), None)
                        unsupported = next((op for op in candidates if op["status"] == "UNSUPPORTED"), None)
                        incomplete = next((op for op in candidates if op["status"] == "INCOMPLETE"), None)
                        if failed:
                            reason = failed.get("error") or f"Required operation {service}:{operation} failed."
                            missing_evidence = RuleResult("ERROR", str(sanitize(reason)))
                        elif unsupported:
                            reason = unsupported.get("error") or f"Required operation {service}:{operation} is unsupported."
                            missing_evidence = RuleResult("NOT_SUPPORTED", str(sanitize(reason)))
                        elif incomplete:
                            missing_evidence = RuleResult(
                                "NOT_SUPPORTED",
                                f"Required operation {service}:{operation} returned a continuation marker; remaining pages were not verified.")
                        else:
                            missing_evidence = RuleResult("NOT_SUPPORTED",
                                f"Required operation evidence {service}:{operation} is missing for this resource.")
                        break
                result = missing_evidence or evaluate(rule, normalized)
                _persist_finding(db, assessment_id, rule, resource["resource_type"], resource["resource_id"],
                                 result, evidence_ops, now)
        incomplete = db.execute("""SELECT 1 FROM findings WHERE assessment_id=?
                                  AND outcome IN ('NOT_SUPPORTED','ERROR') LIMIT 1""", (assessment_id,)).fetchone()
        operation_statuses = [row[0] for row in db.execute(
            "SELECT status FROM operations WHERE assessment_id=?", (assessment_id,)).fetchall()]
        successful = sum(item == "SUCCESS" for item in operation_statuses)
        if not operation_statuses or all(item == "SUCCESS" for item in operation_statuses):
            status = "COMPLETED"
        elif successful:
            status = "PARTIAL"
        else:
            status = "FAILED"
        if incomplete and status == "COMPLETED":
            status = "PARTIAL"
        db.execute("UPDATE assessments SET status=?,completed_at=? WHERE id=?", (status, utcnow(), assessment_id))


def _run_assessment_locked(settings: Settings, adapter: FlociAdapter | None = None,
                           assessment_id: str | None = None) -> str:
    """Discover, evaluate, and persist one run with truthful RUNNING/terminal status."""
    assessment_id = _run_discovery(settings, adapter=adapter, in_progress=True, assessment_id=assessment_id)
    try:
        _evaluate_assessment(settings, assessment_id)
    except Exception:
        # A failed evaluator or persistence step must not leave a collected row
        # appearing complete. Preserve its evidence and mark its terminal state.
        try:
            with connect(settings.database) as db:
                db.execute("UPDATE assessments SET status='FAILED',completed_at=? WHERE id=?",
                           (utcnow(), assessment_id))
        except Exception:
            pass
        raise
    return assessment_id


def run_assessment(settings: Settings, adapter: FlociAdapter | None = None, *,
                   lock: ScanLock | None = None, assessment_id: str | None = None) -> str:
    """Run one serialized assessment; a pre-acquired lock may be passed by the web worker."""
    if lock is not None:
        with lock:
            return _run_assessment_locked(settings, adapter=adapter, assessment_id=assessment_id)
    with acquire_scan_lock(settings.database):
        return _run_assessment_locked(settings, adapter=adapter, assessment_id=assessment_id)


def _persist_finding(db: Any, assessment_id: str, rule: Any, resource_type: str, resource_id: str,
                     result: RuleResult, refs: list[dict[str, Any]], assessed_at: str) -> None:
    evidence_refs = [{"operation_id": op["id"], "service": op["service"], "operation": op["operation"],
                      "subject_resource_id": op.get("subject_resource_id"),
                      "status": op["status"], "evidence_sha256": op["evidence_sha256"]}
                     for op in refs]
    endpoint_row = db.execute("SELECT endpoint FROM assessments WHERE id=?", (assessment_id,)).fetchone()
    previous = db.execute("""SELECT f.outcome FROM findings f JOIN assessments a ON a.id=f.assessment_id
                              WHERE f.rule_id=? AND f.resource_type=? AND f.resource_id=?
                                AND a.endpoint=? AND f.assessment_id<>?
                              ORDER BY f.assessed_at DESC LIMIT 1""",
                          (rule.rule_id, resource_type, resource_id, endpoint_row["endpoint"], assessment_id)).fetchone()
    previous_outcome = previous["outcome"] if previous else None
    change_state = "FIRST_SEEN" if previous is None else ("UNCHANGED" if previous_outcome == result.outcome else "CHANGED")
    db.execute("""INSERT OR REPLACE INTO findings(assessment_id,rule_id,resource_type,resource_id,outcome,severity,title,description,reason,remediation,evidence_refs_json,assessed_at,previous_outcome,change_state)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
               (assessment_id, rule.rule_id, resource_type, resource_id, result.outcome, rule.severity,
                rule.title, rule.description, str(sanitize(result.reason)), rule.remediation,
                canonical_json(evidence_refs), assessed_at, previous_outcome, change_state))


def export_assessment(settings: Settings, assessment_id: str | None = None) -> dict[str, Any]:
    with read_only_connect(settings.database) as db:
        if db is None or not schema_available(db):
            raise LookupError("No matching assessment was found")
        if assessment_id is None:
            row = db.execute("SELECT * FROM assessments ORDER BY started_at DESC LIMIT 1").fetchone()
        else:
            row = db.execute("SELECT * FROM assessments WHERE id=?", (assessment_id,)).fetchone()
        if row is None:
            raise LookupError("No matching assessment was found")
        assessment = dict(row)
        operations = [dict(item) for item in db.execute(
            "SELECT id,service,operation,subject_resource_id,capability,status,error,evidence_json,evidence_sha256,observed_at FROM operations WHERE assessment_id=? ORDER BY id",
            (assessment["id"],)).fetchall()]
        resources = [dict(item) for item in db.execute(
            "SELECT resource_type,resource_id,name,source_service,source_operation,observed_at,attributes_json FROM resources WHERE assessment_id=? ORDER BY resource_type,resource_id",
            (assessment["id"],)).fetchall()]
        findings = [dict(item) for item in db.execute(
            "SELECT rule_id,resource_type,resource_id,outcome,severity,title,description,reason,remediation,evidence_refs_json,assessed_at,previous_outcome,change_state FROM findings WHERE assessment_id=? ORDER BY severity,rule_id,resource_id",
            (assessment["id"],)).fetchall()]
    for item in operations:
        item["error"] = _error_category(item.get("error"))
        item["evidence"] = json.loads(item.pop("evidence_json")) if item["evidence_json"] else None
    for item in resources:
        item["attributes"] = json.loads(item.pop("attributes_json"))
    for item in findings:
        item["evidence_refs"] = json.loads(item.pop("evidence_refs_json"))
    assessment["endpoint"] = safe_endpoint_url(assessment.get("endpoint"))
    outcomes = ("PASS", "FAIL", "NOT_APPLICABLE", "NOT_SUPPORTED", "ERROR")
    severities = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    summary = {
        "by_outcome": {outcome: sum(f["outcome"] == outcome for f in findings) for outcome in outcomes},
        "by_severity": {severity: sum(f["outcome"] == "FAIL" and f["severity"] == severity for f in findings) for severity in severities},
        "finding_count": len(findings),
    }
    return sanitize({"assessment": assessment, "operations": operations, "resources": resources,
                     "findings": findings, "summary": summary})
