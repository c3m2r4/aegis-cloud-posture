"""Comparison and presentation of persisted AEGIS assessments."""
from __future__ import annotations

import json
from collections import Counter
from typing import Any

OUTCOMES = ("PASS", "FAIL", "NOT_APPLICABLE", "NOT_SUPPORTED", "ERROR")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
NON_CLOUD_RESOURCE_TYPES = {"aws_identity", "iam_policy_version"}


def cloud_resource_count(resources: list[dict[str, Any]]) -> int:
    """Count inventory objects, excluding identity metadata and policy-version evidence records."""
    return sum(resource.get("resource_type") not in NON_CLOUD_RESOURCE_TYPES for resource in resources)


def _finding_key(item: dict[str, Any]) -> tuple[str, str, str] | None:
    rule = item.get("rule_id")
    resource_type = item.get("resource_type")
    resource_id = item.get("resource_id")
    if all(isinstance(value, str) and value.strip() for value in (rule, resource_type, resource_id)):
        return rule, resource_type, resource_id
    return None


def _resource_key(item: dict[str, Any]) -> tuple[str, str] | None:
    resource_type, resource_id = item.get("resource_type"), item.get("resource_id")
    if all(isinstance(value, str) and value.strip() for value in (resource_type, resource_id)):
        return resource_type, resource_id
    return None


def _has_successful_evidence(finding: dict[str, Any]) -> bool:
    """Require explicit successful operation references before confirming a finding."""
    refs = finding.get("evidence_refs")
    return bool(refs) and isinstance(refs, list) and all(
        isinstance(ref, dict)
        and ref.get("operation_id") is not None
        and ref.get("status") == "SUCCESS"
        and isinstance(ref.get("evidence_sha256"), str)
        and bool(ref["evidence_sha256"])
        for ref in refs
    )


def compare_assessments(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare two stored snapshots without treating absent/unsupported evidence as safe."""
    old_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    new_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    uncomparable: list[dict[str, Any]] = []
    for side, snapshot, index in (("previous", previous, old_by_key), ("current", current, new_by_key)):
        for finding in snapshot.get("findings", []):
            key = _finding_key(finding)
            if key is None:
                uncomparable.append({"assessment": side, "finding": finding, "reason": "Missing stable rule or resource identity."})
            elif key in index:
                uncomparable.append({"assessment": side, "finding": finding, "reason": "Duplicate finding identity in assessment."})
            else:
                index[key] = finding

    new_findings, resolved, unchanged, changed, not_reassessed = [], [], [], [], []
    for key in sorted(old_by_key.keys() | new_by_key.keys()):
        old, new = old_by_key.get(key), new_by_key.get(key)
        if old is None:
            # A new failed finding is meaningful; a new unsupported/error result is a coverage gap.
            if new["outcome"] == "FAIL":
                if not _has_successful_evidence(new):
                    changed.append({"finding": new, "previous": None, "current": new,
                                    "reason": "Finding lacks complete successful evidence references; confirmation is unavailable."})
                else:
                    new_findings.append({"finding": new, "previous": None, "current": new})
            elif new["outcome"] in {"ERROR", "NOT_SUPPORTED"}:
                changed.append({"finding": new, "previous": None, "current": new,
                                "reason": "New evaluation lacks supported evidence."})
            continue
        if new is None:
            # Absence can mean scope or discovery changed; it is never proof of remediation.
            if old["outcome"] == "FAIL":
                not_reassessed.append({"finding": old, "previous": old, "current": None,
                                       "reason": "No matching current evaluation; resolution is unverified."})
            continue
        old_outcome, new_outcome = old.get("outcome"), new.get("outcome")
        evidence_unavailable = not _has_successful_evidence(new)
        prior_evidence_unavailable = not _has_successful_evidence(old)
        if (evidence_unavailable or prior_evidence_unavailable) and old_outcome not in {"NOT_SUPPORTED", "ERROR"} and new_outcome not in {"NOT_SUPPORTED", "ERROR"}:
            changed.append({"finding": new, "previous": old, "current": new,
                            "reason": "Evidence is missing or unavailable in one or both assessments; the outcome cannot be confirmed."})
            continue
        if old_outcome == "FAIL" and new_outcome in {"PASS", "NOT_APPLICABLE"}:
            resolved.append({"finding": new, "previous": old, "current": new})
        elif old_outcome in {"NOT_SUPPORTED", "ERROR"} or new_outcome in {"NOT_SUPPORTED", "ERROR"}:
            if old_outcome == new_outcome and old.get("severity") == new.get("severity"):
                unchanged.append({"finding": new, "previous": old, "current": new})
            else:
                changed.append({"finding": new, "previous": old, "current": new,
                                "reason": "Evidence support or operation status changed; this is not a confirmed pass or resolution."})
        elif old_outcome in {"PASS", "NOT_APPLICABLE"} and new_outcome == "FAIL":
            changed.append({"finding": new, "previous": old, "current": new,
                            "reason": "Outcome changed from a non-failing result to a confirmed FAIL."})
        elif old_outcome == new_outcome and old.get("severity") == new.get("severity"):
            unchanged.append({"finding": new, "previous": old, "current": new})
        else:
            changed.append({"finding": new, "previous": old, "current": new,
                            "reason": "Finding outcome or severity changed."})

    old_resources, new_resources = {}, {}
    for snapshot, index, side in ((previous, old_resources, "previous"), (current, new_resources, "current")):
        for resource in snapshot.get("resources", []):
            key = _resource_key(resource)
            if key is None or key in index:
                uncomparable.append({"assessment": side, "resource": resource,
                                     "reason": "Missing or duplicate stable resource identity."})
            else:
                index[key] = resource
    inventory = {"added": [], "removed": [], "modified": [], "unchanged": []}
    for key in sorted(new_resources.keys() - old_resources.keys()):
        inventory["added"].append(new_resources[key])
    for key in sorted(old_resources.keys() - new_resources.keys()):
        inventory["removed"].append(old_resources[key])
    for key in sorted(new_resources.keys() & old_resources.keys()):
        old_item, new_item = old_resources[key], new_resources[key]
        fields = ("name", "attributes")
        if any(old_item.get(field) != new_item.get(field) for field in fields):
            inventory["modified"].append({"previous": old_item, "current": new_item})
        else:
            inventory["unchanged"].append(new_item)
    return {
        "schema_version": "1.0", "comparison": {"previous_assessment_id": previous["assessment"]["id"],
            "current_assessment_id": current["assessment"]["id"]},
        "findings": {"new": new_findings, "resolved": resolved, "unchanged": unchanged,
                     "changed": changed, "not_reassessed": not_reassessed, "uncomparable": uncomparable},
        "inventory": inventory,
        "summary": {"findings": {name: len(items) for name, items in {
            "new": new_findings, "resolved": resolved, "unchanged": unchanged, "changed": changed,
            "not_reassessed": not_reassessed, "uncomparable": uncomparable}.items()},
            "inventory": {name: len(items) for name, items in inventory.items()}},
    }


def build_report(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Build stable downstream report schema from a sanitized persisted snapshot."""
    operations = snapshot.get("operations", [])
    unsupported = [op for op in operations if op.get("status") == "UNSUPPORTED"]
    errors = [op for op in operations if op.get("status") == "ERROR"]
    findings = snapshot.get("findings", [])
    counts_outcome = {name: sum(f.get("outcome") == name for f in findings) for name in OUTCOMES}
    counts_severity = {name: sum(f.get("outcome") == "FAIL" and f.get("severity") == name for f in findings)
                       for name in SEVERITIES}
    assessment = snapshot.get("assessment", {})
    limitations = [f"{op.get('service')}:{op.get('operation')} is unsupported" for op in unsupported]
    limitations += [f"{op.get('service')}:{op.get('operation')} returned an error" for op in errors]
    limitations += [f"{finding.get('rule_id')} on {finding.get('resource_type')}:{finding.get('resource_id')} is NOT_SUPPORTED: {finding.get('reason', 'required evidence unavailable')}"
                    for finding in findings if finding.get("outcome") == "NOT_SUPPORTED"]
    limitations += [f"{finding.get('rule_id')} on {finding.get('resource_type')}:{finding.get('resource_id')} has an evaluation ERROR: {finding.get('reason', 'evaluation failed')}"
                    for finding in findings if finding.get("outcome") == "ERROR"]
    limitations.append("AEGIS did not apply remediation; rule guidance is advisory and is not evidence that a change was made.")
    incomplete_checks = any(finding.get("outcome") in {"NOT_SUPPORTED", "ERROR"} for finding in findings)
    if assessment.get("status") == "RUNNING":
        limitations.append("Assessment collection/evaluation is still running; this snapshot is incomplete and is not a security pass.")
    if assessment.get("status") in {"PARTIAL", "FAILED"} or incomplete_checks:
        limitations.append("One or more discovery operations or rule checks have incomplete evidence; the assessment is not a security pass.")
    if cloud_resource_count(snapshot.get("resources", [])) == 0:
        limitations.append("No resources were discovered; no resource-level security conclusions are available.")
    return {
        "schema_version": "1.0", "report_type": "aegis-assessment",
        "assessment": assessment,
        "scope": {"endpoint": assessment.get("endpoint"),
                  "region": assessment.get("region"),
                  "resource_count": len(snapshot.get("resources", [])),
                  "cloud_resource_count": cloud_resource_count(snapshot.get("resources", [])),
                  "resource_types": sorted({r.get("resource_type") for r in snapshot.get("resources", []) if r.get("resource_type")})},
        "coverage": {"operation_count": len(operations),
                     "by_status": dict(sorted(Counter(str(op.get("status", "UNKNOWN")) for op in operations).items())),
                     "unsupported_checks": unsupported, "errors": errors,
                     "limitations": limitations},
        "summary": {"finding_count": len(findings), "by_outcome": counts_outcome, "by_severity": counts_severity},
        "findings": findings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    """Render readable Markdown without dropping evidence state distinctions."""
    assessment, scope, coverage, summary = (report.get(k, {}) for k in ("assessment", "scope", "coverage", "summary"))
    lines = ["# AEGIS Assessment Report", "", f"- Assessment ID: `{assessment.get('id', 'unknown')}`",
             f"- Started: `{assessment.get('started_at', 'unknown')}`",
             f"- Completed: `{assessment.get('completed_at') or 'incomplete'}`",
             f"- Status: **{assessment.get('status', 'UNKNOWN')}**",
             f"- Scope: `{scope.get('endpoint', 'unknown')}` / region `{scope.get('region', 'unknown')}`",
             f"- Inventory: {scope.get('resource_count', 0)} records; {scope.get('cloud_resource_count', scope.get('resource_count', 0))} cloud resources", "",
             *(["> **Assessment coverage is incomplete:** collection is still running or one or more discovery operations/rule checks lack complete evidence.", ""]
               if assessment.get("status") in {"RUNNING", "PARTIAL", "FAILED"} or any(f.get("outcome") in {"NOT_SUPPORTED", "ERROR"} for f in report.get("findings", [])) else []),
             *(["> **No resources were discovered.** No resource-level security conclusions are available.", ""]
               if scope.get("cloud_resource_count", scope.get("resource_count", 0)) == 0 else []),
             "## Summary", "", f"Findings: {summary.get('finding_count', 0)}", "",
             "### By severity (confirmed FAIL only)", "", "| Severity | Count |", "|---|---:|"]
    lines.extend(f"| {name} | {count} |" for name, count in summary.get("by_severity", {}).items())
    lines += ["", "### By outcome", "", "| Outcome | Count |", "|---|---:|"]
    lines.extend(f"| {name} | {count} |" for name, count in summary.get("by_outcome", {}).items())
    lines += ["", "## Findings", ""]
    if not report.get("findings"):
        lines += ["No resource findings were recorded. This is not a security pass or compliance conclusion.", ""]
    for finding in report.get("findings", []):
        lines += [f"### {finding.get('outcome', 'UNKNOWN')} — {finding.get('title', finding.get('rule_id', 'Finding'))}",
                  "", f"- Rule: `{finding.get('rule_id', 'unknown')}`",
                  f"- Severity: {finding.get('severity', 'unknown')} (severity counts include FAIL only)",
                  f"- Resource: `{finding.get('resource_type', 'unknown')}` / `{finding.get('resource_id', 'unknown')}`",
                  f"- Reason: {finding.get('reason', '')}",
                  f"- Description: {finding.get('description', '')}",
                  "- Evidence references:"]
        evidence_refs = finding.get("evidence_refs", [])
        if not evidence_refs:
            lines.append("  - None recorded.")
        for ref in evidence_refs:
            lines.append("  - Operation record "
                         f"{ref.get('operation_id', 'unknown')}: {ref.get('service', 'unknown')}:{ref.get('operation', 'unknown')}; "
                         f"status {ref.get('status', 'unknown')}; subject {json.dumps(ref.get('subject_resource_id'))}; "
                         f"evidence SHA-256 {json.dumps(ref.get('evidence_sha256'))}.")
        if finding.get("outcome") == "NOT_SUPPORTED":
            lines.append("- Evidence status: required evidence is unavailable; this is not a pass or confirmed failure.")
        elif finding.get("outcome") == "ERROR":
            lines.append("- Evidence status: evaluation failed; this is not a pass or confirmed failure.")
        if finding.get("remediation") and finding.get("outcome") == "FAIL":
            lines.append(f"- Remediation guidance for this confirmed failure: {finding['remediation']}")
        elif finding.get("remediation") and finding.get("outcome") in {"NOT_SUPPORTED", "ERROR"}:
            lines.append(f"- General rule guidance (not a determination that changes are needed): {finding['remediation']}")
        lines.append("")
    lines += ["## Discovery coverage", "", f"Operations recorded: {coverage.get('operation_count', 0)}", ""]
    for status, count in coverage.get("by_status", {}).items():
        lines.append(f"- {status}: {count}")
    lines += ["", "### Unsupported checks and errors", ""]
    if not coverage.get("unsupported_checks") and not coverage.get("errors"):
        lines.append("None recorded.")
    for op in coverage.get("unsupported_checks", []):
        lines.append(f"- Unsupported: `{op.get('service')}:{op.get('operation')}` — {op.get('error') or 'capability unavailable'} (operation record {op.get('id')}; evidence SHA-256: {json.dumps(op.get('evidence_sha256'))})")
    for op in coverage.get("errors", []):
        evidence_note = (f"evidence SHA-256: `{op['evidence_sha256']}`" if op.get("evidence_sha256")
                         else "no response evidence hash (the operation returned no evidence payload)")
        lines.append(f"- Error: `{op.get('service')}:{op.get('operation')}` — {op.get('error') or 'operation failed'} (operation record {op.get('id')}; {evidence_note})")
    lines += ["", "### Coverage limitations", ""]
    lines.extend(f"- {item}" for item in coverage.get("limitations", []))
    if not coverage.get("limitations"):
        lines.append("None recorded by operation status.")
    lines.append("")
    return "\n".join(lines)
