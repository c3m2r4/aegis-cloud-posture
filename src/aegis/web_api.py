"""Read-only FastAPI endpoints over persisted AEGIS assessment data."""
from __future__ import annotations

import json
import re
import asyncio
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware

from aegis.config import Settings
from aegis.evidence import safe_endpoint_url, sanitize
from aegis.locking import ScanAlreadyRunning, acquire_scan_lock
from aegis.reporting import build_report, compare_assessments, render_markdown
from aegis.service import run_assessment
from aegis.web_db import (list_assessments, list_findings, list_operations,
                          list_resources, load_assessment, read_only_connect, resource_filter_options,
                          schema_available)
from aegis.web_ui import mount_dashboard
from aegis.workflow import assessment_preview, run_preflight


OUTCOMES = {"PASS", "FAIL", "NOT_APPLICABLE", "NOT_SUPPORTED", "ERROR"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
FORMATS = {"json", "markdown"}


def _assessment_id(value: str) -> str:
    try:
        return str(UUID(value))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=422, detail="Assessment identifier must be a UUID") from None


def _schema_available(db) -> bool:
    return schema_available(db)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _preflight_is_fresh(result: dict) -> bool:
    try:
        checked = datetime.fromisoformat(result["checked_at"])
        checked = checked.replace(tzinfo=checked.tzinfo or timezone.utc)
        age = datetime.now(timezone.utc) - checked
        return timedelta(0) <= age <= timedelta(minutes=5)
    except (KeyError, TypeError, ValueError):
        return False


def _same_origin(request: Request) -> bool:
    origin, host = request.headers.get("origin"), request.headers.get("host", "")
    if not origin or not host:
        return False
    try:
        parsed = urlsplit(origin)
        return (parsed.scheme == request.url.scheme and parsed.netloc.lower() == host.lower()
                and parsed.hostname is not None and parsed.username is None and parsed.password is None
                and parsed.path == "" and not parsed.query and not parsed.fragment
                and origin == f"{parsed.scheme}://{parsed.netloc}")
    except ValueError:
        return False


async def _post_json(request: Request) -> dict:
    if not _same_origin(request):
        raise HTTPException(status_code=403, detail="State-changing requests must come from this dashboard origin")
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(status_code=415, detail="Content-Type must be application/json")
    declared = request.headers.get("content-length")
    if declared:
        try:
            if int(declared) > 1024:
                raise HTTPException(status_code=413, detail="Request body is too large")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid request") from None
    collected = bytearray()
    async for chunk in request.stream():
        collected.extend(chunk)
        if len(collected) > 1024:
            raise HTTPException(status_code=413, detail="Request body is too large")
    try:
        value = json.loads(bytes(collected) or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid request") from None
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="Invalid request")
    return value


def _safe_report(snapshot: dict) -> dict:
    """Build from persisted data while excluding raw operation response bodies."""
    snapshot = dict(snapshot)
    snapshot["assessment"] = _safe_assessment(snapshot.get("assessment", {}))
    for operation in snapshot.get("operations", []):
        operation.pop("evidence", None)
        # Operation error strings originate outside the dashboard and can
        # contain service-supplied secrets, local paths, or diagnostic detail.
        # Keep status/counts but let the report render its generic fallback.
        operation.pop("error", None)
    return build_report(sanitize(snapshot))


def _safe_assessment(assessment: dict) -> dict:
    assessment = dict(assessment)
    assessment["endpoint"] = safe_endpoint_url(assessment.get("endpoint"))
    return assessment


def _empty_overview() -> dict:
    return {"latest_assessment": None, "recent_assessments": [], "resource_count": 0,
            "resource_types": [], "resources_by_service": {}, "resources_by_type": {},
            "discovered_but_unassessed_count": 0,
            "summary": {"finding_count": 0, "by_outcome": {key: 0 for key in OUTCOMES},
                        "by_severity": {key: 0 for key in SEVERITIES}},
            "coverage": {"operation_count": 0, "by_status": {}, "unsupported_checks": [],
                         "incomplete_operations": [],
                         "errors": [], "limitations": [], "discovery": {"services": [], "deferred_operations": []},
                         "assessment": {"by_outcome": {key: 0 for key in OUTCOMES}},
                         "evidence": {"evaluations_with_references": 0, "evaluations_without_references": 0}}}


def create_app(settings: Settings | None = None, *, allowed_hosts: list[str] | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    app = FastAPI(title="AEGIS Local API", version="0.1.0", docs_url=None, redoc_url=None)
    app.state.run_jobs = {}
    app.state.run_jobs_lock = threading.Lock()
    app.state.latest_preflight = None
    app.add_middleware(TrustedHostMiddleware,
                       allowed_hosts=allowed_hosts or ["127.0.0.1", "localhost", "[::1]"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Content-Security-Policy",
                                    "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
                                    "form-action 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'")
        if (request.url.path.startswith(("/api/", "/static/"))
                or request.url.path in {"/", "/assessments", "/compare"}
                or request.url.path.startswith("/assessments/")):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _exc: RequestValidationError):
        return JSONResponse(status_code=422, content={"detail": "Invalid request parameters"})

    @app.get("/api/assessment-preview")
    def assessment_preview_api():
        try:
            return assessment_preview(settings)
        except Exception:
            raise HTTPException(status_code=503, detail="Assessment preview is unavailable") from None

    @app.post("/api/preflight")
    async def preflight_api(request: Request):
        payload = await _post_json(request)
        if payload:
            raise HTTPException(status_code=422, detail="Invalid preflight request")
        with app.state.run_jobs_lock:
            app.state.latest_preflight = None
        try:
            lock = acquire_scan_lock(settings.database)
        except ScanAlreadyRunning:
            raise HTTPException(status_code=409, detail="An assessment or discovery run is already in progress") from None
        except Exception:
            raise HTTPException(status_code=503, detail="Preflight could not acquire the local scan lock") from None
        try:
            task = asyncio.create_task(asyncio.to_thread(run_preflight, settings, lock=lock))
            # Release only when the worker has actually finished; this also
            # covers client disconnects and alternate/test worker functions.
            task.add_done_callback(lambda _task: lock.release())
        except Exception:
            lock.release()
            raise HTTPException(status_code=503, detail="Preflight worker could not be started") from None
        try:
            # Shield the worker from HTTP client cancellation. Its own context
            # releases the shared database lock only after collection ends.
            result = await asyncio.shield(task)
            result["checked_at"] = _utcnow()
            with app.state.run_jobs_lock:
                app.state.latest_preflight = result
            return result
        except Exception:
            raise HTTPException(status_code=503, detail="Preflight could not be completed; check local configuration and endpoint availability") from None

    @app.post("/api/assessment-runs")
    async def start_assessment(request: Request):
        payload = await _post_json(request)
        if set(payload) != {"confirmation"} or payload.get("confirmation") is not True:
            raise HTTPException(status_code=422, detail="Explicit assessment confirmation is required")
        with app.state.run_jobs_lock:
            preflight = app.state.latest_preflight
            if preflight is None:
                raise HTTPException(status_code=409, detail="Run preflight before starting an assessment")
            if not _preflight_is_fresh(preflight):
                app.state.latest_preflight = None
                raise HTTPException(status_code=409, detail="Preflight is older than five minutes; run it again before scanning")
            if preflight.get("readiness") == "BLOCKED":
                raise HTTPException(status_code=409, detail="Preflight is blocked; resolve required checks before scanning")
            try:
                scan_lock = acquire_scan_lock(settings.database)
            except ScanAlreadyRunning:
                raise HTTPException(status_code=409, detail="Another assessment or discovery run is already in progress") from None
            except Exception:
                raise HTTPException(status_code=503, detail="Assessment could not acquire the local scan lock") from None
            # A preflight token is single-use. A repeated browser submission cannot
            # silently launch a second sequential scan after the first one finishes.
            app.state.latest_preflight = None

        run_id = str(uuid.uuid4())
        job = {"run_id": run_id, "state": "QUEUED", "created_at": _utcnow(),
               "started_at": None, "completed_at": None, "assessment_id": None,
               "assessment_status": None, "message": "Assessment accepted and waiting for the local worker."}
        with app.state.run_jobs_lock:
            app.state.run_jobs[run_id] = job

        def worker() -> None:
            with app.state.run_jobs_lock:
                job["state"] = "RUNNING"
                job["started_at"] = _utcnow()
                job["message"] = "Read-only collection and evidence evaluation are running. No progress percentage is available."
            try:
                # Use the public run UUID as the persisted assessment UUID so a
                # browser can recover its status after an API process restart.
                assessment_id = run_assessment(settings, lock=scan_lock, assessment_id=run_id)
                with app.state.run_jobs_lock:
                    job["assessment_id"] = assessment_id
                    job["completed_at"] = _utcnow()
                # Read only the result just produced to report its actual persisted terminal status.
                with read_only_connect(settings.database) as db:
                    row = db.execute("SELECT status FROM assessments WHERE id=?", (assessment_id,)).fetchone() if db else None
                with app.state.run_jobs_lock:
                    status = row["status"] if row else "FAILED"
                    job["assessment_status"] = status
                    job["state"] = status if status in {"COMPLETED", "PARTIAL", "FAILED"} else "FAILED"
                    job["message"] = ("Assessment saved." if status == "COMPLETED" else
                                       "Assessment saved with incomplete coverage." if status == "PARTIAL" else
                                       "Assessment saved with collection failures.")
            except Exception as exc:
                # Discovery persists RUNNING before rule evaluation. If the
                # evaluator failed, expose the persisted FAILED row when one
                # exists; pre-persistence failures have no assessment to open.
                with read_only_connect(settings.database) as db:
                    persisted = db.execute(
                        "SELECT id,status FROM assessments WHERE id=?", (run_id,)
                    ).fetchone() if db else None
                with app.state.run_jobs_lock:
                    job["state"] = "FAILED"
                    job["completed_at"] = _utcnow()
                    if persisted:
                        job["assessment_id"] = persisted["id"]
                        job["assessment_status"] = persisted["status"]
                    job["message"] = "Assessment could not be completed. Check credentials, endpoint access, database availability, and any other active scan."
                    job["error_type"] = type(exc).__name__
            finally:
                scan_lock.release()
                with app.state.run_jobs_lock:
                    terminal = [key for key, value in app.state.run_jobs.items()
                                if value.get("state") in {"COMPLETED", "PARTIAL", "FAILED"}]
                    for old_id in terminal[:-100]:
                        app.state.run_jobs.pop(old_id, None)

        try:
            thread = threading.Thread(target=worker, name=f"aegis-assessment-{run_id[:8]}", daemon=True)
            thread.start()
        except Exception:
            scan_lock.release()
            with app.state.run_jobs_lock:
                app.state.run_jobs.pop(run_id, None)
            raise HTTPException(status_code=503, detail="Assessment worker could not be started") from None
        return {"run_id": run_id, "state": "QUEUED", "status_url": f"/api/assessment-runs/{run_id}"}

    @app.get("/api/assessment-runs/{run_id}")
    def assessment_run_status(run_id: str):
        try:
            run_id = str(UUID(run_id))
        except (ValueError, AttributeError):
            raise HTTPException(status_code=422, detail="Run identifier must be a UUID") from None
        with app.state.run_jobs_lock:
            job = app.state.run_jobs.get(run_id)
            if job is None:
                # Run jobs are intentionally in-memory. The matching assessment
                # row is durable and can report terminal results after restart.
                # A persisted RUNNING row after restart has unknowable worker
                # state, so report UNKNOWN instead of claiming it still runs or
                # was cancelled/completed.
                with read_only_connect(settings.database) as db:
                    row = db.execute(
                        "SELECT id,started_at,completed_at,status FROM assessments WHERE id=?", (run_id,)
                    ).fetchone() if db and _schema_available(db) else None
                if row is None:
                    raise HTTPException(status_code=404, detail="Assessment run not found; server may have restarted")
                status = row["status"]
                if status == "RUNNING":
                    return {"run_id": run_id, "assessment_id": row["id"], "assessment_status": status,
                            "state": "UNKNOWN", "created_at": row["started_at"],
                            "started_at": row["started_at"], "completed_at": None,
                            "message": "The server restarted while this assessment was running. Its final state is unknown; review saved assessment data before retrying.",
                            "history_url": "/assessments"}
                if status not in {"COMPLETED", "PARTIAL", "FAILED"}:
                    status = "FAILED"
                return {"run_id": run_id, "assessment_id": row["id"], "assessment_status": row["status"],
                        "state": status, "created_at": row["started_at"], "started_at": row["started_at"],
                        "completed_at": row["completed_at"],
                        "message": "Recovered saved assessment status." if status != "FAILED" else
                                   "Saved assessment ended with failures; review its persisted evidence.",
                        "assessment_url": f"/assessments/{run_id}"}
            return dict(job)

    @app.get("/api/health")
    def health():
        try:
            with read_only_connect(settings.database) as db:
                if db is None:
                    return {"status": "ok", "database": {"available": False, "state": "not_created"}}
                if not _schema_available(db):
                    raise sqlite3.DatabaseError("incompatible schema")
                db.execute("SELECT 1 FROM assessments LIMIT 1").fetchone()
            return {"status": "ok", "database": {"available": True, "state": "available"}}
        except Exception:
            return JSONResponse(status_code=503, content={"status": "unavailable",
                                  "database": {"available": False, "state": "unavailable"}})

    @app.get("/api/overview")
    def overview():
        try:
            with read_only_connect(settings.database) as db:
                if db is None:
                    return _empty_overview()
                latest_rows = list_assessments(db, 1, 0)
                recent = [_safe_assessment(item) for item in list_assessments(db, 10, 0)]
                if not latest_rows:
                    return _empty_overview()
                snapshot = load_assessment(db, latest_rows[0]["id"])
                report = _safe_report(snapshot)
                return {"latest_assessment": report["assessment"], "recent_assessments": recent,
                        "resource_count": report["scope"]["cloud_resource_count"],
                        "resource_types": report["scope"]["resource_types"],
                        "resources_by_service": report["scope"]["resources_by_service"],
                        "resources_by_type": report["scope"]["resources_by_type"],
                        "discovered_but_unassessed_count": report["scope"]["discovered_but_unassessed_count"],
                        "summary": report["summary"],
                        "coverage": report["coverage"]}
        except Exception:
            raise HTTPException(status_code=503, detail="Assessment database is unavailable") from None

    @app.get("/api/assessments")
    def assessments(limit: Annotated[int, Query(ge=1, le=100)] = 25,
                    offset: Annotated[int, Query(ge=0, le=100000)] = 0):
        with read_only_connect(settings.database) as db:
            rows = list_assessments(db, limit, offset) if db else []
            total = db.execute("SELECT COUNT(*) FROM assessments").fetchone()[0] if db else 0
        return {"items": [_safe_assessment(item) for item in rows], "total": total,
                "limit": limit, "offset": offset}

    @app.get("/api/assessments/{assessment_id}")
    def assessment(assessment_id: str):
        assessment_id = _assessment_id(assessment_id)
        with read_only_connect(settings.database) as db:
            snapshot = load_assessment(db, assessment_id) if db else None
        if snapshot is None:
            raise HTTPException(status_code=404, detail="Assessment not found")
        report = _safe_report(snapshot)
        return {"assessment": report["assessment"], "scope": report["scope"],
                "summary": report["summary"], "coverage": report["coverage"]}

    @app.get("/api/assessments/{assessment_id}/findings")
    def findings(assessment_id: str, limit: Annotated[int, Query(ge=1, le=100)] = 50,
                 offset: Annotated[int, Query(ge=0, le=100000)] = 0,
                 outcome: str | None = None, severity: str | None = None,
                 rule_id: str | None = None, resource: Annotated[str | None, Query(max_length=200)] = None):
        assessment_id = _assessment_id(assessment_id)
        if outcome is not None and outcome not in OUTCOMES:
            raise HTTPException(status_code=422, detail="Invalid request parameters")
        if severity is not None and severity not in SEVERITIES:
            raise HTTPException(status_code=422, detail="Invalid request parameters")
        if rule_id is not None and not re.fullmatch(r"AEGIS-[A-Z]+-\d{3}", rule_id):
            raise HTTPException(status_code=422, detail="Invalid request parameters")
        with read_only_connect(settings.database) as db:
            exists = db.execute("SELECT 1 FROM assessments WHERE id=?", (assessment_id,)).fetchone() if db else None
            rows, total = list_findings(db, assessment_id, limit, offset, outcome, severity, rule_id, resource) if exists else ([], 0)
        if not exists:
            raise HTTPException(status_code=404, detail="Assessment not found")
        return {"items": sanitize(rows), "total": total, "limit": limit, "offset": offset}

    @app.get("/api/assessments/{assessment_id}/resources")
    def resources(assessment_id: str, limit: Annotated[int, Query(ge=1, le=100)] = 50,
                  offset: Annotated[int, Query(ge=0, le=100000)] = 0,
                  service: Annotated[str | None, Query(max_length=40)] = None,
                  resource_type: Annotated[str | None, Query(max_length=80)] = None):
        if service is not None and not re.fullmatch(r"[a-z0-9_-]+", service):
            raise HTTPException(status_code=422, detail="Invalid request parameters")
        if resource_type is not None and not re.fullmatch(r"[a-z0-9_-]+", resource_type):
            raise HTTPException(status_code=422, detail="Invalid request parameters")
        assessment_id = _assessment_id(assessment_id)
        with read_only_connect(settings.database) as db:
            exists = db.execute("SELECT 1 FROM assessments WHERE id=?", (assessment_id,)).fetchone() if db else None
            rows, total = list_resources(db, assessment_id, limit, offset, service, resource_type) if exists else ([], 0)
            filters = resource_filter_options(db, assessment_id) if exists else {"services": [], "resource_types": []}
        if not exists:
            raise HTTPException(status_code=404, detail="Assessment not found")
        return {"items": sanitize(rows), "total": total, "limit": limit, "offset": offset,
                "available_filters": filters}

    @app.get("/api/assessments/{assessment_id}/operations")
    def operations(assessment_id: str, limit: Annotated[int, Query(ge=1, le=100)] = 50,
                   offset: Annotated[int, Query(ge=0, le=100000)] = 0):
        assessment_id = _assessment_id(assessment_id)
        with read_only_connect(settings.database) as db:
            exists = db.execute("SELECT 1 FROM assessments WHERE id=?", (assessment_id,)).fetchone() if db else None
            rows, total = list_operations(db, assessment_id, limit, offset) if exists else ([], 0)
        if not exists:
            raise HTTPException(status_code=404, detail="Assessment not found")
        return {"items": sanitize(rows), "total": total, "limit": limit, "offset": offset}

    @app.get("/api/assessments/{assessment_id}/reports/{report_format}")
    def report(assessment_id: str, report_format: str):
        assessment_id = _assessment_id(assessment_id)
        if report_format not in FORMATS:
            raise HTTPException(status_code=422, detail="Report format must be json or markdown")
        with read_only_connect(settings.database) as db:
            snapshot = load_assessment(db, assessment_id) if db else None
        if snapshot is None:
            raise HTTPException(status_code=404, detail="Assessment not found")
        report_data = _safe_report(snapshot)
        filename = f"aegis-assessment-{assessment_id}.{ 'json' if report_format == 'json' else 'md' }"
        headers = {"Content-Disposition": f'attachment; filename="{filename}"',
                   "X-Content-Type-Options": "nosniff"}
        if report_format == "json":
            return Response(json.dumps(report_data, indent=2, sort_keys=True), media_type="application/json", headers=headers)
        return Response(render_markdown(report_data), media_type="text/markdown; charset=utf-8", headers=headers)

    @app.get("/api/comparisons/{previous_id}/{current_id}")
    def comparison(previous_id: str, current_id: str):
        previous_id, current_id = _assessment_id(previous_id), _assessment_id(current_id)
        if previous_id == current_id:
            raise HTTPException(status_code=422, detail="Comparison requires two different assessments")
        with read_only_connect(settings.database) as db:
            previous = load_assessment(db, previous_id) if db else None
            current = load_assessment(db, current_id) if db else None
        if previous is None or current is None:
            raise HTTPException(status_code=404, detail="Assessment not found")
        terminal = {"COMPLETED", "PARTIAL", "FAILED"}
        if previous["assessment"]["status"] not in terminal or current["assessment"]["status"] not in terminal:
            raise HTTPException(status_code=409, detail="Assessments can be compared after both runs have finished")
        if previous["assessment"]["endpoint"] != current["assessment"]["endpoint"]:
            raise HTTPException(status_code=422, detail="Assessments from different endpoints cannot be compared")
        if current["assessment"]["started_at"] <= previous["assessment"]["started_at"]:
            raise HTTPException(status_code=422, detail="Current assessment must be later than previous assessment")
        return sanitize(compare_assessments(previous, current))

    mount_dashboard(app)
    return app
