"""AEGIS CLI entry points."""
from __future__ import annotations

import json
import socket
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import boto3
import typer
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from aegis.config import Settings, credential_status, dotenv_loaded, load_local_dotenv
from aegis.db import connect
from aegis.evidence import safe_endpoint_url, sanitize
from aegis.locking import ScanAlreadyRunning
from aegis.reporting import build_report, cloud_resource_count, compare_assessments, render_markdown
from aegis.service import export_assessment, run_assessment, run_discovery
from aegis.adapters import specifications
from aegis.rules import RULES
from aegis.web_db import list_assessments, load_assessment, read_only_connect
from aegis.workflow import run_preflight

app = typer.Typer(no_args_is_help=True, help="Read-only local cloud inventory and assessment.")


@app.callback()
def _load_dotenv() -> None:
    """Load optional local settings before any CLI command runs."""
    load_local_dotenv()


def _settings() -> Settings:
    try:
        return Settings.from_env()
    except ValueError as exc:
        typer.secho(f"Configuration error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc


@app.command()
def doctor() -> None:
    """Check configuration, SQLite, endpoint, AWS credentials, and STS readiness."""
    settings = _settings()
    checks: list[tuple[str, bool, str]] = []
    checks.append(("configuration", True,
                   f"endpoint={safe_endpoint_url(settings.endpoint_url)} region={settings.region} timeouts={settings.connect_timeout:g}/{settings.read_timeout:g}s"))
    try:
        with connect(settings.database) as db:
            db.execute("SELECT 1").fetchone()
        checks.append(("sqlite", True, f"database={settings.database}"))
    except Exception as exc:
        checks.append(("sqlite", False, f"{type(exc).__name__}: {exc}"))
    parsed = urlparse(settings.endpoint_url)
    try:
        with socket.create_connection((parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)),
                                      timeout=settings.connect_timeout):
            checks.append(("endpoint_tcp", True, f"{parsed.hostname}:{parsed.port or 80}"))
    except OSError as exc:
        checks.append(("endpoint_tcp", False, f"{type(exc).__name__}: {exc}"))
    session = boto3.Session(region_name=settings.region)
    credentials, credential_detail = credential_status(session)
    checks.append(("credentials", credentials == "AVAILABLE", f"{credentials}: {credential_detail}"))
    if credentials != "AVAILABLE":
        checks.append(("sts:GetCallerIdentity", False,
                       "not attempted because credentials are unavailable; set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"))
    else:
        try:
            sts = session.client("sts", endpoint_url=settings.endpoint_url, region_name=settings.region,
                                config=Config(connect_timeout=settings.connect_timeout, read_timeout=settings.read_timeout,
                                              retries={"max_attempts": 0}))
            identity = sts.get_caller_identity()
            checks.append(("sts:GetCallerIdentity", True,
                           f"verified account={identity.get('Account', '[not returned]')}"))
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "ClientError")
            guidance = " Check local Floci credentials/configuration." if code in {
                "InvalidClientTokenId", "UnrecognizedClientException", "SignatureDoesNotMatch", "AccessDenied", "AccessDeniedException"
            } else ""
            checks.append(("sts:GetCallerIdentity", False,
                           f"authentication/API failure {code}.{guidance}"))
        except (BotoCoreError, OSError) as exc:
            checks.append(("sts:GetCallerIdentity", False,
                           f"network/SDK failure {type(exc).__name__}; verify the configured endpoint is reachable"))
    for name, ok, detail in checks:
        typer.echo(f"{'PASS' if ok else 'FAIL'} {name}: {detail}")
    ready = all(ok for _, ok, _ in checks)
    typer.echo(f"Overall readiness: {'READY' if ready else 'NOT READY'}")
    if not ready:
        typer.echo("Assessment readiness: BLOCKED")
        if credentials == "MISSING":
            typer.echo("For local Floci, select an AWS profile configured with the emulator's local-only credentials.")
            typer.echo("Never reuse emulator credentials with a real AWS account; see the setup guide for the supported provider chain.")
        raise typer.Exit(1)
    typer.echo("Assessment readiness: READY WITH LIMITATIONS; run 'aegis preflight' to discover the supported read operations.")


@app.command()
def preflight(output_json: bool = typer.Option(False, "--json", help="Print preflight checks as JSON.")) -> None:
    """Check endpoint, credentials, database, identity, and verified read operations."""
    settings = _settings()
    try:
        result = run_preflight(settings)
    except ScanAlreadyRunning:
        typer.secho("Another discovery or assessment is running against this database. Wait for it to finish, then run 'aegis preflight' again.",
                     fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(1) from None
    except Exception as exc:
        typer.secho(f"Preflight could not be completed ({type(exc).__name__}). Check configuration, endpoint access, and database permissions.",
                     fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc
    if output_json:
        typer.echo(json.dumps(sanitize(result), indent=2, sort_keys=True))
    else:
        for check in result["checks"]:
            typer.echo(f"{check['state']:7} {check['id']}: {check['message']}")
            if check.get("state") in {"FAIL", "BLOCKED", "WARN"}:
                typer.echo(f"  Next step: {check['next_step']}")
        typer.echo(f"Overall readiness: {result['readiness']}")
        for operation in result["operations"]:
            typer.echo(f"{operation['state']:11} {operation['service']}:{operation['operation']} [{operation['capability']}]")
    if result["readiness"] == "BLOCKED":
        raise typer.Exit(1)


@app.command("config")
def show_config(output_json: bool = typer.Option(False, "--json", help="Print effective non-secret configuration as JSON.")) -> None:
    """Show effective non-secret settings and the credential source mechanism."""
    settings = _settings()
    value = {"endpoint": safe_endpoint_url(settings.endpoint_url), "region": settings.region,
             "database": str(settings.database),
             "connect_timeout_seconds": settings.connect_timeout,
             "read_timeout_seconds": settings.read_timeout,
             "credentials": "boto3 standard provider chain; values are never displayed",
              "dotenv_loaded": dotenv_loaded()}
    if output_json:
        typer.echo(json.dumps(value, indent=2, sort_keys=True))
    else:
        for key, item in value.items():
            typer.echo(f"{key}: {item}")


@app.command()
def version() -> None:
    """Show the installed AEGIS version."""
    from aegis import __version__
    typer.echo(f"aegis {__version__}")


@app.command()
def discover(
    output_json: bool = typer.Option(False, "--json", help="Print the completed inventory as JSON."),
) -> None:
    """Run read-only discovery for the verified Floci operations."""
    settings = _settings()
    try:
        assessment_id = run_discovery(settings)
    except ScanAlreadyRunning:
        typer.secho("Another discovery or assessment is running against this database. Wait for it to finish, then retry.",
                     fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(1) from None
    except Exception as exc:
        typer.secho(f"Discovery could not be persisted: {type(exc).__name__}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc
    try:
        data = export_assessment(settings, assessment_id)
    except LookupError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc
    if output_json:
        typer.echo(json.dumps(sanitize(data), indent=2, sort_keys=True))
    else:
        assessment = data["assessment"]
        typer.echo(f"Assessment {assessment_id}: {assessment['status']}")
        typer.echo(f"Resources discovered: {cloud_resource_count(data['resources'])} cloud resources")
        if cloud_resource_count(data["resources"]) == 0:
            typer.echo("No resources discovered; no resource-level security conclusions are available.")
        for result in data["operations"]:
            typer.echo(f"{result['status']:11} {result['service']}:{result['operation']} [{result['capability']}]")
            if result["error"]:
                typer.echo(f"  Detail hidden; failure category: {_error_category(result['error'])}")
    if data["assessment"]["status"] != "COMPLETED":
        raise typer.Exit(1)




@app.command()
def assess(
    output_json: bool = typer.Option(False, "--json", help="Print findings and summaries as JSON."),
    preview: bool = typer.Option(False, "--preview", help="Show the configured scope and checks without cloud calls."),
    yes: bool = typer.Option(False, "--yes", help="Confirm assessment in non-interactive/scripted use."),
) -> None:
    """Preview or explicitly confirm a fresh read-only assessment."""
    settings = _settings()
    if preview:
        if yes:
            typer.secho("--yes cannot be combined with --preview", fg=typer.colors.RED, err=True)
            raise typer.Exit(2)
        value = {"endpoint": safe_endpoint_url(settings.endpoint_url), "region": settings.region,
                 "database": str(settings.database), "pagination_supported": False,
                 "operations": [{"service": item.service, "operation": item.operation,
                                 "resource_type": item.resource_type} for item in specifications()] + [
                                     {"service": "iam", "operation": "GetPolicyVersion",
                                      "resource_type": "iam_policy_version",
                                      "scope": "Default version for each returned local policy"}],
                 "rules": [{"id": rule.rule_id, "title": rule.title, "severity": rule.severity,
                            "resource_type": rule.resource_type, "required_evidence": list(rule.required_evidence)}
                           for rule in RULES],
                 "notice": "A confirmed run makes read-only network requests and persists sanitized evidence."}
        if output_json:
            typer.echo(json.dumps(value, indent=2, sort_keys=True))
        else:
            typer.echo("Assessment preview (no cloud calls made)")
            typer.echo(f"Endpoint: {safe_endpoint_url(settings.endpoint_url)}\nRegion: {settings.region}\nDatabase: {settings.database}")
            typer.echo("Verified operations:")
            for item in value["operations"]:
                typer.echo(f"  {item['service']}:{item['operation']} → {item['resource_type'] or 'operation'}")
            typer.echo("Rules:")
            for rule in value["rules"]:
                typer.echo(f"  {rule['id']} {rule['severity']}: {rule['title']}")
            typer.echo("Pagination is disabled; unsupported evidence remains NOT_SUPPORTED, never a pass.")
        return
    if not yes:
        if not sys.stdin.isatty():
            typer.secho("Assessment not started. Use --yes for explicit non-interactive confirmation.",
                         fg=typer.colors.YELLOW, err=True)
            raise typer.Exit(2)
        if not typer.confirm("Start a read-only cloud collection and save a new assessment?"):
            typer.echo("Assessment cancelled; no assessment collection was started.")
            return
    try:
        assessment_id = run_assessment(settings)
        data = export_assessment(settings, assessment_id)
    except ScanAlreadyRunning:
        typer.secho("Another discovery or assessment is running against this database. Wait for it to finish, then retry.",
                     fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(1) from None
    except Exception as exc:
        typer.secho(f"Assessment failed: {type(exc).__name__}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc
    if output_json:
        typer.echo(json.dumps(sanitize(data), indent=2, sort_keys=True))
    else:
        typer.echo(f"Assessment {assessment_id}: {data['assessment']['status']}")
        typer.echo(f"Resources discovered: {cloud_resource_count(data['resources'])} cloud resources")
        if cloud_resource_count(data["resources"]) == 0:
            typer.echo("No resources discovered; no resource-level security conclusions are available.")
        typer.echo(f"Findings: {data['summary']['finding_count']}")
        typer.echo("By severity (FAIL outcomes):")
        for severity, count in data["summary"]["by_severity"].items():
            typer.echo(f"  {severity}: {count}")
        typer.echo("By outcome:")
        for outcome, count in data["summary"]["by_outcome"].items():
            typer.echo(f"  {outcome}: {count}")
        for finding in data["findings"]:
            typer.echo(f"{finding['outcome']:15} {finding['severity']:8} {finding['rule_id']} {finding['resource_id']}: {finding['reason']}")
            if finding["previous_outcome"] is not None:
                typer.echo(f"  comparison: {finding['change_state']} from {finding['previous_outcome']}")
        for operation in data["operations"]:
            if operation["status"] in {"ERROR", "UNSUPPORTED"}:
                typer.echo(f"{operation['status']:11} {operation['service']}:{operation['operation']}: failure category {_error_category(operation['error'])}")
    if data["assessment"]["status"] != "COMPLETED":
        raise typer.Exit(1)


def _error_category(value: str | None) -> str:
    """Return a short leading code/type and never echo provider error text."""
    if not value:
        return "details hidden"
    candidate = value.split(":", 1)[0].strip()
    return candidate if candidate and len(candidate) <= 80 and all(c.isalnum() or c in "._-" for c in candidate) else "details hidden"


def _safe_cli_snapshot(data: dict) -> dict:
    """Keep useful saved result metadata while excluding raw operation bodies/errors."""
    assessment = dict(data["assessment"])
    assessment["endpoint"] = safe_endpoint_url(assessment.get("endpoint"))
    operations = [{key: item.get(key) for key in
                   ("id", "service", "operation", "subject_resource_id", "capability", "status",
                    "evidence_sha256", "observed_at")}
                  for item in data.get("operations", [])]
    return sanitize({"assessment": assessment, "operations": operations,
                     "resources": data.get("resources", []), "findings": data.get("findings", [])})


@app.command()
def history(
    limit: int = typer.Option(20, min=1, max=100, help="Maximum number of recent assessments."),
    output_json: bool = typer.Option(False, "--json", help="Print saved assessments as JSON."),
) -> None:
    """List recent persisted assessments without cloud calls or database writes."""
    settings = _settings()
    try:
        with read_only_connect(settings.database) as db:
            rows = list_assessments(db, limit, 0) if db else []
    except Exception:
        typer.secho("Assessment history is unavailable; check the configured database and schema.", err=True)
        raise typer.Exit(1) from None
    if output_json:
        typer.echo(json.dumps([_safe_history_row(row) for row in rows], indent=2, sort_keys=True))
        return
    if not rows:
        typer.echo("No saved assessments. Run 'aegis doctor', then 'aegis assess --preview'.")
        return
    for row in rows:
        typer.echo(f"{row['id']}  {row['status']:9} {row['started_at']}  {row['region']}")


def _safe_history_row(row: dict) -> dict:
    value = dict(row)
    value["endpoint"] = safe_endpoint_url(value.get("endpoint"))
    return sanitize(value)


@app.command()
def show(assessment_id: str = typer.Argument(..., help="Persisted assessment ID."),
         output_json: bool = typer.Option(False, "--json", help="Print saved assessment details as JSON.")) -> None:
    """Show one saved assessment from the local read-only query layer."""
    settings = _settings()
    try:
        with read_only_connect(settings.database) as db:
            data = load_assessment(db, assessment_id) if db else None
    except Exception:
        typer.secho("Assessment database is unavailable or incompatible.", err=True)
        raise typer.Exit(1) from None
    if data is None:
        typer.secho("No matching assessment was found", err=True)
        raise typer.Exit(1)
    if output_json:
        typer.echo(json.dumps(_safe_cli_snapshot(data), indent=2, sort_keys=True))
        return
    assessment = data["assessment"]
    typer.echo(f"Assessment {assessment['id']}: {assessment['status']}")
    typer.echo(f"Started: {assessment['started_at']}  Completed: {assessment['completed_at'] or 'incomplete'}")
    typer.echo(f"Endpoint: {safe_endpoint_url(assessment['endpoint'])}  Region: {assessment['region']}")
    typer.echo(f"Resources: {len(data['resources'])}  Findings: {len(data['findings'])}  Operations: {len(data['operations'])}")


@app.command()
def findings(
    assessment_id: str = typer.Argument(..., help="Persisted assessment ID."),
    outcome: str | None = typer.Option(None, "--outcome", help="Filter by PASS, FAIL, NOT_APPLICABLE, NOT_SUPPORTED, or ERROR."),
    severity: str | None = typer.Option(None, "--severity", help="Filter by CRITICAL, HIGH, MEDIUM, LOW, or INFO."),
    output_json: bool = typer.Option(False, "--json", help="Print matching saved findings as JSON."),
) -> None:
    """List saved rule outcomes; severity is independent from outcome."""
    if outcome and outcome.upper() not in {"PASS", "FAIL", "NOT_APPLICABLE", "NOT_SUPPORTED", "ERROR"}:
        typer.secho("Invalid outcome filter", err=True)
        raise typer.Exit(2)
    if severity and severity.upper() not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        typer.secho("Invalid severity filter", err=True)
        raise typer.Exit(2)
    settings = _settings()
    try:
        with read_only_connect(settings.database) as db:
            data = load_assessment(db, assessment_id) if db else None
    except Exception:
        typer.secho("Assessment database is unavailable or incompatible.", err=True)
        raise typer.Exit(1) from None
    if data is None:
        typer.secho("No matching assessment was found", err=True)
        raise typer.Exit(1)
    rows = [item for item in data["findings"]
            if (outcome is None or item["outcome"] == outcome.upper())
            and (severity is None or item["severity"] == severity.upper())]
    if output_json:
        typer.echo(json.dumps(sanitize(rows), indent=2, sort_keys=True))
    elif not rows:
        typer.echo("No findings match these filters. This is not a compliance or security-pass conclusion.")
    else:
        for item in rows:
            typer.echo(f"{item['outcome']:15} {item['severity']:8} {item['rule_id']} {item['resource_type']}/{item['resource_id']}: {sanitize(item['reason'])}")


@app.command()
def resources(
    assessment_id: str = typer.Argument(..., help="Persisted assessment ID."),
    resource_type: str | None = typer.Option(None, "--type", help="Filter by normalized resource type."),
    output_json: bool = typer.Option(False, "--json", help="Print saved resources as JSON."),
) -> None:
    """List normalized resources from one saved assessment."""
    data = _load_saved_assessment(assessment_id)
    rows = [item for item in data["resources"] if resource_type is None or item["resource_type"] == resource_type]
    if output_json:
        typer.echo(json.dumps(sanitize(rows), indent=2, sort_keys=True))
    else:
        for item in rows:
            typer.echo(f"{item['resource_type']:24} {item['resource_id']}  {item.get('name') or ''}")
        if not rows:
            typer.echo("No resources match this assessment and filter.")


@app.command()
def operations(
    assessment_id: str = typer.Argument(..., help="Persisted assessment ID."),
    output_json: bool = typer.Option(False, "--json", help="Print saved operation statuses as JSON."),
) -> None:
    """List saved collection operation states without raw responses or error messages."""
    data = _load_saved_assessment(assessment_id)
    rows = [{key: item.get(key) for key in
             ("id", "service", "operation", "subject_resource_id", "capability", "status",
              "evidence_sha256", "observed_at")} for item in data["operations"]]
    if output_json:
        typer.echo(json.dumps(sanitize(rows), indent=2, sort_keys=True))
    else:
        for item in data["operations"]:
            detail = f"; failure category {_error_category(item.get('error'))}" if item["status"] in {"ERROR", "UNSUPPORTED"} else ""
            typer.echo(f"{item['status']:11} {item['service']}:{item['operation']} [{item['capability']}]{detail}")
        if not data["operations"]:
            typer.echo("No collection operations were recorded.")


def _load_saved_assessment(assessment_id: str) -> dict:
    settings = _settings()
    try:
        with read_only_connect(settings.database) as db:
            data = load_assessment(db, assessment_id) if db else None
    except Exception:
        typer.secho("Assessment database is unavailable or incompatible.", err=True)
        raise typer.Exit(1) from None
    if data is None:
        typer.secho("No matching assessment was found", err=True)
        raise typer.Exit(1)
    return data


@app.command()
def export(
    format: str = typer.Option("json", "--format", help="Export format (currently json)."),
    assessment_id: str | None = typer.Option(None, "--assessment", help="Assessment UUID; defaults to latest."),
) -> None:
    """Export a stored assessment as sanitized JSON."""
    if format.lower() != "json":
        typer.secho("Only JSON export is currently supported", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    settings = _settings()
    try:
        typer.echo(json.dumps(sanitize(export_assessment(settings, assessment_id)), indent=2, sort_keys=True))
    except LookupError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc
    except Exception:
        typer.secho("Assessment database is unavailable or incompatible.", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from None


@app.command()
def compare(
    previous_assessment: str = typer.Argument(..., help="Persisted assessment ID with the earlier start timestamp."),
    current_assessment: str = typer.Argument(..., help="Persisted assessment ID with the later start timestamp."),
) -> None:
    """Compare two persisted assessment IDs (the second must start later); no cloud API calls are made."""
    settings = _settings()
    try:
        previous = export_assessment(settings, previous_assessment)
        current = export_assessment(settings, current_assessment)
    except LookupError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc
    except Exception:
        typer.secho("Assessment database is unavailable or incompatible.", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from None
    terminal_statuses = {"COMPLETED", "PARTIAL", "FAILED"}
    if previous["assessment"].get("status") not in terminal_statuses or current["assessment"].get("status") not in terminal_statuses:
        typer.secho("Cannot compare assessments until both runs have finished.", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(2)
    if previous_assessment != current_assessment:
        try:
            earlier = datetime.fromisoformat(previous["assessment"]["started_at"].replace("Z", "+00:00"))
            later = datetime.fromisoformat(current["assessment"]["started_at"].replace("Z", "+00:00"))
            earlier = earlier.replace(tzinfo=earlier.tzinfo or timezone.utc)
            later = later.replace(tzinfo=later.tzinfo or timezone.utc)
        except (KeyError, TypeError, ValueError) as exc:
            typer.secho("Cannot compare assessments with missing or invalid start timestamps", fg=typer.colors.RED, err=True)
            raise typer.Exit(2) from exc
        if later <= earlier:
            typer.secho("The current assessment must have a later start timestamp than the previous assessment", fg=typer.colors.RED, err=True)
            raise typer.Exit(2)
    typer.echo(json.dumps(sanitize(compare_assessments(previous, current)), indent=2, sort_keys=True))


@app.command()
def report(
    format: str = typer.Option("markdown", "--format", help="Report format: markdown or json."),
    assessment_id: str | None = typer.Option(None, "--assessment", help="Persisted assessment UUID; defaults to latest."),
) -> None:
    """Render a report from a persisted assessment; this command never discovers resources."""
    if format.lower() not in {"json", "markdown", "md"}:
        typer.secho("Report format must be json or markdown", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    settings = _settings()
    try:
        report_data = build_report(export_assessment(settings, assessment_id))
    except LookupError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc
    except Exception:
        typer.secho("Assessment report could not be read from the configured database.", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from None
    if format.lower() == "json":
        typer.echo(json.dumps(sanitize(report_data), indent=2, sort_keys=True))
    else:
        typer.echo(render_markdown(report_data))


if __name__ == "__main__":
    app()
