"""Dashboard route and browser-rendering safety checks."""
import json
import re
import uuid

from fastapi.testclient import TestClient

from aegis.config import Settings
from aegis.db import connect
from aegis.web_api import create_app


def client_for(database):
    return TestClient(create_app(Settings(database=database), allowed_hosts=["testserver"]))


def test_dashboard_pages_and_assets_work_with_an_empty_database(tmp_path):
    database = tmp_path / "first-run" / "aegis.db"
    client = client_for(database)
    overview = client.get("/")
    assert overview.status_code == 200
    assert overview.headers["x-content-type-options"] == "nosniff"
    assert overview.headers["x-frame-options"] == "DENY"
    assert overview.headers["cache-control"] == "no-store"
    assert "script-src 'self'" in overview.headers["content-security-policy"]
    assert "Overview" in overview.text and 'data-page="overview"' in overview.text
    assert 'href="/static/dashboard.css"' in overview.text
    assert 'src="/static/dashboard.js"' in overview.text
    assert "No assessment history" not in overview.text  # first-run state is rendered after the API response
    assert client.get("/assessments").status_code == 200
    compare = client.get("/compare")
    assert compare.status_code == 200
    assert "Previous must be earlier than Current" in compare.text
    guide = client.get("/guide")
    assert guide.status_code == 200 and "Setup and command guide" in guide.text
    assert "aegis assess --yes" in guide.text
    assert "Copy command" in guide.text
    assert "AWS_ACCESS_KEY_ID=" not in guide.text
    assert "New assessment" in overview.text and "Confirm and start scan" in overview.text
    assert "Run preflight checks" in overview.text
    script = client.get("/static/dashboard.js")
    style = client.get("/static/dashboard.css")
    assert script.status_code == 200 and "textContent" in script.text
    assert "innerHTML" not in script.text and "assessment-runs" in script.text
    assert "Choose the earlier run as Previous and the later run as Current." in script.text
    assert "Choose runs from the same endpoint." in script.text
    assert "const prior = data.items.slice(1).find" in script.text
    assert style.status_code == 200 and "@media (max-width: 760px)" in style.text
    assert re.search(r"\[hidden\]\s*\{\s*display:\s*none\s*!important;", style.text)
    assert not database.exists() and not database.parent.exists()


def test_detail_page_validates_identifier_and_uses_persisted_identifier(tmp_path):
    database = tmp_path / "history.db"
    assessment_id = str(uuid.uuid4())
    with connect(database) as db:
        db.execute("INSERT INTO assessments(id,started_at,completed_at,endpoint,region,status,tool_version) "
                   "VALUES(?,?,?,?,?,?,?)", (assessment_id, "2026-02-03T04:05:00Z", "2026-02-03T04:06:00Z",
                   "http://127.0.0.1:4566", "us-east-1", "PARTIAL", "test"))
    client = client_for(database)
    response = client.get(f"/assessments/{assessment_id}")
    assert response.status_code == 200
    assert assessment_id in response.text
    assert 'data-page="assessment"' in response.text
    assert client.get("/assessments/not-a-uuid").status_code == 404


def test_cloud_derived_markup_is_rendered_as_text_by_dashboard_script(tmp_path):
    database = tmp_path / "xss.sqlite"
    assessment_id = str(uuid.uuid4())
    payload = "<img src=x onerror=alert(1)>"
    with connect(database) as db:
        db.execute("INSERT INTO assessments(id,started_at,completed_at,endpoint,region,status,tool_version) "
                   "VALUES(?,?,?,?,?,?,?)", (assessment_id, "2026-02-03T04:05:00Z", "2026-02-03T04:06:00Z",
                   "http://127.0.0.1:4566", "us-east-1", "COMPLETED", "test"))
        db.execute("INSERT INTO resources(assessment_id,resource_type,resource_id,name,source_service,"
                   "source_operation,observed_at,attributes_json) VALUES(?,?,?,?,?,?,?,?)",
                   (assessment_id, "s3_bucket", "bucket-x", payload, "s3", "ListBuckets",
                    "2026-02-03T04:05:00Z", json.dumps({"DisplayName": payload})))
    client = client_for(database)
    api_resource = client.get(f"/api/assessments/{assessment_id}/resources").json()["items"][0]
    assert api_resource["name"] == payload
    script = client.get("/static/dashboard.js").text
    assert ".textContent" in script
    assert "innerHTML" not in script
    assert payload not in client.get(f"/assessments/{assessment_id}").text


def test_jinja_template_autoescapes_html_values():
    from aegis.web_ui import templates

    template = templates.env.from_string("<p>{{ value }}</p>")
    rendered = template.render(value="<script>alert(1)</script>")
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
