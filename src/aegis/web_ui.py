"""Server-rendered dashboard shell and local static assets."""
from __future__ import annotations

from pathlib import Path
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


ASSET_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(ASSET_DIR / "templates"))


def mount_dashboard(app: FastAPI) -> None:
    app.mount("/static", StaticFiles(directory=str(ASSET_DIR / "static")), name="static")

    @app.get("/", include_in_schema=False)
    def overview_page(request: Request):
        return templates.TemplateResponse(request=request, name="overview.html", context={"page": "overview"})

    @app.get("/assessments", include_in_schema=False)
    def assessment_list_page(request: Request):
        return templates.TemplateResponse(request=request, name="assessments.html", context={"page": "assessments"})

    @app.get("/assessments/{assessment_id}", include_in_schema=False)
    def assessment_detail_page(request: Request, assessment_id: str):
        try:
            normalized_id = str(UUID(assessment_id))
        except (ValueError, AttributeError):
            raise HTTPException(status_code=404, detail="Assessment page not found") from None
        return templates.TemplateResponse(request=request, name="assessment.html",
                                          context={"page": "assessment", "assessment_id": normalized_id})

    @app.get("/compare", include_in_schema=False)
    def comparison_page(request: Request):
        return templates.TemplateResponse(request=request, name="compare.html", context={"page": "compare"})

    @app.get("/guide", include_in_schema=False)
    def guide_page(request: Request):
        return templates.TemplateResponse(request=request, name="guide.html", context={"page": "guide"})
