"""FastAPI route handlers."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, File, HTTPException, Query, UploadFile

from backend.schemas.responses import (
    ApplicationDetailResponse,
    ApplicationSummary,
    DashboardResponse,
    DependencyGraphResponse,
    ErrorResponse,
    UploadResponse,
)
from backend.services import (
    application_service,
    dashboard_service,
    graph_service,
    report_service,
    upload_service,
)
from backend.services.analysis_state import get_state

router = APIRouter()


@router.post(
    "/upload-sbom",
    response_model=UploadResponse,
    responses={400: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
    tags=["Upload"],
)
async def upload_sbom(files: list[UploadFile] = File(...)) -> dict:
    if not files:
        raise HTTPException(status_code=400, detail="No files provided.")

    state = get_state()
    file_data = []
    for f in files:
        content = await f.read()
        if not content:
            raise HTTPException(status_code=400, detail=f"File '{f.filename}' is empty.")
        file_data.append((f.filename or "unknown.json", content))

    try:
        return upload_service.upload_sbom_files(state, file_data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/applications",
    response_model=list[ApplicationSummary],
    tags=["Applications"],
)
def get_applications() -> list:
    state = get_state()
    return application_service.list_applications(state)


@router.get(
    "/applications/{app_id}",
    response_model=ApplicationDetailResponse,
    responses={404: {"model": ErrorResponse}},
    tags=["Applications"],
)
def get_application(app_id: str) -> dict:
    state = get_state()
    detail = application_service.get_application_detail(state, app_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Application '{app_id}' not found.")
    return detail


@router.get(
    "/dashboard",
    response_model=DashboardResponse,
    tags=["Dashboard"],
)
def get_dashboard() -> dict:
    state = get_state()
    return dashboard_service.get_dashboard(state)


@router.get(
    "/dependency-graph/{app_id}",
    response_model=DependencyGraphResponse,
    responses={404: {"model": ErrorResponse}},
    tags=["Dependency Graph"],
)
def get_dependency_graph(
    app_id: str,
    show_vulnerabilities: bool = Query(True, alias="showVulnerabilities"),
    show_license_conflicts: bool = Query(True, alias="showLicenseConflicts"),
    show_maintenance_risks: bool = Query(True, alias="showMaintenanceRisks"),
) -> dict:
    state = get_state()
    if not state.get_application_by_id(app_id):
        raise HTTPException(status_code=404, detail=f"Application '{app_id}' not found.")
    return graph_service.get_dependency_graph(
        state,
        app_id,
        show_vulnerabilities=show_vulnerabilities,
        show_license_conflicts=show_license_conflicts,
        show_maintenance_risks=show_maintenance_risks,
    )


@router.get(
    "/report/{report_id}",
    tags=["Reports"],
    responses={404: {"model": ErrorResponse}},
)
def get_report(report_id: str) -> dict:
    state = get_state()
    report = report_service.get_report_by_id(state, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return report


@router.get(
    "/executive-summary",
    tags=["Reports"],
)
def get_executive_summary() -> dict:
    state = get_state()
    return report_service.get_executive_summary(state)


@router.get(
    "/report/{report_id}/export/json",
    tags=["Reports"],
    responses={404: {"model": ErrorResponse}},
)
def export_report_json(report_id: str) -> dict:
    state = get_state()
    report = report_service.export_report_json(state, report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return report


@router.get(
    "/report/{report_id}/export/html",
    tags=["Reports"],
    responses={404: {"model": ErrorResponse}},
)
def export_report_html(report_id: str) -> dict:
    state = get_state()
    try:
        html = report_service.export_report_html_content(state, report_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    if not html:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return {"html": html}
