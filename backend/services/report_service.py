"""Report and executive summary service."""

from __future__ import annotations

from typing import Any, Dict, Optional

from reports.html_export import export_html
from reports.json_export import export_json
from reports.pdf_export import export_pdf

from backend.services.analysis_state import AnalysisState


def get_full_report(state: AnalysisState) -> Dict[str, Any]:
    return state.report


def get_report_by_id(state: AnalysisState, report_id: str) -> Optional[Dict[str, Any]]:
    if report_id in ("all", "full", "org"):
        return state.report

    app = state.get_application_by_id(report_id)
    if not app:
        return None

    app_report = state.get_app_report(report_id)
    if not app_report:
        return None

    return {
        "Executive Summary": state.report.get("Executive Summary", {}),
        "Remediation Priority": [
            p for p in state.report.get("Remediation Priority", [])
            if p.get("Application") == app["app_name"]
        ],
        "Applications": [app_report],
    }


def get_executive_summary(state: AnalysisState) -> Dict[str, Any]:
    return state.report.get("Executive Summary", {})


def export_report_json(state: AnalysisState, report_id: str = "all") -> Dict[str, Any]:
    report = get_report_by_id(state, report_id) if report_id not in ("all", "full", "org") else get_full_report(state)
    return report or {}


def export_report_html_content(state: AnalysisState, report_id: str = "all") -> str:
    import io
    import tempfile
    import os

    report = export_report_json(state, report_id)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False, encoding="utf-8") as f:
        tmp_path = f.name
    try:
        export_html(report, tmp_path)
        with open(tmp_path, "r", encoding="utf-8") as f:
            return f.read()
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
