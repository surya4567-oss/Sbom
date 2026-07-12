"""Dashboard aggregation service."""

from __future__ import annotations

from typing import Any, Dict, List

from backend.services.analysis_state import AnalysisState


def get_dashboard(state: AnalysisState) -> Dict[str, Any]:
    report = state.report
    exec_summary = report.get("Executive Summary", {})
    apps = report.get("Applications", [])

    total_deps = sum(
        a.get("Dependency Details", {}).get("Total Dependencies", 0) for a in apps
    )

    risk_dist: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for app in apps:
        cat = app.get("Risk Information", {}).get("Risk Category", "Low")
        if cat in risk_dist:
            risk_dist[cat] += 1
        elif cat == "Moderate":
            risk_dist["Medium"] += 1
        else:
            risk_dist["Low"] += 1

    severity_dist: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for app in apps:
        vulns = state.sbom_graph.get_application_vulnerabilities(
            _app_id_for_report_app(state, app),
            state.vulnerability_db,
        )
        for v in vulns:
            sev = v.get("severity", "Low")
            if sev in severity_dist:
                severity_dist[sev] += 1

    top_risky: List[Dict[str, Any]] = []
    for app in apps:
        info = app.get("Application Information", {})
        risk = app.get("Risk Information", {})
        top_risky.append(
            {
                "name": info.get("Name", "Unknown"),
                "score": risk.get("Overall Risk Score", 0),
                "severity": risk.get("Risk Category", "Low"),
            }
        )
    top_risky.sort(key=lambda x: x["score"], reverse=True)
    top_risky = top_risky[:5]

    scores = [a.get("Risk Information", {}).get("Overall Risk Score", 0) for a in apps]
    overall = round(sum(scores) / len(scores), 1) if scores else 0.0

    maintenance_count = sum(
        len(a.get("Maintenance Findings", [])) for a in apps
    )

    return {
        "kpis": {
            "totalApplications": exec_summary.get("Total Applications", len(apps)),
            "totalDependencies": total_deps,
            "criticalApplications": exec_summary.get("Critical Applications", 0),
            "highRiskApplications": exec_summary.get("High Risk Applications", 0),
            "totalVulnerabilities": exec_summary.get("Total Vulnerabilities", 0),
            "licenseConflicts": exec_summary.get("License Violations", 0),
            "maintenanceRisks": maintenance_count,
            "overallRiskScore": overall,
        },
        "charts": {
            "riskDistribution": [{"name": k, "value": v} for k, v in risk_dist.items() if v > 0],
            "severityDistribution": [{"name": k, "value": v} for k, v in severity_dist.items() if v > 0],
            "topRiskyApplications": top_risky,
        },
        "recentAnalysis": {
            "lastScan": state.last_scan or "Unknown",
            "applicationsScanned": len(apps),
            "criticalFindings": exec_summary.get("Critical Applications", 0),
        },
    }


def _app_id_for_report_app(state: AnalysisState, app_report: Dict[str, Any]) -> str:
    name = app_report.get("Application Information", {}).get("Name", "")
    for app in state.applications:
        if app["app_name"] == name:
            return app["app_id"]
    return ""
