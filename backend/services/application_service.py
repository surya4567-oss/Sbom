"""Application listing and detail service."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from backend.services.analysis_state import AnalysisState


def list_applications(state: AnalysisState) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for app in state.applications:
        app_report = state.get_app_report(app["app_id"])
        risk_info = (app_report or {}).get("Risk Information", {})
        dep_info = (app_report or {}).get("Dependency Details", {})
        results.append(
            {
                "id": app["app_id"],
                "name": app["app_name"],
                "owner": app["owner"],
                "riskScore": risk_info.get("Overall Risk Score", 0),
                "severity": risk_info.get("Risk Category", "Unknown"),
                "dependencies": dep_info.get("Total Dependencies", 0),
                "status": "Analyzed",
            }
        )
    results.sort(key=lambda x: x["riskScore"], reverse=True)
    return results


def get_application_detail(state: AnalysisState, app_id: str) -> Optional[Dict[str, Any]]:
    app = state.get_application_by_id(app_id)
    if not app:
        return None

    app_report = state.get_app_report(app_id)
    if not app_report:
        return None

    risk_info = app_report.get("Risk Information", {})
    app_info = app_report.get("Application Information", {})

    tree = _build_dependency_tree(state, app_id)
    vulns = _build_vulnerabilities(state, app_id)
    licenses = _build_licenses(app_report)
    maintenance = _build_maintenance(state, app_id, app_report)
    remediation_priority = _build_remediation_priority(state, app["app_name"])

    return {
        "id": app_id,
        "name": app["app_name"],
        "riskOverview": {
            "riskScore": risk_info.get("Overall Risk Score", 0),
            "severity": risk_info.get("Risk Category", "Unknown"),
            "businessCriticality": app_info.get("Business Criticality", "Unknown"),
        },
        "dependencyTree": tree,
        "vulnerabilities": vulns,
        "licenses": licenses,
        "maintenance": maintenance,
        "aiExplanation": app_report.get("AI Risk Explanation", {}),
        "aiRemediation": app_report.get("AI Remediation Plan", {}),
        "remediationPriority": remediation_priority,
    }


def _build_dependency_tree(state: AnalysisState, app_id: str) -> List[Dict[str, Any]]:
    graph = state.sbom_graph
    app_node = f"app:{app_id}"

    def build_node(node_id: str, visited: set) -> Optional[Dict[str, Any]]:
        if node_id in visited:
            return None
        visited.add(node_id)
        if not graph.graph.has_node(node_id):
            return None
        data = graph.graph.nodes[node_id]
        node_type = "application" if data.get("node_type") == "Application" else "library"
        name = data.get("name", node_id)
        version = data.get("version", "")
        children: List[Dict[str, Any]] = []
        for child in graph.graph.successors(node_id):
            child_node = build_node(child, visited)
            if child_node:
                children.append(child_node)
        return {
            "id": node_id,
            "name": name,
            "version": version,
            "type": node_type,
            "children": children,
        }

    root = build_node(app_node, set())
    return [root] if root else []


def _build_vulnerabilities(state: AnalysisState, app_id: str) -> List[Dict[str, Any]]:
    vulns = state.sbom_graph.get_application_vulnerabilities(app_id, state.vulnerability_db)
    results: List[Dict[str, Any]] = []
    for v in vulns:
        versions = v.get("matching_versions", ["Unknown"])
        for ver in versions:
            results.append(
                {
                    "library": v.get("dependency_name", "Unknown"),
                    "version": ver,
                    "cve": v.get("cve_id", "Unknown"),
                    "cvss": v.get("cvss_score", 0.0),
                    "patchAvailable": v.get("patch_available", False),
                }
            )
    return results


def _build_licenses(app_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = app_report.get("License Findings", [])
    results: List[Dict[str, Any]] = []
    for f in findings:
        results.append(
            {
                "library": f.get("library", ""),
                "license": f.get("license", "Unknown"),
                "compatibility": f.get("status", "Unknown"),
                "conflictReason": _license_reason(f.get("status", "")),
            }
        )
    return results


def _license_reason(status: str) -> str:
    reasons = {
        "Incompatible": "License terms conflict with organizational policy for proprietary SaaS distribution.",
        "Unknown Legal Status": "License could not be evaluated against known rules.",
        "Needs Review": "License requires manual legal review before approval.",
        "Compatible": "No conflicts detected.",
    }
    return reasons.get(status, "")


def _build_maintenance(
    state: AnalysisState, app_id: str, app_report: Dict[str, Any]
) -> List[Dict[str, Any]]:
    findings = app_report.get("Maintenance Findings", [])
    if not findings:
        findings = state.sbom_graph.get_maintenance_risks(app_id, state.vulnerability_db)

    results: List[Dict[str, Any]] = []
    for f in findings:
        results.append(
            {
                "library": f.get("dependency_name", f.get("library", "Unknown")),
                "lastUpdated": f.get("last_updated", "Unknown"),
                "deprecated": f.get("months_stale", 0) >= 24 if "months_stale" in f else False,
                "busFactor": "Low" if f.get("risk_level") == "High" else "Medium",
                "securityPolicy": "Missing" if f.get("risk_level") == "High" else "Unknown",
                "riskLevel": f.get("risk_level", "Low"),
            }
        )
    return results


def _build_remediation_priority(state: AnalysisState, app_name: str) -> List[Dict[str, Any]]:
    priorities = state.report.get("Remediation Priority", [])
    app_rank = next((p for p in priorities if p.get("Application") == app_name), None)
    rank = app_rank.get("Rank", 0) if app_rank else 0

    app_report = next(
        (a for a in state.report.get("Applications", [])
         if a.get("Application Information", {}).get("Name") == app_name),
        {},
    )
    remediation = app_report.get("AI Remediation Plan", {})

    items: List[Dict[str, Any]] = []
    immediate = remediation.get("Immediate Actions", [])
    medium = remediation.get("Medium-Term Improvements", [])
    long_term = remediation.get("Long-Term Recommendations", [])

    if immediate:
        action = immediate[0]
        items.append(
            {
                "rank": 1,
                "title": action.get("What", "Immediate remediation"),
                "description": action.get("Why", ""),
                "priority": action.get("Priority", "High"),
            }
        )
    if medium:
        action = medium[0]
        items.append(
            {
                "rank": 2,
                "title": action.get("What", "Medium-term improvement"),
                "description": action.get("Why", ""),
                "priority": action.get("Priority", "Medium"),
            }
        )
    if long_term:
        action = long_term[0]
        items.append(
            {
                "rank": 3,
                "title": action.get("What", "Long-term recommendation"),
                "description": action.get("Why", ""),
                "priority": action.get("Priority", "Low"),
            }
        )

    if rank and not items:
        items.append(
            {
                "rank": rank,
                "title": f"Organization priority #{rank}",
                "description": app_rank.get("Reason", "") if app_rank else "",
                "priority": app_rank.get("Priority", "Medium") if app_rank else "Medium",
            }
        )
    return items
