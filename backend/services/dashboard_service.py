"""Dashboard aggregation service."""

from __future__ import annotations

from typing import Any, Dict, List

from backend.services.analysis_state import AnalysisState


def get_dashboard(state: AnalysisState) -> Dict[str, Any]:
    import networkx as nx
    from datetime import datetime, timezone

    # Core metadata counts
    apps_scanned = len(state.applications)
    
    scores = []
    crit_count = 0
    high_count = 0
    risk_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    top_risky = []
    total_deps = 0
    maintenance_count = 0
    license_violations = 0
    total_vulns = set()
    severity_dist: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for app in state.applications:
        app_id = app["app_id"]
        
        # 1. Risk Score on the fly
        if state.risk_engine:
            try:
                app_risk = state.risk_engine.calculate_application_risk(
                    app_id=app_id,
                    sbom_graph=state.sbom_graph,
                    vulnerability_db=state.vulnerability_db,
                    app_policy=state.app_policy
                )
                score = app_risk["risk_score"]
                cat = app_risk["risk_category"]
            except Exception:
                score = 0.0
                cat = "Low"
        else:
            score = 0.0
            cat = "Low"
            
        scores.append(score)
        if cat == "Critical":
            crit_count += 1
        elif cat == "High":
            high_count += 1
            
        if cat in risk_dist:
            risk_dist[cat] += 1
        elif cat == "Moderate":
            risk_dist["Medium"] += 1
        else:
            risk_dist["Low"] += 1
            
        top_risky.append({
            "name": app["app_name"],
            "score": score,
            "severity": cat
        })
        
        # 2. Dependency count on the fly
        direct_deps = state.sbom_graph.get_direct_dependencies(app_id)
        transitive_deps = state.sbom_graph.get_transitive_dependencies(app_id)
        total_deps += len(direct_deps) + len(transitive_deps)
        
        # 3. Vulnerability count and severity distribution
        vulns = state.sbom_graph.get_application_vulnerabilities(app_id, state.vulnerability_db)
        for v in vulns:
            total_vulns.add(v["cve_id"])
            sev = v.get("severity", "Low")
            if sev in severity_dist:
                severity_dist[sev] += 1
                
        # 4. Maintenance Risks
        m_risks = state.sbom_graph.get_maintenance_risks(app_id, state.vulnerability_db)
        maintenance_count += len(m_risks)
        
        # 5. License violations on the fly
        app_node_id = f"app:{app_id}"
        if state.sbom_graph.graph.has_node(app_node_id) and state.risk_engine:
            try:
                all_descendants = nx.descendants(state.sbom_graph.graph, app_node_id)
                for lib_id in all_descendants:
                    lib_data = state.sbom_graph.graph.nodes[lib_id]
                    license_name = lib_data.get("license", "Unknown")
                    eval_lic = state.risk_engine.license_engine.evaluate_compatibility(license_name, state.app_policy)
                    if eval_lic["status"] in ("Incompatible", "Unknown Legal Status", "Needs Review"):
                        license_violations += 1
            except Exception:
                pass

    top_risky.sort(key=lambda x: x["score"], reverse=True)
    top_risky = top_risky[:5]
    
    overall = round(sum(scores) / len(scores), 1) if scores else 0.0

    return {
        "kpis": {
            "totalApplications": apps_scanned,
            "totalDependencies": total_deps,
            "criticalApplications": crit_count,
            "highRiskApplications": high_count,
            "totalVulnerabilities": len(total_vulns),
            "licenseConflicts": license_violations,
            "maintenanceRisks": maintenance_count,
            "overallRiskScore": overall,
        },
        "charts": {
            "riskDistribution": [{"name": k, "value": v} for k, v in risk_dist.items() if v > 0],
            "severityDistribution": [{"name": k, "value": v} for k, v in severity_dist.items() if v > 0],
            "topRiskyApplications": top_risky,
        },
        "recentAnalysis": {
            "lastScan": state.last_scan or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "applicationsScanned": apps_scanned,
            "criticalFindings": crit_count,
        },
    }


def _app_id_for_report_app(state: AnalysisState, app_report: Dict[str, Any]) -> str:
    name = app_report.get("Application Information", {}).get("Name", "")
    for app in state.applications:
        if app["app_name"] == name:
            return app["app_id"]
    return ""
