"""
SBOM Risk Analyzer - AI Risk Context Builder

Creates a centralized module that combines outputs from every analysis engine
into a single structured context object for AI services.
"""
from typing import Any, Dict, List
import networkx as nx

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from graph_analyzer import SBOMDependencyGraph
from risk_engine import WeightedRiskEngine


def build_risk_context(
    app_id: str,
    sbom_graph: SBOMDependencyGraph,
    vulnerability_db: List[Dict[str, Any]],
    app_policy: Dict[str, Any],
    risk_engine: WeightedRiskEngine
) -> Dict[str, Any]:
    """
    Builds the standardized Risk Context JSON object for a single application.
    """
    app_node_id = f"app:{app_id}"
    if not sbom_graph.graph.has_node(app_node_id):
        raise ValueError(f"Application node {app_node_id} not found in graph.")

    app_data = sbom_graph.graph.nodes[app_node_id]
    
    # 1. Dependency Analysis
    direct_deps = sbom_graph.get_direct_dependencies(app_id)
    transitive_deps = sbom_graph.get_transitive_dependencies(app_id)
    total_deps = len(direct_deps) + len(transitive_deps)
    
    # Calculate depth using shortest path length max
    max_depth = 0
    all_descendants = nx.descendants(sbom_graph.graph, app_node_id)
    if all_descendants:
        lengths = nx.single_source_shortest_path_length(sbom_graph.graph, app_node_id)
        max_depth = max(lengths.values()) if lengths else 0

    # Path finding
    paths_to_vulns = sbom_graph.find_paths_to_vulnerable_libraries(app_id, vulnerability_db)

    # Calculate overall risk
    app_risk = risk_engine.calculate_application_risk(
        app_id=app_id,
        sbom_graph=sbom_graph,
        vulnerability_db=vulnerability_db,
        app_policy=app_policy
    )
    
    # Extract detailed vuln and license info
    vulnerable_libraries = []
    cve_ids = []
    cvss_scores = []
    has_patch = True
    exploit_status = "Unknown" 
    
    app_vulns = sbom_graph.get_application_vulnerabilities(app_id, vulnerability_db)
    for v in app_vulns:
        cve_ids.append(v["cve_id"])
        cvss_scores.append(v["cvss_score"])
        if not v.get("patch_available", False):
            has_patch = False
    
    license_info = []
    license_conflicts = []
    
    for lib_id in all_descendants:
        lib_data = sbom_graph.graph.nodes[lib_id]
        license_name = lib_data.get("license", "Unknown")
        license_info.append({
            "library": lib_id,
            "license": license_name
        })
        
        # Check license compatibility
        eval_lic = risk_engine.license_engine.evaluate_compatibility(license_name, app_policy)
        if eval_lic["status"] in ("Incompatible", "Unknown Legal Status", "Needs Review"):
            license_conflicts.append({
                "library": lib_id,
                "license": license_name,
                "status": eval_lic["status"]
            })
            
        if lib_id in paths_to_vulns:
            vulnerable_libraries.append(lib_id)

    cve_ids = list(set(cve_ids))
    vulnerable_libraries = list(set(vulnerable_libraries))

    maintenance_findings = sbom_graph.get_maintenance_risks(app_id, vulnerability_db)

    context = {
        "Application Name": app_data.get("name", app_id),
        "Business Criticality": app_data.get("business_criticality", "Medium"),
        "Owner": app_data.get("owner", "Unknown"),
        "Total Dependencies": total_deps,
        "Direct Dependencies": len(direct_deps),
        "Transitive Dependencies": len(transitive_deps),
        "Dependency Depth": max_depth,
        "Dependency Paths": paths_to_vulns,
        "Vulnerable Libraries": vulnerable_libraries,
        "CVE IDs": cve_ids,
        "CVSS Scores": cvss_scores,
        "Patch Availability": has_patch if cve_ids else True,
        "Exploit Status": exploit_status,
        "License Information": license_info,
        "License Conflicts": license_conflicts,
        "Maintenance Findings": maintenance_findings,
        "Last Updated Date": app_data.get("last_scan_date", "Unknown"),
        "Deprecated Status": any(m.get("risk_level") == "High" for m in maintenance_findings),
        "Bus Factor": "Low" if any(m.get("risk_level") == "High" for m in maintenance_findings) else "Medium",
        "Overall Risk Score": app_risk["risk_score"],
        "Risk Category": app_risk["risk_category"],
        "Risk Breakdown": app_risk["breakdown"],
        "Top Risk Factors": app_risk.get("explanation", "")
    }

    return context
