"""Dependency graph service — formats NetworkX graph for React Flow."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

import networkx as nx

from backend.services.analysis_state import AnalysisState


def get_dependency_graph(
    state: AnalysisState,
    app_id: str,
    show_vulnerabilities: bool = True,
    show_license_conflicts: bool = True,
    show_maintenance_risks: bool = True,
) -> Dict[str, Any]:
    app_node = f"app:{app_id}"
    graph = state.sbom_graph.graph
    if not graph.has_node(app_node):
        return {"nodes": [], "edges": []}

    vuln_nodes: Set[str] = set()
    if show_vulnerabilities:
        paths = state.sbom_graph.find_paths_to_vulnerable_libraries(app_id, state.vulnerability_db)
        vuln_nodes = set(paths.keys())

    license_conflict_nodes: Set[str] = set()
    if show_license_conflicts:
        app_report = state.get_app_report(app_id)
        if app_report:
            for f in app_report.get("License Findings", []):
                lib = f.get("library", "")
                if lib:
                    license_conflict_nodes.add(lib)

    maintenance_nodes: Set[str] = set()
    if show_maintenance_risks:
        for m in state.sbom_graph.get_maintenance_risks(app_id, state.vulnerability_db):
            maintenance_nodes.add(m.get("node_id", ""))

    reachable = nx.descendants(graph, app_node) | {app_node}
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    app_vulns = state.sbom_graph.get_application_vulnerabilities(app_id, state.vulnerability_db)
    cve_by_lib: Dict[str, List[str]] = {}
    for v in app_vulns:
        name = v.get("dependency_name", "")
        cve_by_lib.setdefault(name, []).append(v.get("cve_id", ""))

    positions = _layout_tree(graph, app_node, reachable)

    for node_id in reachable:
        data = graph.nodes[node_id]
        node_type_raw = data.get("node_type", "Library")
        if node_type_raw == "Application":
            flow_type = "application"
        else:
            edge_data = None
            for pred in graph.predecessors(node_id):
                if pred == app_node:
                    edge_data = graph.get_edge_data(pred, node_id)
                    break
            if edge_data and edge_data.get("dependency_type") == "Direct":
                flow_type = "direct"
            else:
                is_direct_child = app_node in graph.predecessors(node_id)
                flow_type = "direct" if is_direct_child else "transitive"

        risk_level = _compute_risk_level(
            node_id, data, vuln_nodes, license_conflict_nodes, maintenance_nodes, show_vulnerabilities,
            show_license_conflicts, show_maintenance_risks,
        )

        lib_name = data.get("name", node_id)
        cves = cve_by_lib.get(lib_name, []) if node_type_raw == "Library" else []

        license_str = data.get("license", "Unknown") if node_type_raw == "Library" else ""
        maint_status = "At Risk" if node_id in maintenance_nodes else "Healthy"

        nodes.append(
            {
                "id": node_id,
                "type": "default",
                "position": positions.get(node_id, {"x": 0, "y": 0}),
                "data": {
                    "label": lib_name if node_type_raw == "Library" else data.get("name", app_id),
                    "libraryName": lib_name,
                    "version": data.get("version", ""),
                    "nodeType": flow_type,
                    "riskLevel": risk_level,
                    "cves": cves,
                    "license": license_str,
                    "maintenanceStatus": maint_status,
                },
            }
        )

    for src, dst in graph.edges():
        if src in reachable and dst in reachable:
            edges.append(
                {
                    "id": f"{src}->{dst}",
                    "source": src,
                    "target": dst,
                    "animated": dst in vuln_nodes,
                }
            )

    return {"nodes": nodes, "edges": edges}


def _compute_risk_level(
    node_id: str,
    data: Dict[str, Any],
    vuln_nodes: Set[str],
    license_nodes: Set[str],
    maint_nodes: Set[str],
    show_vuln: bool,
    show_lic: bool,
    show_maint: bool,
) -> str:
    if show_vuln and node_id in vuln_nodes:
        return "critical"
    if show_lic and node_id in license_nodes:
        return "warning"
    if show_maint and node_id in maint_nodes:
        return "warning"
    return "safe"


def _layout_tree(
    graph: nx.DiGraph,
    root: str,
    reachable: Set[str],
    h_spacing: float = 220,
    v_spacing: float = 100,
) -> Dict[str, Dict[str, float]]:
    """Simple layered tree layout for React Flow."""
    positions: Dict[str, Dict[str, float]] = {}
    positions[root] = {"x": 400, "y": 0}

    levels: Dict[int, List[str]] = {}
    visited: Set[str] = set()

    def bfs_levels(start: str) -> None:
        queue = [(start, 0)]
        while queue:
            node, depth = queue.pop(0)
            if node in visited or node not in reachable:
                continue
            visited.add(node)
            levels.setdefault(depth, []).append(node)
            for child in graph.successors(node):
                if child in reachable:
                    queue.append((child, depth + 1))

    bfs_levels(root)

    for depth, nodes_at_level in levels.items():
        total_width = len(nodes_at_level) * h_spacing
        start_x = 400 - total_width / 2 + h_spacing / 2
        for i, node_id in enumerate(nodes_at_level):
            if node_id == root:
                continue
            positions[node_id] = {"x": start_x + i * h_spacing, "y": depth * v_spacing}

    return positions
