"""
SBOM Risk Analyzer - Graph Analyzer Module

This module constructs a directed graph of applications and libraries using NetworkX,
and analyzes the dependency structures, paths to vulnerabilities, and handles
diamond dependency risk deduplication.
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Set, Tuple

import networkx as nx
import pandas as pd
from packaging.version import parse as parse_version

def is_version_affected(installed_ver_str: str, affected_versions_list: List[str]) -> bool:
    """
    Checks if an installed version is affected by a vulnerability.
    Checks exact matches first, then falls back to range expressions (e.g. "<2.15.0", ">=1.0.0").
    """
    # 1. Exact match first
    if installed_ver_str in affected_versions_list:
        return True

    # 2. Check range-based matches if any entry is a range
    try:
        inst_v = parse_version(installed_ver_str)
    except Exception:
        return False

    for aff_ver in affected_versions_list:
        match = re.match(r"^([<>]=?|=)(.*)$", aff_ver.strip())
        if match:
            op, val_str = match.groups()
            try:
                val_v = parse_version(val_str.strip())
                if op == "<" and inst_v < val_v:
                    return True
                elif op == "<=" and inst_v <= val_v:
                    return True
                elif op == ">" and inst_v > val_v:
                    return True
                elif op == ">=" and inst_v >= val_v:
                    return True
                elif op == "=" and inst_v == val_v:
                    return True
            except Exception:
                continue
    return False

def downgrade_severity(severity: str) -> str:
    """Downgrades a severity tier by one level."""
    sev_map = {
        "Critical": "High",
        "High": "Medium",
        "Medium": "Low",
        "Low": "None",
        "None": "None"
    }
    return sev_map.get(severity, severity)

logger = logging.getLogger("SBOMGraphAnalyzer")
logger.setLevel(logging.INFO)

# Setup logger handler if not present
if not logger.handlers:
    ch = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)


class SBOMDependencyGraph:
    """
    Constructs and analyzes the directed dependency graph of applications and components.
    Uses NetworkX DiGraph internally.
    """

    def __init__(self):
        """Initializes an empty directed graph."""
        self.graph = nx.DiGraph()

    def build_graph(self, applications: List[Dict[str, Any]], dependencies_df: pd.DataFrame) -> None:
        """
        Builds the directed dependency graph from applications and dependencies data.

        Transitive Relationship Inference Assumption:
        ----------------------------------------------
        Since sbom_dependencies.csv is a flat table and does not explicitly list parent-child
        relations for transitive libraries, we assume that any 'Transitive' dependency record
        is a child of the nearest preceding 'Direct' dependency in the input order for that
        particular application. If a 'Transitive' dependency is parsed before any 'Direct'
        dependency is encountered, it falls back to being attached directly to the Application node.

        Args:
            applications: List of application dictionaries (from applications.json).
            dependencies_df: pandas DataFrame containing dependencies (from sbom_dependencies.csv).
        """
        logger.info("Building NetworkX SBOM dependency graph...")

        # 1. Add Application Nodes
        for app in applications:
            app_id = app["app_id"]
            node_id = f"app:{app_id}"
            self.graph.add_node(
                node_id,
                node_type="Application",
                app_id=app_id,
                name=app["app_name"],
                owner=app["owner"],
                business_unit=app["business_unit"],
                business_criticality=app["business_criticality"],
                environment=app["environment"],
                last_scan_date=app["last_scan_date"]
            )

        # 2. Add Library Nodes and Edges
        # Group by app_id to construct app-specific dependency structures
        grouped = dependencies_df.groupby("app_id", sort=False)
        for app_id, group_df in grouped:
            app_node_id = f"app:{app_id}"
            if not self.graph.has_node(app_node_id):
                # Fallback: add app node if not explicitly declared in applications list
                self.graph.add_node(app_node_id, node_type="Application", name=app_id)

            current_direct_parent = None

            # Iterate through dependencies in order as they appear in the dataset
            for _, row in group_df.iterrows():
                dep_name = row["dependency_name"]
                version = row["version"]
                lib_node_id = f"lib:{dep_name}@{version}"

                # Add library node if not exists
                if not self.graph.has_node(lib_node_id):
                    self.graph.add_node(
                        lib_node_id,
                        node_type="Library",
                        name=dep_name,
                        version=version,
                        ecosystem=row["ecosystem"],
                        license=row["license"],
                        supplier=row["supplier"],
                        latest_version=row["latest_version"],
                        last_updated=row["last_updated"]
                    )

                dep_type = row["dependency_type"]
                if dep_type == "Direct":
                    # Direct dependency is linked directly to the application
                    self.graph.add_edge(
                        app_node_id,
                        lib_node_id,
                        relation_type="depends_on",
                        dependency_type="Direct"
                    )
                    current_direct_parent = lib_node_id
                elif dep_type == "Transitive":
                    if current_direct_parent:
                        # Link transitive dependency to the current active direct parent
                        self.graph.add_edge(
                            current_direct_parent,
                            lib_node_id,
                            relation_type="transitively_depends_on",
                            dependency_type="Transitive"
                        )
                    else:
                        # Fallback: if transitive dependency is listed before any direct parent
                        logger.warning(
                            f"Transitive dependency '{lib_node_id}' listed before any direct parent "
                            f"for application '{app_id}'. Linking directly to the application."
                        )
                        self.graph.add_edge(
                            app_node_id,
                            lib_node_id,
                            relation_type="depends_on",
                            dependency_type="Direct"
                        )

        logger.info(
            f"SBOM dependency graph built. Total nodes: {self.graph.number_of_nodes()}, "
            f"edges: {self.graph.number_of_edges()}"
        )

    def get_direct_dependencies(self, app_id: str) -> List[str]:
        """
        Retrieves direct dependencies for a given application ID.

        Args:
            app_id: The ID of the application.

        Returns:
            A list of library node IDs that are direct dependencies.
        """
        app_node_id = f"app:{app_id}"
        if not self.graph.has_node(app_node_id):
            return []

        directs = []
        for neighbor in self.graph.successors(app_node_id):
            edge_data = self.graph.get_edge_data(app_node_id, neighbor)
            if edge_data and edge_data.get("dependency_type") == "Direct":
                directs.append(neighbor)
        return directs

    def get_transitive_dependencies(self, app_id: str) -> List[str]:
        """
        Retrieves all transitive dependencies (reachable but not direct) for an application ID.

        Args:
            app_id: The ID of the application.

        Returns:
            A list of library node IDs that are transitive dependencies.
        """
        app_node_id = f"app:{app_id}"
        if not self.graph.has_node(app_node_id):
            return []

        # Find all reachable nodes using DFS/BFS descendants
        all_descendants = nx.descendants(self.graph, app_node_id)
        directs = set(self.get_direct_dependencies(app_id))
        
        # Transitive are all descendants minus direct ones
        transitively_reachable = all_descendants - directs
        return list(transitively_reachable)

    def find_paths_to_vulnerable_libraries(
        self, app_id: str, vulnerability_db: List[Dict[str, Any]]
    ) -> Dict[str, List[List[str]]]:
        """
        Finds all simple paths from the application node to any vulnerable libraries.

        Args:
            app_id: The ID of the application.
            vulnerability_db: List of vulnerability dictionaries.

        Returns:
            A dictionary mapping vulnerable library node ID to a list of paths.
            Each path is a list of node IDs from the application node to the library node.
        """
        app_node_id = f"app:{app_id}"
        if not self.graph.has_node(app_node_id):
            return {}

        # 1. Identify which library nodes in the graph are vulnerable
        vulnerable_nodes = []
        all_descendants = nx.descendants(self.graph, app_node_id)
        for node in all_descendants:
            node_data = self.graph.nodes[node]
            if node_data.get("node_type") == "Library":
                name = node_data["name"]
                ver = node_data["version"]
                
                # Check against vulnerability_db
                for vuln in vulnerability_db:
                    if vuln["dependency_name"] == name:
                        if is_version_affected(ver, vuln["affected_versions"]):
                            vulnerable_nodes.append(node)
                            break
                        # Also check if it's potentially affected but we have fixed_version
                        fixed_ver = vuln.get("fixed_version")
                        if fixed_ver:
                            try:
                                if parse_version(ver) < parse_version(fixed_ver):
                                    vulnerable_nodes.append(node)
                                    break
                            except Exception:
                                pass

        # 2. Find all simple paths to these vulnerable nodes
        paths_by_node: Dict[str, List[List[str]]] = {}
        for target in vulnerable_nodes:
            # Find all simple paths from source app to target lib
            simple_paths = list(nx.all_simple_paths(self.graph, source=app_node_id, target=target))
            if simple_paths:
                paths_by_node[target] = simple_paths

        return paths_by_node

    def get_application_vulnerabilities(
        self, app_id: str, vulnerability_db: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Retrieves unique vulnerabilities affecting the application.
        Handles diamond dependencies by deduplicating CVEs at the application level
        while keeping trace of all vulnerable components.

        Args:
            app_id: The ID of the application.
            vulnerability_db: List of vulnerability dictionaries.

        Returns:
            A list of unique vulnerability records (dictionaries) affecting the application.
        """
        app_node_id = f"app:{app_id}"
        if not self.graph.has_node(app_node_id):
            return []

        # Find all libraries reachable from application
        reachable_libs = [
            node for node in nx.descendants(self.graph, app_node_id)
            if self.graph.nodes[node].get("node_type") == "Library"
        ]

        # Map dependency names to version sets in reachable libraries
        reachable_lib_versions: Dict[str, Set[str]] = {}
        for lib in reachable_libs:
            node_data = self.graph.nodes[lib]
            name = node_data["name"]
            ver = node_data["version"]
            if name not in reachable_lib_versions:
                reachable_lib_versions[name] = set()
            reachable_lib_versions[name].add(ver)

        # Find matching vulnerabilities in vulnerability_db
        matched_cves: Dict[str, Dict[str, Any]] = {}
        for vuln in vulnerability_db:
            cve_id = vuln["cve_id"]
            dep_name = vuln["dependency_name"]

            # If the affected dependency is reachable by the app
            if dep_name in reachable_lib_versions:
                active_versions = reachable_lib_versions[dep_name]
                
                for installed_ver in active_versions:
                    is_affected = False
                    is_patched_mitigation = False
                    
                    # 1. Exact or range match check
                    if is_version_affected(installed_ver, vuln["affected_versions"]):
                        is_affected = True
                        
                    # 2. Check if installed_ver < fixed_version (fallback vulnerability check)
                    fixed_ver = vuln.get("fixed_version")
                    if not is_affected and fixed_ver:
                        try:
                            if parse_version(installed_ver) < parse_version(fixed_ver):
                                is_affected = True
                        except Exception:
                            pass
                            
                    # 3. Check patch exists nuance (installed_ver >= fixed_version)
                    if fixed_ver:
                        try:
                            if parse_version(installed_ver) >= parse_version(fixed_ver):
                                is_patched_mitigation = True
                        except Exception:
                            pass
                    
                    if is_affected or is_patched_mitigation:
                        vuln_severity = vuln["severity"]
                        cvss = vuln["cvss_score"]
                        patch_avail = vuln["patch_available"]
                        
                        # Apply patch exists nuance: if CVSS >= 7 but patch is available and installed >= patched
                        if cvss >= 7.0 and patch_avail and is_patched_mitigation:
                            vuln_severity = downgrade_severity(vuln_severity)
                        elif is_patched_mitigation and not (cvss >= 7.0 and patch_avail):
                            # Default downgrade for non-critical patched CVEs
                            vuln_severity = "None"
                            
                        # Store matched CVE with deduplication
                        if cve_id not in matched_cves:
                            matched_cves[cve_id] = {
                                "cve_id": cve_id,
                                "dependency_name": dep_name,
                                "matching_versions": [installed_ver],
                                "cvss_score": cvss,
                                "severity": vuln_severity,
                                "exploit_available": vuln["exploit_available"],
                                "patch_available": patch_avail,
                                "published_date": vuln["published_date"],
                                "status": "Vulnerable" if is_affected else "Mitigated"
                            }
                        else:
                            existing = set(matched_cves[cve_id]["matching_versions"])
                            matched_cves[cve_id]["matching_versions"] = list(existing | {installed_ver})
                            # If any matching version is actually vulnerable, keep "Vulnerable" status and base severity
                            if is_affected:
                                matched_cves[cve_id]["severity"] = vuln["severity"]
                                matched_cves[cve_id]["status"] = "Vulnerable"

        return list(matched_cves.values())

    def get_maintenance_risks(
        self, app_id: str, vulnerability_db: List[Dict[str, Any]], scan_date_str: str = "2026-07-11"
    ) -> List[Dict[str, Any]]:
        """
        Analyzes maintenance risks for libraries reachable from the application.

        Maintenance Staleness Threshold:
        -------------------------------
        We use an 18-month threshold to define unmaintained libraries (staleness).
        - If a library has not been updated in 18 months or more and has NO known CVEs,
          it is flagged as a Low severity (informational) maintenance risk.
          This resolves the ambiguity regarding moderately stale but clean libraries.
        - If a library has not been updated in 18 months or more and has ONE OR MORE known CVEs,
          it is flagged as a High severity (elevated) maintenance risk because no patch is expected.

        Args:
            app_id: The ID of the application.
            vulnerability_db: List of vulnerability database records.
            scan_date_str: The current date for reference (defaults to '2026-07-11').

        Returns:
            A list of maintenance risk dictionaries containing:
            - node_id: str
            - dependency_name: str
            - version: str
            - last_updated: str
            - months_stale: float
            - risk_level: str ("Low" | "High")
            - explanation: str
        """
        app_node_id = f"app:{app_id}"
        if not self.graph.has_node(app_node_id):
            return []

        # Find all libraries reachable from application
        reachable_libs = [
            node for node in nx.descendants(self.graph, app_node_id)
            if self.graph.nodes[node].get("node_type") == "Library"
        ]

        risks = []
        
        # Build set of vulnerable library names and versions
        # to check if the stale library has active CVEs
        vuln_lookup = set()
        for vuln in vulnerability_db:
            dep_name = vuln["dependency_name"]
            for ver in vuln["affected_versions"]:
                vuln_lookup.add((dep_name, ver))

        for lib in reachable_libs:
            node_data = self.graph.nodes[lib]
            name = node_data["name"]
            ver = node_data["version"]
            last_updated = node_data.get("last_updated", "Unknown")

            if last_updated == "Unknown":
                continue

            # Calculate staleness in months
            try:
                lu_dt = datetime.strptime(last_updated, "%Y-%m-%d")
                scan_dt = datetime.strptime(scan_date_str, "%Y-%m-%d")
                delta = scan_dt - lu_dt
                months_stale = delta.days / 30.436875
            except Exception:
                continue

            # Threshold: 18 months (1.5 years)
            if months_stale >= 18.0:
                has_cve = (name, ver) in vuln_lookup
                
                # Check also if any CVE fixed_version is > ver
                if not has_cve:
                    for vuln in vulnerability_db:
                        if vuln["dependency_name"] == name:
                            fixed_ver = vuln.get("fixed_version")
                            if fixed_ver:
                                try:
                                    if parse_version(ver) < parse_version(fixed_ver):
                                        has_cve = True
                                        break
                                except Exception:
                                    pass

                if has_cve:
                    risk_level = "High"
                    explanation = (
                        f"Library '{name}' has not been updated in {months_stale:.1f} months "
                        f"(exceeds 18-month threshold) and has active CVEs. "
                        f"Because the library is unmaintained, an official patch is unlikely to be released."
                    )
                else:
                    risk_level = "Low"
                    explanation = (
                        f"Library '{name}' has not been updated in {months_stale:.1f} months "
                        f"(exceeds 18-month threshold) but has no known CVEs. "
                        f"This is flagged as an informational maintenance concern."
                    )

                risks.append({
                    "node_id": lib,
                    "dependency_name": name,
                    "version": ver,
                    "last_updated": last_updated,
                    "months_stale": round(months_stale, 1),
                    "risk_level": risk_level,
                    "explanation": explanation
                })

        return risks
