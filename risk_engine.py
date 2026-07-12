"""
SBOM Risk Analyzer - Weighted Risk Score Engine

This module calculates the weighted risk scores (0-100) and risk classifications
for individual dependencies and aggregate application risk, incorporating CVE deduplication
to prevent double-counting.
"""

import logging
from typing import Any, Dict, List, Tuple

from graph_analyzer import SBOMDependencyGraph
from license_engine import LicenseCompatibilityEngine

logger = logging.getLogger("SBOMRiskEngine")
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


class RiskEngineError(Exception):
    """Base exception for risk score engine errors."""
    pass


class WeightedRiskEngine:
    """
    Calculates 0-100 risk scores for dependencies and applications
    based on vulnerability, license compliance, maintenance, dependency type,
    business criticality, and patch availability metrics.
    """

    def __init__(self, license_engine: LicenseCompatibilityEngine):
        """
        Initializes the risk engine.

        Args:
            license_engine: An instantiated LicenseCompatibilityEngine.
        """
        self.license_engine = license_engine

    def classify_score(self, score: float) -> str:
        """
        Classifies a 0-100 score into risk tiers.

        Args:
            score: Risk score between 0 and 100.

        Returns:
            Risk category string ("Low" | "Moderate" | "Medium" | "High" | "Critical").
        """
        rounded = round(score)
        if rounded <= 20:
            return "Low"
        elif rounded <= 40:
            return "Moderate"
        elif rounded <= 60:
            return "Medium"
        elif rounded <= 80:
            return "High"
        else:
            return "Critical"

    def calculate_dependency_risk(
        self,
        app_id: str,
        lib_node_id: str,
        sbom_graph: SBOMDependencyGraph,
        vulnerability_db: List[Dict[str, Any]],
        app_policy: Dict[str, Any],
        scan_date_str: str = "2026-07-11"
    ) -> Dict[str, Any]:
        """
        Calculates the risk score and details for a specific library dependency.

        Args:
            app_id: The ID of the application.
            lib_node_id: The NetworkX node ID of the library (e.g. 'lib:spring-core@5.3.18').
            sbom_graph: The built SBOM dependency graph.
            vulnerability_db: The vulnerability database list.
            app_policy: The application compliance policy.
            scan_date_str: Reference scan date.

        Returns:
            A dictionary containing the calculated risk score, category, and factor breakdown.
        """
        app_node_id = f"app:{app_id}"
        if not sbom_graph.graph.has_node(app_node_id):
            raise RiskEngineError(f"Application node '{app_node_id}' not found in graph.")
        if not sbom_graph.graph.has_node(lib_node_id):
            raise RiskEngineError(f"Library node '{lib_node_id}' not found in graph.")

        app_data = sbom_graph.graph.nodes[app_node_id]
        lib_data = sbom_graph.graph.nodes[lib_node_id]

        name = lib_data["name"]
        ver = lib_data["version"]
        license_name = lib_data["license"]
        last_updated = lib_data.get("last_updated", "Unknown")

        # 1. Vulnerability Factor (40%)
        # Get matching CVEs for this library version
        max_cvss = 0.0
        has_cve = False
        has_patch = True
        
        # Look up CVEs affecting this specific name and version
        from graph_analyzer import is_version_affected
        for vuln in vulnerability_db:
            if vuln["dependency_name"] == name:
                if is_version_affected(ver, vuln["affected_versions"]):
                    has_cve = True
                    max_cvss = max(max_cvss, vuln["cvss_score"])
                    if not vuln["patch_available"]:
                        has_patch = False

        vuln_factor = max_cvss * 10.0  # Scale 0-10 to 0-100
        weighted_vuln = vuln_factor * 0.40

        # 2. License Risk Factor (20%)
        eval_license = self.license_engine.evaluate_compatibility(license_name, app_policy)
        status = eval_license["status"]
        
        license_map = {
            "Compatible": 0,
            "Low Risk Review": 30,
            "Needs Review": 60,
            "Unknown Legal Status": 80,
            "Incompatible": 100
        }
        license_score = license_map.get(status, 60)
        weighted_license = license_score * 0.20

        # 3. Maintenance Factor (15%)
        maint_score = 0
        months_stale = 0.0
        if last_updated != "Unknown":
            try:
                from datetime import datetime
                lu_dt = datetime.strptime(last_updated, "%Y-%m-%d")
                scan_dt = datetime.strptime(scan_date_str, "%Y-%m-%d")
                delta = scan_dt - lu_dt
                months_stale = delta.days / 30.436875
            except Exception:
                pass

        if months_stale < 12.0:
            maint_score = 0
        elif months_stale < 24.0:
            maint_score = 30
        elif months_stale < 36.0:
            maint_score = 60
        else:
            maint_score = 100
        weighted_maint = maint_score * 0.15

        # 4. Dependency Type Factor (10%)
        # Check relation type from application node
        edge_data = sbom_graph.graph.get_edge_data(app_node_id, lib_node_id)
        if edge_data and edge_data.get("dependency_type") == "Direct":
            dep_score = 100
            dep_type = "Direct"
        else:
            # Check if reachable transitively
            dep_score = 70
            dep_type = "Transitive"
        
        weighted_dep = dep_score * 0.10

        # 5. Business Criticality Factor (10%)
        crit = app_data.get("business_criticality", "Medium")
        crit_map = {
            "Low": 25,
            "Medium": 50,
            "High": 75,
            "Critical": 100
        }
        crit_score = crit_map.get(crit, 50)
        weighted_crit = crit_score * 0.10

        # 6. Patch Availability Factor (5%)
        patch_score = 0
        if has_cve:
            patch_score = 20 if has_patch else 100
        else:
            patch_score = 0  # No vulnerability, no penalty
        
        weighted_patch = patch_score * 0.05

        # Calculate Dependency Risk Score
        total_score = (
            weighted_vuln +
            weighted_license +
            weighted_maint +
            weighted_dep +
            weighted_crit +
            weighted_patch
        )

        breakdown = {
            "vulnerability": {"raw": vuln_factor, "weighted": weighted_vuln, "weight": 0.40, "detail": f"Max CVSS: {max_cvss}"},
            "license": {"raw": license_score, "weighted": weighted_license, "weight": 0.20, "detail": f"Status: {status} ({license_name})"},
            "maintenance": {"raw": maint_score, "weighted": weighted_maint, "weight": 0.15, "detail": f"Staleness: {months_stale:.1f} months ({last_updated})"},
            "dependency_type": {"raw": dep_score, "weighted": weighted_dep, "weight": 0.10, "detail": f"Type: {dep_type}"},
            "business_criticality": {"raw": crit_score, "weighted": weighted_crit, "weight": 0.10, "detail": f"Level: {crit}"},
            "patch_availability": {"raw": patch_score, "weighted": weighted_patch, "weight": 0.05, "detail": f"Has CVE: {has_cve}, Patch: {has_patch}"}
        }

        explanation = (
            f"Dependency '{name}@{ver}' has a risk score of {total_score:.1f} ({self.classify_score(total_score)}). "
            f"Risk factors: Vulnerability contributions ({weighted_vuln:.1f}), License risk ({weighted_license:.1f}), "
            f"Maintenance staleness ({weighted_maint:.1f}), Dependency type weight ({weighted_dep:.1f}), "
            f"App Business Criticality ({weighted_crit:.1f}), and Patch status ({weighted_patch:.1f})."
        )

        return {
            "dependency_name": name,
            "version": ver,
            "node_id": lib_node_id,
            "risk_score": round(total_score, 1),
            "risk_category": self.classify_score(total_score),
            "breakdown": breakdown,
            "explanation": explanation
        }

    def calculate_application_risk(
        self,
        app_id: str,
        sbom_graph: SBOMDependencyGraph,
        vulnerability_db: List[Dict[str, Any]],
        app_policy: Dict[str, Any],
        scan_date_str: str = "2026-07-11"
    ) -> Dict[str, Any]:
        """
        Calculates the aggregate risk score for an application.
        Avoids duplicate counting of the same CVE at the application level.

        Args:
            app_id: The ID of the application.
            sbom_graph: The built SBOM dependency graph.
            vulnerability_db: The vulnerability database list.
            app_policy: The application compliance policy.
            scan_date_str: Reference scan date.

        Returns:
            A dictionary containing the application risk score, category, and breakdown.
        """
        app_node_id = f"app:{app_id}"
        if not sbom_graph.graph.has_node(app_node_id):
            raise RiskEngineError(f"Application node '{app_node_id}' not found in graph.")

        app_data = sbom_graph.graph.nodes[app_node_id]

        # Get deduplicated vulnerabilities affecting the application
        app_vulns = sbom_graph.get_application_vulnerabilities(app_id, vulnerability_db)

        # 1. Vulnerability Factor (40%)
        # Take max CVSS score among deduplicated active CVEs
        max_cvss = 0.0
        has_patch = True
        has_cve = len(app_vulns) > 0
        
        for v in app_vulns:
            if v["status"] == "Vulnerable":  # Only active vulnerabilities affect raw risk
                max_cvss = max(max_cvss, v["cvss_score"])
                if not v["patch_available"]:
                    has_patch = False

        vuln_factor = max_cvss * 10.0
        weighted_vuln = vuln_factor * 0.40

        # Retrieve all dependency scores to aggregate other factors
        import networkx as nx
        reachable_libs = [
            node for node in nx.descendants(sbom_graph.graph, app_node_id)
            if sbom_graph.graph.nodes[node].get("node_type") == "Library"
        ]

        if not reachable_libs:
            # Clean application with no dependencies
            return {
                "app_id": app_id,
                "app_name": app_data.get("name", app_id),
                "risk_score": 0.0,
                "risk_category": "Low",
                "explanation": "Application has no dependencies or risks detected."
            }

        # 2. License Factor (20%) - Maximum license risk score among components
        max_license_score = 0
        for lib in reachable_libs:
            lib_data = sbom_graph.graph.nodes[lib]
            eval_license = self.license_engine.evaluate_compatibility(lib_data["license"], app_policy)
            status = eval_license["status"]
            
            license_map = {
                "Compatible": 0,
                "Low Risk Review": 30,
                "Needs Review": 60,
                "Unknown Legal Status": 80,
                "Incompatible": 100
            }
            max_license_score = max(max_license_score, license_map.get(status, 60))

        weighted_license = max_license_score * 0.20

        # 3. Maintenance Factor (15%) - Average maintenance risk score
        total_maint_score = 0
        for lib in reachable_libs:
            lib_data = sbom_graph.graph.nodes[lib]
            last_updated = lib_data.get("last_updated", "Unknown")
            months_stale = 0.0
            if last_updated != "Unknown":
                try:
                    from datetime import datetime
                    lu_dt = datetime.strptime(last_updated, "%Y-%m-%d")
                    scan_dt = datetime.strptime(scan_date_str, "%Y-%m-%d")
                    delta = scan_dt - lu_dt
                    months_stale = delta.days / 30.436875
                except Exception:
                    pass

            if months_stale < 12.0:
                m_score = 0
            elif months_stale < 24.0:
                m_score = 30
            elif months_stale < 36.0:
                m_score = 60
            else:
                m_score = 100
            total_maint_score += m_score

        avg_maint_score = total_maint_score / len(reachable_libs)
        weighted_maint = avg_maint_score * 0.15

        # 4. Dependency Type Factor (10%) - Average dependency type score
        total_dep_score = 0
        for lib in reachable_libs:
            edge_data = sbom_graph.graph.get_edge_data(app_node_id, lib)
            if edge_data and edge_data.get("dependency_type") == "Direct":
                total_dep_score += 100
            else:
                total_dep_score += 70

        avg_dep_score = total_dep_score / len(reachable_libs)
        weighted_dep = avg_dep_score * 0.10

        # 5. Business Criticality Factor (10%) - App criticality
        crit = app_data.get("business_criticality", "Medium")
        crit_map = {
            "Low": 25,
            "Medium": 50,
            "High": 75,
            "Critical": 100
        }
        crit_score = crit_map.get(crit, 50)
        weighted_crit = crit_score * 0.10

        # 6. Patch Availability Factor (5%)
        patch_score = 0
        if has_cve:
            patch_score = 20 if has_patch else 100
        else:
            patch_score = 0
        
        weighted_patch = patch_score * 0.05

        # Total Aggregate Application Risk Score
        total_score = (
            weighted_vuln +
            weighted_license +
            weighted_maint +
            weighted_dep +
            weighted_crit +
            weighted_patch
        )

        breakdown = {
            "vulnerability": {"raw": vuln_factor, "weighted": weighted_vuln, "weight": 0.40, "detail": f"Deduplicated active CVE count: {len([v for v in app_vulns if v['status'] == 'Vulnerable'])} (Max CVSS: {max_cvss})"},
            "license": {"raw": max_license_score, "weighted": weighted_license, "weight": 0.20, "detail": f"Peak license risk: {max_license_score}"},
            "maintenance": {"raw": avg_maint_score, "weighted": weighted_maint, "weight": 0.15, "detail": f"Average staleness score: {avg_maint_score:.1f}"},
            "dependency_type": {"raw": avg_dep_score, "weighted": weighted_dep, "weight": 0.10, "detail": f"Average dependency weight: {avg_dep_score:.1f}"},
            "business_criticality": {"raw": crit_score, "weighted": weighted_crit, "weight": 0.10, "detail": f"Level: {crit}"},
            "patch_availability": {"raw": patch_score, "weighted": weighted_patch, "weight": 0.05, "detail": f"Has active CVEs: {has_cve}, Patch status: {has_patch}"}
        }

        explanation = (
            f"Application '{app_data.get('name', app_id)}' has an aggregate risk score of {total_score:.1f} ({self.classify_score(total_score)}). "
            f"Vulnerability risk contributes {weighted_vuln:.1f} (based on deduplicated CVE metrics). "
            f"License compliance risk adds {weighted_license:.1f}. "
            f"Maintenance and dependency structure contribute {weighted_maint:.1f} and {weighted_dep:.1f} respectively. "
            f"Business Criticality weight: {weighted_crit:.1f}. Patch availability weight: {weighted_patch:.1f}."
        )

        return {
            "app_id": app_id,
            "app_name": app_data.get("name", app_id),
            "risk_score": round(total_score, 1),
            "risk_category": self.classify_score(total_score),
            "breakdown": breakdown,
            "explanation": explanation
        }
