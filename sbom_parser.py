"""
SBOM Risk Analyzer - CycloneDX SBOM Parser

This module provides classes and functions to parse and normalize CycloneDX JSON SBOMs.
It extracts application metadata, component declarations, licenses, suppliers,
and parses the dependency graph to determine direct/transitive relationships.
"""

import json
import logging
from typing import Any, Dict, List, Set, Optional

logger = logging.getLogger("SBOMParser")
logger.setLevel(logging.INFO)


class SBOMParserError(Exception):
    """Base exception for all errors that occur during SBOM parsing."""
    pass


class SBOMValidationError(SBOMParserError):
    """Exception raised when CycloneDX validation checks fail."""
    pass


class CycloneDXParser:
    """
    Parser for CycloneDX JSON SBOM files.
    Supports parsing spec versions 1.2, 1.3, 1.4, and 1.5.
    """

    def __init__(self, raw_json_content: str):
        """
        Initializes the parser with the raw JSON content of the SBOM.

        Args:
            raw_json_content: The JSON string content of the CycloneDX SBOM.

        Raises:
            SBOMParserError: If the input is not valid JSON.
        """
        try:
            self.data = json.loads(raw_json_content)
        except json.JSONDecodeError as e:
            raise SBOMParserError(f"Failed to parse input as JSON: {e}") from e

    def validate(self) -> None:
        """
        Validates the parsed JSON against basic CycloneDX expectations.

        Raises:
            SBOMValidationError: If the structure does not meet CycloneDX specs.
        """
        if not isinstance(self.data, dict):
            raise SBOMValidationError("CycloneDX SBOM root must be a JSON object.")

        # Check basic CycloneDX identifier fields
        if self.data.get("bomFormat") != "CycloneDX":
            raise SBOMValidationError(
                f"Unsupported bomFormat: '{self.data.get('bomFormat')}' (Expected: 'CycloneDX')"
            )

        spec_version = self.data.get("specVersion")
        if not spec_version:
            raise SBOMValidationError("specVersion is missing from the CycloneDX SBOM.")

        # Warn or log the parsed spec version
        logger.info(f"Validating CycloneDX JSON SBOM (Spec Version: {spec_version})")

    def _extract_licenses(self, component: Dict[str, Any]) -> List[str]:
        """Extracts licenses from a CycloneDX component dict."""
        licenses_list = []
        licenses_node = component.get("licenses")
        if not licenses_node or not isinstance(licenses_node, list):
            return licenses_list

        for lic_item in licenses_node:
            if not isinstance(lic_item, dict):
                continue
            # CycloneDX can contain a 'license' dict or a 'expression' string
            if "license" in lic_item and isinstance(lic_item["license"], dict):
                lic_details = lic_item["license"]
                # Try to use SPDX id first, fallback to name
                lic_id = lic_details.get("id") or lic_details.get("name")
                if lic_id:
                    licenses_list.append(lic_id)
            elif "expression" in lic_item and isinstance(lic_item["expression"], str):
                licenses_list.append(lic_item["expression"])

        return licenses_list

    def _extract_supplier(self, component: Dict[str, Any]) -> str:
        """Extracts supplier name from a CycloneDX component dict."""
        supplier_node = component.get("supplier")
        if isinstance(supplier_node, dict):
            return supplier_node.get("name") or "Unknown"
        return "Unknown"

    def parse(self) -> Dict[str, Any]:
        """
        Parses the CycloneDX SBOM and returns a normalized dictionary.

        Returns:
            A normalized dictionary representing the SBOM contents.
            Format:
            {
                "application": {
                    "name": str,
                    "version": str,
                    "type": str,
                    "timestamp": str,
                    "supplier": str,
                    "bom_ref": str
                },
                "components": [
                    {
                        "bom_ref": str,
                        "name": str,
                        "group": str,
                        "version": str,
                        "purl": str,
                        "type": str,
                        "licenses": List[str],
                        "supplier": str,
                        "description": str
                    },
                    ...
                ],
                "dependency_graph": {
                    "root_ref": str,
                    "graph": Dict[str, List[str]],
                    "dependency_types": Dict[str, str]  # bom_ref -> "Direct" | "Transitive"
                }
            }
        """
        self.validate()

        # 1. Parse Application (Metadata)
        metadata = self.data.get("metadata", {})
        timestamp = metadata.get("timestamp", "Unknown")

        app_component = metadata.get("component", {})
        app_name = app_component.get("name") or "UnknownApplication"
        app_version = app_component.get("version") or "0.0.0"
        app_type = app_component.get("type") or "application"
        app_bom_ref = app_component.get("bom-ref") or "root-app-ref"
        app_supplier = self._extract_supplier(app_component)

        normalized_app = {
            "name": app_name,
            "version": app_version,
            "type": app_type,
            "timestamp": timestamp,
            "supplier": app_supplier,
            "bom_ref": app_bom_ref
        }

        # 2. Parse Components
        components_list = self.data.get("components", [])
        normalized_components = []
        components_by_ref = {}

        for idx, comp in enumerate(components_list):
            if not isinstance(comp, dict):
                continue

            name = comp.get("name")
            if not name:
                logger.warning(f"Component at index {idx} is missing a name. Skipping.")
                continue

            version = comp.get("version") or "0.0.0"
            bom_ref = comp.get("bom-ref") or f"comp-{idx}-{name}"
            group = comp.get("group") or ""
            purl = comp.get("purl") or ""
            comp_type = comp.get("type") or "library"
            description = comp.get("description") or ""

            licenses = self._extract_licenses(comp)
            supplier = self._extract_supplier(comp)

            comp_data = {
                "bom_ref": bom_ref,
                "name": name,
                "group": group,
                "version": version,
                "purl": purl,
                "type": comp_type,
                "licenses": licenses,
                "supplier": supplier,
                "description": description
            }
            normalized_components.append(comp_data)
            components_by_ref[bom_ref] = comp_data

        # 3. Parse Dependencies & Categorize Direct vs Transitive
        dependencies = self.data.get("dependencies", [])
        graph: Dict[str, List[str]] = {}

        # Load dependencies into adjacency list
        for dep in dependencies:
            if not isinstance(dep, dict):
                continue
            ref = dep.get("ref")
            depends_on = dep.get("dependsOn", [])
            if ref:
                # Ensure depends_on is a list of strings
                if isinstance(depends_on, list):
                    graph[ref] = [str(x) for x in depends_on]
                else:
                    graph[ref] = []

        # Find the root of the dependency graph
        # If metadata.component.bom-ref exists and is in dependencies, use it
        root_ref = app_bom_ref
        if root_ref not in graph and len(dependencies) > 0:
            # Fallback: if app_bom_ref is not defined in graph, try to find a ref with no incoming edges,
            # or simply use the first element in dependencies if nothing else works.
            all_targets = set()
            for targets in graph.values():
                all_targets.update(targets)
            sources = set(graph.keys())
            root_candidates = sources - all_targets
            if root_ref in root_candidates:
                pass  # app_bom_ref is indeed a root candidate
            elif root_candidates:
                root_ref = list(root_candidates)[0]
            else:
                root_ref = list(graph.keys())[0]

        # Calculate Dependency Types (Direct vs Transitive)
        dependency_types: Dict[str, str] = {}
        
        # Direct dependencies are those directly listed under root_ref
        direct_refs = set(graph.get(root_ref, []))
        
        # Transitive dependencies are those reachable from direct_refs, but are not direct themselves
        # and are not the root itself.
        visited: Set[str] = set()

        def dfs(node_ref: str) -> None:
            if node_ref in visited:
                return
            visited.add(node_ref)
            for child in graph.get(node_ref, []):
                dfs(child)

        # Traverse from each direct dependency
        for d_ref in direct_refs:
            # We want to traverse its children
            for child in graph.get(d_ref, []):
                dfs(child)

        transitive_refs = visited - direct_refs - {root_ref}

        # Label all component references
        for comp in normalized_components:
            ref = comp["bom_ref"]
            if ref in direct_refs:
                dependency_types[ref] = "Direct"
            elif ref in transitive_refs:
                dependency_types[ref] = "Transitive"
            else:
                # Disconnected components or components not reachable from root
                # Default to Transitive or label based on adjacency to root
                dependency_types[ref] = "Transitive"

        normalized_data = {
            "application": normalized_app,
            "components": normalized_components,
            "dependency_graph": {
                "root_ref": root_ref,
                "graph": graph,
                "dependency_types": dependency_types
            }
        }

        logger.info(
            f"Successfully parsed CycloneDX SBOM. Components: {len(normalized_components)}, "
            f"Direct: {len(direct_refs)}, Transitive: {len(transitive_refs)}"
        )
        return normalized_data
