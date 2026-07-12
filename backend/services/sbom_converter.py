"""Convert parsed CycloneDX SBOM output into pipeline-compatible formats."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import pandas as pd


def parsed_sbom_to_pipeline(
    parsed: Dict[str, Any],
    app_id: str,
    owner: str = "Unknown",
    business_criticality: str = "Medium",
) -> Tuple[Dict[str, Any], pd.DataFrame]:
    """
    Convert CycloneDXParser output to applications.json + sbom_dependencies.csv formats.

    Returns:
        (application_dict, dependencies_dataframe)
    """
    app_meta = parsed["application"]
    components = parsed["components"]
    dep_graph = parsed["dependency_graph"]
    dep_types = dep_graph.get("dependency_types", {})
    graph = dep_graph.get("graph", {})
    root_ref = dep_graph.get("root_ref", "")

    application: Dict[str, Any] = {
        "app_id": app_id,
        "app_name": app_meta.get("name", app_id),
        "owner": owner,
        "business_unit": "Uploaded SBOM",
        "business_criticality": business_criticality,
        "technology_stack": [],
        "environment": "Unknown",
        "last_scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }

    comp_by_ref: Dict[str, Dict[str, Any]] = {c["bom_ref"]: c for c in components}

    ordered_refs = _ordered_component_refs(root_ref, graph, components)

    rows: List[Dict[str, Any]] = []
    for ref in ordered_refs:
        comp = comp_by_ref.get(ref)
        if not comp:
            continue
        dep_type = dep_types.get(ref, "Direct")
        license_str = comp["licenses"][0] if comp.get("licenses") else "Unknown"
        rows.append(
            {
                "app_id": app_id,
                "dependency_name": comp["name"],
                "version": comp.get("version", "0.0.0"),
                "dependency_type": dep_type,
                "ecosystem": _ecosystem_from_purl(comp.get("purl", "")),
                "license": license_str,
                "supplier": comp.get("supplier", "Unknown"),
                "latest_version": comp.get("version", "0.0.0"),
                "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            }
        )

    if not rows and components:
        for comp in components:
            rows.append(
                {
                    "app_id": app_id,
                    "dependency_name": comp["name"],
                    "version": comp.get("version", "0.0.0"),
                    "dependency_type": "Direct",
                    "ecosystem": _ecosystem_from_purl(comp.get("purl", "")),
                    "license": comp["licenses"][0] if comp.get("licenses") else "Unknown",
                    "supplier": comp.get("supplier", "Unknown"),
                    "latest_version": comp.get("version", "0.0.0"),
                    "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                }
            )

    df = pd.DataFrame(rows)
    return application, df


def _ordered_component_refs(
    root_ref: str,
    graph: Dict[str, List[str]],
    components: List[Dict[str, Any]],
) -> List[str]:
    """BFS order from root — direct first, then transitive."""
    ordered: List[str] = []
    seen: set[str] = set()
    queue = list(graph.get(root_ref, []))
    while queue:
        ref = queue.pop(0)
        if ref in seen:
            continue
        seen.add(ref)
        ordered.append(ref)
        queue.extend(graph.get(ref, []))

    comp_refs = {c["bom_ref"] for c in components}
    for ref in comp_refs - seen:
        ordered.append(ref)
    return ordered


def _ecosystem_from_purl(purl: str) -> str:
    if purl.startswith("pkg:"):
        parts = purl[4:].split("/")
        if parts:
            return parts[0]
    return "unknown"
