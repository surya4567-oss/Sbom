"""SBOM upload service."""

from __future__ import annotations

from typing import Any, Dict, List

from sbom_parser import CycloneDXParser, SBOMParserError

from backend.services.analysis_state import AnalysisState
from backend.services.sbom_converter import parsed_sbom_to_pipeline


def upload_sbom_files(
    state: AnalysisState,
    files: List[tuple[str, bytes]],
) -> Dict[str, Any]:
    """
    Process one or more uploaded SBOM files.

    Args:
        state: Analysis state singleton.
        files: List of (filename, content_bytes) tuples.
    """
    results: List[Dict[str, Any]] = []

    for filename, content in files:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"File '{filename}' is not valid UTF-8 text.") from exc

        try:
            parser = CycloneDXParser(text)
            parsed = parser.parse()
        except SBOMParserError as exc:
            raise ValueError(f"Failed to parse '{filename}': {exc}") from exc

        app_id = state.next_app_id()
        application, deps_df = parsed_sbom_to_pipeline(parsed, app_id)
        state.add_uploaded_application(application, deps_df)

        results.append(
            {
                "appId": app_id,
                "appName": application["app_name"],
                "components": len(parsed.get("components", [])),
                "message": f"Successfully analyzed '{filename}'",
            }
        )

    return {
        "uploaded": results,
        "totalApplications": len(state.applications),
    }
