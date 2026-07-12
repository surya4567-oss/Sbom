"""Global analysis state singleton — holds loaded data, graph, engines, and report."""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pandas as pd

from data_loader import load_all_data, DataLoaderError
from graph_analyzer import SBOMDependencyGraph
from license_engine import LicenseCompatibilityEngine
from risk_engine import WeightedRiskEngine
from reports.report_generator import generate_full_report

DEFAULT_APP_POLICY: Dict[str, Any] = {
    "is_proprietary": True,
    "linking_type": "dynamic",
    "distribution_type": "saas",
}


class AnalysisState:
    """Thread-safe container for the current SBOM analysis pipeline state."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.applications: List[Dict[str, Any]] = []
        self.sbom_dependencies: pd.DataFrame = pd.DataFrame()
        self.vulnerability_db: List[Dict[str, Any]] = []
        self.license_rules: Dict[str, Any] = {}
        self.sbom_graph: SBOMDependencyGraph = SBOMDependencyGraph()
        self.license_engine: Optional[LicenseCompatibilityEngine] = None
        self.risk_engine: Optional[WeightedRiskEngine] = None
        self.report: Dict[str, Any] = {}
        self.app_policy: Dict[str, Any] = dict(DEFAULT_APP_POLICY)
        self.last_scan: Optional[str] = None
        self._app_id_counter: int = 100

    def initialize(self, data_dir: Optional[str] = None) -> None:
        """Load sample datasets and build the full analysis pipeline."""
        if data_dir is None:
            root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            data_dir = os.path.join(root, "data", "sample")

        with self._lock:
            (
                self.applications,
                self.sbom_dependencies,
                self.vulnerability_db,
                self.license_rules,
                _,
            ) = load_all_data(data_dir)
            self._rebuild()

    def _rebuild(self) -> None:
        """Rebuild graph, engines, and report from current data."""
        self.sbom_graph = SBOMDependencyGraph()
        self.sbom_graph.build_graph(self.applications, self.sbom_dependencies)
        self.license_engine = LicenseCompatibilityEngine(self.license_rules)
        self.risk_engine = WeightedRiskEngine(self.license_engine)
        self.report = generate_full_report(
            self.applications,
            self.sbom_graph,
            self.vulnerability_db,
            self.app_policy,
            self.risk_engine,
        )
        scan_dates = [app.get("last_scan_date", "") for app in self.applications]
        self.last_scan = max(scan_dates) if scan_dates else datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def next_app_id(self) -> str:
        self._app_id_counter += 1
        return f"APP-{self._app_id_counter:03d}"

    def add_uploaded_application(
        self,
        application: Dict[str, Any],
        dependencies_df: pd.DataFrame,
    ) -> str:
        """Merge a newly parsed SBOM application into the analysis state."""
        with self._lock:
            app_id = application["app_id"]
            self.applications.append(application)
            if self.sbom_dependencies.empty:
                self.sbom_dependencies = dependencies_df
            else:
                self.sbom_dependencies = pd.concat(
                    [self.sbom_dependencies, dependencies_df],
                    ignore_index=True,
                )
            self._rebuild()
            return app_id

    def get_application_by_id(self, app_id: str) -> Optional[Dict[str, Any]]:
        for app in self.applications:
            if app["app_id"] == app_id:
                return app
        return None

    def get_app_report(self, app_id: str) -> Optional[Dict[str, Any]]:
        app = self.get_application_by_id(app_id)
        if not app:
            return None
        app_name = app["app_name"]
        for entry in self.report.get("Applications", []):
            if entry.get("Application Information", {}).get("Name") == app_name:
                return entry
        return None


_state: Optional[AnalysisState] = None


def get_state() -> AnalysisState:
    global _state
    if _state is None:
        _state = AnalysisState()
        try:
            _state.initialize()
        except (DataLoaderError, FileNotFoundError) as exc:
            raise RuntimeError(
                "Failed to initialize analysis state. Run 'python generate_sample_data.py' first."
            ) from exc
    return _state
