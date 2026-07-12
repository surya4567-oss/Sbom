"""Pydantic response schemas for API endpoints."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class KPIs(BaseModel):
    total_applications: int = Field(alias="totalApplications")
    total_dependencies: int = Field(alias="totalDependencies")
    critical_applications: int = Field(alias="criticalApplications")
    high_risk_applications: int = Field(alias="highRiskApplications")
    total_vulnerabilities: int = Field(alias="totalVulnerabilities")
    license_conflicts: int = Field(alias="licenseConflicts")
    maintenance_risks: int = Field(alias="maintenanceRisks")
    overall_risk_score: float = Field(alias="overallRiskScore")

    model_config = {"populate_by_name": True}


class ChartItem(BaseModel):
    name: str
    value: float


class TopRiskyApp(BaseModel):
    name: str
    score: float
    severity: str


class RecentAnalysis(BaseModel):
    last_scan: str = Field(alias="lastScan")
    applications_scanned: int = Field(alias="applicationsScanned")
    critical_findings: int = Field(alias="criticalFindings")

    model_config = {"populate_by_name": True}


class DashboardResponse(BaseModel):
    kpis: KPIs
    charts: Dict[str, List[Any]]
    recent_analysis: RecentAnalysis = Field(alias="recentAnalysis")

    model_config = {"populate_by_name": True}


class ApplicationSummary(BaseModel):
    id: str
    name: str
    owner: str
    risk_score: float = Field(alias="riskScore")
    severity: str
    dependencies: int
    status: str

    model_config = {"populate_by_name": True}


class RiskOverview(BaseModel):
    risk_score: float = Field(alias="riskScore")
    severity: str
    business_criticality: str = Field(alias="businessCriticality")

    model_config = {"populate_by_name": True}


class DependencyTreeNode(BaseModel):
    id: str
    name: str
    version: str
    type: str
    children: List["DependencyTreeNode"] = []

    model_config = {"populate_by_name": True}


class VulnerabilityItem(BaseModel):
    library: str
    version: str
    cve: str
    cvss: float
    patch_available: bool = Field(alias="patchAvailable")

    model_config = {"populate_by_name": True}


class LicenseItem(BaseModel):
    license: str
    compatibility: str
    conflict_reason: str = Field(alias="conflictReason")
    library: str = ""

    model_config = {"populate_by_name": True}


class MaintenanceItem(BaseModel):
    library: str
    last_updated: str = Field(alias="lastUpdated")
    deprecated: bool
    bus_factor: str = Field(alias="busFactor")
    security_policy: str = Field(alias="securityPolicy")
    risk_level: str = Field(alias="riskLevel", default="")

    model_config = {"populate_by_name": True}


class RemediationPriorityItem(BaseModel):
    rank: int
    title: str
    description: str
    priority: str


class ApplicationDetailResponse(BaseModel):
    id: str
    name: str
    risk_overview: RiskOverview = Field(alias="riskOverview")
    dependency_tree: List[DependencyTreeNode] = Field(alias="dependencyTree")
    vulnerabilities: List[VulnerabilityItem]
    licenses: List[LicenseItem]
    maintenance: List[MaintenanceItem]
    ai_explanation: Dict[str, Any] = Field(alias="aiExplanation")
    ai_remediation: Dict[str, Any] = Field(alias="aiRemediation")
    remediation_priority: List[RemediationPriorityItem] = Field(alias="remediationPriority")

    model_config = {"populate_by_name": True}


class GraphNodeData(BaseModel):
    label: str
    library_name: str = Field(alias="libraryName")
    version: str = ""
    node_type: str = Field(alias="nodeType")
    risk_level: str = Field(alias="riskLevel")
    cves: List[str] = []
    license: str = ""
    maintenance_status: str = Field(alias="maintenanceStatus")

    model_config = {"populate_by_name": True}


class GraphNode(BaseModel):
    id: str
    type: str = "default"
    position: Dict[str, float]
    data: GraphNodeData


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    animated: bool = False


class DependencyGraphResponse(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]


class UploadResult(BaseModel):
    app_id: str = Field(alias="appId")
    app_name: str = Field(alias="appName")
    components: int
    message: str

    model_config = {"populate_by_name": True}


class UploadResponse(BaseModel):
    uploaded: List[UploadResult]
    total_applications: int = Field(alias="totalApplications")

    model_config = {"populate_by_name": True}


class ErrorResponse(BaseModel):
    detail: str
    code: Optional[str] = None
