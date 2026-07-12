export interface KPIs {
  totalApplications: number
  totalDependencies: number
  criticalApplications: number
  highRiskApplications: number
  totalVulnerabilities: number
  licenseConflicts: number
  maintenanceRisks: number
  overallRiskScore: number
}

export interface ChartItem {
  name: string
  value: number
}

export interface TopRiskyApp {
  name: string
  score: number
  severity: string
}

export interface DashboardData {
  kpis: KPIs
  charts: {
    riskDistribution: ChartItem[]
    severityDistribution: ChartItem[]
    topRiskyApplications: TopRiskyApp[]
  }
  recentAnalysis: {
    lastScan: string
    applicationsScanned: number
    criticalFindings: number
  }
}

export interface ApplicationSummary {
  id: string
  name: string
  owner: string
  riskScore: number
  severity: string
  dependencies: number
  status: string
}

export interface DependencyTreeNode {
  id: string
  name: string
  version: string
  type: string
  children: DependencyTreeNode[]
}

export interface VulnerabilityItem {
  library: string
  version: string
  cve: string
  cvss: number
  patchAvailable: boolean
}

export interface LicenseItem {
  library: string
  license: string
  compatibility: string
  conflictReason: string
}

export interface MaintenanceItem {
  library: string
  lastUpdated: string
  deprecated: boolean
  busFactor: string
  securityPolicy: string
  riskLevel?: string
}

export interface RemediationPriorityItem {
  rank: number
  title: string
  description: string
  priority: string
}

export interface ApplicationDetail {
  id: string
  name: string
  riskOverview: {
    riskScore: number
    severity: string
    businessCriticality: string
  }
  dependencyTree: DependencyTreeNode[]
  vulnerabilities: VulnerabilityItem[]
  licenses: LicenseItem[]
  maintenance: MaintenanceItem[]
  aiExplanation: Record<string, string>
  aiRemediation: {
    'Immediate Actions'?: Array<Record<string, string>>
    'Medium-Term Improvements'?: Array<Record<string, string>>
    'Long-Term Recommendations'?: Array<Record<string, string>>
  }
  remediationPriority: RemediationPriorityItem[]
}

export interface GraphNodeData {
  label: string
  libraryName: string
  version: string
  nodeType: string
  riskLevel: string
  cves: string[]
  license: string
  maintenanceStatus: string
}

export interface GraphNode {
  id: string
  type: string
  position: { x: number; y: number }
  data: GraphNodeData
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  animated?: boolean
}

export interface DependencyGraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export interface ExecutiveSummary {
  'Total Applications': number
  'Critical Applications': number
  'High Risk Applications': number
  'Total Vulnerabilities': number
  'License Violations': number
  'Executive Summary': string
  'Key Findings': string
  'Top Risks': string
  'Business Impact': string
  'Immediate Actions': string
  'Long-Term Strategy': string
}

export interface RemediationRankItem {
  Rank: number
  Application: string
  Priority: string
  Reason: string
  'Expected Risk Reduction': string
  'Estimated Fix Effort': string
}

export interface FullReport {
  'Executive Summary': ExecutiveSummary
  'Remediation Priority': RemediationRankItem[]
  Applications: Array<Record<string, unknown>>
}

export interface UploadResult {
  appId: string
  appName: string
  components: number
  message: string
}

export interface UploadResponse {
  uploaded: UploadResult[]
  totalApplications: number
}
