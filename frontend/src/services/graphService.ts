import api from './api'
import type { DependencyGraphData } from '../types'

export interface GraphFilters {
  showVulnerabilities?: boolean
  showLicenseConflicts?: boolean
  showMaintenanceRisks?: boolean
}

export const graphService = {
  getGraph: async (appId: string, filters: GraphFilters = {}): Promise<DependencyGraphData> => {
    const { data } = await api.get<DependencyGraphData>(`/dependency-graph/${appId}`, {
      params: {
        showVulnerabilities: filters.showVulnerabilities ?? true,
        showLicenseConflicts: filters.showLicenseConflicts ?? true,
        showMaintenanceRisks: filters.showMaintenanceRisks ?? true,
      },
    })
    return data
  },
}
