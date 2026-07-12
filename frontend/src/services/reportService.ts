import api from './api'
import type { ExecutiveSummary, FullReport } from '../types'

export const reportService = {
  getReport: async (id: string = 'all'): Promise<FullReport> => {
    const { data } = await api.get<FullReport>(`/report/${id}`)
    return data
  },

  getExecutiveSummary: async (): Promise<ExecutiveSummary> => {
    const { data } = await api.get<ExecutiveSummary>('/executive-summary')
    return data
  },

  exportJson: async (id: string = 'all'): Promise<FullReport> => {
    const { data } = await api.get<FullReport>(`/report/${id}/export/json`)
    return data
  },

  exportHtml: async (id: string = 'all'): Promise<string> => {
    const { data } = await api.get<{ html: string }>(`/report/${id}/export/html`)
    return data.html
  },
}
