import api from './api'
import type { ApplicationDetail, ApplicationSummary } from '../types'

export const applicationService = {
  getApplications: async (): Promise<ApplicationSummary[]> => {
    const { data } = await api.get<ApplicationSummary[]>('/applications')
    return data
  },

  getApplication: async (id: string): Promise<ApplicationDetail> => {
    const { data } = await api.get<ApplicationDetail>(`/applications/${id}`)
    return data
  },
}
