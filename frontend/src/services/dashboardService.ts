import api from './api'
import type { DashboardData } from '../types'

export const dashboardService = {
  getDashboard: async (): Promise<DashboardData> => {
    const { data } = await api.get<DashboardData>('/dashboard')
    return data
  },
}
