import { useQuery } from '@tanstack/react-query'
import {
  AppWindow,
  AlertTriangle,
  ShieldAlert,
  Package,
  Scale,
  Wrench,
  Activity,
} from 'lucide-react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts'
import { KPICard } from '../components/KPICard'
import { ChartCard } from '../components/ChartCard'
import { ErrorCard, LoadingSkeleton } from '../components/ErrorCard'
import { dashboardService } from '../services/dashboardService'
import { formatScore } from '../utils'

const CHART_COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#06b6d4']

export function DashboardPage() {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['dashboard'],
    queryFn: dashboardService.getDashboard,
  })

  if (isLoading) return <LoadingSkeleton rows={6} />
  if (isError || !data) return <ErrorCard message="Failed to load dashboard data." onRetry={() => refetch()} />

  const { kpis, charts, recentAnalysis } = data

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-2xl font-bold text-white">Dashboard</h2>
        <p className="mt-1 text-sm text-slate-400">Executive overview of supply chain risk posture</p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <KPICard title="Total Applications" value={kpis.totalApplications} icon={AppWindow} />
        <KPICard title="Total Dependencies" value={kpis.totalDependencies} icon={Package} />
        <KPICard title="Critical Applications" value={kpis.criticalApplications} icon={ShieldAlert} variant="critical" />
        <KPICard title="High Risk Applications" value={kpis.highRiskApplications} icon={AlertTriangle} variant="warning" />
        <KPICard title="Total Vulnerabilities" value={kpis.totalVulnerabilities} icon={AlertTriangle} variant="critical" />
        <KPICard title="License Conflicts" value={kpis.licenseConflicts} icon={Scale} variant="warning" />
        <KPICard title="Maintenance Risks" value={kpis.maintenanceRisks} icon={Wrench} />
        <KPICard title="Overall Risk Score" value={formatScore(kpis.overallRiskScore)} icon={Activity} variant="critical" />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <ChartCard title="Risk Distribution">
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={charts.riskDistribution}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={80}
                label={({ name, value }) => `${name}: ${value}`}
              >
                {charts.riskDistribution.map((_, i) => (
                  <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: '#151d2e', border: '1px solid #334155' }} />
            </PieChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Severity Distribution">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={charts.severityDistribution}>
              <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 12 }} />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 12 }} />
              <Tooltip contentStyle={{ background: '#151d2e', border: '1px solid #334155' }} />
              <Bar dataKey="value" fill="#06b6d4" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Top Risky Applications">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={charts.topRiskyApplications} layout="vertical">
              <XAxis type="number" domain={[0, 100]} tick={{ fill: '#94a3b8', fontSize: 12 }} />
              <YAxis type="category" dataKey="name" width={100} tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#151d2e', border: '1px solid #334155' }} />
              <Bar dataKey="score" fill="#ef4444" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      <div className="rounded-xl border border-cyber-700 bg-cyber-800/50 p-6">
        <h3 className="mb-4 text-sm font-semibold uppercase tracking-wider text-slate-400">Recent Analysis</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div>
            <p className="text-xs text-slate-500">Last Scan</p>
            <p className="mt-1 text-lg font-semibold text-white">{recentAnalysis.lastScan}</p>
          </div>
          <div>
            <p className="text-xs text-slate-500">Applications Scanned</p>
            <p className="mt-1 text-lg font-semibold text-white">{recentAnalysis.applicationsScanned}</p>
          </div>
          <div>
            <p className="text-xs text-slate-500">Critical Findings</p>
            <p className="mt-1 text-lg font-semibold text-risk-critical">{recentAnalysis.criticalFindings}</p>
          </div>
        </div>
      </div>
    </div>
  )
}
